//! Control-plane mode — fleet registry, agent registration, dashboard, shell.
//!
//! One HTTP port (`$DD_PORT`, default 8080) behind the CP's own CF tunnel.
//! On startup we: self-provision a CF tunnel at `$DD_HOSTNAME`, spawn
//! cloudflared, STONITH any older CP (by `dd-{env}-cp-*` name prefix),
//! provision CF Access apps + a shared service token, start the
//! self-watchdog and collector, then serve the router. No app-layer
//! auth — CF Access validates every request at the edge.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{Path, Query, State};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use tokio::sync::{Mutex, RwLock};

use crate::cf;
use crate::collector::{self, Store};
use crate::config::Cp as Cfg;
use crate::config::ItaMode;
use crate::ee::Ee;
use crate::error::{Error, Result};
use crate::html::{self, shell};
use crate::ita;
use crate::metrics;
use crate::noise_gateway;
use crate::stonith;

/// Re-mint interval for the CP's own ITA token. The CP isn't scraped
/// by its own collector (different tunnel prefix), so a background
/// task is the only thing keeping the `control-plane` entry's claims
/// fresh on the dashboard.
const ITA_REFRESH: Duration = Duration::from_secs(180);

#[derive(Clone)]
struct St {
    cfg: Arc<Cfg>,
    ee: Arc<Ee>,
    store: Store,
    started: Instant,
    verifier: Arc<ita::Verifier>,
    /// The CP's own ITA token. Refreshed by a background task.
    cp_ita_token: Arc<RwLock<String>>,
    /// GH OIDC verifier for `/api/agents` callers (CI, humans). Same
    /// audience as dd-agent, shared owner claim.
    gh: Arc<crate::gh_oidc::Verifier>,
    /// Paired device pubkeys. Mutations persist to disk and emit a
    /// runtime view for the local ee-proxy workload.
    devices: Arc<crate::devices::Store>,
    /// TDX-quote + Noise-static-pubkey bundle. Surfaced by `/health`
    /// as `{ noise: { quote_b64, pubkey_hex } }` so a bastion-app
    /// bootstraps in one fetch (the former standalone `/attest`
    /// endpoint was folded in). Shared `Arc` with the Noise gateway
    /// module's handshake responder — one keypair / one quote per
    /// boot.
    attest: Arc<noise_gateway::attest::Attestor>,
}

pub async fn run() -> Result<()> {
    let cfg = Arc::new(Cfg::from_env()?);
    let ee = Arc::new(Ee::new("/var/lib/easyenclave/agent.sock"));

    let http = reqwest::Client::new();

    // Stage 1: mint + verify our own ITA token before touching CF.
    // We need the token as a Bearer for the hydrate call below; if
    // the old CP is still serving at `cfg.hostname`, it'll verify
    // our ITA and hand over its state.
    let verifier = match cfg.ita.mode {
        ItaMode::Intel => ita::Verifier::new(cfg.ita.jwks_url.clone(), cfg.ita.issuer.clone()),
        ItaMode::Local => ita::Verifier::new_local(cfg.ita.api_key.clone(), cfg.ita.issuer.clone()),
    };
    eprintln!(
        "cp: ITA verifier enabled (mode={:?}, issuer={})",
        cfg.ita.mode, cfg.ita.issuer
    );
    let initial_token = match mint_cp_ita(&cfg, &ee).await {
        Ok(t) => t,
        Err(e) => {
            eprintln!("cp: ITA mint failed: {e}");
            stonith::poweroff();
        }
    };
    let cp_claims_initial = match verifier.verify(&initial_token).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("cp: ITA self-verify failed: {e}");
            stonith::poweroff();
        }
    };
    eprintln!(
        "cp: own ITA verified mrtd={} tcb={}",
        cp_claims_initial.mrtd.as_deref().unwrap_or("?"),
        cp_claims_initial.tcb_status.as_deref().unwrap_or("?")
    );

    // Stage 2: hydrate state from the predecessor CP if one is live
    // at `cfg.hostname`. DNS hasn't flipped yet — any existing CNAME
    // still points at the old CP's tunnel, so this GET lands on the
    // old CP. Tolerant of failure (first boot, old CP already dead,
    // stale code without `/api/v1/admin/export`).
    //
    // Gated on "does a predecessor CP tunnel exist for this env?"
    // because on a *fresh* env (first PR deploy, or after cleanup
    // reaped the old tunnel) the hostname has no CNAME, `getaddrinfo`
    // returns NXDOMAIN, and the host's libvirt dnsmasq at
    // 192.168.122.1 negative-caches that — with a default neg-TTL of
    // minutes. Stage 3 below then creates the CNAME, but every VM on
    // the default network (including the dd-local-preview agent that
    // `release.yml` spins up right after) keeps seeing the cached
    // NXDOMAIN until the TTL expires, blowing past the agent's
    // register-retry budget and dying fatal. We diagnosed this by
    // (a) the agent's `Name does not resolve` spam in its serial log
    // while (b) the same hostname resolving from the CI runner, then
    // (c) confirming via `dig @192.168.122.1`. The `cf::list` probe
    // is against `api.cloudflare.com` (always resolves), so it's
    // safe to run unconditionally — it doesn't touch the poisonable
    // hostname at all.
    let store: Store = Arc::new(Mutex::new(HashMap::new()));
    let trust = noise_gateway::new_trust_handle();
    let devices = crate::devices::Store::load(cfg.devices_path.clone(), trust.clone())
        .await
        .map_err(|e| Error::Internal(format!("devices store load: {e}")))?;
    let predecessor_prefix = cf::cp_prefix(&cfg.common.env_label);
    let has_predecessor = match cf::list(&http, &cfg.cf).await {
        Ok(tunnels) => tunnels.iter().any(|t| {
            t["name"]
                .as_str()
                .is_some_and(|n| n.starts_with(&predecessor_prefix))
        }),
        Err(e) => {
            // Ambiguous — CF API unreachable. Skip hydrate rather than
            // probe-and-poison; the CP's own tunnel Stage 3 creates
            // below doesn't depend on this branch, and a missed
            // hydrate is strictly less bad than a poisoned dnsmasq.
            eprintln!("cp: predecessor probe failed ({e}); skipping hydrate");
            false
        }
    };
    if has_predecessor {
        hydrate_from_peer(&http, &cfg.hostname, &initial_token, &devices, &store).await;
    } else {
        eprintln!("cp: no predecessor {predecessor_prefix}* tunnel — skipping hydrate (fresh env)");
    }

    // Stage 3: create our own tunnel. `cf::create` upserts the CNAME
    // for `cfg.hostname` → our tunnel id; traffic moves to us the
    // moment CF's edge propagates that change.
    eprintln!("cp: self-provisioning tunnel for {}", cfg.hostname);
    let self_name = cf::cp_tunnel_name(&cfg.common.env_label);
    let cp_extras: Vec<(String, u16)> = vec![("block".into(), 7681)];
    let tunnel = match cf::create(&http, &cfg.cf, &self_name, &cfg.hostname, &cp_extras).await {
        Ok(t) => t,
        Err(e) => {
            eprintln!("cp: self-register failed: {e}");
            stonith::poweroff();
        }
    };
    eprintln!("cp: self tunnel {} → {}", tunnel.id, tunnel.hostname);

    spawn_cloudflared(tunnel.token.clone());

    {
        let http = http.clone();
        let cf = cfg.cf.clone();
        let id = tunnel.id.clone();
        let env = cfg.common.env_label.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(5)).await;
            stonith::kill_old_tunnels(&http, &cf, &id, &env).await;
        });
    }

    // Graceful shutdown signal. The watchdog triggers it when the
    // tunnel's been reaped by a successor CP; axum::serve below
    // awaits it and drains in-flight connections before exiting.
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::broadcast::channel::<()>(1);
    tokio::spawn(stonith::self_watchdog(
        cfg.cf.clone(),
        tunnel.id.clone(),
        shutdown_tx.clone(),
    ));

    // Stage 4: provision CF Access apps for our own tunnel. Workload
    // labels (e.g. `block` for ttyd) get the human policy; the
    // paths in the bypass list (`/register`, `/api/agents`,
    // `/api/v1/devices/trusted`, `/api/v1/admin/export`, `/noise/ws`,
    // `/health`, …) are CF-bypassed with in-code gating. `/health`
    // also carries the Noise pre-handshake quote + pubkey (the former
    // `/attest` — now inlined to save a bootstrap round-trip).
    let cp_labels: Vec<String> = cp_extras.iter().map(|(l, _)| l.clone()).collect();
    if let Err(e) = cf::provision_cp_access(
        &http,
        &cfg.cf,
        &cfg.common.env_label,
        &cfg.hostname,
        &cfg.common.owner,
        &cfg.access.admin_email,
        &cp_labels,
    )
    .await
    {
        eprintln!("cp: CF Access provisioning failed: {e}");
        stonith::poweroff();
    }
    eprintln!("cp: CF Access ready");
    let cp_ita_token = Arc::new(RwLock::new(initial_token));

    // Seed the CP into the store before the collector starts ticking.
    // The refresh loop below will keep these numbers current every
    // ITA_REFRESH ticks; we fill them once at startup so the first
    // render isn't all zeros while the refresh loop sleeps.
    let cp_m = metrics::collect().await;
    store.lock().await.insert(
        "control-plane".into(),
        collector::Agent {
            agent_id: "control-plane".into(),
            hostname: cfg.hostname.clone(),
            vm_name: format!("dd-{}-cp", cfg.common.env_label),
            attestation_type: "tdx".into(),
            status: "healthy".into(),
            last_seen: chrono::Utc::now(),
            deployment_count: 0,
            deployment_names: Vec::new(),
            cpu_percent: cp_m.cpu_pct,
            memory_used_mb: cp_m.mem_used_mb,
            memory_total_mb: cp_m.mem_total_mb,
            nets: cp_m.nets,
            disks: cp_m.disks,
            ita: cp_claims_initial,
            // CP doesn't take per-workload runtime ingress — its own tunnel
            // only routes `DD_HOSTNAME → localhost:8080`. tunnel_id stays
            // empty so the runtime-ingress endpoint rejects attempts to
            // target "control-plane".
            tunnel_id: String::new(),
            extras: Vec::new(),
        },
    );

    // Background re-mint of the CP's own ITA token. Also re-verifies
    // and updates the `control-plane` store entry so the fleet card
    // doesn't show "Expired".
    {
        let cfg = cfg.clone();
        let ee = ee.clone();
        let verifier = verifier.clone();
        let token = cp_ita_token.clone();
        let store = store.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(ITA_REFRESH).await;
                let fresh = match mint_cp_ita(&cfg, &ee).await {
                    Ok(t) => t,
                    Err(e) => {
                        eprintln!("cp: own ITA refresh mint failed: {e}");
                        continue;
                    }
                };
                let claims = match verifier.verify(&fresh).await {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("cp: own ITA refresh verify failed: {e}");
                        continue;
                    }
                };
                *token.write().await = fresh;
                // Also refresh live system metrics on the CP's own
                // store entry — the collector scrapes other tunnels,
                // not itself, so without this the /agent/control-plane
                // detail page would show empty disks/nets/cpu forever.
                let m = crate::metrics::collect().await;
                if let Some(cp) = store.lock().await.get_mut("control-plane") {
                    cp.ita = claims;
                    cp.last_seen = chrono::Utc::now();
                    cp.cpu_percent = m.cpu_pct;
                    cp.memory_used_mb = m.mem_used_mb;
                    cp.memory_total_mb = m.mem_total_mb;
                    cp.nets = m.nets;
                    cp.disks = m.disks;
                }
                eprintln!("cp: own ITA token refreshed");
            }
        });
    }

    // Start the collector with the verifier. It re-verifies each
    // scraped agent's ita_token, so expired / revoked / unsigned
    // agents drop off the dashboard automatically.
    tokio::spawn(collector::run(
        store.clone(),
        cfg.cf.clone(),
        cfg.common.env_label.clone(),
        cfg.hostname.clone(),
        ee.clone(),
        verifier.clone(),
        Duration::from_secs(cfg.scrape_interval_secs),
    ));

    let gh = crate::gh_oidc::Verifier::new(cfg.common.owner.clone(), "dd-agent".into());

    // Noise gateway state. `devices` already loaded in Stage 2 + any
    // inherited records merged in; `trust` is already populated.
    let attestor = Arc::new(
        noise_gateway::attest::Attestor::load_or_mint(&cfg.noise_key_path)
            .await
            .map_err(|e| Error::Internal(format!("noise keypair: {e}")))?,
    );
    eprintln!("cp: noise_pubkey={}", hex::encode(attestor.public_key()));
    let ee_token = std::env::var("EE_TOKEN").ok();
    let upstream = Arc::new(noise_gateway::upstream::EeAgent::new(
        std::path::PathBuf::from(noise_gateway::upstream::DEFAULT_EE_AGENT_SOCK),
        ee_token,
    ));
    let ng_state = noise_gateway::State {
        attest: attestor.clone(),
        trust: trust.clone(),
        upstream,
    };

    let state = St {
        cfg: cfg.clone(),
        ee,
        store,
        started: Instant::now(),
        verifier,
        cp_ita_token,
        gh,
        devices,
        attest: attestor,
    };

    let app = Router::new()
        .route("/", get(fleet))
        .route("/health", get(health))
        .route("/register", post(register))
        .route("/ingress/replace", post(ingress_replace))
        .route("/agent/{id}", get(agent_detail))
        .route("/agent/{id}/logs/{app}", get(agent_logs))
        .route("/api/agents", get(api_agents))
        .route("/api/v1/devices", post(create_device))
        .route("/api/v1/devices/trusted", get(list_trusted_devices))
        .route(
            "/api/v1/devices/{pubkey}",
            axum::routing::delete(revoke_device),
        )
        .route("/api/v1/admin/export", get(export_state))
        .route("/admin/enroll", get(enroll_page))
        .with_state(state)
        .merge(noise_gateway::router(ng_state));

    let addr = format!("0.0.0.0:{}", cfg.common.port);
    eprintln!("cp: listening on {addr}");
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    // `into_make_service_with_connect_info` so handlers can see the
    // peer socket address via the `ConnectInfo` extractor. Used by
    // `api_agents` to grant auth-free access to same-VM loopback
    // callers (same-VM workloads + dd-management proxy paths).
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        let _ = shutdown_rx.recv().await;
        eprintln!("cp: graceful shutdown signaled; draining in-flight requests");
    })
    .await
    .map_err(|e| Error::Internal(e.to_string()))
}

fn spawn_cloudflared(token: String) {
    tokio::spawn(async move {
        eprintln!("cp: spawning cloudflared");
        match tokio::process::Command::new("cloudflared")
            .args([
                "tunnel",
                "--no-autoupdate",
                "--metrics=",
                "run",
                "--token",
                &token,
            ])
            .spawn()
        {
            Ok(mut child) => {
                let status = child.wait().await;
                eprintln!("cp: cloudflared exited: {status:?} — poweroff");
                stonith::poweroff();
            }
            Err(e) => {
                eprintln!("cp: cloudflared spawn failed: {e} — poweroff");
                stonith::poweroff();
            }
        }
    });
}

/// Try to pull devices + agent snapshot from a predecessor CP still
/// serving at `hostname`. The CNAME hasn't flipped yet when this runs,
/// so any existing DNS record still points at the old CP's tunnel.
/// Failures (first boot, DNS miss, old code, timeout) are logged and
/// swallowed — deploy still proceeds as if fresh.
async fn hydrate_from_peer(
    http: &reqwest::Client,
    hostname: &str,
    ita_token: &str,
    devices: &crate::devices::Store,
    agents: &Store,
) {
    let url = format!("https://{hostname}/api/v1/admin/export");
    let resp = match http
        .get(&url)
        .bearer_auth(ita_token)
        .timeout(Duration::from_secs(10))
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("cp: hydrate skipped ({url}): {e}");
            return;
        }
    };
    let status = resp.status();
    if !status.is_success() {
        eprintln!("cp: hydrate skipped — {url} → {status}");
        return;
    }
    let body: serde_json::Value = match resp.json().await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("cp: hydrate parse failed ({url}): {e}");
            return;
        }
    };

    let mut imported_devices = 0usize;
    if let Some(arr) = body.get("devices").cloned() {
        match serde_json::from_value::<Vec<crate::devices::Device>>(arr) {
            Ok(devs) => {
                let n = devs.len();
                if let Err(e) = devices.import_merge(devs).await {
                    eprintln!("cp: hydrate devices.import_merge: {e}");
                } else {
                    imported_devices = n;
                }
            }
            Err(e) => eprintln!("cp: hydrate devices shape mismatch: {e}"),
        }
    }

    let mut imported_agents = 0usize;
    if let Some(arr) = body.get("agents").cloned() {
        match serde_json::from_value::<Vec<collector::Agent>>(arr) {
            Ok(ags) => {
                let mut store = agents.lock().await;
                for a in ags {
                    store.insert(a.agent_id.clone(), a);
                    imported_agents += 1;
                }
            }
            Err(e) => eprintln!("cp: hydrate agents shape mismatch: {e}"),
        }
    }

    eprintln!(
        "cp: hydrated from {hostname} — {imported_devices} device(s), {imported_agents} agent(s)"
    );
}

// ── Routes ──────────────────────────────────────────────────────────────

async fn health(
    State(s): State<St>,
    Query(q): Query<HashMap<String, String>>,
) -> Json<serde_json::Value> {
    use base64::Engine as _;
    let agents = s.store.lock().await;
    let mut body = serde_json::json!({
        "ok": true,
        "service": "cp",
        "hostname": s.cfg.hostname,
        "env": s.cfg.common.env_label,
        "ita_mode": s.cfg.ita.mode.as_str(),
        "uptime_secs": s.started.elapsed().as_secs(),
        "agent_count": agents.len(),
        "healthy_count": agents.values().filter(|a| a.status == "healthy").count(),
        // Pre-Noise-handshake bundle — the former `GET /attest`
        // endpoint folded in here so bastion-app bootstraps in one
        // fetch and we drop a CF Access bypass-app per env × per
        // service. Stable per boot; `Arc` clones are effectively free
        // per request. `quote_b64` binds the raw Noise pubkey into
        // TDX `report_data`, self-authenticating via ITA.
        "noise": {
            "quote_b64": base64::engine::general_purpose::STANDARD.encode(s.attest.quote()),
            "pubkey_hex": hex::encode(s.attest.public_key()),
        },
    });
    // `?verbose=1` folds in the CP's current ITA token so operators
    // can inspect the CP VM's TDX measurement without a second route
    // (the old `/cp/ita` + `/cp/attest` paths were removed; the
    // TDX quote for the Noise pubkey is also above, unconditionally).
    if q.get("verbose").map(|v| v.as_str()) == Some("1") {
        if let Some(obj) = body.as_object_mut() {
            obj.insert(
                "cp_ita".into(),
                serde_json::Value::String(s.cp_ita_token.read().await.clone()),
            );
        }
    }
    Json(body)
}

#[derive(Debug, Deserialize)]
struct RegisterReq {
    vm_name: String,
    ita_token: String,
    /// Optional per-workload ingress: each entry becomes
    /// `{hostname_label}.{agent_hostname}` → `localhost:{port}` in the
    /// agent's cloudflared tunnel config, in addition to the default
    /// `{agent_hostname}` → `localhost:8080` dashboard rule.
    #[serde(default)]
    extra_ingress: Vec<ExtraIngress>,
}

#[derive(Debug, Deserialize)]
struct ExtraIngress {
    hostname_label: String,
    port: u16,
}

/// POST /register — the CF Access bypass app on this path lets anyone
/// reach it; the real gate is ITA attestation in-code. We verify the
/// agent's Intel-signed quote, create its tunnel, provision its CF
/// Access apps, and return the tunnel token. `owner` / `env_label`
/// used to be in the body for double-check; they're implicit now —
/// the CP authoritatively owns them from its config and the ITA
/// token authenticates the agent regardless.
async fn register(
    State(s): State<St>,
    Json(req): Json<RegisterReq>,
) -> Result<Json<serde_json::Value>> {
    // ITA is mandatory. Any failure → 401.
    let ita_claims = s.verifier.verify(&req.ita_token).await?;
    eprintln!(
        "cp: ITA verified for {} mrtd={} tcb={}",
        req.vm_name,
        ita_claims.mrtd.as_deref().unwrap_or("?"),
        ita_claims.tcb_status.as_deref().unwrap_or("?")
    );

    let http = reqwest::Client::new();
    let name = cf::agent_tunnel_name(&s.cfg.common.env_label);
    let agent_hostname = format!("{name}.{}", s.cfg.cf.domain);
    let extras: Vec<(String, u16)> = req
        .extra_ingress
        .iter()
        .map(|e| (e.hostname_label.clone(), e.port))
        .collect();
    let tunnel = cf::create(&http, &s.cfg.cf, &name, &agent_hostname, &extras).await?;
    if !tunnel.extra_hostnames.is_empty() {
        eprintln!(
            "cp: registered extra ingress for {}: {:?}",
            req.vm_name, tunnel.extra_hostnames
        );
    }

    let labels: Vec<String> = extras.iter().map(|(l, _)| l.clone()).collect();
    if let Err(e) = cf::provision_agent_access(
        &http,
        &s.cfg.cf,
        &s.cfg.common.env_label,
        &agent_hostname,
        &s.cfg.common.owner,
        &s.cfg.access.admin_email,
        &labels,
    )
    .await
    {
        eprintln!("cp: provision_agent_access {agent_hostname} failed: {e}");
    }

    // Seed the store so the dashboard shows the agent before the first
    // collector tick. Also evict any prior entries with the same
    // vm_name — a relaunched VM registers a new agent_id/hostname, but
    // the stale old one hangs around until the collector's dead
    // threshold (5 min). During that window `/api/agents` returns
    // duplicates and host-side scripts can pick the dead hostname.
    let now = chrono::Utc::now();
    {
        let mut store = s.store.lock().await;
        let stale: Vec<String> = store
            .iter()
            .filter(|(id, a)| a.vm_name == req.vm_name && id.as_str() != name)
            .map(|(id, _)| id.clone())
            .collect();
        for id in stale {
            store.remove(&id);
        }
        store.insert(
            name.clone(),
            collector::Agent {
                agent_id: name.clone(),
                hostname: tunnel.hostname.clone(),
                vm_name: req.vm_name.clone(),
                attestation_type: "tdx".into(),
                status: "healthy".into(),
                last_seen: now,
                deployment_count: 0,
                deployment_names: Vec::new(),
                cpu_percent: 0,
                memory_used_mb: 0,
                memory_total_mb: 0,
                nets: Vec::new(),
                disks: Vec::new(),
                ita: ita_claims,
                // Seeded from the boot `extra_ingress`; runtime /deploy
                // requests extend this list via /ingress/replace (below).
                tunnel_id: tunnel.id.clone(),
                extras: extras.clone(),
            },
        );
    }

    eprintln!("cp: registered {} as {}", req.vm_name, agent_hostname);

    Ok(Json(serde_json::json!({
        "tunnel_token": tunnel.token,
        "hostname": tunnel.hostname,
        "agent_id": name,
    })))
}

#[derive(Debug, Deserialize)]
struct IngressReplaceReq {
    /// The agent's own `agent_id` (== tunnel name) as returned from
    /// /register. Used to look up the tunnel id in the CP's store.
    agent_id: String,
    /// Fresh Intel-signed attestation token from the agent — same
    /// shape as /register, re-presented here because this endpoint
    /// is CF Access-bypassed and the ITA verification is the auth.
    /// The agent already refreshes this token every few minutes for
    /// /health, so forwarding it on each call is trivial.
    ita_token: String,
    /// Full replacement set of per-workload ingress rules for this
    /// agent. The CP re-PUTs the tunnel config with `extras` first,
    /// the primary `hostname → localhost:8080` rule, and the 404
    /// catch-all. Runtime additions from /deploy live alongside the
    /// boot-time `extra_ingress` from /register here — the agent
    /// owns the merge.
    extras: Vec<IngressPair>,
}

#[derive(Debug, Deserialize)]
struct IngressPair {
    hostname_label: String,
    port: u16,
}

/// POST /ingress/replace — CF-Access-bypassed; authenticated by the
/// same Intel ITA token the agent already refreshes for /health.
/// The agent forwards its full current ingress list; the CP re-PUTs
/// the tunnel config + CNAMEs and reconciles per-workload CF Access
/// bypass apps (creates new, deletes stale).
async fn ingress_replace(
    State(s): State<St>,
    Json(req): Json<IngressReplaceReq>,
) -> Result<Json<serde_json::Value>> {
    // ITA is the auth — any failure → 401.
    let _claims = s.verifier.verify(&req.ita_token).await?;

    let (tunnel_id, hostname) = {
        let store = s.store.lock().await;
        let agent = store.get(&req.agent_id).ok_or(Error::NotFound)?;
        if agent.tunnel_id.is_empty() {
            // Control-plane pseudo-entry, or an older store entry that
            // pre-dates the tunnel_id field. Either way, nothing to update.
            return Err(Error::BadRequest(format!(
                "{} has no tunnel — runtime ingress applies only to agent tunnels",
                req.agent_id
            )));
        }
        (agent.tunnel_id.clone(), agent.hostname.clone())
    };

    let extras: Vec<(String, u16)> = req
        .extras
        .iter()
        .map(|e| (e.hostname_label.clone(), e.port))
        .collect();

    let http = reqwest::Client::new();
    let hostnames = cf::update_ingress(&http, &s.cfg.cf, &tunnel_id, &hostname, &extras).await?;

    let labels: Vec<String> = extras.iter().map(|(l, _)| l.clone()).collect();
    if let Err(e) = cf::provision_agent_access(
        &http,
        &s.cfg.cf,
        &s.cfg.common.env_label,
        &hostname,
        &s.cfg.common.owner,
        &s.cfg.access.admin_email,
        &labels,
    )
    .await
    {
        eprintln!("cp: provision_agent_access on /ingress/replace failed: {e}");
    }

    {
        let mut store = s.store.lock().await;
        if let Some(agent) = store.get_mut(&req.agent_id) {
            agent.extras = extras;
        }
    }

    eprintln!("cp: ingress/replace {} → {:?}", req.agent_id, hostnames);
    Ok(Json(serde_json::json!({
        "agent_id": req.agent_id,
        "extra_hostnames": hostnames,
    })))
}

/// Mint the CP's own ITA token at startup. Fatal on any failure —
/// the CP refuses to start without proving its own TDX measurement.
async fn mint_cp_ita(cfg: &Cfg, ee: &Ee) -> Result<String> {
    if cfg.ita.mode == ItaMode::Local {
        return ita::mint_local(&cfg.ita.issuer, &cfg.ita.api_key, "control-plane");
    }
    use base64::Engine;
    let nonce = base64::engine::general_purpose::STANDARD.encode(uuid::Uuid::new_v4().as_bytes());
    let quote_b64 = ee.attest(&nonce).await?["quote_b64"]
        .as_str()
        .ok_or_else(|| Error::Upstream("EE attest returned no quote_b64".into()))?
        .to_string();
    ita::mint(&cfg.ita.base_url, &cfg.ita.api_key, &quote_b64).await
}

// ── Fleet dashboard ──────────────────────────────────────────────────────

async fn fleet(State(s): State<St>) -> Response {
    let agents = s.store.lock().await.clone();
    let mut rows = String::new();
    let mut by_id: Vec<_> = agents.into_iter().collect();
    by_id.sort_by(|a, b| a.0.cmp(&b.0));
    for (_, a) in &by_id {
        let mem = if a.memory_total_mb > 0 {
            format!("{}/{} MB", a.memory_used_mb, a.memory_total_mb)
        } else {
            "—".into()
        };
        rows.push_str(&format!(
            r#"<tr><td><a href="/agent/{id}">{vm}</a></td>
<td><span class="pill {st}">{st}</span></td><td>{att}</td>
<td>{cpu}%</td><td>{mem}</td><td>{n}</td>
<td class="dim">{host}</td></tr>"#,
            id = html::escape(&a.agent_id),
            vm = html::escape(&a.vm_name),
            st = html::escape(&a.status),
            att = html::escape(&a.attestation_type),
            cpu = a.cpu_percent,
            n = a.deployment_count,
            host = html::escape(&a.hostname),
        ));
    }

    let table = if by_id.is_empty() {
        r#"<div class="empty">No agents registered</div>"#.to_string()
    } else {
        format!(
            r#"<table><tr><th>vm</th><th>status</th><th>att</th><th>cpu</th><th>mem</th><th>wl</th><th>host</th></tr>{rows}</table>"#
        )
    };

    Html(shell(
        "DD Fleet",
        &html::nav(&[("Fleet", "/", true)]),
        &format!(
            r#"<h1>Fleet</h1><div class="sub">{host} · env {env} · {n} agent(s)</div>{table}"#,
            host = html::escape(&s.cfg.hostname),
            env = html::escape(&s.cfg.common.env_label),
            n = by_id.len(),
        ),
    ))
    .into_response()
}

// ── Devices API ─────────────────────────────────────────────────────────
//
// Paired client-device X25519 pubkeys that the local Noise gateway
// accepts during the handshake. POST + DELETE are behind the CP's
// human CF Access app (admin enrollment); the machine-readable
// `/trusted` view is edge-bypassed for cross-VM agent polls.

/// GET /api/v1/admin/export — full state snapshot for a successor CP
/// to hydrate from during a zero-downtime deploy. Returns the
/// device registry (full records, including revoked) and the live
/// agents HashMap. CF-Access-bypassed at the edge; gated in-code by
/// a valid owner-scoped ITA Bearer (any attested enclave in the
/// fleet can authenticate). The new CP calls this against the old
/// CP's still-pointed DNS before flipping CNAMEs.
async fn export_state(
    State(s): State<St>,
    headers: axum::http::HeaderMap,
) -> Result<Json<serde_json::Value>> {
    let bearer = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(Error::Unauthorized)?;
    // Any owner-scoped ITA token is OK for v0; tighten to a pinned
    // MRTD list once we stop rotating measurements every dev push.
    let _ = s.verifier.verify(bearer).await?;

    let devices = s.devices.export_full().await;
    let agents: Vec<collector::Agent> = s.store.lock().await.values().cloned().collect();
    Ok(Json(serde_json::json!({
        "devices": devices,
        "agents": agents,
    })))
}

/// GET /api/v1/devices/trusted — minimal, machine-readable view:
/// `{ "pubkeys": ["<hex>", ...] }` with only currently-trusted keys.
/// CF-Access-bypassed at the edge so cross-VM dd-agent callers can
/// reach it; gated in-code by the same three-way policy as
/// `/api/agents`. This is the agent's poll target for mirroring the
/// trust list into its in-memory `TrustHandle`.
async fn list_trusted_devices(
    State(s): State<St>,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: axum::http::HeaderMap,
) -> Result<Json<serde_json::Value>> {
    if !agents_auth_ok(&s, peer, &headers).await {
        return Err(Error::Unauthorized);
    }
    let devices = s.devices.list().await;
    let pubkeys: Vec<String> = devices
        .into_iter()
        .filter(|d| d.revoked_at_ms.is_none())
        .map(|d| d.pubkey)
        .collect();
    Ok(Json(serde_json::json!({ "pubkeys": pubkeys })))
}

#[derive(Debug, Deserialize)]
struct CreateDeviceReq {
    pubkey: String,
    label: String,
}

/// POST /api/v1/devices — enroll a device pubkey. Idempotent on
/// pubkey: re-posting with a new label replaces the record in place.
async fn create_device(
    State(s): State<St>,
    Json(req): Json<CreateDeviceReq>,
) -> Result<(axum::http::StatusCode, Json<crate::devices::Device>)> {
    let pubkey = req.pubkey.to_lowercase();
    crate::devices::validate_hex_pubkey(&pubkey).map_err(|e| Error::BadRequest(e.to_string()))?;
    let label = req.label.trim().to_string();
    if label.is_empty() || label.len() > 128 {
        return Err(Error::BadRequest("label must be 1..=128 chars".into()));
    }
    let device = crate::devices::Device {
        pubkey,
        label,
        created_at_ms: chrono::Utc::now().timestamp_millis(),
        revoked_at_ms: None,
    };
    s.devices
        .upsert(device.clone())
        .await
        .map_err(|e| Error::Internal(format!("devices upsert: {e}")))?;
    Ok((axum::http::StatusCode::CREATED, Json(device)))
}

/// DELETE /api/v1/devices/{pubkey} — revoke. Returns 404 if the
/// pubkey isn't known or was already revoked.
async fn revoke_device(
    State(s): State<St>,
    Path(pubkey): Path<String>,
) -> Result<Json<serde_json::Value>> {
    let pubkey = pubkey.to_lowercase();
    let now = chrono::Utc::now().timestamp_millis();
    let ok = s
        .devices
        .revoke(&pubkey, now)
        .await
        .map_err(|e| Error::Internal(format!("devices revoke: {e}")))?;
    if !ok {
        return Err(Error::NotFound);
    }
    Ok(Json(serde_json::json!({
        "revoked": pubkey,
        "at_ms": now,
    })))
}

/// GET /admin/enroll?pubkey=…&label=… — human-facing confirmation
/// page that a `bastion-app` (CLI or desktop) bounces the operator
/// to. Behind the CP's human CF Access app: by the time this
/// handler renders, the browser has a valid CF Access session
/// cookie. The rendered page POSTs to `/api/v1/devices` with the
/// same cookie via `credentials: "same-origin"`, completing the
/// enrollment that headless clients can't do themselves.
///
/// Intent-over-GET: we deliberately don't enroll on page load —
/// the user clicks Confirm so a copy-pasted link can't silently
/// add a pubkey.
async fn enroll_page(Query(q): Query<HashMap<String, String>>) -> Response {
    let pubkey = q.get("pubkey").cloned().unwrap_or_default();
    let label = q.get("label").cloned().unwrap_or_default();

    if let Err(e) = crate::devices::validate_hex_pubkey(&pubkey) {
        return Html(shell(
            "Enroll device",
            "",
            &format!(
                r#"<div class="card"><h1>Invalid pubkey</h1><p class="dim">{}</p></div>"#,
                html::escape(&e.to_string())
            ),
        ))
        .into_response();
    }
    if label.trim().is_empty() || label.len() > 128 {
        return Html(shell(
            "Enroll device",
            "",
            r#"<div class="card"><h1>Invalid label</h1><p class="dim">label must be 1..=128 chars</p></div>"#,
        ))
        .into_response();
    }

    let short = &pubkey[..16];
    let body = format!(
        r#"<div class="card">
  <h1>Enroll this device?</h1>
  <div class="row"><span>Label</span><span>{label}</span></div>
  <div class="row"><span>Pubkey</span><code>{short}…</code></div>
  <p class="dim">
    Confirming adds this X25519 public key to the trust list. Every
    DD agent mirrors that list within 30&nbsp;s; thereafter, a client
    holding the matching private key can open Noise_IK sessions to
    any enclave in the fleet. Revoke any time with
    <code>DELETE /api/v1/devices/&lt;pubkey&gt;</code>.
  </p>
  <p id="status"></p>
  <div style="display:flex;gap:8px">
    <button id="confirm" class="ok">Confirm</button>
    <a href="/" class="btn">Cancel</a>
  </div>
</div>
<script>
  const pubkey = {pubkey_js};
  const label  = {label_js};
  const status = document.getElementById("status");
  document.getElementById("confirm").addEventListener("click", async (ev) => {{
    ev.target.disabled = true;
    status.textContent = "Enrolling…";
    try {{
      const resp = await fetch("/api/v1/devices", {{
        method: "POST",
        credentials: "same-origin",
        headers: {{ "Content-Type": "application/json" }},
        body: JSON.stringify({{ pubkey, label }}),
      }});
      if (!resp.ok) {{
        const text = await resp.text();
        status.innerHTML = "<span class='err'>Enrollment failed: " +
          resp.status + " " + text.slice(0, 400).replace(/</g, "&lt;") +
          "</span>";
        ev.target.disabled = false;
        return;
      }}
      status.innerHTML = "<span class='ok'>Enrolled ✓ — you can close this tab</span>";
    }} catch (e) {{
      status.innerHTML = "<span class='err'>Network error: " + String(e) + "</span>";
      ev.target.disabled = false;
    }}
  }});
</script>"#,
        label = html::escape(&label),
        short = html::escape(short),
        pubkey_js = serde_json::to_string(&pubkey).unwrap_or_else(|_| "\"\"".into()),
        label_js = serde_json::to_string(&label).unwrap_or_else(|_| "\"\"".into()),
    );

    Html(shell("Enroll device", "", &body)).into_response()
}

/// GET /api/agents — JSON list of
/// `{agent_id, vm_name, hostname, status, last_seen}`.
///
/// Gated three ways, any of which succeeds:
/// 1. **Loopback** (`127.0.0.1`, `::1`) — same-VM callers (any
///    workload on the CP VM, dd-agent's own proxy). Trust is anchored
///    by EE's Tier-1 seal: a process on the VM at all is already a
///    workload EE spawned and gave the shared `EE_TOKEN` env to.
/// 2. **GH OIDC** — CI action (`dd-deploy`, etc.) presents a GitHub
///    Actions OIDC JWT as `Authorization: Bearer <jwt>`; we verify
///    against GitHub's JWKS and require the principal carried by
///    `DD_OWNER`/`DD_OWNER_ID`/`DD_OWNER_KIND` (see
///    [`gh_oidc::Principal::matches`]). Matches the pattern dd-agent
///    uses for `/deploy` + `/exec`.
/// 3. **ITA** — dd-agent's `/api/agents` proxy forwards its own
///    Intel-attested ITA token so cross-VM calls from any attested
///    DD agent in the fleet succeed.
///
/// Without one of those, respond with 401.
async fn api_agents(
    State(s): State<St>,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: axum::http::HeaderMap,
) -> Result<Json<Vec<serde_json::Value>>> {
    if !agents_auth_ok(&s, peer, &headers).await {
        return Err(Error::Unauthorized);
    }
    let agents = s.store.lock().await.clone();
    Ok(Json(
        agents
            .into_values()
            .map(|a| {
                serde_json::json!({
                    "agent_id": a.agent_id,
                    "vm_name": a.vm_name,
                    "hostname": a.hostname,
                    "status": a.status,
                    "last_seen": a.last_seen.to_rfc3339(),
                })
            })
            .collect(),
    ))
}

/// Accept the request if the caller is on the loopback interface
/// (same-VM trust — any CP-VM workload / dd-agent-proxy) or presents a valid
/// bearer that verifies as either a GitHub Actions OIDC token for
/// this owner, or a fresh Intel-signed ITA token for this CP. See
/// [`api_agents`] for the full policy.
async fn agents_auth_ok(
    s: &St,
    peer: std::net::SocketAddr,
    headers: &axum::http::HeaderMap,
) -> bool {
    if peer.ip().is_loopback() {
        return true;
    }
    let bearer = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| {
            s.strip_prefix("Bearer ")
                .or_else(|| s.strip_prefix("bearer "))
        })
        .map(str::trim)
        .filter(|t| !t.is_empty());
    let Some(token) = bearer else {
        return false;
    };
    // `gh.verify` already enforces the principal match — a successful
    // result is itself the authorization.
    if s.gh.verify(token).await.is_ok() {
        return true;
    }
    if s.verifier.verify(token).await.is_ok() {
        return true;
    }
    false
}

async fn agent_detail(State(s): State<St>, Path(id): Path<String>) -> Response {
    let agent = s.store.lock().await.get(&id).cloned();
    let Some(a) = agent else {
        return (
            axum::http::StatusCode::NOT_FOUND,
            Html(shell("Not found", "", "<h1>Not found</h1>")),
        )
            .into_response();
    };

    let is_cp = a.agent_id == "control-plane";
    let mut workloads = String::new();
    for w in &a.deployment_names {
        let link = if is_cp {
            format!(
                r#"<a href="/agent/{id}/logs/{w}">logs</a>"#,
                id = html::escape(&a.agent_id),
                w = html::escape(w)
            )
        } else {
            String::new()
        };
        workloads.push_str(&format!(
            r#"<tr><td>{w}</td><td>{link}</td></tr>"#,
            w = html::escape(w)
        ));
    }
    let wl_table = if a.deployment_names.is_empty() {
        r#"<div class="empty">No workloads</div>"#.to_string()
    } else {
        format!(r#"<table><tr><th>workload</th><th></th></tr>{workloads}</table>"#)
    };

    let ita_card = {
        let c = &a.ita;
        let tcb = c.tcb_status.as_deref().unwrap_or("?");
        let tcb_cls = match tcb {
            "UpToDate" | "OK" => "running",
            "OutOfDate" | "SWHardeningNeeded" | "ConfigurationNeeded" => "deploying",
            "Revoked" | "Invalid" => "failed",
            _ => "idle",
        };
        let mrtd_short = c
            .mrtd
            .as_deref()
            .map(|m| if m.len() > 16 { &m[..16] } else { m })
            .unwrap_or("?");
        let delta = c.exp - chrono::Utc::now().timestamp();
        let expiry = if delta > 0 {
            format!("in {}m", delta / 60)
        } else {
            "expired".to_string()
        };
        format!(
            r#"<div class="section">Intel Trust Authority</div>
<div class="card">
  <div class="row"><span>TCB status</span><span class="pill {cls}">{tcb}</span></div>
  <div class="row"><span>MRTD</span><span class="dim">{mrtd}…</span></div>
  <div class="row"><span>Attester type</span><span>{typ}</span></div>
  <div class="row"><span>Expires</span><span>{exp}</span></div>
</div>"#,
            cls = tcb_cls,
            tcb = html::escape(tcb),
            mrtd = html::escape(mrtd_short),
            typ = html::escape(c.attester_type.as_deref().unwrap_or("?")),
            exp = expiry,
        )
    };

    // `{hostname-base}-block.{tld}` is the ttyd subdomain (CP's own
    // tunnel publishes it; agents publish it via their register-time
    // `extra_ingress`). Flat shape so Universal SSL covers the cert.
    // Human-gated by CF Access.
    let term_host = html::escape(&cf::label_hostname(&a.hostname, "block"));
    let extra = if is_cp {
        format!(
            r#"<p><a href="https://{term_host}/" target="_blank">Terminal ↗</a> · <a href="/health">health (incl. noise quote)</a> · <a href="/health?verbose=1">health?verbose=1 (incl. ita)</a></p>"#
        )
    } else {
        format!(
            r#"<p><a href="https://{h}/">open agent dashboard ↗</a> · <a href="https://{term_host}/" target="_blank">Terminal ↗</a></p>"#,
            h = html::escape(&a.hostname)
        )
    };

    let disks_table = if a.disks.is_empty() {
        String::new()
    } else {
        let mut rows = String::new();
        for d in &a.disks {
            rows.push_str(&format!(
                "<tr><td>{m}</td><td class=\"dim\">{fs}</td><td>{u} / {t}</td></tr>",
                m = html::escape(&d.mount),
                fs = html::escape(&d.fstype),
                u = metrics::format_bytes_si(d.used_bytes),
                t = metrics::format_bytes_si(d.total_bytes),
            ));
        }
        format!(
            r#"<div class="section">Disks</div><table><tr><th>mount</th><th>fs</th><th>used</th></tr>{rows}</table>"#
        )
    };

    let nets_table = if a.nets.is_empty() {
        String::new()
    } else {
        let mut rows = String::new();
        for n in &a.nets {
            rows.push_str(&format!(
                "<tr><td>{i}</td><td>{rx}</td><td>{tx}</td></tr>",
                i = html::escape(&n.iface),
                rx = metrics::format_bytes_si(n.rx_bytes),
                tx = metrics::format_bytes_si(n.tx_bytes),
            ));
        }
        format!(
            r#"<div class="section">Network</div><table><tr><th>iface</th><th>rx</th><th>tx</th></tr>{rows}</table>"#
        )
    };

    Html(shell(
        &format!("DD — {}", a.vm_name),
        &html::nav(&[("Fleet", "/", false)]),
        &format!(
            r#"<div class="back"><a href="/">← fleet</a></div>
<h1>{vm}</h1><div class="sub">{id} · {host}</div>
<div class="card">
  <div class="row"><span>Status</span><span class="pill {st}">{st}</span></div>
  <div class="row"><span>Attestation</span><span>{att}</span></div>
  <div class="row"><span>Last seen</span><span>{ls}</span></div>
  <div class="row"><span>CPU</span><span>{cpu}%</span></div>
  <div class="row"><span>Memory</span><span>{mu}/{mt} MB</span></div>
</div>
{disks_table}
{nets_table}
{ita_card}
<div class="section">Workloads</div>{wl_table}
{extra}"#,
            vm = html::escape(&a.vm_name),
            id = html::escape(&a.agent_id),
            host = html::escape(&a.hostname),
            st = html::escape(&a.status),
            att = html::escape(&a.attestation_type),
            ls = a.last_seen.to_rfc3339(),
            cpu = a.cpu_percent,
            mu = a.memory_used_mb,
            mt = a.memory_total_mb,
            disks_table = disks_table,
            nets_table = nets_table,
            ita_card = ita_card,
        ),
    ))
    .into_response()
}

/// GET /agent/control-plane/logs/{app} — show logs for a CP workload via the
/// local easyenclave socket. For other agents we'd proxy to their dashboard;
/// today the detail page links directly there instead.
async fn agent_logs(State(s): State<St>, Path((id, app)): Path<(String, String)>) -> Response {
    if id != "control-plane" {
        return Error::NotFound.into_response();
    }
    // Find the workload by app_name.
    let list = s.ee.list().await.unwrap_or_default();
    let dep_id = list["deployments"]
        .as_array()
        .and_then(|a| a.iter().find(|d| d["app_name"].as_str() == Some(&app)))
        .and_then(|d| d["id"].as_str())
        .map(String::from);
    let Some(dep_id) = dep_id else {
        return Error::NotFound.into_response();
    };
    let logs = s.ee.logs(&dep_id).await.unwrap_or_default();
    let text = logs["lines"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str())
                .map(html::escape)
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default();
    Html(shell(
        &format!("{app} logs"),
        &html::nav(&[("Fleet", "/", false)]),
        &format!(
            r#"<div class="back"><a href="/agent/control-plane">← control-plane</a></div>
<h1>{app}</h1><div class="sub">auto-refresh 2s</div>
<pre style="max-height:80vh">{text}</pre>
<script>setTimeout(() => location.reload(), 2000);</script>"#,
            app = html::escape(&app)
        ),
    ))
    .into_response()
}
