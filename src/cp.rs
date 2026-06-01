//! Control-plane mode — fleet registry, agent registration, dashboard, shell.
//!
//! One HTTP port (`$DD_PORT`, default 8080) behind the CP's own CF tunnel.
//! On startup we: self-provision a CF tunnel at `$DD_HOSTNAME`, spawn
//! cloudflared, STONITH any older CP (by `dd-{env}-cp-*` name prefix),
//! provision routing entries, start the self-watchdog and collector,
//! then serve the router. Browser auth is in-app GitHub App OAuth via
//! a shared DD session cookie; machine auth remains ITA / GitHub
//! Actions OIDC.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, Uri};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use tokio::sync::{Mutex, Notify, RwLock};

use crate::cf;
use crate::collector::{self, Store};
use crate::config::Cp as Cfg;
use crate::config::ItaMode;
use crate::ee::Ee;
use crate::error::{Error, Result};
use crate::html::{self, shell};
use crate::ita;
use crate::metrics;
use crate::stonith;
use crate::taint::IntegrityState;
use crate::units::{AgentMode, UnitKind};

/// Re-mint interval for the CP's own ITA token. The CP isn't scraped
/// by its own collector (different tunnel prefix), so a background
/// task is the only thing keeping the `control-plane` entry's claims
/// fresh on the dashboard.
const ITA_REFRESH: Duration = Duration::from_secs(180);
const EE_READY_TIMEOUT: Duration = Duration::from_secs(90);

#[derive(Clone)]
struct St {
    cfg: Arc<Cfg>,
    ee: Arc<Ee>,
    store: Store,
    collector_wake: Arc<Notify>,
    started: Instant,
    verifier: Arc<ita::Verifier>,
    /// Expected enclave measurement allowlist (MRTD/TCB). Pins the fleet to
    /// known-good code; unpinned = observe-only.
    expected: Arc<ita::ExpectedMeasurements>,
    /// The CP's own ITA token. Refreshed by a background task.
    cp_ita_token: Arc<RwLock<String>>,
    /// GH OIDC verifier for `/api/agents` callers (CI, humans). Same
    /// audience as dd-agent, shared owner claim.
    gh: Arc<crate::gh_oidc::Verifier>,
}

pub async fn run() -> Result<()> {
    let cfg = Arc::new(Cfg::from_env()?);
    let ee = Arc::new(Ee::new("/var/lib/easyenclave/agent.sock"));

    let http = cf::http_client();
    let h = match ee.wait_ready(EE_READY_TIMEOUT).await {
        Ok(h) => h,
        Err(e) => {
            eprintln!("cp: EE socket not ready: {e}");
            stonith::poweroff();
        }
    };
    eprintln!(
        "cp: EE connected (attestation={})",
        h["attestation_type"].as_str().unwrap_or("?")
    );

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
        hydrate_from_peer(&http, &cfg.hostname, &initial_token, &store).await;
    } else {
        eprintln!("cp: no predecessor {predecessor_prefix}* tunnel — skipping hydrate (fresh env)");
    }

    // Stage 3: create our own tunnel. `cf::create` upserts the CNAME
    // for `cfg.hostname` → our tunnel id; traffic moves to us the
    // moment CF's edge propagates that change.
    eprintln!("cp: self-provisioning tunnel for {}", cfg.hostname);
    let self_name = cf::cp_tunnel_name(&cfg.common.env_label);
    let cp_extras: Vec<(String, u16)> = vec![("shell".into(), 7682)];
    let tunnel = match cf::create(&http, &cfg.cf, &self_name, &cfg.hostname, &cp_extras).await {
        Ok(t) => t,
        Err(e) => {
            eprintln!("cp: self-register failed: {e}");
            stonith::poweroff();
        }
    };
    eprintln!("cp: self tunnel {} → {}", tunnel.id, tunnel.hostname);

    spawn_cloudflared(tunnel.token.clone());

    // STONITH (new-CP-evicts-old: tunnel-delete + a self-watchdog that
    // powered the old CP off when its tunnel vanished) was removed — it
    // churned the Cloudflare tunnel hand-off, and the SSH/prod relaunch
    // already destroys the old CP VM before booting this one. We just
    // create our tunnel, flip the CNAME (in `cf::create`), and serve.

    // Stage 4: delete legacy Cloudflare Access apps for our published
    // hosts/paths. DD owns browser and machine auth in-code; Cloudflare
    // should only provide DNS + tunnel ingress.
    let cp_labels: Vec<String> = cp_extras.iter().map(|(l, _)| l.clone()).collect();
    let mut access_cleanup_ready = false;
    for attempt in 1..=5 {
        match cf::delete_cp_access_apps(
            &http,
            &cfg.cf,
            &cfg.common.env_label,
            &cfg.hostname,
            &cp_labels,
        )
        .await
        {
            Ok(()) => {
                access_cleanup_ready = true;
                break;
            }
            Err(e) => {
                eprintln!("cp: Cloudflare Access cleanup attempt {attempt}/5 failed: {e}");
                tokio::time::sleep(Duration::from_secs(5 * attempt)).await;
            }
        }
    }
    if !access_cleanup_ready {
        eprintln!("cp: Cloudflare Access cleanup failed after retries");
        stonith::poweroff();
    }
    eprintln!("cp: Cloudflare Access cleanup complete");
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
            agent_mode: AgentMode::ReadWrite,
            integrity_state: IntegrityState::Controlled,
            owner: None,
            deployment_count: 0,
            deployment_names: Vec::new(),
            unit_count: 0,
            units: Vec::new(),
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
            oracles: Vec::new(),
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
    let expected = Arc::new(ita::ExpectedMeasurements::from_env());
    if expected.is_pinned() {
        eprintln!(
            "cp: measurement pinning ON ({} mrtd(s), tcb={}, enforce={})",
            expected.mrtds.len(),
            expected.tcb_status.as_deref().unwrap_or("any"),
            expected.enforce
        );
    } else {
        eprintln!("cp: measurement pinning OFF (DD_EXPECTED_MRTD unset) — observe only");
    }

    let collector_wake = Arc::new(Notify::new());
    tokio::spawn(collector::run(
        store.clone(),
        cfg.cf.clone(),
        cfg.common.env_label.clone(),
        cfg.hostname.clone(),
        ee.clone(),
        verifier.clone(),
        expected.clone(),
        collector_wake.clone(),
        Duration::from_secs(cfg.scrape_interval_secs),
        Duration::from_secs(cfg.discovery_interval_secs),
        cfg.scraper_shard_index,
        cfg.scraper_shard_total,
    ));

    let gh = crate::gh_oidc::Verifier::new(cfg.common.owner.clone(), "dd-agent".into());

    let state = St {
        cfg: cfg.clone(),
        ee,
        store,
        collector_wake,
        started: Instant::now(),
        verifier,
        expected,
        cp_ita_token,
        gh,
    };

    let app = Router::new()
        .route("/", get(fleet))
        .route("/auth/github/start", get(auth_start))
        .route("/auth/github/callback", get(auth_callback))
        .route("/auth/device/start", post(device_start))
        .route("/auth/device/poll", post(device_poll))
        .route("/health", get(health))
        .route("/register", post(register))
        .route("/ingress/replace", post(ingress_replace))
        .route("/agent/{id}", get(agent_detail))
        .route("/agent/{id}/logs/{app}", get(agent_logs))
        .route("/api/agents", get(api_agents))
        .route("/api/fleet", get(fleet_fragment))
        .route("/admin/cf/snapshot", get(cf_snapshot_handler))
        .route("/api/v1/admin/export", get(export_state))
        .route("/admin/enroll", get(enroll_page))
        .with_state(state);

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

/// Try to pull an agent snapshot from a predecessor CP still serving
/// at `hostname`. The CNAME hasn't flipped yet when this runs,
/// so any existing DNS record still points at the old CP's tunnel.
/// Failures (first boot, DNS miss, old code, timeout) are logged and
/// swallowed — deploy still proceeds as if fresh.
async fn hydrate_from_peer(
    http: &reqwest::Client,
    hostname: &str,
    ita_token: &str,
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

    eprintln!("cp: hydrated from {hostname} — {imported_agents} agent(s)");
}

// ── Routes ──────────────────────────────────────────────────────────────

async fn health(
    State(s): State<St>,
    Query(q): Query<HashMap<String, String>>,
) -> Json<serde_json::Value> {
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
        "oracle_count": agents.values().map(|a| a.oracles.len()).sum::<usize>(),
    });
    // `?verbose=1` folds in the CP's current ITA token so operators
    // can inspect the CP VM's TDX measurement without a second route.
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

/// POST /register — ITA attestation is the gate. We verify the
/// agent's Intel-signed quote, create its tunnel, remove legacy
/// Cloudflare Access apps, and return the tunnel token. `owner` / `env_label`
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
    if let Err(reason) = s.expected.check(&ita_claims) {
        if s.expected.enforce {
            eprintln!("cp: REJECT register {}: {reason}", req.vm_name);
            return Err(Error::Unauthorized);
        }
        eprintln!(
            "cp: WARN register {} measurement mismatch (not enforced): {reason}",
            req.vm_name
        );
    }

    let http = cf::http_client();
    let name = cf::agent_tunnel_name(&s.cfg.common.env_label);
    let agent_hostname = format!("{name}.{}", s.cfg.cf.domain);
    let extras: Vec<(String, u16)> = req
        .extra_ingress
        .iter()
        .map(|e| (e.hostname_label.clone(), e.port))
        .collect();
    let tunnel_extras = agent_tunnel_extras(&extras);
    let tunnel = cf::create(&http, &s.cfg.cf, &name, &agent_hostname, &tunnel_extras).await?;
    if !tunnel.extra_hostnames.is_empty() {
        eprintln!(
            "cp: registered extra ingress for {}: {:?}",
            req.vm_name, tunnel.extra_hostnames
        );
    }

    let labels: Vec<String> = tunnel_extras.iter().map(|(l, _)| l.clone()).collect();
    if let Err(e) = cf::delete_agent_access_apps(
        &http,
        &s.cfg.cf,
        &s.cfg.common.env_label,
        &agent_hostname,
        &labels,
    )
    .await
    {
        eprintln!("cp: delete_agent_access_apps {agent_hostname} failed: {e}");
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
                status: "registering".into(),
                last_seen: now,
                agent_mode: AgentMode::ReadWrite,
                integrity_state: IntegrityState::Controlled,
                owner: None,
                deployment_count: 0,
                deployment_names: Vec::new(),
                unit_count: 0,
                units: Vec::new(),
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
                oracles: Vec::new(),
            },
        );
    }

    eprintln!("cp: registered {} as {}", req.vm_name, agent_hostname);
    s.collector_wake.notify_one();

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
    /// shape as /register, re-presented here because ITA verification
    /// is the auth.
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

/// POST /ingress/replace — authenticated by the same Intel ITA token
/// the agent already refreshes for /health. The agent forwards its
/// full current ingress list; the CP re-PUTs the tunnel config +
/// CNAMEs and removes legacy Cloudflare Access apps for those hosts.
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
    let tunnel_extras = agent_tunnel_extras(&extras);

    let http = cf::http_client();
    let hostnames =
        cf::update_ingress(&http, &s.cfg.cf, &tunnel_id, &hostname, &tunnel_extras).await?;

    let labels: Vec<String> = tunnel_extras.iter().map(|(l, _)| l.clone()).collect();
    if let Err(e) = cf::delete_agent_access_apps(
        &http,
        &s.cfg.cf,
        &s.cfg.common.env_label,
        &hostname,
        &labels,
    )
    .await
    {
        eprintln!("cp: delete_agent_access_apps on /ingress/replace failed: {e}");
    }

    {
        let mut store = s.store.lock().await;
        if let Some(agent) = store.get_mut(&req.agent_id) {
            agent.extras = extras;
        }
    }

    eprintln!("cp: ingress/replace {} → {:?}", req.agent_id, hostnames);
    s.collector_wake.notify_one();
    Ok(Json(serde_json::json!({
        "agent_id": req.agent_id,
        "extra_hostnames": hostnames,
    })))
}

fn agent_tunnel_extras(extras: &[(String, u16)]) -> Vec<(String, u16)> {
    let mut tunnel_extras = extras.to_vec();
    if !tunnel_extras
        .iter()
        .any(|(label, _)| label == cf::AGENT_API_LABEL)
    {
        tunnel_extras.push((cf::AGENT_API_LABEL.to_string(), cf::AGENT_API_PORT));
    }
    tunnel_extras
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

fn path_and_query(uri: &Uri) -> &str {
    uri.path_and_query().map(|p| p.as_str()).unwrap_or("/")
}

fn require_browser_auth(s: &St, headers: &HeaderMap, uri: &Uri) -> Option<Response> {
    if s.cfg
        .auth
        .verify_session(&s.cfg.common.owner, headers)
        .is_some()
    {
        None
    } else {
        let return_to = crate::auth::absolute_url(headers, &s.cfg.hostname, path_and_query(uri));
        Some(crate::auth::unauthorized_or_redirect(
            &s.cfg.auth,
            headers,
            &return_to,
        ))
    }
}

#[derive(Debug, Deserialize)]
struct AuthStart {
    return_to: String,
}

#[derive(Debug, Deserialize)]
struct AuthCallback {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

async fn auth_start(State(s): State<St>, Query(q): Query<AuthStart>) -> Response {
    match s.cfg.auth.start_response(&q.return_to, &s.cfg.cf.domain) {
        Ok(resp) => resp,
        Err(e) => e.into_response(),
    }
}

async fn auth_callback(
    State(s): State<St>,
    headers: HeaderMap,
    Query(q): Query<AuthCallback>,
) -> Response {
    if let Some(error) = q.error {
        return Error::BadRequest(format!("github auth failed: {error}")).into_response();
    }
    let Some(code) = q.code.as_deref() else {
        return Error::BadRequest("missing github code".into()).into_response();
    };
    let Some(state) = q.state.as_deref() else {
        return Error::BadRequest("missing github state".into()).into_response();
    };
    match s
        .cfg
        .auth
        .callback_response(
            &crate::system_http_client(),
            &s.cfg.common.owner,
            code,
            state,
            &headers,
            &s.cfg.cf.domain,
        )
        .await
    {
        Ok(resp) => resp,
        Err(e) => e.into_response(),
    }
}

/// `POST /auth/device/start` — native/iOS client begins GitHub device
/// flow. Returns `{device_code, user_code, verification_uri, interval,
/// expires_in}`; the client shows the user code + opens the URL, then
/// polls `/auth/device/poll`.
async fn device_start(State(s): State<St>) -> Response {
    match s.cfg.auth.device_start(&crate::system_http_client()).await {
        Ok(body) => Json(body).into_response(),
        Err(e) => e.into_response(),
    }
}

#[derive(Debug, Deserialize)]
struct DevicePollReq {
    device_code: String,
}

/// `POST /auth/device/poll {device_code}` — exchange an approved device
/// code for a CP-issued bearer. 202 `{status:"pending"}` until the user
/// approves; then `{status:"ready", token, exp, login, is_fleet_admin}`.
/// The bearer is the same signed session the cookie carries; send it as
/// `Authorization: Bearer` to `/api/fleet`.
async fn device_poll(State(s): State<St>, Json(req): Json<DevicePollReq>) -> Response {
    match s
        .cfg
        .auth
        .device_poll(
            &crate::system_http_client(),
            &s.cfg.common.owner,
            &req.device_code,
        )
        .await
    {
        Ok(crate::auth::DevicePoll::Pending) => (
            axum::http::StatusCode::ACCEPTED,
            Json(serde_json::json!({ "status": "pending" })),
        )
            .into_response(),
        Ok(crate::auth::DevicePoll::Ready {
            token,
            exp,
            login,
            is_fleet_admin,
        }) => Json(serde_json::json!({
            "status": "ready",
            "token": token,
            "exp": exp,
            "login": login,
            "is_fleet_admin": is_fleet_admin,
        }))
        .into_response(),
        Err(e) => e.into_response(),
    }
}

/// Live dashboard script: poll `/api/fleet` every 5s, swap the
/// `#fleet-body` fragment, and drive the "updated Xs ago" indicator —
/// which goes amber then red if polling stalls (frozen or unreachable
/// CP), so liveness is visible at a glance without any alerting backend.
const FLEET_POLL_JS: &str = r#"(function(){
  var body=document.getElementById('fleet-body');
  var stat=document.getElementById('fleet-status');
  if(!body||!stat)return;
  var last=Date.now();
  function ago(){
    var s=Math.round((Date.now()-last)/1000);
    stat.textContent='updated '+(s<2?'just now':s+'s ago');
    stat.className='live'+(s>20?' stale':'')+(s>60?' dead':'');
  }
  function tick(){
    fetch('/api/fleet',{credentials:'same-origin'})
      .then(function(r){ if(!r.ok) throw new Error(r.status); return r.text(); })
      .then(function(h){ body.innerHTML=h; last=Date.now(); ago(); })
      .catch(function(){ ago(); });
  }
  setInterval(tick,5000); setInterval(ago,1000); tick();
})();"#;

/// Resolve the human caller (native-client bearer OR browser session
/// cookie), bound to this fleet. `Err` is the ready-to-return
/// redirect-to-login (browser) or 401 (API).
// The `Err` arm is a ready-to-return axum `Response` (inherently large);
// boxing it would just churn every call site for no real benefit.
#[allow(clippy::result_large_err)]
fn human_session(
    s: &St,
    headers: &HeaderMap,
    uri: &Uri,
) -> std::result::Result<crate::auth::Session, Response> {
    match s.cfg.auth.verify_human(&s.cfg.common.owner, headers) {
        Some(sess) => Ok(sess),
        None => Err(crate::auth::unauthorized_or_redirect(
            &s.cfg.auth,
            headers,
            &crate::auth::absolute_url(headers, &s.cfg.hostname, path_and_query(uri)),
        )),
    }
}

/// Whether `session` may see `agent`. Fleet admins (fleet owner / org
/// member) see everything; everyone else sees an agent only if its owner
/// matches their GitHub login/id or one of their orgs. Unowned agents
/// (incl. the `control-plane` entry) are admin-only.
fn agent_visible(session: &crate::auth::Session, agent: &collector::Agent) -> bool {
    owner_visible(session, agent.owner.as_ref())
}

/// Pure visibility decision (extracted for testing): admin sees all;
/// otherwise the item is visible only if its owner matches the viewer.
fn owner_visible(
    session: &crate::auth::Session,
    owner: Option<&crate::gh_oidc::Principal>,
) -> bool {
    session.is_fleet_admin || owner.is_some_and(|p| principal_matches_viewer(p, session))
}

fn principal_matches_viewer(p: &crate::gh_oidc::Principal, s: &crate::auth::Session) -> bool {
    use crate::gh_oidc::PrincipalKind::{Org, Repo, User};
    match p.kind {
        User => p.id == s.user_id || p.name.eq_ignore_ascii_case(&s.login),
        Org => s.orgs.iter().any(|o| o.eq_ignore_ascii_case(&p.name)),
        // "owner/repo" — match the owner segment against login or orgs.
        Repo => {
            let seg = p.name.split('/').next().unwrap_or(&p.name);
            seg.eq_ignore_ascii_case(&s.login) || s.orgs.iter().any(|o| o.eq_ignore_ascii_case(seg))
        }
    }
}

/// Id-sorted fleet snapshot scoped to what `session` may see.
async fn scoped_snapshot(
    s: &St,
    session: &crate::auth::Session,
) -> Vec<(String, collector::Agent)> {
    let mut by_id: Vec<_> = s
        .store
        .lock()
        .await
        .iter()
        .filter(|(_, a)| agent_visible(session, a))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    by_id.sort_by(|a, b| a.0.cmp(&b.0));
    by_id
}

/// Does the caller want JSON (the native client) vs the HTML fragment
/// (the browser dashboard poll)?
fn wants_json(headers: &HeaderMap) -> bool {
    headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.contains("application/json"))
        .unwrap_or(false)
}

/// Scoped fleet snapshot as JSON for the native/iOS client.
fn fleet_json(s: &St, by_id: &[(String, collector::Agent)]) -> serde_json::Value {
    let healthy = by_id.iter().filter(|(_, a)| a.status == "healthy").count();
    let unit_total: usize = by_id.iter().map(|(_, a)| a.units.len()).sum();
    let oracle_total: usize = by_id.iter().map(|(_, a)| a.oracles.len()).sum();
    serde_json::json!({
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "env": s.cfg.common.env_label,
        "hostname": s.cfg.hostname,
        "summary": {
            "agents": by_id.len(),
            "healthy": healthy,
            "units": unit_total,
            "oracles": oracle_total,
        },
        "agents": by_id.iter().map(|(_, a)| a).collect::<Vec<_>>(),
    })
}

/// Render the live-swappable fleet body: summary line, count cards, the
/// agent table, and the managed-units table. Shared by the initial
/// server-rendered `fleet()` page and the `/api/fleet` poll fragment so
/// the two never diverge.
fn render_fleet_body(host: &str, env: &str, by_id: &[(String, collector::Agent)]) -> String {
    let healthy = by_id.iter().filter(|(_, a)| a.status == "healthy").count();
    let read_only = by_id
        .iter()
        .filter(|(_, a)| a.agent_mode == AgentMode::ReadOnly)
        .count();
    let read_write = by_id
        .iter()
        .filter(|(_, a)| a.agent_mode == AgentMode::ReadWrite)
        .count();
    let unit_total: usize = by_id.iter().map(|(_, a)| a.units.len()).sum();
    let oracle_total: usize = by_id.iter().map(|(_, a)| a.oracles.len()).sum();

    let mut rows = String::new();
    for (_, a) in by_id {
        let mem = if a.memory_total_mb > 0 {
            format!("{}/{} MB", a.memory_used_mb, a.memory_total_mb)
        } else {
            "—".into()
        };
        rows.push_str(&format!(
            r#"<tr><td><a href="/agent/{id}">{vm}</a></td>
<td><span class="pill {st_cls}">{st}</span></td><td>{att}</td>
<td>{mode}</td><td>{integrity}</td>
<td>{cpu}%</td><td>{mem}</td><td>{n}</td><td>{u}</td><td>{o}</td>
<td>{actions}</td><td class="dim">{host}</td></tr>"#,
            id = html::escape(&a.agent_id),
            vm = html::escape(&a.vm_name),
            st_cls = status_class(&a.status),
            st = html::escape(&a.status),
            att = html::escape(&a.attestation_type),
            mode = html::escape(a.agent_mode.as_str()),
            integrity = html::escape(&format!("{:?}", a.integrity_state).to_lowercase()),
            cpu = a.cpu_percent,
            n = a.deployment_count,
            u = a.unit_count,
            o = a.oracles.len(),
            actions = agent_actions(a),
            host = html::escape(&a.hostname),
        ));
    }

    let mut unit_rows = String::new();
    for (_, a) in by_id {
        for u in &a.units {
            let refs = if u.refs.is_empty() {
                r#"<span class="dim">none</span>"#.into()
            } else {
                u.refs
                    .iter()
                    .take(3)
                    .map(|r| html::unit_ref(&r.label, &r.value))
                    .collect::<Vec<_>>()
                    .join(" · ")
            };
            let actions = unit_actions(a, u);
            unit_rows.push_str(&format!(
                r#"<tr><td><a href="/agent/{id}">{vm}</a></td><td>{title}<div class="dim">{app}</div></td><td>{kind}</td><td>{mode}</td><td>{integrity}</td><td><span class="pill {cls}">{status}</span></td><td>{logs}</td><td>{actions}</td><td>{refs}</td></tr>"#,
                id = html::escape(&a.agent_id),
                vm = html::escape(&a.vm_name),
                title = html::escape(&u.title),
                app = html::escape(&u.app_name),
                kind = html::escape(u.kind.as_str()),
                mode = html::escape(u.agent_mode.as_str()),
                integrity = html::escape(&format!("{:?}", u.agent_integrity_state).to_lowercase()),
                cls = status_class(&u.status),
                status = html::escape(&u.status),
                logs = if u.log_line_count == 0 {
                    r#"<span class="dim">No logs yet</span>"#.into()
                } else {
                    format!("{} line(s)", u.log_line_count)
                },
                actions = actions,
                refs = refs,
            ));
        }
    }

    let table = if by_id.is_empty() {
        r#"<div class="empty">No agents registered</div>"#.to_string()
    } else {
        format!(
            r#"<table><tr><th>vm</th><th>status</th><th>att</th><th>mode</th><th>integrity</th><th>cpu</th><th>mem</th><th>wl</th><th>units</th><th>oracles</th><th>actions</th><th>host</th></tr>{rows}</table>"#
        )
    };
    let unit_table = if unit_rows.is_empty() {
        r#"<div class="empty">No managed units reported yet</div>"#.to_string()
    } else {
        format!(
            r#"<div class="section">Managed units</div><table><tr><th>agent</th><th>unit</th><th>kind</th><th>mode</th><th>integrity</th><th>status</th><th>logs</th><th>actions</th><th>refs</th></tr>{unit_rows}</table>"#
        )
    };

    format!(
        r#"<div class="sub">{host} · env {env} · {n} agent(s)</div>
<div class="cards">
  <div class="card"><div class="label">Healthy</div><div class="value green">{healthy}/{n}</div></div>
  <div class="card"><div class="label">Read/write</div><div class="value blue">{read_write}</div></div>
  <div class="card"><div class="label">Read-only</div><div class="value mauve">{read_only}</div></div>
  <div class="card"><div class="label">Units</div><div class="value peach">{unit_total}</div></div>
  <div class="card"><div class="label">Oracles</div><div class="value green">{oracle_total}</div></div>
</div>
{table}{unit_table}"#,
        host = html::escape(host),
        env = html::escape(env),
        n = by_id.len(),
    )
}

async fn fleet(State(s): State<St>, headers: HeaderMap, uri: Uri) -> Response {
    let session = match human_session(&s, &headers, &uri) {
        Ok(sess) => sess,
        Err(resp) => return resp,
    };
    let by_id = scoped_snapshot(&s, &session).await;
    let body = render_fleet_body(&s.cfg.hostname, &s.cfg.common.env_label, &by_id);
    Html(shell(
        "DD Fleet",
        &html::nav(&[("Fleet", "/", true)]),
        &format!(
            r#"<div class="livebar"><h1>Fleet</h1><span id="fleet-status" class="live">updated just now</span></div>
<div id="fleet-body">{body}</div>
<script>{FLEET_POLL_JS}</script>"#
        ),
    ))
    .into_response()
}

/// `GET /api/fleet` — ownership-scoped fleet, for both the browser
/// dashboard poll (HTML fragment) and the native/iOS client
/// (`Accept: application/json`). Auth is `verify_human`: the `dd_session`
/// cookie (browser) OR a CP-issued `Authorization: Bearer` (native).
/// The result is filtered to what the caller may see — admins get the
/// whole fleet, everyone else only the deployments they own.
async fn fleet_fragment(State(s): State<St>, headers: HeaderMap, uri: Uri) -> Response {
    let session = match human_session(&s, &headers, &uri) {
        Ok(sess) => sess,
        Err(resp) => return resp,
    };
    let by_id = scoped_snapshot(&s, &session).await;
    if wants_json(&headers) {
        Json(fleet_json(&s, &by_id)).into_response()
    } else {
        Html(render_fleet_body(
            &s.cfg.hostname,
            &s.cfg.common.env_label,
            &by_id,
        ))
        .into_response()
    }
}

// ── Enrollment broker ───────────────────────────────────────────────────
//
// CP keeps enrollment stateless: it authenticates the browser and redirects
// to a read-write agent. The agent stores and enforces paired-device trust.

/// GET /api/v1/admin/export — full state snapshot for a successor CP
/// to hydrate from during a zero-downtime deploy. Returns the live
/// agents HashMap. Gated in-code by a valid owner-scoped ITA Bearer
/// (any attested enclave in the fleet can authenticate). The new CP
/// calls this against the old CP's still-pointed DNS before flipping
/// CNAMEs.
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

    let agents: Vec<collector::Agent> = s.store.lock().await.values().cloned().collect();
    Ok(Json(serde_json::json!({
        "agents": agents,
    })))
}

/// GET /admin/enroll?pubkey=…&label=… — human-facing confirmation
/// broker. CP does not store paired-device trust; it redirects the
/// authenticated browser to a healthy read-write agent, where the
/// agent-local enrollment page performs the mutation.
async fn enroll_page(
    State(s): State<St>,
    headers: HeaderMap,
    uri: Uri,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    if let Some(resp) = require_browser_auth(&s, &headers, &uri) {
        return resp;
    }
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

    let agents = s.store.lock().await;
    let Some(agent) = agents.values().find(|a| {
        a.status == "healthy"
            && a.agent_mode == AgentMode::ReadWrite
            && a.agent_id != "control-plane"
    }) else {
        return Html(shell(
            "Enroll device",
            "",
            r#"<div class="card"><h1>No read-write agent available</h1><p class="dim">Try again after an agent registers.</p></div>"#,
        ))
        .into_response();
    };
    let url = format!(
        "https://{}/admin/enroll?pubkey={}&label={}",
        agent.hostname,
        urlencoding::encode(&pubkey),
        urlencoding::encode(&label),
    );
    Redirect::temporary(&url).into_response()
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
                    "agent_mode": a.agent_mode,
                    "integrity_state": a.integrity_state,
                    "last_seen": a.last_seen.to_rfc3339(),
                    "deployment_count": a.deployment_count,
                    "unit_count": a.unit_count,
                    "units": a.units,
                    "oracle_count": a.oracles.len(),
                    "oracles": a.oracles,
                })
            })
            .collect(),
    ))
}

/// GET /admin/cf/snapshot — operator debug surface. Returns CP state,
/// CF API state, and a server-computed `drift` block (orphans /
/// missing / mismatches). Same auth as `/api/agents` (loopback OR GH
/// OIDC OR ITA bearer). The iOS Manage view consumes this to surface
/// reconciliation issues for operator triage. Read-only — no mutations.
async fn cf_snapshot_handler(
    State(s): State<St>,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: axum::http::HeaderMap,
) -> Result<Json<crate::cf_snapshot::Snapshot>> {
    if !agents_auth_ok(&s, peer, &headers).await {
        return Err(Error::Unauthorized);
    }
    let http = cf::http_client();
    let snap = crate::cf_snapshot::snapshot(
        &http,
        &s.cfg.cf,
        &s.cfg.common.env_label,
        &s.cfg.hostname,
        &s.store,
    )
    .await;
    Ok(Json(snap))
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

async fn agent_detail(
    State(s): State<St>,
    headers: HeaderMap,
    uri: Uri,
    Path(id): Path<String>,
) -> Response {
    let session = match human_session(&s, &headers, &uri) {
        Ok(sess) => sess,
        Err(resp) => return resp,
    };
    let agent = s.store.lock().await.get(&id).cloned();
    // Scope: hide agents the caller may not see behind the same 404 as a
    // missing one, so a non-admin can't probe for agents they don't own.
    let Some(a) = agent.filter(|a| agent_visible(&session, a)) else {
        return (
            axum::http::StatusCode::NOT_FOUND,
            Html(shell("Not found", "", "<h1>Not found</h1>")),
        )
            .into_response();
    };

    let is_cp = a.agent_id == "control-plane";
    let mut workloads = String::new();
    if !a.units.is_empty() {
        for u in &a.units {
            let refs = if u.refs.is_empty() {
                r#"<span class="dim">none</span>"#.into()
            } else {
                u.refs
                    .iter()
                    .map(|r| html::unit_ref(&r.label, &r.value))
                    .collect::<Vec<_>>()
                    .join(" · ")
            };
            let caps = if u.capabilities.is_empty() {
                String::new()
            } else {
                u.capabilities
                    .iter()
                    .map(|c| format!(r#"<span class="pill idle">{}</span>"#, html::escape(c)))
                    .collect::<Vec<_>>()
                    .join(" ")
            };
            workloads.push_str(&format!(
                r#"<tr><td>{title}<div class="dim">{app}</div></td><td>{kind}</td><td><span class="pill {cls}">{status}</span></td><td>{logs}</td><td>{caps}</td><td>{refs}</td></tr>"#,
                title = html::escape(&u.title),
                app = html::escape(&u.app_name),
                kind = html::escape(u.kind.as_str()),
                cls = status_class(&u.status),
                status = html::escape(&u.status),
                logs = if u.log_line_count == 0 {
                    r#"<span class="dim">No logs yet</span>"#.into()
                } else {
                    format!("{} line(s)", u.log_line_count)
                },
                caps = caps,
                refs = refs,
            ));
        }
    } else {
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
    }
    let wl_table = if workloads.is_empty() {
        r#"<div class="empty">No managed units</div>"#.to_string()
    } else if !a.units.is_empty() {
        format!(
            r#"<table><tr><th>unit</th><th>kind</th><th>status</th><th>logs</th><th>capabilities</th><th>refs</th></tr>{workloads}</table>"#
        )
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

    let has_shell = is_cp || a.units.iter().any(|u| u.kind == UnitKind::Shell);
    let extra = if is_cp {
        // `{hostname-base}-shell.{tld}` is the dd-shell subdomain (CP's own
        // tunnel publishes it; agents publish it via their register-time
        // `extra_ingress`). Flat shape so Universal SSL covers the cert.
        // Human-gated by DD browser auth.
        let term_host = html::escape(&cf::label_hostname(&a.hostname, "shell"));
        format!(
            r#"<p><a href="https://{term_host}/" target="_blank">Terminal ↗</a> · <a href="/health">health (incl. noise quote)</a> · <a href="/health?verbose=1">health?verbose=1 (incl. ita)</a></p>"#
        )
    } else if has_shell {
        let term_host = html::escape(&cf::label_hostname(&a.hostname, "shell"));
        format!(
            r#"<p><a href="https://{h}/">open agent dashboard ↗</a> · <a href="https://{term_host}/" target="_blank">Terminal ↗</a></p>"#,
            h = html::escape(&a.hostname)
        )
    } else {
        format!(
            r#"<p><a href="https://{h}/">open agent dashboard ↗</a></p>"#,
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
  <div class="row"><span>Mode</span><span>{mode}</span></div>
  <div class="row"><span>Integrity</span><span>{integrity}</span></div>
  <div class="row"><span>Attestation</span><span>{att}</span></div>
  <div class="row"><span>Last seen</span><span>{ls}</span></div>
  <div class="row"><span>CPU</span><span>{cpu}%</span></div>
  <div class="row"><span>Memory</span><span>{mu}/{mt} MB</span></div>
</div>
{disks_table}
{nets_table}
{ita_card}
<div class="section">Managed units</div>{wl_table}
{extra}"#,
            vm = html::escape(&a.vm_name),
            id = html::escape(&a.agent_id),
            host = html::escape(&a.hostname),
            st = html::escape(&a.status),
            mode = html::escape(a.agent_mode.as_str()),
            integrity = html::escape(&format!("{:?}", a.integrity_state).to_lowercase()),
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

fn status_class(status: &str) -> &'static str {
    match status {
        "healthy" | "running" => "running",
        "deploying" | "registering" | "unknown" | "stale" => "deploying",
        "failed" | "exited" | "error" | "dead" => "failed",
        _ => "idle",
    }
}

fn action_link(label: &str, href: &str) -> String {
    format!(
        r#"<a href="{href}" target="_blank">{label}</a>"#,
        href = html::escape(href),
        label = html::escape(label),
    )
}

fn has_shell(a: &collector::Agent) -> bool {
    a.agent_id == "control-plane" || a.units.iter().any(|u| u.kind == UnitKind::Shell)
}

fn agent_actions(a: &collector::Agent) -> String {
    let mut links = Vec::new();
    links.push(action_link("details", &format!("/agent/{}", a.agent_id)));
    if a.agent_id != "control-plane" {
        links.push(action_link(
            "dashboard",
            &format!("https://{}/", a.hostname),
        ));
        links.push(action_link(
            "api",
            &format!("https://{}/health", cf::agent_api_hostname(&a.hostname)),
        ));
    } else {
        links.push(action_link("health", "/health"));
    }
    if has_shell(a) {
        links.push(action_link(
            "shell",
            &format!("https://{}/", cf::label_hostname(&a.hostname, "shell")),
        ));
    }
    for oracle in &a.oracles {
        if let Some(url) = &oracle.vanity_url {
            links.push(action_link(&oracle.hostname_label, url));
        }
    }
    if links.is_empty() {
        r#"<span class="dim">none</span>"#.into()
    } else {
        links.join(" · ")
    }
}

fn unit_actions(a: &collector::Agent, u: &crate::units::ManagedUnit) -> String {
    let mut links = Vec::new();
    if u.kind == UnitKind::Shell {
        links.push(action_link(
            "shell",
            &format!("https://{}/", cf::label_hostname(&a.hostname, "shell")),
        ));
    }
    if let Some(oracle) = &u.oracle {
        if let Some(url) = &oracle.vanity_url {
            links.push(action_link("oracle", url));
        }
    }
    if a.agent_id == "control-plane" && u.log_line_count > 0 {
        links.push(action_link(
            "logs",
            &format!("/agent/control-plane/logs/{}", u.app_name),
        ));
    }
    if links.is_empty() {
        r#"<span class="dim">none</span>"#.into()
    } else {
        links.join(" · ")
    }
}

/// GET /agent/control-plane/logs/{app} — show logs for a CP workload via the
/// local easyenclave socket. For other agents we'd proxy to their dashboard;
/// today the detail page links directly there instead.
async fn agent_logs(
    State(s): State<St>,
    headers: HeaderMap,
    uri: Uri,
    Path((id, app)): Path<(String, String)>,
) -> Response {
    if let Some(resp) = require_browser_auth(&s, &headers, &uri) {
        return resp;
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gh_oidc::{Principal, PrincipalKind};

    fn sess(login: &str, user_id: u64, orgs: &[&str], admin: bool) -> crate::auth::Session {
        crate::auth::Session {
            login: login.into(),
            user_id,
            exp: i64::MAX,
            owner_name: "devopsdefender".into(),
            owner_id: 1,
            owner_kind: PrincipalKind::Org,
            orgs: orgs.iter().map(|o| o.to_string()).collect(),
            is_fleet_admin: admin,
        }
    }
    fn principal(kind: PrincipalKind, name: &str, id: u64) -> Principal {
        Principal {
            name: name.into(),
            id,
            kind,
        }
    }

    #[test]
    fn admin_sees_everything_including_unowned() {
        let admin = sess("ops", 7, &[], true);
        assert!(owner_visible(&admin, None));
        assert!(owner_visible(
            &admin,
            Some(&principal(PrincipalKind::User, "someone", 999))
        ));
    }

    #[test]
    fn non_admin_cannot_see_unowned() {
        let user = sess("alice", 42, &["acme"], false);
        assert!(!owner_visible(&user, None));
    }

    #[test]
    fn non_admin_sees_own_by_user_id_or_login() {
        let user = sess("alice", 42, &[], false);
        // match by numeric id (login differs / renamed)
        assert!(owner_visible(
            &user,
            Some(&principal(PrincipalKind::User, "renamed", 42))
        ));
        // match by login (case-insensitive)
        assert!(owner_visible(
            &user,
            Some(&principal(PrincipalKind::User, "ALICE", 999))
        ));
        // different user → hidden
        assert!(!owner_visible(
            &user,
            Some(&principal(PrincipalKind::User, "bob", 43))
        ));
    }

    #[test]
    fn non_admin_sees_org_owned_only_if_member() {
        let user = sess("alice", 42, &["acme", "widgets"], false);
        assert!(owner_visible(
            &user,
            Some(&principal(PrincipalKind::Org, "Acme", 5))
        ));
        assert!(!owner_visible(
            &user,
            Some(&principal(PrincipalKind::Org, "other-co", 6))
        ));
    }

    #[test]
    fn non_admin_repo_owner_matches_owner_segment() {
        let user = sess("alice", 42, &["acme"], false);
        // repo owned by org the viewer belongs to
        assert!(owner_visible(
            &user,
            Some(&principal(PrincipalKind::Repo, "acme/app", 9))
        ));
        // repo owned by the viewer's own login
        let solo = sess("alice", 42, &[], false);
        assert!(owner_visible(
            &solo,
            Some(&principal(PrincipalKind::Repo, "alice/tool", 10))
        ));
        // repo owned by a stranger org
        assert!(!owner_visible(
            &user,
            Some(&principal(PrincipalKind::Repo, "evil/app", 11))
        ));
    }

    #[test]
    fn fleet_body_empty_fleet_renders_zeroed_summary() {
        let body = render_fleet_body("app.example.com", "production", &[]);
        // Summary line reflects host/env/count.
        assert!(body.contains("app.example.com · env production · 0 agent(s)"));
        // Healthy card shows 0/0; five summary cards present.
        assert!(body.contains(r#"<div class="value green">0/0</div>"#));
        assert_eq!(body.matches(r#"<div class="card">"#).count(), 5);
        // Empty-state rows for both tables.
        assert!(body.contains("No agents registered"));
        assert!(body.contains("No managed units reported yet"));
    }

    #[test]
    fn fleet_body_escapes_host_and_env() {
        let body = render_fleet_body("a<b>", "e&f", &[]);
        assert!(body.contains("a&lt;b&gt; · env e&amp;f"));
        assert!(!body.contains("a<b>"));
    }
}
