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

use bastion;

use crate::cf;
use crate::collector::{self, Store};
use crate::config::Cp as Cfg;
use crate::ee::Ee;
use crate::error::{Error, Result};
use crate::html::{self, shell};
use crate::ita;
use crate::metrics;
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
    /// CP's long-term Noise static keypair — exposed via `/attest`
    /// and used to authenticate m2m connections from agents.
    /// `None` when `--noise-key-dir` wasn't passed (local dev).
    noise: Option<Arc<dd_common::noise_static::NoiseStatic>>,
    /// `agent_id → pinned Noise pubkey` — populated at registration.
    /// Future m2m endpoints (Phase 2c+) consult this before accepting
    /// a handshake.
    agent_pubkeys: crate::noise_m2m::AgentRegistry,
}

pub async fn run() -> Result<()> {
    let cfg = Arc::new(Cfg::from_env()?);
    let ee = Arc::new(Ee::new("/var/lib/easyenclave/agent.sock"));

    eprintln!("cp: self-provisioning tunnel for {}", cfg.hostname);
    let http = reqwest::Client::new();
    let self_name = cf::cp_tunnel_name(&cfg.common.env_label);
    // `block.<hostname>` routes to the bastion workload on port 7681.
    // The CP boot set always includes bastion, so the CNAME + ingress
    // rule always resolve. CF Access gates this subdomain with the
    // same human policy as the CP dashboard (see `ADMIN_LABELS` in
    // cf.rs for the gating decision).
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

    tokio::spawn(stonith::self_watchdog(cfg.cf.clone(), tunnel.id.clone()));

    let store: Store = Arc::new(Mutex::new(HashMap::new()));

    // Provision CF Access apps — one human app + bypass paths for
    // endpoints gated in-code. Fatal on any failure; the CP refuses
    // to start without edge auth configured.
    //
    // Workload labels (for flat `{base}-{label}.{tld}` subdomains) come
    // straight from the CP's extras list. Admin labels get the human
    // policy; others get bypass. Stale apps under this CP's subdomain
    // space (e.g. a `term.<host>` left over from a previous deploy)
    // get reaped inside `provision_cp_access`.
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

    // ITA verifier — required.
    let verifier = ita::Verifier::new(cfg.ita.jwks_url.clone(), cfg.ita.issuer.clone());
    eprintln!("cp: ITA verifier enabled (issuer={})", cfg.ita.issuer);

    // Mint + verify our own ITA token. Any failure is fatal —
    // attestation is mandatory.
    let initial_token = match mint_cp_ita(&cfg, &ee).await {
        Ok(t) => t,
        Err(e) => {
            eprintln!("cp: ITA mint failed: {e}");
            stonith::poweroff();
        }
    };
    let cp_claims = match verifier.verify(&initial_token).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("cp: ITA self-verify failed: {e}");
            stonith::poweroff();
        }
    };
    eprintln!(
        "cp: own ITA verified mrtd={} tcb={}",
        cp_claims.mrtd.as_deref().unwrap_or("?"),
        cp_claims.tcb_status.as_deref().unwrap_or("?")
    );
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
            ita: cp_claims,
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

    // Load or mint the CP's long-term Noise static keypair if
    // `DD_NOISE_KEY_DIR` is set. Optional for local dev; mandatory in
    // prod because the fleet m2m cutover relies on it.
    let noise: Option<Arc<dd_common::noise_static::NoiseStatic>> =
        match std::env::var("DD_NOISE_KEY_DIR")
            .ok()
            .filter(|s| !s.is_empty())
        {
            Some(dir) => match crate::noise_m2m::load_static(std::path::Path::new(&dir)) {
                Ok(key) => {
                    eprintln!(
                        "cp: noise static key {:?} ({}…)",
                        key.source(),
                        &key.public_hex()[..16]
                    );
                    Some(key)
                }
                Err(e) => {
                    eprintln!("cp: noise key load failed at {dir}: {e}");
                    None
                }
            },
            None => None,
        };

    let state = St {
        cfg: cfg.clone(),
        ee,
        store,
        started: Instant::now(),
        verifier,
        cp_ita_token,
        gh,
        noise,
        agent_pubkeys: crate::noise_m2m::AgentRegistry::new(),
    };

    let app = Router::new()
        .route("/", get(fleet))
        .route("/bastion", get(bastion_aggregator))
        .route("/health", get(health))
        .route("/register", post(register))
        .route("/ingress/replace", post(ingress_replace))
        .route("/agent/{id}", get(agent_detail))
        .route("/agent/{id}/logs/{app}", get(agent_logs))
        .route("/api/agents", get(api_agents))
        .route("/cp/attest", get(cp_attest))
        .route("/cp/ita", get(cp_ita))
        .route("/cp/noise/attest", get(cp_noise_attest))
        .with_state(state);

    let addr = format!("0.0.0.0:{}", cfg.common.port);
    eprintln!("cp: listening on {addr}");
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    // `into_make_service_with_connect_info` so handlers can see the
    // peer socket address via the `ConnectInfo` extractor. Used by
    // `api_agents` to grant auth-free access to same-VM loopback
    // callers (bastion + dd-management proxy paths).
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

// ── Routes ──────────────────────────────────────────────────────────────

async fn health(State(s): State<St>) -> Json<serde_json::Value> {
    let agents = s.store.lock().await;
    Json(serde_json::json!({
        "ok": true,
        "service": "cp",
        "hostname": s.cfg.hostname,
        "env": s.cfg.common.env_label,
        "uptime_secs": s.started.elapsed().as_secs(),
        "agent_count": agents.len(),
        "healthy_count": agents.values().filter(|a| a.status == "healthy").count(),
    }))
}

#[derive(Debug, Deserialize)]
struct RegisterReq {
    vm_name: String,
    env_label: String,
    owner: String,
    ita_token: String,
    /// Optional per-workload ingress: each entry becomes
    /// `{hostname_label}.{agent_hostname}` → `localhost:{port}` in the
    /// agent's cloudflared tunnel config, in addition to the default
    /// `{agent_hostname}` → `localhost:8080` dashboard rule.
    #[serde(default)]
    extra_ingress: Vec<ExtraIngress>,
    /// Agent's long-term Noise static pubkey (hex). Optional during
    /// the m2m migration — agents built before Phase 2b still send
    /// only `ita_token` and fall through to the old auth path. Once
    /// every agent carries a key, the ITA bearer paths are removed.
    #[serde(default)]
    noise_pubkey_hex: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ExtraIngress {
    hostname_label: String,
    port: u16,
}

/// POST /register — the CF Access bypass app on this path lets anyone
/// reach it; the real gate is ITA attestation in-code. We verify the
/// agent's Intel-signed quote, create its tunnel, provision its CF
/// Access apps (human dashboard + per-workload bypass URLs), and
/// return the tunnel token + shared CF Access service token pair so
/// the agent can authenticate future M2M calls.
async fn register(
    State(s): State<St>,
    Json(req): Json<RegisterReq>,
) -> Result<Json<serde_json::Value>> {
    if req.owner != s.cfg.common.owner {
        return Err(Error::BadRequest(format!(
            "owner mismatch: got {} expected {}",
            req.owner, s.cfg.common.owner
        )));
    }
    if req.env_label != s.cfg.common.env_label {
        return Err(Error::BadRequest(format!(
            "env_label mismatch: got {} expected {}",
            req.env_label, s.cfg.common.env_label
        )));
    }

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

    // Pin the agent's Noise pubkey if it presented one. Mismatch (the
    // same agent_id re-registering under a fresh key) is rejected —
    // operators must `forget` the old pin before accepting a new one.
    if let Some(hex) = req.noise_pubkey_hex.as_deref() {
        match crate::noise_m2m::decode_pubkey(hex) {
            Ok(pk) => match s.agent_pubkeys.pin(&name, pk).await {
                Ok(crate::noise_m2m::PinOutcome::Fresh) => {
                    eprintln!(
                        "cp: pinned noise pubkey for {} ({}…)",
                        name,
                        &hex.get(..16).unwrap_or(hex)
                    );
                }
                Ok(crate::noise_m2m::PinOutcome::Reused) => {}
                Err(e) => {
                    return Err(Error::BadRequest(format!("noise pubkey: {e}")));
                }
            },
            Err(e) => {
                return Err(Error::BadRequest(format!("noise_pubkey_hex: {e}")));
            }
        }
    }

    eprintln!("cp: registered {} as {}", req.vm_name, agent_hostname);

    // Include CP's noise pubkey so the agent can pin it for future
    // m2m handshakes. `null` during the migration window when
    // `DD_NOISE_KEY_DIR` is unset.
    let cp_noise_pubkey = s.noise.as_ref().map(|k| k.public_hex());

    Ok(Json(serde_json::json!({
        "tunnel_token": tunnel.token,
        "hostname": tunnel.hostname,
        "agent_id": name,
        "cp_hostname": s.cfg.hostname,
        "cp_noise_pubkey_hex": cp_noise_pubkey,
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
        &html::nav(&[("Fleet", "/", true), ("Bastion", "/bastion", false)]),
        &format!(
            r#"<h1>Fleet</h1><div class="sub">{host} · env {env} · {n} agent(s)</div>{table}"#,
            host = html::escape(&s.cfg.hostname),
            env = html::escape(&s.cfg.common.env_label),
            n = by_id.len(),
        ),
    ))
    .into_response()
}

/// GET /bastion — fleet-wide bastion SPA. Builds the list of
/// `(vm_name, block-origin)` pairs from the agent catalog (plus the
/// CP itself), and returns bastion's Svelte SPA with
/// `window.__DD_AGENTS__` preloaded so it fans out cross-origin to
/// every node and renders one unified sidebar. CF Access's shared
/// session-domain cookie on `.devopsdefender.com` makes the browser
/// send credentials on every `fetch`/`wss` across subdomains.
async fn bastion_aggregator(State(s): State<St>) -> Response {
    let mut agents: Vec<(String, String)> = Vec::new();

    // CP itself — has a bastion workload at `block.<cp-hostname>`.
    let cp_block = cf::label_hostname(&s.cfg.hostname, "block");
    agents.push((
        format!("cp ({})", s.cfg.common.env_label),
        format!("https://{cp_block}"),
    ));

    // Every registered agent, sorted for stable ordering.
    let store = s.store.lock().await;
    let mut by_vm: Vec<_> = store.values().cloned().collect();
    drop(store);
    by_vm.sort_by(|a, b| a.vm_name.cmp(&b.vm_name));
    for a in &by_vm {
        let block = cf::label_hostname(&a.hostname, "block");
        agents.push((a.vm_name.clone(), format!("https://{block}")));
    }

    Html(bastion::aggregator_body(&agents)).into_response()
}

/// GET /api/agents — JSON list of
/// `{agent_id, vm_name, hostname, status, last_seen}`.
///
/// Gated three ways, any of which succeeds:
/// 1. **Loopback** (`127.0.0.1`, `::1`) — same-VM callers (bastion
///    workload, dd-agent's own proxy). Trust is anchored by EE's
///    Tier-1 seal: a process on the VM at all is already a workload
///    EE spawned and gave the shared `EE_TOKEN` env to.
/// 2. **GH OIDC** — CI action (`dd-deploy`, etc.) presents a GitHub
///    Actions OIDC JWT as `Authorization: Bearer <jwt>`; we verify
///    against GitHub's JWKS and require `repository_owner ==
///    DD_OWNER`. Matches the pattern dd-agent uses for `/deploy` +
///    `/exec`.
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
/// (same-VM trust — bastion / dd-agent-proxy) or presents a valid
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
    if let Ok(claims) = s.gh.verify(token).await {
        if claims.repository_owner == s.cfg.common.owner {
            return true;
        }
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

    // `{hostname-base}-block.{tld}` is the bastion subdomain (CP's own
    // tunnel publishes it; agents publish it via their register-time
    // `extra_ingress`). Flat shape so Universal SSL covers the cert.
    // Human-gated by CF Access; the block-aware terminal lives there,
    // persistent per-session with OSC 133 command history.
    let term_host = html::escape(&cf::label_hostname(&a.hostname, "block"));
    let extra = if is_cp {
        format!(
            r#"<p><a href="https://{term_host}/" target="_blank">Terminal ↗</a> · <a href="/cp/attest">raw quote</a> · <a href="/cp/ita">ITA token</a></p>"#
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
        &html::nav(&[("Fleet", "/", false), ("Bastion", "/bastion", false)]),
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
        &html::nav(&[("Fleet", "/", false), ("Bastion", "/bastion", false)]),
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

async fn cp_attest(
    State(s): State<St>,
    Query(q): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>> {
    // EE base64-decodes the nonce; synthesize one if the caller didn't
    // pass one (browser-click from the dashboard).
    let nonce = q
        .get("nonce")
        .cloned()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(uuid::Uuid::new_v4().as_bytes())
        });
    Ok(Json(s.ee.attest(&nonce).await?))
}

/// GET /cp/ita — the CP's own ITA token, minted + self-verified at
/// startup. External verifiers can confirm the CP VM's TDX measurement
/// by decoding it against Intel's JWKS.
async fn cp_ita(State(s): State<St>) -> Result<Json<serde_json::Value>> {
    let token = s.cp_ita_token.read().await.clone();
    let claims = s.verifier.verify(&token).await?;
    Ok(Json(serde_json::json!({
        "token": token,
        "claims": claims,
    })))
}

/// GET /cp/noise/attest — the CP's long-term Noise static pubkey.
/// Agents cache this on first contact and use it as the responder
/// key for m2m Noise_IK handshakes. Matches the shape of bastion's
/// own `/attest` so Phase 2d's TDX-quote-binds-pubkey upgrade works
/// the same way here.
///
/// 404 when `DD_NOISE_KEY_DIR` wasn't set at startup (local-dev CP).
async fn cp_noise_attest(State(s): State<St>) -> axum::response::Response {
    let Some(key) = s.noise.as_ref() else {
        return (
            axum::http::StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "noise key not configured"})),
        )
            .into_response();
    };
    Json(serde_json::json!({
        "noise_pubkey_hex": key.public_hex(),
        "source": format!("{:?}", key.source()).to_lowercase(),
    }))
    .into_response()
}
