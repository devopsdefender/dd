//! dd-web -- fleet dashboard with GitHub OAuth, Prometheus-style agent scraping,
//! and horizontal scaling via federation.
//!
//! READ-ONLY fleet view: discovers agents via CF tunnels, scrapes them, shows
//! dashboard. Does NOT handle agent registration (that's dd-register's job).
//! OAuth + JWT issuance is dd-web's responsibility -- it's the auth provider
//! for the fleet. The dd_auth JWT cookie is scoped to .{domain} so it works
//! across all agent hostnames.

pub mod auth;
pub mod collector;
pub mod config;
pub mod federate;
pub mod fleet;
pub mod html;
pub mod router;
pub mod state;
pub mod terminal;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use tokio::sync::Mutex;

use dd_common::ee_client::EeClient;
use dd_common::tunnel;

/// Build the dd-web router with its state, spawn the agent collector
/// background task, and bootstrap the initial agent list from CF
/// tunnels. Returns a Router ready to be merged with dd-register's
/// router in the unified binary, or served standalone via `run()`.
pub async fn prepare() -> axum::Router {
    let config = config::Config::from_env();

    eprintln!(
        "dd-web: starting (env={}, hostname={}, peers={})",
        config.env_label,
        config.hostname,
        config.peers.len()
    );

    // Generate auth signing keypair for dd_auth JWTs
    let mut secret = Vec::with_capacity(32);
    secret.extend_from_slice(uuid::Uuid::new_v4().as_bytes());
    secret.extend_from_slice(uuid::Uuid::new_v4().as_bytes());
    let signing_key = jsonwebtoken::EncodingKey::from_secret(&secret);
    let decoding_key = jsonwebtoken::DecodingKey::from_secret(&secret);

    let agents: state::AgentStore = Arc::new(Mutex::new(HashMap::new()));

    // Connect to local easyenclave socket (for CP self-inspection).
    let ee_socket = std::env::var("EE_SOCKET_PATH")
        .unwrap_or_else(|_| "/var/lib/easyenclave/agent.sock".into());
    let ee_client = Arc::new(EeClient::new(&ee_socket));

    let web_state = state::WebState {
        config: Arc::new(config),
        agents: agents.clone(),
        sessions: Arc::new(Mutex::new(HashMap::new())),
        pending_oauth_states: Arc::new(Mutex::new(HashMap::new())),
        signing_key,
        decoding_key,
        started_at: Instant::now(),
        ee_client,
    };

    // Bootstrap: discover existing agents from CF tunnels
    let env_label = &web_state.config.env_label;
    let tunnel_prefix = format!("dd-{env_label}-");
    eprintln!("dd-web: bootstrapping agent list from CF tunnels ({tunnel_prefix}*)");

    let http_client = reqwest::Client::new();
    match tunnel::list_tunnels(&http_client, &web_state.config.cf).await {
        Ok(tunnel_list) => {
            let mut store = agents.lock().await;
            let now = chrono::Utc::now();
            let mut count = 0;
            for t in &tunnel_list {
                let Some(name) = t["name"].as_str() else {
                    continue;
                };
                if !name.starts_with(&tunnel_prefix) {
                    continue;
                }
                let Some(tunnel_id) = t["id"].as_str() else {
                    continue;
                };
                // Use the tunnel's real ingress hostname, not `{name}.{domain}`.
                // See collector.rs::list_agent_tunnels for the rationale — if
                // the CP's own tunnel got bootstrapped under a synthesised
                // hostname, the collector would later orphan-delete it.
                let hostnames = match tunnel::tunnel_ingress_hostnames(
                    &http_client,
                    &web_state.config.cf,
                    tunnel_id,
                )
                .await
                {
                    Ok(h) => h,
                    Err(e) => {
                        eprintln!("dd-web: bootstrap ingress lookup failed for {name}: {e}");
                        continue;
                    }
                };
                if hostnames.is_empty() {
                    continue;
                }
                if hostnames.iter().any(|h| h == &web_state.config.hostname) {
                    continue; // our own tunnel
                }
                let Some(hostname) = hostnames.into_iter().next() else {
                    continue;
                };
                let agent_id = name
                    .strip_prefix(&tunnel_prefix)
                    .unwrap_or(name)
                    .to_string();
                store.insert(
                    agent_id.clone(),
                    state::AgentSnapshot {
                        agent_id,
                        hostname,
                        vm_name: "unknown".to_string(),
                        attestation_type: "unknown".to_string(),
                        status: "stale".to_string(),
                        last_seen: now,
                        deployment_count: 0,
                        deployment_names: Vec::new(),
                        cpu_percent: 0,
                        memory_used_mb: 0,
                        memory_total_mb: 0,
                    },
                );
                count += 1;
            }
            eprintln!("dd-web: bootstrapped {count} agents from CF tunnels");
        }
        Err(e) => {
            eprintln!("dd-web: bootstrap tunnel list failed: {e}");
        }
    }

    // Spawn collector background task
    let collector_state = web_state.clone();
    tokio::spawn(async move {
        collector::run_collector(collector_state).await;
    });

    // dd-web does NOT create its own Cloudflare tunnel. dd-register
    // owns the tunnel for this hostname — it creates it, runs
    // cloudflared, and forwards traffic to localhost:8080 where
    // dd-web listens. Having both services create tunnels for the
    // same hostname races the DNS CNAME, causing error 1033.

    let hostname = &web_state.config.hostname;
    eprintln!("dd-web: dashboard at https://{hostname}/");

    router::build_router(web_state.clone())
}

/// Standalone entry point — binds DD_PORT (default 8080) and serves
/// the prepared router. The unified `dd management` binary uses
/// `prepare()` instead and merges in dd-register's routes.
pub async fn run() {
    let app = prepare().await;

    let port: u16 = std::env::var("DD_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8080);
    let addr = format!("0.0.0.0:{port}");

    eprintln!("dd-web: listening on {addr}");

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("failed to bind");
    axum::serve(listener, app).await.expect("server error");
}
