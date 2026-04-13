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

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use tokio::sync::Mutex;

use dd_common::ee_client::EeClient;
use dd_common::tunnel;

pub async fn run() {
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
                if let Some(name) = t["name"].as_str() {
                    if name.starts_with(&tunnel_prefix) {
                        let hostname = format!("{name}.{}", web_state.config.cf.domain);
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
                }
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

    // Build router and start HTTP server
    let app = router::build_router(web_state.clone());
    let port = web_state.config.port;
    let addr = format!("0.0.0.0:{port}");

    let hostname = &web_state.config.hostname;
    eprintln!("dd-web: listening on {addr}");
    eprintln!("dd-web: dashboard at https://{hostname}/");

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("failed to bind");
    axum::serve(listener, app).await.expect("server error");
}
