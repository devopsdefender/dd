//! dd-web -- fleet dashboard with GitHub OAuth, Prometheus-style agent scraping,
//! and horizontal scaling via federation.
//!
//! READ-ONLY fleet view: discovers agents via CF tunnels, scrapes them, shows
//! dashboard. Does NOT handle agent registration (that's dd-register's job).
//! OAuth + JWT issuance is dd-web's responsibility -- it's the auth provider
//! for the fleet. The dd_auth JWT cookie is scoped to .{domain} so it works
//! across all agent hostnames.

mod auth;
mod collector;
mod config;
mod federate;
mod fleet;
mod html;
mod router;
mod state;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use tokio::sync::Mutex;

use dd_common::tunnel;

#[tokio::main]
async fn main() {
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

    let web_state = state::WebState {
        config: Arc::new(config),
        agents: agents.clone(),
        sessions: Arc::new(Mutex::new(HashMap::new())),
        pending_oauth_states: Arc::new(Mutex::new(HashMap::new())),
        signing_key,
        decoding_key,
        started_at: Instant::now(),
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

    // Create own CF tunnel
    let hostname = web_state.config.hostname.clone();
    let web_id = uuid::Uuid::new_v4().to_string();
    eprintln!("dd-web: creating tunnel for {hostname}");

    let tunnel_info = match tunnel::create_agent_tunnel(
        &http_client,
        &web_state.config.cf,
        &web_id,
        "dd-web",
        Some(&hostname),
    )
    .await
    {
        Ok(info) => info,
        Err(e) => {
            eprintln!("dd-web: tunnel creation failed: {e}");
            std::process::exit(1);
        }
    };

    eprintln!("dd-web: tunnel created -- {}", tunnel_info.hostname);

    // Spawn cloudflared (if available — dd-web's container may not
    // have it, in which case dd-register handles the tunnel).
    let token = tunnel_info.tunnel_token.clone();
    tokio::spawn(async move {
        eprintln!("dd-web: starting cloudflared");
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
                let _ = child.wait().await;
                eprintln!("dd-web: cloudflared exited");
            }
            Err(e) => {
                eprintln!(
                    "dd-web: cloudflared not available ({e}), relying on dd-register's tunnel"
                );
            }
        }
    });

    // Build router and start HTTP server
    let app = router::build_router(web_state.clone());
    let port = web_state.config.port;
    let addr = format!("0.0.0.0:{port}");

    eprintln!("dd-web: listening on {addr}");
    eprintln!("dd-web: dashboard at https://{hostname}/");

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("failed to bind");
    axum::serve(listener, app).await.expect("server error");
}
