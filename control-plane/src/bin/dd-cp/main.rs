use dd_control_plane::config::CpConfig;
use dd_control_plane::db;
use dd_control_plane::routes;
use dd_control_plane::services::attestation::{AttestationService, RuntimeEnv};
use dd_control_plane::services::github_oidc::GithubOidcService;
use dd_control_plane::services::tunnel::TunnelService;
use dd_control_plane::state::AppState;
use dd_control_plane::stores::agent as agent_store;

#[tokio::main]
async fn main() {
    let config = CpConfig::from_env();

    eprintln!("DevOps Defender Control Plane starting...");
    eprintln!("  bind_addr: {}", config.bind_addr);
    eprintln!("  database:  {}", config.database_url);

    // Connect to database and run migrations
    let db = db::connect_and_migrate(&config.database_url).expect("failed to connect to database");

    eprintln!("  database connected, migrations applied");

    // Build application state
    let mut state = AppState::from_env(db);

    // Override with real services if configured
    let env = RuntimeEnv::detect();
    if let Ok(ita_url) = std::env::var("DD_CP_ITA_JWKS_URL") {
        let ita_issuer = std::env::var("DD_CP_ITA_ISSUER").ok();
        let ita_audience = std::env::var("DD_CP_ITA_AUDIENCE").ok();
        let verifier =
            dd_control_plane::attestation::ita::ItaVerifier::new(ita_url, ita_issuer, ita_audience);
        state.attestation = AttestationService::new(verifier, env);
    }

    if std::env::var("DD_CP_CF_API_TOKEN").is_ok() {
        state.tunnel = TunnelService::from_env();
    }

    if std::env::var("DD_CP_GITHUB_OIDC_AUDIENCE").is_ok() {
        state.github_oidc = GithubOidcService::from_env();
    }

    // Capture tunnel service, DB, and hostname before moving state into the router.
    let tunnel_svc = state.tunnel.clone();
    let shutdown_tunnel_svc = state.tunnel.clone();
    let cleanup_tunnel_svc = state.tunnel.clone();
    let cleanup_db = state.db.clone();
    let stale_timeout = state.stale_agent_timeout_seconds;
    let cp_public_hostname = std::env::var("DD_CP_PUBLIC_HOSTNAME").unwrap_or_default();
    let cp_port: u16 = config
        .bind_addr
        .rsplit(':')
        .next()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);

    // Build router
    let app = routes::build_router(state);

    // Start server
    let listener = tokio::net::TcpListener::bind(&config.bind_addr)
        .await
        .expect("failed to bind");

    eprintln!("  listening on {}", listener.local_addr().unwrap());

    // Spawn CF tunnel setup in the background (after the listener is bound).
    if !cp_public_hostname.is_empty() {
        let hostname = cp_public_hostname.clone();
        tokio::spawn(async move {
            eprintln!("  creating CF tunnel for {hostname}...");
            match tunnel_svc
                .create_and_run_cp_tunnel(&hostname, cp_port)
                .await
            {
                Ok(info) => eprintln!(
                    "  CF tunnel active: {} (tunnel_id={})",
                    info.hostname, info.tunnel_id
                ),
                Err(e) => eprintln!("  CF tunnel setup failed (non-fatal): {e}"),
            }
        });
    }

    // Spawn background stale-agent cleanup loop.
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            let cutoff =
                (chrono::Utc::now() - chrono::Duration::seconds(stale_timeout as i64)).to_rfc3339();
            match agent_store::list_stale_agents(&cleanup_db, &cutoff) {
                Ok(stale_agents) => {
                    for agent in stale_agents {
                        eprintln!(
                            "dd-cp: cleaning up stale agent {} ({})",
                            agent.id, agent.vm_name
                        );
                        let tunnel_name = format!("dd-agent-{}", agent.id);
                        if let Err(e) = cleanup_tunnel_svc.delete_tunnel_by_name(&tunnel_name).await
                        {
                            eprintln!(
                                "dd-cp: warning: tunnel cleanup for stale agent {} failed: {e}",
                                agent.id
                            );
                        }
                        if let Some(ref hostname) = agent.hostname {
                            if let Err(e) = cleanup_tunnel_svc.delete_dns_record(hostname).await {
                                eprintln!(
                                    "dd-cp: warning: DNS cleanup for stale agent {} failed: {e}",
                                    agent.id
                                );
                            }
                        }
                        if let Err(e) = agent_store::delete_agent(&cleanup_db, &agent.id) {
                            eprintln!(
                                "dd-cp: warning: DB cleanup for stale agent {} failed: {e}",
                                agent.id
                            );
                        }
                    }
                }
                Err(e) => {
                    eprintln!("dd-cp: stale agent check failed: {e}");
                }
            }
        }
    });

    // Graceful shutdown: clean CP tunnel + DNS on SIGTERM/SIGINT.
    let shutdown_hostname = cp_public_hostname.clone();
    let shutdown = async {
        tokio::signal::ctrl_c().await.ok();
        eprintln!("dd-cp: shutdown signal received");
    };

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
        .expect("server error");

    // Post-shutdown: clean up the CP's own Cloudflare tunnel and DNS record.
    if !shutdown_hostname.is_empty() {
        let tunnel_name = format!("dd-cp-{}", shutdown_hostname.replace('.', "-"));
        eprintln!("dd-cp: cleaning up CP tunnel {tunnel_name}...");
        if let Err(e) = shutdown_tunnel_svc
            .delete_tunnel_by_name(&tunnel_name)
            .await
        {
            eprintln!("dd-cp: CP tunnel cleanup failed: {e}");
        }
        if let Err(e) = shutdown_tunnel_svc
            .delete_dns_record(&shutdown_hostname)
            .await
        {
            eprintln!("dd-cp: CP DNS cleanup failed: {e}");
        }
        eprintln!("dd-cp: shutdown complete");
    }
}
