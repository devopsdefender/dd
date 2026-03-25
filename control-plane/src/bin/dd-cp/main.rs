use dd_control_plane::config::CpConfig;
use dd_control_plane::db;
use dd_control_plane::routes;
use dd_control_plane::services::attestation::AttestationService;
use dd_control_plane::services::github_oidc::GithubOidcService;
use dd_control_plane::services::tunnel::TunnelService;
use dd_control_plane::state::AppState;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct FileConfig {
    #[serde(default)]
    raw_kv: std::collections::HashMap<String, String>,
}

fn load_raw_env_from_config_file() {
    let config_path = match std::env::var("DD_CONFIG") {
        Ok(path) => path,
        Err(_) => return,
    };

    let text = match std::fs::read_to_string(&config_path) {
        Ok(text) => text,
        Err(err) => {
            eprintln!("  warning: failed to read DD_CONFIG file {config_path}: {err}");
            return;
        }
    };

    let file_cfg: FileConfig = match serde_json::from_str(&text) {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("  warning: failed to parse DD_CONFIG file {config_path}: {err}");
            return;
        }
    };

    for (key, value) in file_cfg.raw_kv {
        if std::env::var_os(&key).is_none() {
            unsafe { std::env::set_var(key, value) };
        }
    }
}

#[tokio::main]
async fn main() {
    load_raw_env_from_config_file();

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
    if let Ok(ita_url) = std::env::var("DD_CP_ITA_JWKS_URL") {
        let ita_issuer = std::env::var("DD_CP_ITA_ISSUER").ok();
        let ita_audience = std::env::var("DD_CP_ITA_AUDIENCE").ok();
        let verifier =
            dd_control_plane::attestation::ita::ItaVerifier::new(ita_url, ita_issuer, ita_audience);
        state.attestation = AttestationService::new(verifier);
    }

    if std::env::var("DD_CP_CF_API_TOKEN").is_ok() {
        state.tunnel = TunnelService::from_env();
    }

    if std::env::var("DD_CP_GITHUB_OIDC_AUDIENCE").is_ok() {
        state.github_oidc = GithubOidcService::from_env();
    }

    // Capture tunnel service and hostname before moving state into the router.
    let tunnel_svc = state.tunnel.clone();
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
        tokio::spawn(async move {
            eprintln!("  creating CF tunnel for {cp_public_hostname}...");
            match tunnel_svc
                .create_and_run_cp_tunnel(&cp_public_hostname, cp_port)
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

    axum::serve(listener, app).await.expect("server error");
}
