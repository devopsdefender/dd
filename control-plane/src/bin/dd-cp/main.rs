use dd_control_plane::config::CpConfig;
use dd_control_plane::db;
use dd_control_plane::routes;
use dd_control_plane::services::attestation::{AttestationService, RuntimeEnv};
use dd_control_plane::services::github_oidc::GithubOidcService;
use dd_control_plane::services::migration::SeedConfig;
use dd_control_plane::services::tunnel::TunnelService;
use dd_control_plane::state::AppState;

#[tokio::main]
async fn main() {
    let config = CpConfig::from_env();

    eprintln!("DevOps Defender Control Plane starting...");
    eprintln!("  bind_addr: {}", config.bind_addr);
    eprintln!("  database:  {}", config.database_url);

    // Connect to database and run migrations
    let db = db::connect_and_migrate(&config.database_url).expect("failed to connect to database");

    eprintln!("  database connected, migrations applied");

    // Import seed config if provided (deployed by another CP via deploy-cp)
    import_seed_if_configured(&db);

    // Import full state bundle if provided (instant cutover migration)
    if let Some(ref path) = config.import_state_path {
        import_state_from_file(&db, path);
    }

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

    // Capture tunnel service and hostname before moving state into the router.
    let tunnel_svc = state.tunnel.clone();
    let cp_public_hostname = std::env::var("DD_CP_PUBLIC_HOSTNAME").unwrap_or_default();
    let cp_port: u16 = config
        .bind_addr
        .rsplit(':')
        .next()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);

    // Capture proxy state for the middleware
    let proxy_target = state.proxy_target.clone();

    // Build router
    let app = routes::build_router(state);

    // Wrap with proxy middleware for zero-downtime migration
    let app = app.layer(axum::middleware::from_fn(
        move |req: axum::http::Request<axum::body::Body>, next: axum::middleware::Next| {
            let proxy = proxy_target.clone();
            async move {
                let target = proxy.read().unwrap().clone();
                if let Some(target_url) = target {
                    // Don't proxy migration control endpoints
                    let path = req.uri().path();
                    if path.starts_with("/api/v1/admin/migration/") || path == "/health" {
                        return next.run(req).await;
                    }

                    match proxy_request(&target_url, req).await {
                        Ok(resp) => resp,
                        Err(_) => axum::http::Response::builder()
                            .status(502)
                            .body(axum::body::Body::from("proxy target unreachable"))
                            .unwrap(),
                    }
                } else {
                    next.run(req).await
                }
            }
        },
    ));

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

    axum::serve(listener, app.into_make_service())
        .await
        .expect("server error");
}

/// Import seed config from the DD_CP_IMPORT_SEED_INLINE env var.
/// This is set when a CP deploys another CP via the deploy-cp endpoint.
fn import_seed_if_configured(db: &dd_control_plane::db::Db) {
    if let Ok(seed_json) = std::env::var("DD_CP_IMPORT_SEED_INLINE") {
        eprintln!("  importing seed config from DD_CP_IMPORT_SEED_INLINE...");
        match serde_json::from_str::<SeedConfig>(&seed_json) {
            Ok(seed) => {
                let summary = seed.summary();
                match seed.import(db) {
                    Ok(()) => {
                        eprintln!("  seed config imported: {:?}", summary.table_counts);
                    }
                    Err(e) => {
                        eprintln!("  WARNING: seed config import failed: {e}");
                    }
                }
            }
            Err(e) => {
                eprintln!("  WARNING: failed to parse seed config: {e}");
            }
        }
    }
}

/// Import a full state bundle from a JSON file on disk.
fn import_state_from_file(db: &dd_control_plane::db::Db, path: &str) {
    eprintln!("  importing state from {path}...");
    match std::fs::read(path) {
        Ok(data) => {
            use dd_control_plane::services::migration::StateBundle;
            match StateBundle::from_json(&data) {
                Ok(bundle) => {
                    let summary = bundle.summary();
                    bundle.apply_secrets_to_env();
                    match bundle.import(db) {
                        Ok(()) => {
                            eprintln!("  state imported: {:?}", summary.table_counts);
                        }
                        Err(e) => {
                            eprintln!("  WARNING: state import failed: {e}");
                        }
                    }
                }
                Err(e) => {
                    eprintln!("  WARNING: failed to parse state bundle: {e}");
                }
            }
        }
        Err(e) => {
            eprintln!("  WARNING: failed to read state file {path}: {e}");
        }
    }
}

/// Forward an HTTP request to the proxy target.
async fn proxy_request(
    target_url: &str,
    req: axum::http::Request<axum::body::Body>,
) -> Result<axum::http::Response<axum::body::Body>, reqwest::Error> {
    let client = reqwest::Client::new();

    let uri = format!("{}{}", target_url.trim_end_matches('/'), req.uri().path());
    let method = req.method().clone();

    let body_bytes = axum::body::to_bytes(req.into_body(), 10 * 1024 * 1024)
        .await
        .unwrap_or_default();

    let resp = client
        .request(method, &uri)
        .body(body_bytes.to_vec())
        .send()
        .await?;

    let status = resp.status();
    let body = resp.bytes().await.unwrap_or_default();

    Ok(axum::http::Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(body))
        .unwrap())
}
