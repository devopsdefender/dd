//! `bastion serve` — standalone block-aware terminal on localhost.
//!
//! Useful for local iteration and as a reference for embedding.

use axum::Router;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(|s| s.as_str()) != Some("serve") {
        eprintln!("usage: bastion serve [--port N] [--bind ADDR] [--capture-socket PATH] [--ee-socket PATH]");
        std::process::exit(2);
    }

    let mut port: u16 = 7681;
    let mut bind: String = "127.0.0.1".into();
    let mut capture_socket: Option<String> = None;
    let mut ee_socket: Option<String> = None;
    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--port" => {
                port = args.get(i + 1).and_then(|s| s.parse().ok()).unwrap_or(port);
                i += 2;
            }
            "--bind" => {
                if let Some(s) = args.get(i + 1) {
                    bind = s.clone();
                }
                i += 2;
            }
            "--capture-socket" => {
                capture_socket = args.get(i + 1).cloned();
                i += 2;
            }
            "--ee-socket" => {
                ee_socket = args.get(i + 1).cloned();
                i += 2;
            }
            other => {
                eprintln!("bastion: unknown arg {other}");
                std::process::exit(2);
            }
        }
    }

    let mgr = bastion::Manager::new();

    if let Some(path) = capture_socket {
        if let Err(e) = bastion::capture::spawn_listener(&path, mgr.clone()).await {
            // Non-fatal: if EE isn't configured to emit yet, the socket
            // just stays quiet. But if bind itself fails (e.g. bad
            // path, permissions), surface it.
            eprintln!("bastion: capture listener failed to bind {path}: {e}");
        }
    }

    if let Some(path) = ee_socket {
        // Pull-based bootstrap: on startup (and every 30s after),
        // query EE's `list` + `logs` over its unix socket and seed
        // the Manager so boot workloads render with their history.
        // Requires `inherit_token: true` in the workload spec so the
        // Tier-1 seal lets us talk to EE.
        eprintln!("bastion: ee_sync polling {path}");
        bastion::ee_sync::start(mgr.clone(), &path);
    }

    let addr = format!("{bind}:{port}");
    eprintln!("bastion: listening on http://{addr}/");
    let app: Router = bastion::router(mgr);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app)
        .await
        .map_err(|e| std::io::Error::other(format!("{e}")))
}
