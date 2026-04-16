//! dd — unified binary for DevOps Defender fleet management.
//!
//! Modes (set via DD_MODE env var or first CLI argument):
//!   management  — run the control plane (dd-register + dd-web)
//!   agent       — run the in-VM agent (dd-client)

#[tokio::main]
async fn main() {
    // DD_MODE env var takes precedence (for easyenclave workload spec),
    // CLI arg is the fallback (for local dev / standalone use).
    let mode = std::env::var("DD_MODE")
        .ok()
        .or_else(|| std::env::args().nth(1).filter(|s| !s.starts_with('-')));

    match mode.as_deref() {
        Some("management") => {
            // Merge dd-register's and dd-web's routers onto a single
            // HTTP server on DD_PORT (default 8080). This is what the
            // CF tunnel routes to — previously dd-register ran on 8081
            // and wasn't externally reachable, so /register 404'd for
            // remote fleet agents trying to register.
            //
            // `prepare()` on each crate does the async state setup and
            // spawns background tasks (self-register tunnel, cloudflared
            // child, STONITH watchdogs, agent collector, etc.) before
            // returning a stateful Router.
            let register_router = dd_register::prepare().await;
            let web_router = dd_web::prepare().await;
            let merged = web_router.merge(register_router);

            let port: u16 = std::env::var("DD_PORT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(8080);
            let addr = format!("0.0.0.0:{port}");
            eprintln!("dd: management listening on {addr} (dd-web + dd-register routes merged)");

            let listener = tokio::net::TcpListener::bind(&addr)
                .await
                .expect("failed to bind");
            axum::serve(listener, merged).await.expect("server error");
        }
        Some("agent") => {
            dd_client::run().await;
        }
        _ => {
            eprintln!("usage: devopsdefender <management|agent>");
            eprintln!("   or: DD_MODE=management devopsdefender");
            eprintln!();
            eprintln!("  management  Run the control plane (register + dashboard)");
            eprintln!("  agent       Run the in-VM agent");
            std::process::exit(1);
        }
    }
}
