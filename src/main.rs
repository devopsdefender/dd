//! devopsdefender — unified binary.
//!
//!   DD_MODE=cp          devopsdefender    # control-plane
//!   DD_MODE=agent       devopsdefender    # in-VM agent
//!   devopsdefender webtmux-dev [PORT]     # local dev harness for /term
//!
//! (Also accepts `devopsdefender cp` / `devopsdefender agent` for local dev.)

use devopsdefender::{agent, cp, webtmux};

#[tokio::main]
async fn main() {
    let mode = std::env::var("DD_MODE")
        .ok()
        .or_else(|| std::env::args().nth(1).filter(|s| !s.starts_with('-')));

    let result = match mode.as_deref() {
        Some("cp") | Some("management") => cp::run().await,
        Some("agent") => agent::run().await,
        Some("webtmux-dev") => webtmux_dev().await,
        _ => {
            eprintln!("usage: devopsdefender <cp|agent|webtmux-dev>");
            eprintln!("   or: DD_MODE=<cp|agent> devopsdefender");
            std::process::exit(2);
        }
    };

    if let Err(e) = result {
        eprintln!("devopsdefender: fatal: {e}");
        std::process::exit(1);
    }
}

/// Local dev harness: starts axum on 127.0.0.1:<port> with just /term
/// mounted. No CP registration, no CF Access, no TLS — for iterating
/// on the terminal UI locally.
async fn webtmux_dev() -> devopsdefender::error::Result<()> {
    let port: u16 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(7681);
    let addr = format!("127.0.0.1:{port}");
    eprintln!("webtmux-dev: listening on http://{addr}/term");
    let app = webtmux::router(webtmux::Manager::new());
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .map_err(|e| devopsdefender::error::Error::Internal(e.to_string()))?;
    axum::serve(listener, app)
        .await
        .map_err(|e| devopsdefender::error::Error::Internal(e.to_string()))
}
