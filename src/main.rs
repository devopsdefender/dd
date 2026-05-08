//! devopsdefender — unified binary.
//!
//!   DD_MODE=cp      devopsdefender    # control-plane
//!   DD_MODE=agent   devopsdefender    # in-VM agent
//!   DD_MODE=shell   devopsdefender    # multi-session shell service
//!
//! (Also accepts `devopsdefender cp` / `devopsdefender agent` for local dev.)

use devopsdefender::{agent, cp, shell};

#[tokio::main]
async fn main() {
    let mode = std::env::var("DD_MODE")
        .ok()
        .or_else(|| std::env::args().nth(1).filter(|s| !s.starts_with('-')));

    let result: anyhow::Result<()> = match mode.as_deref() {
        Some("cp") | Some("management") => cp::run().await.map_err(Into::into),
        Some("agent") => agent::run().await.map_err(Into::into),
        Some("shell") => shell::run().await.map_err(Into::into),
        _ => {
            eprintln!("usage: devopsdefender <cp|agent|shell>");
            eprintln!("   or: DD_MODE=<mode> devopsdefender");
            std::process::exit(2);
        }
    };

    if let Err(e) = result {
        eprintln!("devopsdefender: fatal: {e}");
        std::process::exit(1);
    }
}
