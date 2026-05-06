//! devopsdefender — unified binary.
//!
//!   DD_MODE=cp      devopsdefender    # control-plane
//!   DD_MODE=agent   devopsdefender    # in-VM agent
//!
//! (Also accepts `devopsdefender cp` / `devopsdefender agent` for local dev.)

use devopsdefender::{agent, cp};

#[tokio::main]
async fn main() {
    let mode = std::env::var("DD_MODE")
        .ok()
        .or_else(|| std::env::args().nth(1).filter(|s| !s.starts_with('-')));

    let result = match mode.as_deref() {
        Some("cp") | Some("management") => cp::run().await,
        Some("agent") => agent::run().await,
        _ => {
            eprintln!("usage: devopsdefender <cp|agent>");
            eprintln!("   or: DD_MODE=<cp|agent> devopsdefender");
            std::process::exit(2);
        }
    };

    if let Err(e) = result {
        eprintln!("devopsdefender: fatal: {e}");
        std::process::exit(1);
    }
}
