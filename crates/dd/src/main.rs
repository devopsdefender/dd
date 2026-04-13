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
            // Run dd-register and dd-web concurrently — both are
            // long-lived servers that should run for the VM lifetime.
            // dd-register binds DD_REGISTER_PORT (default 8081),
            // dd-web binds DD_PORT (default 8080).
            tokio::select! {
                _ = dd_register::run() => {
                    eprintln!("dd: dd-register exited unexpectedly");
                }
                _ = dd_web::run() => {
                    eprintln!("dd: dd-web exited unexpectedly");
                }
            }
        }
        Some("agent") => {
            dd_client::run().await;
        }
        _ => {
            eprintln!("usage: dd <management|agent>");
            eprintln!("   or: DD_MODE=management dd");
            eprintln!();
            eprintln!("  management  Run the control plane (register + dashboard)");
            eprintln!("  agent       Run the in-VM agent");
            std::process::exit(1);
        }
    }
}
