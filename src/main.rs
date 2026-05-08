//! devopsdefender — unified binary.
//!
//!   DD_MODE=cp      devopsdefender    # control-plane
//!   DD_MODE=agent   devopsdefender    # in-VM agent
//!   DD_MODE=shell   devopsdefender    # multi-session shell service
//!
//! (Also accepts `devopsdefender cp` / `devopsdefender agent` for local dev.)

use devopsdefender::{agent, cp, shell, workload_helpers};
use std::path::Path;

#[tokio::main]
async fn main() {
    let argv0 = std::env::args().next().unwrap_or_default();
    let invoked_as = Path::new(&argv0)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    let podman_args: Vec<_> = std::env::args_os().skip(1).collect();
    let mode = std::env::var("DD_MODE")
        .ok()
        .or_else(|| {
            (invoked_as == "podman" || invoked_as == "dd-podman").then(|| "podman-wrapper".into())
        })
        .or_else(|| std::env::args().nth(1).filter(|s| !s.starts_with('-')));

    let result: anyhow::Result<()> = match mode.as_deref() {
        Some("cp") | Some("management") => cp::run().await.map_err(Into::into),
        Some("agent") => agent::run().await.map_err(Into::into),
        Some("shell") => shell::run().await.map_err(Into::into),
        Some("mount-data") => workload_helpers::mount_data().await,
        Some("podman-bootstrap") => workload_helpers::podman_bootstrap().await,
        Some("podman-wrapper") => workload_helpers::podman_wrapper(podman_args),
        Some("human-readonly") => workload_helpers::human_readonly().await,
        Some("oracle-readonly") => workload_helpers::oracle_readonly().await,
        _ => {
            eprintln!(
                "usage: devopsdefender <cp|agent|shell|mount-data|podman-bootstrap|human-readonly>"
            );
            eprintln!("   or: DD_MODE=<mode> devopsdefender");
            std::process::exit(2);
        }
    };

    if let Err(e) = result {
        eprintln!("devopsdefender: fatal: {e}");
        std::process::exit(1);
    }
}
