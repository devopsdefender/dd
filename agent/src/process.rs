//! Process manager — run workloads as plain processes on the VM.

use std::path::Path;
use tokio::process::{Child, Command};

/// Spawn a command directly on the VM.
pub async fn spawn_command(program: &str, args: &[&str], tty: bool) -> Result<Child, String> {
    let _ = tokio::fs::create_dir_all("/var/lib/dd/workloads/logs").await;

    let mut cmd = if tty {
        let mut c = Command::new("script");
        c.arg("-qfc");
        let full_cmd = std::iter::once(program)
            .chain(args.iter().copied())
            .collect::<Vec<_>>()
            .join(" ");
        c.arg(full_cmd);
        c.arg("/dev/null");
        c.env("TERM", "xterm-256color");
        c
    } else {
        let mut c = Command::new(program);
        c.args(args);
        c
    };

    cmd.stdin(if tty {
        std::process::Stdio::piped()
    } else {
        std::process::Stdio::null()
    });
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    let child = cmd.spawn().map_err(|e| format!("spawn {program}: {e}"))?;
    eprintln!(
        "dd-agent: spawned {program} (pid={})",
        child.id().unwrap_or(0)
    );
    Ok(child)
}

/// Kill a process by PID.
pub async fn kill_process(pid: u32) -> Result<(), String> {
    let _ = Command::new("kill")
        .arg("-TERM")
        .arg(pid.to_string())
        .output()
        .await;
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let _ = Command::new("kill")
        .arg("-9")
        .arg(pid.to_string())
        .output()
        .await;
    Ok(())
}

/// Check if a process is still running.
pub fn is_running(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}
