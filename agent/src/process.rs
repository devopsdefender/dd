//! Process manager — pull OCI images, run workloads as plain processes.
//! No Docker, no containers, no daemon. Just chroot + exec.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tokio::process::{Child, Command};

const WORKLOADS_DIR: &str = "/var/lib/dd/workloads";

/// Parsed OCI image config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageConfig {
    #[serde(default)]
    pub entrypoint: Vec<String>,
    #[serde(default)]
    pub cmd: Vec<String>,
    #[serde(default)]
    pub env: Vec<String>,
    #[serde(default)]
    pub working_dir: String,
}

/// Raw OCI image config.json (partial, just what we need).
#[derive(Debug, Deserialize)]
struct OciConfig {
    config: Option<OciConfigInner>,
}

#[derive(Debug, Deserialize)]
struct OciConfigInner {
    #[serde(rename = "Entrypoint")]
    entrypoint: Option<Vec<String>>,
    #[serde(rename = "Cmd")]
    cmd: Option<Vec<String>>,
    #[serde(rename = "Env")]
    env: Option<Vec<String>>,
    #[serde(rename = "WorkingDir")]
    working_dir: Option<String>,
}

/// Pull an OCI image and extract it. Returns the image config.
pub async fn pull_image(image: &str, app_name: &str) -> Result<ImageConfig, String> {
    let dest = PathBuf::from(WORKLOADS_DIR).join(app_name);

    if dest.exists() {
        tokio::fs::remove_dir_all(&dest)
            .await
            .map_err(|e| format!("cleanup {}: {e}", dest.display()))?;
    }
    tokio::fs::create_dir_all(&dest)
        .await
        .map_err(|e| format!("mkdir {}: {e}", dest.display()))?;

    eprintln!("dd-agent: pulling {image} → {}", dest.display());

    let image_str = image.to_string();
    let dest_clone = dest.clone();
    tokio::task::spawn_blocking(move || {
        let reference = oci_unpack::Reference::try_from(image_str.as_str())
            .map_err(|e| format!("parse image ref: {e}"))?;
        oci_unpack::Unpacker::new(reference)
            .require_sandbox(false)
            .unpack(&dest_clone)
            .map_err(|e| format!("unpack: {e}"))
    })
    .await
    .map_err(|e| format!("pull task: {e}"))??;

    // Read config.json written by oci-unpack
    let config_path = dest.join("config.json");
    let config_str = tokio::fs::read_to_string(&config_path)
        .await
        .map_err(|e| format!("read config.json: {e}"))?;

    let oci_config: OciConfig =
        serde_json::from_str(&config_str).map_err(|e| format!("parse config.json: {e}"))?;

    let inner = oci_config.config.unwrap_or(OciConfigInner {
        entrypoint: None,
        cmd: None,
        env: None,
        working_dir: None,
    });

    let config = ImageConfig {
        entrypoint: inner.entrypoint.unwrap_or_default(),
        cmd: inner.cmd.unwrap_or_default(),
        env: inner.env.unwrap_or_default(),
        working_dir: inner.working_dir.unwrap_or_else(|| "/".into()),
    };

    eprintln!(
        "dd-agent: pulled {image} — entrypoint={:?} cmd={:?}",
        config.entrypoint, config.cmd
    );

    Ok(config)
}

/// Spawn a workload process from a pulled OCI image.
/// Uses chroot into the extracted rootfs — the VM is the security boundary,
/// chroot provides filesystem isolation so images work as expected.
pub async fn spawn_workload(
    app_name: &str,
    config: &ImageConfig,
    extra_env: Vec<String>,
    tty: bool,
) -> Result<Child, String> {
    let workdir = PathBuf::from(WORKLOADS_DIR).join(app_name);

    if !workdir.exists() {
        return Err(format!("workload dir not found: {}", workdir.display()));
    }

    // Entrypoint + cmd
    let mut args: Vec<String> = config.entrypoint.clone();
    args.extend(config.cmd.clone());

    if args.is_empty() {
        return Err("no entrypoint or cmd in image config".into());
    }

    let program = args.remove(0);

    // Environment from image config + extras
    let mut env_map: HashMap<String, String> = HashMap::new();
    for kv in &config.env {
        if let Some((k, v)) = kv.split_once('=') {
            env_map.insert(k.to_string(), v.to_string());
        }
    }
    for kv in &extra_env {
        if let Some((k, v)) = kv.split_once('=') {
            env_map.insert(k.to_string(), v.to_string());
        }
    }

    // Standard PATH inside the chroot
    env_map.insert(
        "PATH".into(),
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into(),
    );
    env_map
        .entry("HOME".into())
        .or_insert_with(|| "/root".into());
    env_map
        .entry("TERM".into())
        .or_insert_with(|| "xterm-256color".into());

    let _ = tokio::fs::create_dir_all("/var/lib/dd/workloads/logs").await;

    // Prepare chroot: bind-mount /proc, /sys, /dev, and copy resolv.conf for DNS
    setup_chroot_mounts(&workdir).await?;

    // Working directory inside the chroot
    let cwd = if !config.working_dir.is_empty() && config.working_dir != "/" {
        config.working_dir.clone()
    } else {
        "/".into()
    };

    // Build the inner command (what runs inside chroot)
    let inner_cmd = if args.is_empty() {
        program.clone()
    } else {
        format!("{} {}", program, args.join(" "))
    };

    let mut cmd = if tty {
        let mut c = Command::new("chroot");
        c.arg(workdir.as_os_str());
        c.args(["script", "-qfc", &inner_cmd, "/dev/null"]);
        c
    } else {
        let mut c = Command::new("chroot");
        c.arg(workdir.as_os_str());
        c.arg(&program);
        c.args(&args);
        c
    };

    cmd.current_dir(&cwd);

    cmd.env_clear();
    for (k, v) in &env_map {
        cmd.env(k, v);
    }

    cmd.stdin(if tty {
        std::process::Stdio::piped()
    } else {
        std::process::Stdio::null()
    });
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    let child = cmd.spawn().map_err(|e| format!("spawn {program}: {e}"))?;

    eprintln!(
        "dd-agent: spawned {app_name} (pid={}) — chroot {} {program} {:?}",
        child.id().unwrap_or(0),
        workdir.display(),
        args
    );

    Ok(child)
}

/// Set up bind mounts inside the chroot rootfs for /proc, /sys, /dev, and DNS.
async fn setup_chroot_mounts(rootfs: &Path) -> Result<(), String> {
    use tokio::process::Command;

    for dir in &["proc", "sys", "dev"] {
        let target = rootfs.join(dir);
        let _ = tokio::fs::create_dir_all(&target).await;
        let source = format!("/{dir}");
        let _ = Command::new("mount")
            .args(["--bind", &source, &target.to_string_lossy()])
            .output()
            .await;
    }

    // Copy resolv.conf for DNS resolution
    let etc = rootfs.join("etc");
    let _ = tokio::fs::create_dir_all(&etc).await;
    let _ = tokio::fs::copy("/etc/resolv.conf", etc.join("resolv.conf")).await;

    Ok(())
}

/// Spawn a direct command (not from an OCI image). For system tools like tmux, bash, etc.
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
    // Give it a moment, then force kill
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
