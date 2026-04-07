mod config;
mod local_control;
mod measure;
mod server;

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

use config::{AgentMode, AgentRuntimeConfig};
use server::{AgentState, Deployments};

// ── PID 1 init (sealed VM boot) ───────────────────────────────────────────

/// When dd-agent is PID 1 (booting as init in a sealed VM), mount virtual
/// filesystems and set up networking before doing anything else.
fn maybe_init() {
    if std::process::id() != 1 {
        return;
    }

    eprintln!("dd-agent: running as PID 1 — sealed VM init");

    // Set PATH so we can find busybox tools
    std::env::set_var(
        "PATH",
        "/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin",
    );

    // Mount virtual filesystems
    for (src, target, fstype) in [
        ("proc", "/proc", "proc"),
        ("sysfs", "/sys", "sysfs"),
        ("devtmpfs", "/dev", "devtmpfs"),
        ("tmpfs", "/tmp", "tmpfs"),
        ("tmpfs", "/run", "tmpfs"),
    ] {
        match nix_mount(src, target, fstype) {
            Ok(()) => eprintln!("dd-agent: init: mounted {target}"),
            Err(e) => eprintln!("dd-agent: init: mount {target} ({fstype}): {e}"),
        }
    }

    // Mount configfs for TDX attestation (tsm report interface)
    let _ = std::fs::create_dir_all("/sys/kernel/config");
    if let Err(e) = nix_mount("configfs", "/sys/kernel/config", "configfs") {
        eprintln!("dd-agent: init: mount configfs: {e}");
    }

    // Create /dev/pts for PTY support (needed for TTY workloads)
    let _ = std::fs::create_dir_all("/dev/pts");
    if let Err(e) = nix_mount("devpts", "/dev/pts", "devpts") {
        eprintln!("dd-agent: init: mount devpts: {e}");
    }

    // Writable tmpfs for workload data (rootfs is read-only dm-verity)
    if let Err(e) = nix_mount("tmpfs", "/var/lib/dd", "tmpfs") {
        eprintln!("dd-agent: init: mount /var/lib/dd tmpfs: {e}");
    } else {
        let _ = std::fs::create_dir_all("/var/lib/dd/workloads");
        let _ = std::fs::create_dir_all("/var/lib/dd/shared");
        eprintln!("dd-agent: init: mounted /var/lib/dd (tmpfs, writable)");
    }

    // Parse kernel cmdline for dd.* params → set as env vars
    // e.g. dd.DD_OWNER=devopsdefender → env DD_OWNER=devopsdefender
    if let Ok(cmdline) = std::fs::read_to_string("/proc/cmdline") {
        for param in cmdline.split_whitespace() {
            if let Some(kv) = param.strip_prefix("dd.") {
                if let Some((key, val)) = kv.split_once('=') {
                    std::env::set_var(key, val);
                    eprintln!("dd-agent: init: cmdline env {key}={val}");
                }
            }
            if let Some(hostname) = param.strip_prefix("hostname=") {
                let _ = std::fs::write("/etc/hostname", hostname);
                eprintln!("dd-agent: init: hostname={hostname}");
            }
        }
    }

    // Load config from config disk (second virtio disk with agent.env)
    // This is the per-deployment config — not baked into the VM image.
    // Note: rootfs is read-only (dm-verity), so /mnt/config must exist in the image
    // or we mount on /tmp/config instead (tmpfs is writable).
    let config_dir = "/tmp/config";
    let _ = std::fs::create_dir_all(config_dir);
    // Wait for config disk device to appear
    // Try vdb (virtio), sdb (scsi), or any second block device
    let config_mounted = {
        let mut mounted = false;
        // List /dev to find available block devices
        if let Ok(entries) = std::fs::read_dir("/dev") {
            let devs: Vec<String> = entries
                .flatten()
                .map(|e| e.file_name().to_string_lossy().to_string())
                .filter(|n| n.starts_with("vd") || n.starts_with("sd"))
                .collect();
            eprintln!("dd-agent: init: block devices: {devs:?}");
        }
        // Wait for device nodes to be fully created, then try mounting
        std::thread::sleep(std::time::Duration::from_secs(1));

        // Check device accessibility
        eprintln!(
            "dd-agent: init: /dev/vdb exists={}, metadata={:?}",
            std::path::Path::new("/dev/vdb").exists(),
            std::fs::metadata("/dev/vdb").err()
        );

        for dev in ["/dev/vdb", "/dev/sdb"] {
            for fstype in ["ext4", "vfat", "ext2"] {
                match nix_mount_ro(dev, config_dir, fstype) {
                    Ok(()) => {
                        eprintln!("dd-agent: init: mounted config disk ({dev}, {fstype})");
                        mounted = true;
                        break;
                    }
                    Err(e) => {
                        eprintln!("dd-agent: init: mount {dev} ({fstype}): {e}");
                    }
                }
            }
            if mounted {
                break;
            }
        }
        mounted
    };
    if !config_mounted {
        eprintln!("dd-agent: init: no config disk at /dev/vdb (or mount failed)");
    }
    if config_mounted {
        let env_path = format!("{config_dir}/agent.env");
        if let Ok(env_file) = std::fs::read_to_string(&env_path) {
            for line in env_file.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                if let Some((key, val)) = line.split_once('=') {
                    std::env::set_var(key.trim(), val.trim());
                    eprintln!("dd-agent: init: config env {key}={val}");
                }
            }
        }
        let _ = std::process::Command::new("umount")
            .arg(config_dir)
            .status();
    } else {
        eprintln!("dd-agent: init: no config disk at /dev/vdb");
    }

    // Set up networking from config (DD_IP, DD_GATEWAY, DD_DNS)
    let ip_bin = "/sbin/ip";
    let _ = std::process::Command::new(ip_bin)
        .args(["link", "set", "lo", "up"])
        .status();

    // Find first non-lo interface
    let iface = std::fs::read_dir("/sys/class/net")
        .ok()
        .and_then(|entries| {
            entries
                .flatten()
                .map(|e| e.file_name().to_string_lossy().to_string())
                .find(|n| n != "lo")
        });

    if let Some(ref iface) = iface {
        let _ = std::process::Command::new(ip_bin)
            .args(["link", "set", iface, "up"])
            .status();

        if let Ok(dd_ip) = std::env::var("DD_IP") {
            eprintln!("dd-agent: init: setting {iface} ip={dd_ip}");
            let _ = std::process::Command::new(ip_bin)
                .args(["addr", "add", &dd_ip, "dev", iface])
                .status();
        }
        if let Ok(gw) = std::env::var("DD_GATEWAY") {
            eprintln!("dd-agent: init: default route via {gw}");
            let _ = std::process::Command::new(ip_bin)
                .args(["route", "add", "default", "via", &gw, "dev", iface])
                .status();
        }
    }
    if let Ok(dns) = std::env::var("DD_DNS") {
        eprintln!("dd-agent: init: dns={dns}");
        let _ = std::fs::write("/tmp/resolv.conf", format!("nameserver {dns}\n"));
        // Bind-mount over the read-only /etc/resolv.conf
        let _ = nix_mount_flags("/tmp/resolv.conf", "/etc/resolv.conf", "", libc::MS_BIND);
    }

    // Start zombie reaper thread (PID 1 must reap children)
    std::thread::spawn(|| loop {
        unsafe {
            libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG);
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    });

    eprintln!("dd-agent: init complete");
}

fn nix_mount(src: &str, target: &str, fstype: &str) -> Result<(), String> {
    nix_mount_flags(src, target, fstype, 0)
}

fn nix_mount_ro(src: &str, target: &str, fstype: &str) -> Result<(), String> {
    nix_mount_flags(src, target, fstype, libc::MS_RDONLY)
}

fn nix_mount_flags(
    src: &str,
    target: &str,
    fstype: &str,
    flags: libc::c_ulong,
) -> Result<(), String> {
    use std::ffi::CString;
    let src = CString::new(src).unwrap();
    let target = CString::new(target).unwrap();
    let fstype = CString::new(fstype).unwrap();
    let ret = unsafe {
        libc::mount(
            src.as_ptr(),
            target.as_ptr(),
            fstype.as_ptr(),
            flags as libc::c_ulong,
            std::ptr::null(),
        )
    };
    if ret != 0 {
        Err(format!("errno {}", std::io::Error::last_os_error()))
    } else {
        Ok(())
    }
}

/// Exit safely — PID 1 cannot exit or the kernel panics.
/// When running as init, sleep forever instead of exiting.
fn safe_exit(code: i32) -> ! {
    if std::process::id() == 1 {
        eprintln!("dd-agent: fatal error (would exit {code}), halting as PID 1");
        loop {
            std::thread::sleep(std::time::Duration::from_secs(3600));
        }
    } else {
        std::process::exit(code);
    }
}

// ── Entry point ────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    maybe_init();

    let cfg = match AgentRuntimeConfig::load() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("dd-agent: configuration error: {e}");
            safe_exit(1);
        }
    };

    eprintln!("dd-agent: starting in {:?} mode", cfg.mode);

    match cfg.mode {
        AgentMode::Agent | AgentMode::Register => run_agent_mode(cfg).await,
        AgentMode::Scraper => {
            eprintln!("dd-agent: scraper mode deprecated — use dd-scraper binary instead");
            // Fallback: run the scraper binary if available, otherwise exit
            let status = tokio::process::Command::new("dd-scraper").status().await;
            match status {
                Ok(s) => std::process::exit(s.code().unwrap_or(1)),
                Err(_) => {
                    eprintln!("dd-agent: dd-scraper not found");
                    std::process::exit(1);
                }
            }
        }
        AgentMode::ControlPlane => run_control_plane_mode(cfg),
        AgentMode::Measure => measure::run_measure_mode(),
    }
}

// ── Agent mode ─────────────────────────────────────────────────────────────

async fn run_agent_mode(cfg: AgentRuntimeConfig) {
    if let Err(e) = std::fs::create_dir_all("/var/lib/dd/shared") {
        eprintln!("dd-agent: warning: failed to create shared volume dir: {e}");
    }

    let vm_name = hostname();
    let agent_id = stable_agent_id(&vm_name);
    let port: u16 = cfg.port.unwrap_or(8080);
    let attestation = dd_agent::attestation::detect();
    eprintln!(
        "dd-agent: attestation backend: {}",
        attestation.attestation_type()
    );

    let owner = std::env::var("DD_OWNER").unwrap_or_else(|_| {
        eprintln!("dd-agent: DD_OWNER not set");
        safe_exit(1);
    });
    let auth_mode = match server::GithubOAuthConfig::from_env() {
        Ok(Some(config)) => {
            if std::env::var("DD_PASSWORD")
                .ok()
                .filter(|s| !s.is_empty())
                .is_some()
            {
                eprintln!("dd-agent: warning: DD_PASSWORD ignored (GitHub OAuth takes priority)");
            }
            server::AuthMode::GitHub(config)
        }
        Ok(None) => {
            if let Some(password) = std::env::var("DD_PASSWORD").ok().filter(|s| !s.is_empty()) {
                let secure = std::env::var("DD_HOSTNAME")
                    .ok()
                    .map(|h| !h.contains("localhost"))
                    .unwrap_or(false);
                eprintln!("dd-agent: password auth enabled");
                server::AuthMode::Password {
                    password,
                    secure_cookies: secure,
                }
            } else {
                server::AuthMode::None
            }
        }
        Err(error) => {
            eprintln!("dd-agent: configuration error: {error}");
            safe_exit(1);
        }
    };

    // Ensure workloads directory exists
    let _ = tokio::fs::create_dir_all("/var/lib/dd/workloads/logs").await;

    // Auth config from register bootstrap (populated if agent registers via Noise)
    let mut bootstrap_auth_key: Option<jsonwebtoken::DecodingKey> = None;
    let mut bootstrap_auth_issuer: Option<String> = None;
    let mut register_url_for_deregister: Option<String> = None;
    let mut bootstrap_register_child: Option<tokio::process::Child> = None;

    // Bootstrap priority: pre-provisioned token > local register bootstrap > self-register via
    // CF API > register via Noise > standalone.
    let mut saved_tunnel_token: Option<String> = None;
    if let Some(token) = std::env::var("DD_TUNNEL_TOKEN")
        .ok()
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
    {
        eprintln!("dd-agent: using pre-provisioned tunnel token");
        saved_tunnel_token = Some(token.clone());
        if let Err(e) = start_cloudflared(&token).await {
            eprintln!("dd-agent: cloudflared start failed: {e}");
        }
    } else if let Some(register_binary_url) = env_var_nonempty("DD_BOOTSTRAP_REGISTER_BINARY_URL") {
        match bootstrap_local_register(&register_binary_url).await {
            Ok((child, register_url)) => {
                bootstrap_register_child = Some(child);
                let config = match start_register_supervisor(RegisterSupervisorConfig {
                    agent_id: agent_id.clone(),
                    vm_name: vm_name.clone(),
                    owner: owner.clone(),
                    register_url: register_url.clone(),
                    attestation: dd_agent::attestation::detect(),
                })
                .await
                {
                    Ok(config) => config,
                    Err(e) => {
                        eprintln!("dd-agent: register supervisor bootstrap failed: {e}");
                        safe_exit(1);
                    }
                };
                eprintln!(
                    "dd-agent: registered via local bootstrap register — owner={} hostname={}",
                    config.owner, config.hostname
                );
                register_url_for_deregister = Some(register_url.clone());
                if let Some(ref key_b64) = config.auth_public_key {
                    if let Some((_, decoding)) = server::auth_keys_from_b64(key_b64) {
                        bootstrap_auth_key = Some(decoding);
                        bootstrap_auth_issuer = config.auth_issuer.clone();
                        eprintln!("dd-agent: register auth tokens enabled");
                    }
                }
            }
            Err(e) => {
                eprintln!("dd-agent: bootstrap register failed: {e}");
                safe_exit(1);
            }
        }
    } else if dd_agent::tunnel::CfConfig::from_env().is_ok() {
        // Self-register: agent has CF API credentials, creates its own tunnel
        let cf = dd_agent::tunnel::CfConfig::from_env().unwrap();
        eprintln!("dd-agent: self-registering via CF API");
        let http = reqwest::Client::new();
        let hostname_override = std::env::var("DD_HOSTNAME").ok().filter(|s| !s.is_empty());
        match dd_agent::tunnel::create_agent_tunnel(
            &http,
            &cf,
            &agent_id,
            &vm_name,
            hostname_override.as_deref(),
        )
        .await
        {
            Ok(info) => {
                eprintln!("dd-agent: tunnel created — hostname={}", info.hostname);
                saved_tunnel_token = Some(info.tunnel_token.clone());
                if let Err(e) = start_cloudflared(&info.tunnel_token).await {
                    eprintln!("dd-agent: cloudflared start failed: {e}");
                }
            }
            Err(e) => {
                eprintln!("dd-agent: self-registration failed: {e}");
                safe_exit(1);
            }
        }
    } else if let Ok(register_url) = std::env::var("DD_REGISTER_URL") {
        let config = match start_register_supervisor(RegisterSupervisorConfig {
            agent_id: agent_id.clone(),
            vm_name: vm_name.clone(),
            owner: owner.clone(),
            register_url: register_url.clone(),
            attestation: dd_agent::attestation::detect(),
        })
        .await
        {
            Ok(config) => config,
            Err(e) => {
                eprintln!("dd-agent: register supervisor bootstrap failed: {e}");
                safe_exit(1);
            }
        };
        eprintln!(
            "dd-agent: registered — owner={} hostname={}",
            config.owner, config.hostname
        );
        register_url_for_deregister = Some(register_url.clone());
        // Store register-issued auth config for JWT verification
        if let Some(ref key_b64) = config.auth_public_key {
            if let Some((_, decoding)) = server::auth_keys_from_b64(key_b64) {
                bootstrap_auth_key = Some(decoding);
                bootstrap_auth_issuer = config.auth_issuer.clone();
                eprintln!("dd-agent: register auth tokens enabled");
            }
        }
    } else {
        eprintln!("dd-agent: no tunnel config set, running without tunnel");
    }

    let deployments: Deployments = Arc::new(Mutex::new(HashMap::new()));
    let process_handles: server::ProcessHandles = Arc::new(Mutex::new(HashMap::new()));
    let browser_sessions: server::BrowserSessions = Arc::new(Mutex::new(HashMap::new()));
    let pending_oauth_states: server::PendingOauthStates = Arc::new(Mutex::new(HashMap::new()));

    let register_mode = cfg.mode == config::AgentMode::Register;
    let cf_config = if register_mode {
        dd_agent::tunnel::CfConfig::from_env().ok()
    } else {
        None
    };

    // In register mode, generate auth signing keypair for issuing JWTs to agents
    let (auth_signing_key, auth_public_key_decoded, auth_public_key_b64, auth_issuer) =
        if register_mode {
            let (enc, dec, b64) = server::generate_auth_secret();
            let hostname = std::env::var("DD_HOSTNAME").unwrap_or_else(|_| "localhost".into());
            let issuer = format!("https://{hostname}");
            eprintln!("dd-agent: register auth token signing enabled");
            (Some(enc), Some(dec), Some(b64), Some(issuer))
        } else {
            // Agent mode: use bootstrap auth key if available
            (None, bootstrap_auth_key, None, bootstrap_auth_issuer)
        };

    let state = AgentState {
        owner,
        vm_name,
        agent_id,
        attestation_type: attestation.attestation_type().to_string(),
        deployments: deployments.clone(),
        process_handles,
        started_at: std::time::Instant::now(),
        auth_mode,
        browser_sessions,
        pending_oauth_states,
        register_mode,
        agent_registry: Arc::new(Mutex::new(HashMap::new())),
        cf_config,
        auth_signing_key,
        auth_public_key_decoded,
        auth_issuer,
        auth_public_key_b64,
    };

    // In register mode, add ourselves to the registry
    if register_mode {
        let hostname = std::env::var("DD_HOSTNAME").unwrap_or_else(|_| "localhost".into());
        let now = chrono::Utc::now();
        state.agent_registry.lock().await.insert(
            state.agent_id.clone(),
            server::RegisteredAgent {
                agent_id: state.agent_id.clone(),
                hostname,
                vm_name: state.vm_name.clone(),
                attestation_type: state.attestation_type.clone(),
                registered_at: now.to_rfc3339(),
                last_seen: now,
                status: "healthy".into(),
                deployment_count: 0,
                deployment_names: Vec::new(),
                cpu_percent: 0,
                memory_used_mb: 0,
                memory_total_mb: 0,
            },
        );
        eprintln!("dd-agent: registered self in fleet registry");
    }

    let local_mode = if register_mode { "register" } else { "agent" };
    let local_control_socket = match local_control::start(state.clone(), local_mode).await {
        Ok(path) => path,
        Err(error) => {
            eprintln!("dd-agent: local control startup failed: {error}");
            safe_exit(1);
        }
    };
    eprintln!("dd-agent: local control listening on {local_control_socket}");

    // HTTP server
    let http_port = port;
    let app = server::build_router(state.clone());
    let bind_addr = format!("0.0.0.0:{http_port}");
    eprintln!("dd-agent: HTTP server listening on {bind_addr}");

    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .expect("failed to bind HTTP server");

    // Monitoring loop (process liveness + self-update in register mode)
    let monitor_deps = deployments.clone();
    let monitor_registry = if register_mode {
        Some((state.agent_registry.clone(), state.agent_id.clone()))
    } else {
        None
    };
    tokio::spawn(async move {
        monitoring_loop(monitor_deps, monitor_registry, saved_tunnel_token).await;
    });

    // Run HTTP server until shutdown
    let app = app.into_make_service_with_connect_info::<std::net::SocketAddr>();
    let server = axum::serve(listener, app).with_graceful_shutdown(async {
        tokio::signal::ctrl_c().await.ok();
        eprintln!("dd-agent: shutdown signal received");
    });

    if let Err(e) = server.await {
        eprintln!("dd-agent: server error: {e}");
    }

    // Deregister from fleet on clean shutdown
    if let Some(ref register_url) = register_url_for_deregister {
        let url = register_url
            .replace("wss://", "https://")
            .replace("ws://", "http://")
            .replace("/register", "/deregister");
        let client = reqwest::Client::new();
        let _ = client
            .post(&url)
            .json(&serde_json::json!({"agent_id": state.agent_id}))
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await;
        eprintln!("dd-agent: deregistered from fleet");
    }

    if let Some(mut child) = bootstrap_register_child {
        if let Err(e) = stop_bootstrap_register(&mut child).await {
            eprintln!("dd-agent: bootstrap register shutdown failed: {e}");
        }
    }

    shutdown_deployments(deployments).await;
    eprintln!("dd-agent: shutdown complete");
}

fn build_attestation(
    vm_name: &str,
    backend: &dyn dd_agent::attestation::AttestationBackend,
    noise_static_public_key: &[u8],
) -> dd_agent::noise::AttestationPayload {
    dd_agent::noise::build_attestation_payload(vm_name, None, backend, noise_static_public_key)
}

async fn bootstrap_local_register(
    register_binary_url: &str,
) -> Result<(tokio::process::Child, String), String> {
    let port = env_var_nonempty("DD_BOOTSTRAP_REGISTER_PORT")
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(8081);
    let wait_secs = env_var_nonempty("DD_BOOTSTRAP_REGISTER_WAIT_SECS")
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(60);
    let install_dir = "/var/lib/dd/bootstrap";
    let binary_path = format!("{install_dir}/dd-register");
    let health_url = format!("http://127.0.0.1:{port}/health");
    let register_url = format!("ws://127.0.0.1:{port}/register");

    tokio::fs::create_dir_all(install_dir)
        .await
        .map_err(|e| format!("create bootstrap dir: {e}"))?;
    download_file(register_binary_url, &binary_path).await?;

    let mut perms = tokio::fs::metadata(&binary_path)
        .await
        .map_err(|e| format!("stat bootstrap register: {e}"))?
        .permissions();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        perms.set_mode(0o755);
    }
    tokio::fs::set_permissions(&binary_path, perms)
        .await
        .map_err(|e| format!("chmod bootstrap register: {e}"))?;

    eprintln!("dd-agent: starting local bootstrap register on 127.0.0.1:{port}");
    let mut cmd = tokio::process::Command::new(&binary_path);
    cmd.env("DD_REGISTER_BIND_ADDR", "127.0.0.1")
        .env("DD_REGISTER_PORT", port.to_string())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit());
    configure_parent_death_signal(&mut cmd);

    let mut child = cmd
        .spawn()
        .map_err(|e| format!("spawn bootstrap register: {e}"))?;

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()
        .map_err(|e| format!("build bootstrap health client: {e}"))?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(wait_secs);

    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|e| format!("check bootstrap register: {e}"))?
        {
            return Err(format!("bootstrap register exited early with {status}"));
        }

        match client.get(&health_url).send().await {
            Ok(resp) if resp.status().is_success() => {
                eprintln!("dd-agent: local bootstrap register healthy");
                return Ok((child, register_url));
            }
            Ok(_) | Err(_) if std::time::Instant::now() >= deadline => {
                let _ = stop_bootstrap_register(&mut child).await;
                return Err(format!(
                    "bootstrap register did not become healthy within {wait_secs}s"
                ));
            }
            Ok(_) | Err(_) => {
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
        }
    }
}

async fn download_file(url: &str, path: &str) -> Result<(), String> {
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::limited(10))
        .build()
        .map_err(|e| format!("build download client: {e}"))?;
    let response = client
        .get(url)
        .header(reqwest::header::ACCEPT, "application/octet-stream")
        .send()
        .await
        .map_err(|e| format!("download {url}: {e}"))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("download {url} failed: {status} {body}"));
    }

    let bytes = response
        .bytes()
        .await
        .map_err(|e| format!("read download {url}: {e}"))?;
    let tmp_path = format!("{path}.tmp");
    tokio::fs::write(&tmp_path, bytes)
        .await
        .map_err(|e| format!("write {tmp_path}: {e}"))?;
    tokio::fs::rename(&tmp_path, path)
        .await
        .map_err(|e| format!("rename {tmp_path} -> {path}: {e}"))?;
    Ok(())
}

// ── Noise registration (agent calls out to registration service) ─────────

type RegisterWsStream =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

struct RegisterSession {
    ws_stream: RegisterWsStream,
    transport: snow::TransportState,
    config: dd_agent::noise::BootstrapConfig,
}

struct RegisterSupervisorConfig {
    agent_id: String,
    vm_name: String,
    owner: String,
    register_url: String,
    attestation: Box<dyn dd_agent::attestation::AttestationBackend>,
}

async fn start_register_supervisor(
    cfg: RegisterSupervisorConfig,
) -> Result<dd_agent::noise::BootstrapConfig, String> {
    let session = connect_register_session(&cfg, &cfg.register_url).await?;
    let initial_config = session.config.clone();
    apply_bootstrap_config(&initial_config, None).await?;
    tokio::spawn(async move {
        register_supervisor_loop(cfg, session).await;
    });
    Ok(initial_config)
}

async fn register_supervisor_loop(cfg: RegisterSupervisorConfig, mut session: RegisterSession) {
    let mut current_config = session.config.clone();
    let mut current_register_url = current_config
        .redirect_url
        .clone()
        .unwrap_or_else(|| cfg.register_url.clone());

    loop {
        let renew_secs = std::cmp::max(current_config.lease_ttl_secs / 3, 5);
        tokio::time::sleep(std::time::Duration::from_secs(renew_secs)).await;

        match renew_register_lease(&mut session, &cfg.agent_id, current_config.register_epoch).await
        {
            Ok(response) => {
                let redirect_url = response
                    .redirect_url
                    .clone()
                    .filter(|url| url != &current_register_url);

                if response.revoked {
                    if let Some(ref url) = redirect_url {
                        current_register_url = url.clone();
                    }
                    eprintln!("dd-agent: register lease revoked, reconnecting");
                } else if !response.ok {
                    if let Some(ref url) = redirect_url {
                        current_register_url = url.clone();
                    }
                    eprintln!("dd-agent: register lease renewal rejected, reconnecting");
                } else if response.register_epoch > current_config.register_epoch {
                    if let Some(ref url) = redirect_url {
                        current_register_url = url.clone();
                    }
                    eprintln!(
                        "dd-agent: register epoch advanced from {} to {}, reconnecting{}",
                        current_config.register_epoch,
                        response.register_epoch,
                        redirect_url
                            .as_ref()
                            .map(|url| format!(" via {url}"))
                            .unwrap_or_default()
                    );
                    current_config.register_epoch = response.register_epoch;
                } else if let Some(url) = redirect_url {
                    eprintln!("dd-agent: register redirected control plane to {url}");
                    current_register_url = url;
                } else {
                    current_config.lease_ttl_secs = response.lease_ttl_secs.max(5);
                    session.config.lease_ttl_secs = current_config.lease_ttl_secs;
                    if !is_cloudflared_running().await {
                        eprintln!("dd-agent: cloudflared missing during active lease, restarting");
                        if let Err(error) = apply_bootstrap_config(
                            &current_config,
                            Some(&current_config.tunnel_token),
                        )
                        .await
                        {
                            eprintln!("dd-agent: cloudflared restart failed: {error}");
                        }
                    }
                    continue;
                }
            }
            Err(error) => {
                eprintln!("dd-agent: register lease renewal failed: {error}");
            }
        }

        let mut reconnect_delay = std::time::Duration::from_secs(1);
        loop {
            tokio::time::sleep(reconnect_delay).await;
            match connect_register_session(&cfg, &current_register_url).await {
                Ok(new_session) => {
                    let next_config = new_session.config.clone();
                    if let Err(error) =
                        apply_bootstrap_config(&next_config, Some(&current_config.tunnel_token))
                            .await
                    {
                        eprintln!(
                            "dd-agent: apply bootstrap config after reconnect failed: {error}"
                        );
                    }
                    current_config = next_config;
                    if let Some(ref redirect_url) = current_config.redirect_url {
                        current_register_url = redirect_url.clone();
                    }
                    session = new_session;
                    eprintln!(
                        "dd-agent: re-registered — hostname={} epoch={} register={}",
                        current_config.hostname,
                        current_config.register_epoch,
                        current_register_url
                    );
                    break;
                }
                Err(error) => {
                    eprintln!("dd-agent: register reconnect failed: {error}");
                    reconnect_delay = std::cmp::min(
                        reconnect_delay.saturating_mul(2),
                        std::time::Duration::from_secs(60),
                    );
                }
            }
        }
    }
}

async fn connect_register_session(
    cfg: &RegisterSupervisorConfig,
    register_url: &str,
) -> Result<RegisterSession, String> {
    use futures_util::SinkExt;
    use tokio_tungstenite::tungstenite;

    let keypair = dd_agent::noise::generate_keypair()?;
    let attestation = build_attestation(&cfg.vm_name, cfg.attestation.as_ref(), &keypair.public);
    let ws_url = register_url.to_string();

    let (mut ws_stream, _) = tokio_tungstenite::connect_async(&ws_url)
        .await
        .map_err(|e| format!("ws connect to {ws_url}: {e}"))?;

    let mut noise = snow::Builder::new(dd_agent::noise::NOISE_PATTERN.parse().unwrap())
        .local_private_key(&keypair.private)
        .map_err(|e| format!("key setup: {e}"))?
        .build_initiator()
        .map_err(|e| format!("build initiator: {e}"))?;

    let mut buf = vec![0u8; 65535];

    let mut msg1_buf = vec![0u8; 65535];
    let msg1_len = noise
        .write_message(&[], &mut msg1_buf)
        .map_err(|e| format!("msg1: {e}"))?;
    ws_stream
        .send(tungstenite::Message::Binary(msg1_buf[..msg1_len].to_vec()))
        .await
        .map_err(|e| format!("send msg1: {e}"))?;

    let msg2 = next_register_binary_message(&mut ws_stream, "msg2").await?;
    let payload_len = noise
        .read_message(&msg2, &mut buf)
        .map_err(|e| format!("msg2: {e}"))?;
    let responder_attestation: dd_agent::noise::AttestationPayload =
        serde_json::from_slice(&buf[..payload_len]).map_err(|e| format!("attestation: {e}"))?;
    let remote_static = noise
        .get_remote_static()
        .ok_or_else(|| "noise responder static key missing after msg2".to_string())?;
    dd_agent::noise::verify_remote_attestation(&responder_attestation, remote_static)?;

    let attestation_json = serde_json::to_vec(&attestation).unwrap();
    let mut msg3_buf = vec![0u8; 65535];
    let msg3_len = noise
        .write_message(&attestation_json, &mut msg3_buf)
        .map_err(|e| format!("msg3: {e}"))?;
    ws_stream
        .send(tungstenite::Message::Binary(msg3_buf[..msg3_len].to_vec()))
        .await
        .map_err(|e| format!("send msg3: {e}"))?;

    let mut transport = noise
        .into_transport_mode()
        .map_err(|e| format!("transport: {e}"))?;

    let req = dd_agent::noise::RegisterRequest {
        owner: cfg.owner.clone(),
        vm_name: cfg.vm_name.clone(),
        agent_id: cfg.agent_id.clone(),
    };
    let req_json = serde_json::to_vec(&req).unwrap();
    let mut enc_buf = vec![0u8; 65535];
    let enc_len = transport
        .write_message(&req_json, &mut enc_buf)
        .map_err(|e| format!("encrypt register request: {e}"))?;
    ws_stream
        .send(tungstenite::Message::Binary(enc_buf[..enc_len].to_vec()))
        .await
        .map_err(|e| format!("send register request: {e}"))?;

    let enc_resp = next_register_binary_message(&mut ws_stream, "bootstrap").await?;
    let resp_len = transport
        .read_message(&enc_resp, &mut buf)
        .map_err(|e| format!("decrypt bootstrap config: {e}"))?;
    let config: dd_agent::noise::BootstrapConfig =
        serde_json::from_slice(&buf[..resp_len]).map_err(|e| format!("parse config: {e}"))?;

    Ok(RegisterSession {
        ws_stream,
        transport,
        config,
    })
}

async fn renew_register_lease(
    session: &mut RegisterSession,
    agent_id: &str,
    register_epoch: u64,
) -> Result<dd_agent::noise::LeaseRenewResponse, String> {
    use futures_util::SinkExt;
    use tokio_tungstenite::tungstenite;

    let request = dd_agent::noise::LeaseRenewRequest {
        agent_id: agent_id.to_string(),
        register_epoch,
    };
    let request_json = serde_json::to_vec(&request).unwrap();
    let mut enc_buf = vec![0u8; 65535];
    let enc_len = session
        .transport
        .write_message(&request_json, &mut enc_buf)
        .map_err(|e| format!("encrypt lease renew: {e}"))?;
    session
        .ws_stream
        .send(tungstenite::Message::Binary(enc_buf[..enc_len].to_vec()))
        .await
        .map_err(|e| format!("send lease renew: {e}"))?;

    let enc_resp = next_register_binary_message(&mut session.ws_stream, "lease renew").await?;
    let mut buf = vec![0u8; 65535];
    let resp_len = session
        .transport
        .read_message(&enc_resp, &mut buf)
        .map_err(|e| format!("decrypt lease renew response: {e}"))?;
    serde_json::from_slice(&buf[..resp_len]).map_err(|e| format!("parse lease renew response: {e}"))
}

async fn next_register_binary_message(
    ws_stream: &mut RegisterWsStream,
    label: &str,
) -> Result<Vec<u8>, String> {
    use futures_util::StreamExt;
    use tokio_tungstenite::tungstenite;

    match ws_stream.next().await {
        Some(Ok(tungstenite::Message::Binary(data))) => Ok(data.to_vec()),
        Some(Ok(tungstenite::Message::Close(frame))) => {
            Err(format!("register closed during {label}: {frame:?}"))
        }
        Some(Ok(other)) => Err(format!("expected binary {label}, got {other:?}")),
        Some(Err(error)) => Err(format!("receive {label}: {error}")),
        None => Err(format!("register stream ended during {label}")),
    }
}

async fn apply_bootstrap_config(
    config: &dd_agent::noise::BootstrapConfig,
    previous_tunnel_token: Option<&str>,
) -> Result<(), String> {
    let token_changed = previous_tunnel_token
        .map(|token| token != config.tunnel_token)
        .unwrap_or(true);

    if token_changed {
        stop_cloudflared().await?;
    }

    if token_changed || !is_cloudflared_running().await {
        start_cloudflared(&config.tunnel_token).await?;
    }

    Ok(())
}

// ── Monitoring loop — check process liveness by PID ─────────────────────

async fn monitoring_loop(
    deployments: Deployments,
    self_registry: Option<(server::AgentRegistry, String)>,
    tunnel_token: Option<String>,
) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
    let mut last_reregister: Option<std::time::Instant> = None;
    let reregister_cooldown = std::time::Duration::from_secs(5 * 60);
    loop {
        interval.tick().await;

        let entries: Vec<(String, Option<u32>, Option<String>)> = {
            let deps = deployments.lock().await;
            deps.values()
                .filter(|d| d.status == "running")
                .map(|d| (d.id.clone(), d.pid, d.container_id.clone()))
                .collect()
        };

        for (dep_id, pid, container_id) in &entries {
            let alive = if let Some(cid) = container_id {
                dd_agent::container::is_running(cid).await
            } else if let Some(pid) = pid {
                dd_agent::process::is_running(*pid)
            } else {
                false
            };
            if !alive {
                eprintln!("dd-agent: deployment {dep_id} workload gone");
                let mut deps = deployments.lock().await;
                if let Some(info) = deps.get_mut(dep_id) {
                    info.status = "exited".into();
                }
            }
        }

        // In register mode, update own entry with current metrics
        if let Some((ref registry, ref self_id)) = self_registry {
            let deps = deployments.lock().await;
            let deployment_count = deps.len();
            let dep_names: Vec<String> = deps
                .values()
                .filter(|d| d.status == "running")
                .map(|d| d.app_name.clone())
                .collect();
            drop(deps);
            let metrics = server::collect_system_metrics().await;
            let mut reg = registry.lock().await;
            if let Some(self_entry) = reg.get_mut(self_id) {
                self_entry.last_seen = chrono::Utc::now();
                self_entry.deployment_count = deployment_count;
                self_entry.deployment_names = dep_names;
                self_entry.cpu_percent = metrics.cpu_pct;
                self_entry.memory_used_mb = metrics.mem_used_mb;
                self_entry.memory_total_mb = metrics.mem_total_mb;
            }
        }

        // Check if cloudflared is alive; if dead and we have a static tunnel token, restart it.
        if !is_cloudflared_running().await {
            let can_reregister = last_reregister
                .map(|t: std::time::Instant| t.elapsed() > reregister_cooldown)
                .unwrap_or(true);
            if let Some(ref token) = tunnel_token {
                // Self-registered or pre-provisioned tunnel — restart with saved token
                if can_reregister {
                    last_reregister = Some(std::time::Instant::now());
                    eprintln!("dd-agent: cloudflared dead, restarting with saved tunnel token");
                    if let Err(e) = start_cloudflared(token).await {
                        eprintln!("dd-agent: cloudflared restart failed: {e}");
                    }
                }
            } else {
                eprintln!("dd-agent: cloudflared not running (no way to reconnect)");
            }
        }
    }
}

// ── Cloudflared ───────────────────────────────────────────────────────────

async fn start_cloudflared(tunnel_token: &str) -> Result<(), String> {
    use tokio::process::Command;
    eprintln!("dd-agent: starting cloudflared tunnel");
    let _child = Command::new("cloudflared")
        .args(["tunnel", "--no-autoupdate", "run", "--token", tunnel_token])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn cloudflared: {e}"))?;
    // Give it a moment, then check stderr if it died
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    if !is_process_running("cloudflared") {
        // Try to read stderr from the dead process
        eprintln!("dd-agent: cloudflared died quickly, checking output...");
        let output = Command::new("cloudflared").args(["version"]).output().await;
        eprintln!("dd-agent: cloudflared version: {output:?}");
    }
    // Wait for cloudflared to initialize, then check /proc for the process.
    // We can't use try_wait() when PID 1 because the zombie reaper thread
    // may have already reaped the child via waitpid(-1).
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    if is_process_running("cloudflared") {
        eprintln!("dd-agent: cloudflared running");
        Ok(())
    } else {
        Err("cloudflared not running after spawn".into())
    }
}

async fn stop_bootstrap_register(child: &mut tokio::process::Child) -> Result<(), String> {
    if child
        .try_wait()
        .map_err(|e| format!("check bootstrap register: {e}"))?
        .is_some()
    {
        return Ok(());
    }

    child
        .start_kill()
        .map_err(|e| format!("signal bootstrap register: {e}"))?;
    match tokio::time::timeout(std::time::Duration::from_secs(5), child.wait()).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(format!("wait bootstrap register: {e}")),
        Err(_) => Err("timed out waiting for bootstrap register exit".into()),
    }
}

async fn is_cloudflared_running() -> bool {
    is_process_running("cloudflared")
}

async fn stop_cloudflared() -> Result<(), String> {
    let pids = process_ids_by_name("cloudflared");
    for pid in pids {
        dd_agent::process::kill_process(pid).await?;
    }
    Ok(())
}

fn stable_agent_id(vm_name: &str) -> String {
    if let Some(id) = env_var_nonempty("DD_AGENT_ID") {
        return id;
    }

    let env = std::env::var("DD_ENV").unwrap_or_else(|_| "dev".into());
    let owner = std::env::var("DD_OWNER").unwrap_or_else(|_| "unknown".into());
    let source = format!("{owner}:{env}:{vm_name}");
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(source.as_bytes());
    digest[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn configure_parent_death_signal(cmd: &mut tokio::process::Command) {
    #[cfg(target_os = "linux")]
    {
        unsafe {
            cmd.pre_exec(|| {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
}

fn env_var_nonempty(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// Check if a process with the given name is running by scanning /proc.
fn is_process_running(name: &str) -> bool {
    !process_ids_by_name(name).is_empty()
}

fn process_ids_by_name(name: &str) -> Vec<u32> {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    let mut pids = Vec::new();
    for entry in entries.flatten() {
        let fname = entry.file_name();
        let pid_str = fname.to_string_lossy();
        if pid_str.chars().all(|c| c.is_ascii_digit()) {
            let cmdline_path = format!("/proc/{pid_str}/cmdline");
            if let Ok(cmdline) = std::fs::read_to_string(&cmdline_path) {
                if cmdline.contains(name) {
                    if let Ok(pid) = pid_str.parse::<u32>() {
                        pids.push(pid);
                    }
                }
            }
        }
    }
    pids
}

// ── Graceful shutdown ────────────────────────────────────────────────────

async fn shutdown_deployments(deployments: Deployments) {
    let entries: Vec<(String, Option<u32>)> = {
        let deps = deployments.lock().await;
        deps.values().map(|d| (d.id.clone(), d.pid)).collect()
    };

    for (dep_id, pid) in entries {
        if let Some(pid) = pid {
            eprintln!("dd-agent: stopping deployment {dep_id} (pid {pid})...");
            let _ = dd_agent::process::kill_process(pid).await;
        }
    }

    deployments.lock().await.clear();
}

// ── Control-plane mode ─────────────────────────────────────────────────────

fn run_control_plane_mode(cfg: AgentRuntimeConfig) {
    eprintln!("dd-agent: starting control plane (dd-cp)");
    let mut cmd = std::process::Command::new("dd-cp");
    if let Some(ref dc) = cfg.datacenter {
        cmd.env("DD_DATACENTER", dc);
    }
    if let Some(ref key) = cfg.intel_api_key {
        cmd.env("DD_INTEL_API_KEY", key);
    }
    if let Some(ref port) = cfg.port {
        cmd.env("DD_PORT", port.to_string());
    }
    for (k, v) in &cfg.raw_kv {
        cmd.env(k, v);
    }
    match cmd.status() {
        Ok(status) if !status.success() => {
            eprintln!("dd-agent: dd-cp exited with {status}");
            safe_exit(status.code().unwrap_or(1));
        }
        Err(e) => {
            eprintln!("dd-agent: failed to start dd-cp: {e}");
            safe_exit(1);
        }
        _ => {}
    }
}

// ── Helpers ────────────────────────────────────────────────────────────────

fn hostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .unwrap_or_else(|_| "unknown".into())
        .trim()
        .to_string()
}
