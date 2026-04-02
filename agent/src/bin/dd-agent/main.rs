mod config;
mod measure;

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

use config::{AgentMode, AgentRuntimeConfig};
use dd_agent::server::{AgentState, Deployments};

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

    // Bring up loopback
    let _ = std::process::Command::new("ip")
        .args(["link", "set", "lo", "up"])
        .status();

    // DHCP on first non-lo interface
    if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name != "lo" {
                eprintln!("dd-agent: init: bringing up {name}");
                let _ = std::process::Command::new("ip")
                    .args(["link", "set", &name, "up"])
                    .status();
                // Simple DHCP via busybox udhcpc or dhclient if available
                if std::process::Command::new("udhcpc")
                    .args(["-i", &name, "-n", "-q"])
                    .status()
                    .is_err()
                {
                    // Fallback: try dhclient
                    let _ = std::process::Command::new("dhclient")
                        .args([&name])
                        .status();
                }
                break;
            }
        }
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
    // This is the per-deployment config — not baked into the sealed image.
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
        AgentMode::Scraper => run_scraper_mode().await,
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
    let agent_id = uuid::Uuid::new_v4().to_string();
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
    let oauth = match dd_agent::server::GithubOAuthConfig::from_env() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("dd-agent: configuration error: {error}");
            safe_exit(1);
        }
    };

    // Ensure workloads directory exists
    let _ = tokio::fs::create_dir_all("/var/lib/dd/workloads/logs").await;

    // Bootstrap priority: pre-provisioned token > self-register via CF API > register via Noise > standalone
    if let Some(token) = std::env::var("DD_TUNNEL_TOKEN")
        .ok()
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
    {
        eprintln!("dd-agent: using pre-provisioned tunnel token");
        if let Err(e) = start_cloudflared(&token).await {
            eprintln!("dd-agent: cloudflared start failed: {e}");
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
        let config = register(&vm_name, &owner, &register_url, attestation.as_ref()).await;
        eprintln!(
            "dd-agent: registered — owner={} hostname={}",
            config.owner, config.hostname
        );
        if let Err(e) = start_cloudflared(&config.tunnel_token).await {
            eprintln!("dd-agent: cloudflared start failed: {e}");
        }
    } else {
        eprintln!("dd-agent: no tunnel config set, running without tunnel");
    }

    let deployments: Deployments = Arc::new(Mutex::new(HashMap::new()));
    let process_handles: dd_agent::server::ProcessHandles = Arc::new(Mutex::new(HashMap::new()));
    let browser_sessions: dd_agent::server::BrowserSessions = Arc::new(Mutex::new(HashMap::new()));
    let pending_oauth_states: dd_agent::server::PendingOauthStates =
        Arc::new(Mutex::new(HashMap::new()));

    // Auto-deploy boot workload if configured
    // DD_BOOT_CMD="bash" — run a direct command (no OCI pull)
    // DD_BOOT_IMAGE="alpine:latest" — pull OCI image and chroot
    if let Ok(boot_cmd) = std::env::var("DD_BOOT_CMD") {
        let boot_app = std::env::var("DD_BOOT_APP").unwrap_or_else(|_| "shell".into());
        eprintln!("dd-agent: starting boot shell: {boot_cmd}");
        let boot_app_clone = boot_app.clone();
        match dd_agent::process::spawn_command(&boot_cmd, &[], true).await {
            Ok(mut child) => {
                let dep_id = uuid::Uuid::new_v4().to_string();
                let short_id = dep_id[..8].to_string();
                let pid = child.id();
                deployments.lock().await.insert(
                    short_id.clone(),
                    dd_agent::server::DeploymentInfo {
                        id: short_id,
                        pid,
                        app_name: boot_app,
                        image: boot_cmd,
                        status: "running".into(),
                        error_message: None,
                        started_at: chrono::Utc::now().to_rfc3339(),
                    },
                );
                // Store I/O handles for web terminal
                let (stdout_tx, _) = tokio::sync::broadcast::channel::<Vec<u8>>(256);
                if let Some(stdin) = child.stdin.take() {
                    process_handles.lock().await.insert(
                        boot_app_clone.clone(),
                        dd_agent::server::ProcessIO {
                            stdin,
                            stdout_tx: stdout_tx.clone(),
                        },
                    );
                }
                // Pipe stdout through broadcast channel
                if let Some(stdout) = child.stdout.take() {
                    tokio::spawn(async move {
                        use tokio::io::AsyncReadExt;
                        let mut stdout = stdout;
                        let mut buf = vec![0u8; 4096];
                        loop {
                            match stdout.read(&mut buf).await {
                                Ok(0) => break,
                                Ok(n) => {
                                    let _ = stdout_tx.send(buf[..n].to_vec());
                                }
                                Err(_) => break,
                            }
                        }
                    });
                }
                // Wait for process in background
                tokio::spawn(async move {
                    let _ = child.wait().await;
                });
                eprintln!("dd-agent: boot shell running");
            }
            Err(e) => eprintln!("dd-agent: boot shell failed: {e}"),
        }
    } else if let Ok(boot_image) = std::env::var("DD_BOOT_IMAGE") {
        let boot_app = std::env::var("DD_BOOT_APP").unwrap_or_else(|_| "boot".into());
        let boot_tty = std::env::var("DD_BOOT_TTY")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false);
        // DD_BOOT_ENV: semicolon-separated KEY=VALUE pairs passed to the workload
        let boot_env = std::env::var("DD_BOOT_ENV").ok().map(|s| {
            s.split(';')
                .map(|kv| kv.trim().to_string())
                .filter(|kv| !kv.is_empty())
                .collect::<Vec<String>>()
        });
        eprintln!("dd-agent: auto-deploying boot workload {boot_app} ({boot_image})");
        let req = dd_agent::server::DeployRequest {
            image: boot_image,
            env: boot_env,
            cmd: None,
            app_name: Some(boot_app),
            app_version: None,
            tty: boot_tty,
        };
        let (id, status) = dd_agent::server::execute_deploy(&deployments, req).await;
        eprintln!("dd-agent: boot workload {id} {status}");
    }

    // Deploy additional boot workloads: DD_BOOT_IMAGE_2, DD_BOOT_APP_2, etc.
    for i in 2..=9 {
        let image_key = format!("DD_BOOT_IMAGE_{i}");
        if let Ok(image) = std::env::var(&image_key) {
            let app_name =
                std::env::var(format!("DD_BOOT_APP_{i}")).unwrap_or_else(|_| format!("boot-{i}"));
            let tty = std::env::var(format!("DD_BOOT_TTY_{i}"))
                .map(|v| v == "true" || v == "1")
                .unwrap_or(false);
            let env = std::env::var(format!("DD_BOOT_ENV_{i}")).ok().map(|s| {
                s.split(';')
                    .map(|kv| kv.trim().to_string())
                    .filter(|kv| !kv.is_empty())
                    .collect::<Vec<String>>()
            });
            eprintln!("dd-agent: auto-deploying additional workload {app_name} ({image})");
            let req = dd_agent::server::DeployRequest {
                image,
                env,
                cmd: None,
                app_name: Some(app_name),
                app_version: None,
                tty,
            };
            let (id, status) = dd_agent::server::execute_deploy(&deployments, req).await;
            eprintln!("dd-agent: additional workload {id} {status}");
        } else {
            break;
        }
    }

    let register_mode = cfg.mode == config::AgentMode::Register;
    let cf_config = if register_mode {
        dd_agent::tunnel::CfConfig::from_env().ok()
    } else {
        None
    };

    let state = AgentState {
        owner,
        vm_name,
        agent_id,
        attestation_type: attestation.attestation_type().to_string(),
        deployments: deployments.clone(),
        process_handles,
        started_at: std::time::Instant::now(),
        oauth,
        browser_sessions,
        pending_oauth_states,
        register_mode,
        agent_registry: Arc::new(Mutex::new(HashMap::new())),
        cf_config,
    };

    // In register mode, add ourselves to the registry
    if register_mode {
        let hostname = std::env::var("DD_HOSTNAME").unwrap_or_else(|_| "localhost".into());
        let now = chrono::Utc::now();
        state.agent_registry.lock().await.insert(
            state.agent_id.clone(),
            dd_agent::server::RegisteredAgent {
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

    // HTTP server
    let http_port = port;
    let app = dd_agent::server::build_router(state.clone());
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
        monitoring_loop(monitor_deps, monitor_registry).await;
    });

    // Run HTTP server until shutdown
    let register_url_for_deregister = std::env::var("DD_REGISTER_URL").ok();
    let app = app.into_make_service_with_connect_info::<std::net::SocketAddr>();
    let server = axum::serve(listener, app).with_graceful_shutdown(async {
        tokio::signal::ctrl_c().await.ok();
        eprintln!("dd-agent: shutdown signal received");
    });

    if let Err(e) = server.await {
        eprintln!("dd-agent: server error: {e}");
    }

    // Deregister from fleet on clean shutdown
    if let Some(register_url) = register_url_for_deregister {
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

    shutdown_deployments(deployments).await;
    eprintln!("dd-agent: shutdown complete");
}

// ── Scraper mode ──────────────────────────────────────────────────────────

async fn run_scraper_mode() {
    let cf = dd_agent::tunnel::CfConfig::from_env().unwrap_or_else(|e| {
        eprintln!("dd-scraper: CF config required: {e}");
        safe_exit(1);
    });

    let register_url = std::env::var("DD_REGISTER_URL").unwrap_or_else(|_| {
        eprintln!("dd-scraper: DD_REGISTER_URL required");
        safe_exit(1);
    });

    let env_label = std::env::var("DD_ENV").unwrap_or_else(|_| "dev".into());
    let tunnel_prefix = format!("dd-{env_label}-");
    let scrape_interval = std::time::Duration::from_secs(30);
    let scrape_timeout = std::time::Duration::from_secs(3);

    let attestation = dd_agent::attestation::detect();
    eprintln!(
        "dd-scraper: starting (env={env_label}, attestation={})",
        attestation.attestation_type()
    );

    // Connect to register via Noise WebSocket
    let ws_url = register_url.replace("/register", "/scraper");
    let ws_url = if ws_url.ends_with("/scraper") {
        ws_url
    } else {
        format!("{ws_url}/scraper")
    };

    loop {
        eprintln!("dd-scraper: connecting to register at {ws_url}");
        match connect_and_scrape(
            &ws_url,
            &cf,
            &tunnel_prefix,
            scrape_interval,
            scrape_timeout,
            attestation.as_ref(),
        )
        .await
        {
            Ok(()) => eprintln!("dd-scraper: session ended, reconnecting..."),
            Err(e) => eprintln!("dd-scraper: error: {e}, reconnecting in 10s..."),
        }
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
    }
}

async fn connect_and_scrape(
    ws_url: &str,
    cf: &dd_agent::tunnel::CfConfig,
    tunnel_prefix: &str,
    interval: std::time::Duration,
    timeout: std::time::Duration,
    backend: &dyn dd_agent::attestation::AttestationBackend,
) -> Result<(), String> {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite;

    let keypair = dd_agent::noise::generate_keypair()?;
    let attestation = dd_agent::noise::AttestationPayload {
        attestation_type: backend.attestation_type().to_string(),
        vm_name: "scraper".to_string(),
        tdx_quote_b64: backend.generate_quote_b64(),
    };

    // Connect WebSocket
    let (ws_stream, _) = tokio_tungstenite::connect_async(ws_url)
        .await
        .map_err(|e| format!("ws connect: {e}"))?;
    let (mut ws_tx, mut ws_rx) = ws_stream.split();

    // Noise XX handshake (scraper is initiator)
    let mut noise = snow::Builder::new(dd_agent::noise::NOISE_PATTERN.parse().unwrap())
        .local_private_key(&keypair.private)
        .map_err(|e| format!("key: {e}"))?
        .build_initiator()
        .map_err(|e| format!("init: {e}"))?;

    let mut buf = vec![0u8; 65535];

    // msg1
    let mut msg1 = vec![0u8; 65535];
    let len = noise
        .write_message(&[], &mut msg1)
        .map_err(|e| format!("msg1: {e}"))?;
    ws_tx
        .send(tungstenite::Message::Binary(msg1[..len].to_vec()))
        .await
        .map_err(|e| format!("send msg1: {e}"))?;

    // msg2
    let msg2 = match ws_rx.next().await {
        Some(Ok(tungstenite::Message::Binary(d))) => d.to_vec(),
        other => return Err(format!("expected msg2, got: {other:?}")),
    };
    noise
        .read_message(&msg2, &mut buf)
        .map_err(|e| format!("msg2: {e}"))?;

    // msg3 with attestation
    let att_json = serde_json::to_vec(&attestation).unwrap();
    let mut msg3 = vec![0u8; 65535];
    let len = noise
        .write_message(&att_json, &mut msg3)
        .map_err(|e| format!("msg3: {e}"))?;
    ws_tx
        .send(tungstenite::Message::Binary(msg3[..len].to_vec()))
        .await
        .map_err(|e| format!("send msg3: {e}"))?;

    let mut transport = noise
        .into_transport_mode()
        .map_err(|e| format!("transport: {e}"))?;

    eprintln!("dd-scraper: connected to register, starting scrape loop");

    let http = reqwest::Client::builder()
        .timeout(timeout)
        .build()
        .map_err(|e| format!("http client: {e}"))?;

    let mut ticker = tokio::time::interval(interval);
    loop {
        ticker.tick().await;

        // 1. List CF tunnels
        let tunnels = list_cf_tunnels(&http, cf, tunnel_prefix).await;
        eprintln!(
            "dd-scraper: found {} tunnels matching {tunnel_prefix}*",
            tunnels.len()
        );

        // 2. Scrape all agents concurrently with timeout
        let scrape_futures: Vec<_> = tunnels
            .iter()
            .map(|(name, hostname)| {
                let http = http.clone();
                let hostname = hostname.clone();
                let name = name.clone();
                async move {
                    let url = format!("https://{hostname}/health");
                    match http.get(&url).send().await {
                        Ok(resp) if resp.status().is_success() => {
                            let health: serde_json::Value = resp.json().await.unwrap_or_default();
                            (name, hostname, true, Some(health), None)
                        }
                        Ok(resp) => (
                            name,
                            hostname,
                            false,
                            None,
                            Some(format!("status {}", resp.status())),
                        ),
                        Err(e) => (name, hostname, false, None, Some(e.to_string())),
                    }
                }
            })
            .collect();

        let results = futures_util::future::join_all(scrape_futures).await;

        // 3. Build fleet report
        let mut agents = Vec::new();
        let mut orphan_tunnels = Vec::new();

        for (tunnel_name, hostname, healthy, health, error) in &results {
            if *healthy {
                if let Some(h) = health {
                    agents.push(serde_json::json!({
                        "hostname": hostname,
                        "healthy": true,
                        "agent_id": h.get("agent_id").and_then(|v| v.as_str()),
                        "vm_name": h.get("vm_name").and_then(|v| v.as_str()),
                        "attestation_type": h.get("attestation_type").and_then(|v| v.as_str()),
                        "deployment_count": h.get("deployment_count").and_then(|v| v.as_u64()),
                        "cpu_percent": h.get("cpu_percent").and_then(|v| v.as_u64()),
                        "memory_used_mb": h.get("memory_used_mb").and_then(|v| v.as_u64()),
                        "memory_total_mb": h.get("memory_total_mb").and_then(|v| v.as_u64()),
                        "deployments": h.get("deployments"),
                    }));
                }
            } else {
                agents.push(serde_json::json!({
                    "hostname": hostname,
                    "healthy": false,
                    "error": error,
                }));
                // If agent didn't respond at all, it might be an orphan tunnel
                if error
                    .as_ref()
                    .is_some_and(|e| e.contains("connect") || e.contains("timed out"))
                {
                    orphan_tunnels.push(tunnel_name.clone());
                }
            }
        }

        let report = serde_json::json!({
            "agents": agents,
            "orphan_tunnels": orphan_tunnels,
        });

        eprintln!(
            "dd-scraper: reporting {} agents ({} healthy, {} unhealthy, {} orphans)",
            results.len(),
            results.iter().filter(|r| r.2).count(),
            results.iter().filter(|r| !r.2).count(),
            orphan_tunnels.len(),
        );

        // 4. Send encrypted report to register
        let report_json = serde_json::to_vec(&report).unwrap();
        let mut enc = vec![0u8; 65535];
        let len = transport
            .write_message(&report_json, &mut enc)
            .map_err(|e| format!("encrypt: {e}"))?;
        ws_tx
            .send(tungstenite::Message::Binary(enc[..len].to_vec()))
            .await
            .map_err(|e| format!("send: {e}"))?;

        // Wait for ack
        match tokio::time::timeout(std::time::Duration::from_secs(10), ws_rx.next()).await {
            Ok(Some(Ok(tungstenite::Message::Binary(data)))) => {
                let data = data.to_vec();
                let _ = transport.read_message(&data, &mut buf);
            }
            _ => {
                return Err("no ack from register".into());
            }
        }
    }
}

/// List CF tunnels matching prefix, returns (tunnel_name, hostname).
async fn list_cf_tunnels(
    client: &reqwest::Client,
    cf: &dd_agent::tunnel::CfConfig,
    prefix: &str,
) -> Vec<(String, String)> {
    let url = format!(
        "https://api.cloudflare.com/client/v4/accounts/{}/cfd_tunnel?is_deleted=false",
        cf.account_id
    );

    let resp = match client
        .get(&url)
        .header("Authorization", format!("Bearer {}", cf.api_token))
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("dd-scraper: CF API error: {e}");
            return Vec::new();
        }
    };

    let body: serde_json::Value = resp.json().await.unwrap_or_default();
    let mut tunnels = Vec::new();

    if let Some(results) = body["result"].as_array() {
        for t in results {
            if let Some(name) = t["name"].as_str() {
                if name.starts_with(prefix) {
                    // Derive hostname from tunnel name: dd-{env}-{uuid} → dd-{env}-{uuid}.{domain}
                    let hostname = format!("{name}.{}", cf.domain);
                    tunnels.push((name.to_string(), hostname));
                }
            }
        }
    }

    tunnels
}

fn build_attestation(
    vm_name: &str,
    backend: &dyn dd_agent::attestation::AttestationBackend,
) -> dd_agent::noise::AttestationPayload {
    dd_agent::noise::AttestationPayload {
        attestation_type: backend.attestation_type().to_string(),
        vm_name: vm_name.to_string(),
        tdx_quote_b64: backend.generate_quote_b64(),
    }
}

// ── Bootstrap resolution ─────────────────────────────────────────────────

async fn register(
    vm_name: &str,
    owner: &str,
    register_url: &str,
    backend: &dyn dd_agent::attestation::AttestationBackend,
) -> dd_agent::noise::BootstrapConfig {
    match register_via_noise(register_url, vm_name, owner, backend).await {
        Ok(config) => config,
        Err(e) => {
            eprintln!("dd-agent: registration failed: {e}");
            safe_exit(1);
        }
    }
}

// ── Noise registration (agent calls out to registration service) ─────────

async fn register_via_noise(
    register_url: &str,
    vm_name: &str,
    owner: &str,
    backend: &dyn dd_agent::attestation::AttestationBackend,
) -> Result<dd_agent::noise::BootstrapConfig, String> {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite;

    let keypair = dd_agent::noise::generate_keypair()?;
    let attestation = build_attestation(vm_name, backend);

    // Connect via WebSocket — DD_REGISTER_URL is already a full URL like wss://host/register
    let ws_url = register_url.to_string();
    let (ws_stream, _) = tokio_tungstenite::connect_async(&ws_url)
        .await
        .map_err(|e| format!("ws connect to {ws_url}: {e}"))?;

    let (mut ws_tx, mut ws_rx) = ws_stream.split();

    let mut noise = snow::Builder::new(dd_agent::noise::NOISE_PATTERN.parse().unwrap())
        .local_private_key(&keypair.private)
        .map_err(|e| format!("key setup: {e}"))?
        .build_initiator()
        .map_err(|e| format!("build initiator: {e}"))?;

    let mut buf = vec![0u8; 65535];

    // XX handshake over WebSocket binary frames

    // msg1
    let mut msg1_buf = vec![0u8; 65535];
    let msg1_len = noise
        .write_message(&[], &mut msg1_buf)
        .map_err(|e| format!("msg1: {e}"))?;
    ws_tx
        .send(tungstenite::Message::Binary(msg1_buf[..msg1_len].to_vec()))
        .await
        .map_err(|e| format!("send msg1: {e}"))?;

    // msg2
    let msg2 = match ws_rx.next().await {
        Some(Ok(tungstenite::Message::Binary(data))) => data.to_vec(),
        other => return Err(format!("expected binary msg2, got: {other:?}")),
    };
    noise
        .read_message(&msg2, &mut buf)
        .map_err(|e| format!("msg2: {e}"))?;

    // msg3 with attestation
    let attestation_json = serde_json::to_vec(&attestation).unwrap();
    let mut msg3_buf = vec![0u8; 65535];
    let msg3_len = noise
        .write_message(&attestation_json, &mut msg3_buf)
        .map_err(|e| format!("msg3: {e}"))?;
    ws_tx
        .send(tungstenite::Message::Binary(msg3_buf[..msg3_len].to_vec()))
        .await
        .map_err(|e| format!("send msg3: {e}"))?;

    let mut transport = noise
        .into_transport_mode()
        .map_err(|e| format!("transport: {e}"))?;

    // Send encrypted registration request
    let req = serde_json::json!({ "owner": owner, "vm_name": vm_name });
    let req_json = serde_json::to_vec(&req).unwrap();
    let mut enc_buf = vec![0u8; 65535];
    let enc_len = transport
        .write_message(&req_json, &mut enc_buf)
        .map_err(|e| format!("encrypt: {e}"))?;
    ws_tx
        .send(tungstenite::Message::Binary(enc_buf[..enc_len].to_vec()))
        .await
        .map_err(|e| format!("send req: {e}"))?;

    // Read encrypted bootstrap config
    let enc_resp = match ws_rx.next().await {
        Some(Ok(tungstenite::Message::Binary(data))) => data.to_vec(),
        other => return Err(format!("expected binary response, got: {other:?}")),
    };
    let resp_len = transport
        .read_message(&enc_resp, &mut buf)
        .map_err(|e| format!("decrypt: {e}"))?;

    serde_json::from_slice(&buf[..resp_len]).map_err(|e| format!("parse config: {e}"))
}

// ── Monitoring loop — check process liveness by PID ─────────────────────

async fn monitoring_loop(
    deployments: Deployments,
    self_registry: Option<(dd_agent::server::AgentRegistry, String)>,
) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
    loop {
        interval.tick().await;

        let entries: Vec<(String, Option<u32>)> = {
            let deps = deployments.lock().await;
            deps.values()
                .filter(|d| d.status == "running")
                .map(|d| (d.id.clone(), d.pid))
                .collect()
        };

        for (dep_id, pid) in &entries {
            if let Some(pid) = pid {
                if !dd_agent::process::is_running(*pid) {
                    eprintln!("dd-agent: deployment {dep_id} process gone (pid {pid})");
                    let mut deps = deployments.lock().await;
                    if let Some(info) = deps.get_mut(dep_id) {
                        info.status = "exited".into();
                    }
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
            let metrics = dd_agent::server::collect_system_metrics().await;
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

        check_cloudflared().await;
    }
}

// ── Cloudflared ───────────────────────────────────────────────────────────

async fn start_cloudflared(tunnel_token: &str) -> Result<(), String> {
    use tokio::process::Command;
    eprintln!("dd-agent: starting cloudflared tunnel");
    let mut child = Command::new("cloudflared")
        .args(["tunnel", "--no-autoupdate", "run", "--token", tunnel_token])
        .spawn()
        .map_err(|e| format!("spawn cloudflared: {e}"))?;
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    match child.try_wait() {
        Ok(Some(status)) => Err(format!("cloudflared exited immediately: {status}")),
        Ok(None) => {
            eprintln!("dd-agent: cloudflared running");
            Ok(())
        }
        Err(e) => Err(format!("cloudflared wait error: {e}")),
    }
}

async fn check_cloudflared() {
    use tokio::process::Command;
    let output = Command::new("pgrep").arg("cloudflared").output().await;
    if !matches!(output, Ok(o) if o.status.success()) {
        eprintln!("dd-agent: cloudflared not running (may need restart)");
    }
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
