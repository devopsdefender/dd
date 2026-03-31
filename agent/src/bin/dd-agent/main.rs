mod config;
mod measure;

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

use config::{AgentMode, AgentRuntimeConfig};
use dd_agent::server::{AgentState, Deployments};

// ── Entry point ────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let cfg = match AgentRuntimeConfig::load() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("dd-agent: configuration error: {e}");
            std::process::exit(1);
        }
    };

    eprintln!("dd-agent: starting in {:?} mode", cfg.mode);

    match cfg.mode {
        AgentMode::Agent => run_agent_mode(cfg).await,
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
        std::process::exit(1);
    });

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
        match dd_agent::tunnel::create_agent_tunnel(&http, &cf, &owner, &vm_name).await {
            Ok(info) => {
                eprintln!("dd-agent: tunnel created — hostname={}", info.hostname);
                if let Err(e) = start_cloudflared(&info.tunnel_token).await {
                    eprintln!("dd-agent: cloudflared start failed: {e}");
                }
            }
            Err(e) => {
                eprintln!("dd-agent: self-registration failed: {e}");
                std::process::exit(1);
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
        eprintln!("dd-agent: auto-deploying boot workload {boot_app} ({boot_image})");
        let req = dd_agent::server::DeployRequest {
            image: boot_image,
            env: None,
            cmd: None,
            app_name: Some(boot_app),
            app_version: None,
            tty: boot_tty,
        };
        let (id, status) = dd_agent::server::execute_deploy(&deployments, req).await;
        eprintln!("dd-agent: boot workload {id} {status}");
    }

    let state = AgentState {
        owner,
        vm_name,
        agent_id,
        attestation_type: attestation.attestation_type().to_string(),
        deployments: deployments.clone(),
        process_handles,
        started_at: std::time::Instant::now(),
    };

    // HTTP server (read-only: health, list deployments, logs)
    let http_port = port;
    let app = dd_agent::server::build_router(state.clone());
    let bind_addr = format!("0.0.0.0:{http_port}");
    eprintln!("dd-agent: HTTP server listening on {bind_addr}");

    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .expect("failed to bind HTTP server");

    // Monitoring loop
    let monitor_deps = deployments.clone();
    tokio::spawn(async move {
        monitoring_loop(monitor_deps).await;
    });

    // Run HTTP server until shutdown
    let server = axum::serve(listener, app).with_graceful_shutdown(async {
        tokio::signal::ctrl_c().await.ok();
        eprintln!("dd-agent: shutdown signal received");
    });

    if let Err(e) = server.await {
        eprintln!("dd-agent: server error: {e}");
    }

    shutdown_deployments(deployments).await;
    eprintln!("dd-agent: shutdown complete");
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
            std::process::exit(1);
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

    // Connect via WebSocket
    let ws_url = format!("ws://{register_url}/register");
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

async fn monitoring_loop(deployments: Deployments) {
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

        for (dep_id, pid) in entries {
            if let Some(pid) = pid {
                if !dd_agent::process::is_running(pid) {
                    eprintln!("dd-agent: deployment {dep_id} process gone (pid {pid})");
                    let mut deps = deployments.lock().await;
                    if let Some(info) = deps.get_mut(&dep_id) {
                        info.status = "exited".into();
                    }
                }
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
            std::process::exit(status.code().unwrap_or(1));
        }
        Err(e) => {
            eprintln!("dd-agent: failed to start dd-cp: {e}");
            std::process::exit(1);
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
