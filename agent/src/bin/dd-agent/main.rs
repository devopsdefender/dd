mod config;
mod measure;
mod oci;

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

use config::{AgentMode, AgentRuntimeConfig};
use dd_agent::api::{
    AgentChallengeResponse, AgentRegisterResponse, HeartbeatResponse, PendingDeployment,
    UpdateDeploymentStatusRequest,
};

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

// ── Deployment tracking ──────────────────────────────────────────────────

struct DeploymentState {
    id: String,
    project_name: String,
    compose_dir: String,
}

type ActiveDeployments = Arc<Mutex<HashMap<String, DeploymentState>>>;

// ── Agent mode ─────────────────────────────────────────────────────────────

async fn run_agent_mode(cfg: AgentRuntimeConfig) {
    let cp_url = match &cfg.control_plane_url {
        Some(url) => url.clone(),
        None => {
            eprintln!("dd-agent: DD_CP_URL / control_plane_url not set");
            std::process::exit(1);
        }
    };

    let http = match reqwest::Client::builder()
        .danger_accept_invalid_certs(false)
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("dd-agent: failed to build HTTP client: {e}");
            std::process::exit(1);
        }
    };

    let registration = match register_with_retry(&http, &cp_url, &cfg).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("dd-agent: registration failed: {e}");
            std::process::exit(1);
        }
    };

    eprintln!(
        "dd-agent: registered as {} at {}",
        registration.agent_id, registration.hostname
    );

    if let Err(e) = start_cloudflared(&registration.tunnel_token).await {
        eprintln!("dd-agent: cloudflared start failed: {e}");
    }

    // Run any statically configured workloads (backwards compat)
    if let Err(e) = run_workloads(&cfg).await {
        eprintln!("dd-agent: workload launch failed: {e}");
    }

    // Ensure deployment directory exists
    let _ = tokio::fs::create_dir_all("/var/lib/dd/deployments").await;

    let active_deployments: ActiveDeployments = Arc::new(Mutex::new(HashMap::new()));
    let agent_id = registration.agent_id.clone();

    heartbeat_loop(&http, &cp_url, &agent_id, active_deployments.clone()).await;
}

// ── Registration ──────────────────────────────────────────────────────────

async fn register_with_retry(
    http: &reqwest::Client,
    cp_url: &str,
    cfg: &AgentRuntimeConfig,
) -> Result<AgentRegisterResponse, String> {
    let max_retries = 30u32;

    for attempt in 1..=max_retries {
        let challenge = match fetch_challenge(http, cp_url).await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("dd-agent: challenge failed (attempt {attempt}/{max_retries}): {e}");
                backoff_sleep(attempt).await;
                continue;
            }
        };

        let quote_b64 = match dd_agent::attestation::tsm::generate_tdx_quote_base64() {
            Ok(q) => q,
            Err(e) => {
                eprintln!("dd-agent: TDX quote generation failed, using fallback: {e}");
                "no-tdx-available".to_string()
            }
        };

        match register_agent(http, cp_url, &challenge.nonce, &quote_b64, cfg).await {
            Ok(r) => return Ok(r),
            Err(e) => {
                eprintln!("dd-agent: registration failed (attempt {attempt}/{max_retries}): {e}");
                backoff_sleep(attempt).await;
            }
        }
    }

    Err(format!("failed after {max_retries} attempts"))
}

async fn fetch_challenge(
    http: &reqwest::Client,
    cp_url: &str,
) -> Result<AgentChallengeResponse, String> {
    let url = format!("{cp_url}/api/v1/agents/challenge");
    let resp = http
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("GET {url}: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!("GET {url}: status {}", resp.status()));
    }

    resp.json::<AgentChallengeResponse>()
        .await
        .map_err(|e| format!("parse challenge response: {e}"))
}

async fn register_agent(
    http: &reqwest::Client,
    cp_url: &str,
    nonce: &str,
    quote_b64: &str,
    cfg: &AgentRuntimeConfig,
) -> Result<AgentRegisterResponse, String> {
    let url = format!("{cp_url}/api/v1/agents/register");

    let body = serde_json::json!({
        "nonce": nonce,
        "intel_ta_token": quote_b64,
        "vm_name": hostname(),
        "node_size": cfg.node_size,
        "datacenter": cfg.datacenter,
    });

    let resp = http
        .post(&url)
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("POST {url}: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body_text = resp.text().await.unwrap_or_default();
        return Err(format!("POST {url}: status {status}: {body_text}"));
    }

    resp.json::<AgentRegisterResponse>()
        .await
        .map_err(|e| format!("parse register response: {e}"))
}

// ── Cloudflared ───────────────────────────────────────────────────────────

async fn start_cloudflared(tunnel_token: &str) -> Result<(), String> {
    use tokio::process::Command;

    eprintln!("dd-agent: starting cloudflared tunnel");

    let mut child = Command::new("cloudflared")
        .args(["tunnel", "--no-autoupdate", "run", "--token", tunnel_token])
        .spawn()
        .map_err(|e| format!("spawn cloudflared: {e}"))?;

    // Give cloudflared a moment to start, then check it hasn't crashed.
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    match child.try_wait() {
        Ok(Some(status)) => Err(format!("cloudflared exited immediately: {status}")),
        Ok(None) => {
            eprintln!("dd-agent: cloudflared running");
            // Detach -- we don't await the child so it keeps running.
            Ok(())
        }
        Err(e) => Err(format!("cloudflared wait error: {e}")),
    }
}

async fn check_cloudflared() {
    use tokio::process::Command;

    let output = Command::new("pgrep").arg("cloudflared").output().await;

    match output {
        Ok(o) if o.status.success() => { /* still running */ }
        _ => {
            eprintln!("dd-agent: cloudflared not running (may need restart)");
        }
    }
}

// ── Static workloads (backwards compat) ──────────────────────────────────

async fn run_workloads(cfg: &AgentRuntimeConfig) -> Result<(), String> {
    let runtime = oci::DockerOciRuntime::new()?;

    // Determine which image to launch based on provided_app or mode.
    let image = match &cfg.provided_app {
        Some(config::ProvidedApp::ControlPlane) => cfg.control_plane_image.as_deref(),
        Some(config::ProvidedApp::Measure) => cfg.measure_app_image.as_deref(),
        None => None,
    };

    let image = match image {
        Some(img) => img.to_string(),
        None => {
            eprintln!("dd-agent: no workload image configured, skipping");
            return Ok(());
        }
    };

    eprintln!("dd-agent: pulling image {image}");
    runtime.pull_image(&image).await?;

    let port = cfg.port.unwrap_or(8080);

    let req = oci::LaunchRequest {
        image: image.clone(),
        name: Some("dd-workload".into()),
        env: cfg.raw_kv.iter().map(|(k, v)| format!("{k}={v}")).collect(),
        ports: vec![oci::PortMapping {
            host_port: port,
            container_port: port,
            protocol: "tcp".into(),
        }],
        cmd: vec![],
    };

    let container_id = runtime.create_and_start(&req).await?;
    eprintln!("dd-agent: workload container started: {container_id}");
    Ok(())
}

// ── Heartbeat loop with deployment processing ────────────────────────────

async fn heartbeat_loop(
    http: &reqwest::Client,
    cp_url: &str,
    agent_id: &str,
    active_deployments: ActiveDeployments,
) {
    let url = format!("{cp_url}/api/v1/agents/{agent_id}/heartbeat");
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));

    loop {
        tokio::select! {
            _ = interval.tick() => {
                // Send heartbeat and process any pending deployments
                match send_heartbeat(http, &url).await {
                    Ok(resp) => {
                        if !resp.pending_deployments.is_empty() {
                            eprintln!(
                                "dd-agent: received {} pending deployment(s)",
                                resp.pending_deployments.len()
                            );
                            for dep in resp.pending_deployments {
                                process_deployment(
                                    http,
                                    cp_url,
                                    dep,
                                    active_deployments.clone(),
                                )
                                .await;
                            }
                        }

                        // Check health of active deployments
                        check_active_deployments(http, cp_url, active_deployments.clone()).await;
                    }
                    Err(e) => {
                        eprintln!("dd-agent: heartbeat failed: {e}");
                    }
                }

                check_cloudflared().await;
            }
            _ = tokio::signal::ctrl_c() => {
                eprintln!("dd-agent: received shutdown signal, cleaning up...");
                shutdown_deployments(http, cp_url, active_deployments.clone()).await;
                eprintln!("dd-agent: shutdown complete");
                return;
            }
        }
    }
}

async fn send_heartbeat(http: &reqwest::Client, url: &str) -> Result<HeartbeatResponse, String> {
    let resp = http
        .post(url)
        .send()
        .await
        .map_err(|e| format!("heartbeat request: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        return Err(format!("heartbeat rejected (status {status})"));
    }

    resp.json::<HeartbeatResponse>()
        .await
        .map_err(|e| format!("parse heartbeat response: {e}"))
}

// ── Deployment processing ────────────────────────────────────────────────

async fn process_deployment(
    http: &reqwest::Client,
    cp_url: &str,
    dep: PendingDeployment,
    active_deployments: ActiveDeployments,
) {
    let short_id = &dep.id[..8.min(dep.id.len())];
    let project_name = format!("dd-{short_id}");
    let compose_dir = format!("/var/lib/dd/deployments/{}", dep.id);

    eprintln!(
        "dd-agent: deploying {} (app: {}, project: {})",
        dep.id,
        dep.app_name.as_deref().unwrap_or("unnamed"),
        project_name
    );

    // Write compose file to deployment directory
    if let Err(e) = write_compose_files(&compose_dir, &dep).await {
        eprintln!(
            "dd-agent: failed to write compose files for {}: {e}",
            dep.id
        );
        let _ = report_deployment_status(http, cp_url, &dep.id, "failed", Some(&e)).await;
        return;
    }

    // Run docker compose up
    match run_compose_up(&compose_dir, &project_name).await {
        Ok(()) => {
            eprintln!("dd-agent: deployment {} started successfully", dep.id);
            let _ = report_deployment_status(http, cp_url, &dep.id, "running", None).await;

            let state = DeploymentState {
                id: dep.id.clone(),
                project_name,
                compose_dir,
            };
            active_deployments.lock().await.insert(dep.id, state);
        }
        Err(e) => {
            eprintln!("dd-agent: deployment {} failed: {e}", dep.id);
            let _ = report_deployment_status(http, cp_url, &dep.id, "failed", Some(&e)).await;
        }
    }
}

async fn write_compose_files(compose_dir: &str, dep: &PendingDeployment) -> Result<(), String> {
    tokio::fs::create_dir_all(compose_dir)
        .await
        .map_err(|e| format!("create dir {compose_dir}: {e}"))?;

    let compose_path = format!("{compose_dir}/docker-compose.yml");
    tokio::fs::write(&compose_path, &dep.compose)
        .await
        .map_err(|e| format!("write compose file: {e}"))?;

    if let Some(config) = &dep.config {
        let config_path = format!("{compose_dir}/config.json");
        tokio::fs::write(&config_path, config)
            .await
            .map_err(|e| format!("write config file: {e}"))?;
    }

    Ok(())
}

async fn run_compose_up(compose_dir: &str, project_name: &str) -> Result<(), String> {
    use tokio::process::Command;

    let output = Command::new("docker")
        .args([
            "compose",
            "-f",
            &format!("{compose_dir}/docker-compose.yml"),
            "-p",
            project_name,
            "up",
            "-d",
        ])
        .output()
        .await
        .map_err(|e| format!("docker compose up: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("docker compose up failed: {stderr}"));
    }

    Ok(())
}

async fn run_compose_down(compose_dir: &str, project_name: &str) -> Result<(), String> {
    use tokio::process::Command;

    let output = Command::new("docker")
        .args([
            "compose",
            "-f",
            &format!("{compose_dir}/docker-compose.yml"),
            "-p",
            project_name,
            "down",
        ])
        .output()
        .await
        .map_err(|e| format!("docker compose down: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("docker compose down failed: {stderr}"));
    }

    Ok(())
}

async fn run_compose_ps(compose_dir: &str, project_name: &str) -> Result<String, String> {
    use tokio::process::Command;

    let output = Command::new("docker")
        .args([
            "compose",
            "-f",
            &format!("{compose_dir}/docker-compose.yml"),
            "-p",
            project_name,
            "ps",
            "--format",
            "json",
        ])
        .output()
        .await
        .map_err(|e| format!("docker compose ps: {e}"))?;

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

async fn run_compose_restart(compose_dir: &str, project_name: &str) -> Result<(), String> {
    use tokio::process::Command;

    let output = Command::new("docker")
        .args([
            "compose",
            "-f",
            &format!("{compose_dir}/docker-compose.yml"),
            "-p",
            project_name,
            "restart",
        ])
        .output()
        .await
        .map_err(|e| format!("docker compose restart: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("docker compose restart failed: {stderr}"));
    }

    Ok(())
}

// ── Health monitoring ────────────────────────────────────────────────────

async fn check_active_deployments(
    http: &reqwest::Client,
    cp_url: &str,
    active_deployments: ActiveDeployments,
) {
    let deployments = active_deployments.lock().await;
    let entries: Vec<(String, String, String)> = deployments
        .values()
        .map(|d| (d.id.clone(), d.project_name.clone(), d.compose_dir.clone()))
        .collect();
    drop(deployments);

    for (dep_id, project_name, compose_dir) in entries {
        match run_compose_ps(&compose_dir, &project_name).await {
            Ok(ps_output) => {
                // Check if any containers have exited
                if ps_output.contains("\"exited\"") || ps_output.contains("\"dead\"") {
                    eprintln!(
                        "dd-agent: deployment {} has unhealthy containers, attempting restart",
                        dep_id
                    );

                    // Attempt auto-recovery via restart
                    match run_compose_restart(&compose_dir, &project_name).await {
                        Ok(()) => {
                            eprintln!("dd-agent: deployment {} restarted successfully", dep_id);
                        }
                        Err(e) => {
                            eprintln!("dd-agent: deployment {} restart failed: {e}", dep_id);
                            let _ = report_deployment_status(
                                http,
                                cp_url,
                                &dep_id,
                                "failed",
                                Some(&format!("auto-recovery failed: {e}")),
                            )
                            .await;
                            active_deployments.lock().await.remove(&dep_id);
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!(
                    "dd-agent: failed to check deployment {} status: {e}",
                    dep_id
                );
            }
        }
    }
}

// ── Status reporting ─────────────────────────────────────────────────────

async fn report_deployment_status(
    http: &reqwest::Client,
    cp_url: &str,
    deployment_id: &str,
    status: &str,
    error_message: Option<&str>,
) -> Result<(), String> {
    let url = format!("{cp_url}/api/v1/deployments/{deployment_id}/status");

    let body = UpdateDeploymentStatusRequest {
        status: status.to_string(),
        error_message: error_message.map(|s| s.to_string()),
    };

    let resp = http
        .patch(&url)
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("report status: {e}"))?;

    if !resp.status().is_success() {
        let status_code = resp.status();
        return Err(format!("report status failed: {status_code}"));
    }

    Ok(())
}

// ── Graceful shutdown ────────────────────────────────────────────────────

async fn shutdown_deployments(
    http: &reqwest::Client,
    cp_url: &str,
    active_deployments: ActiveDeployments,
) {
    let deployments = active_deployments.lock().await;
    let entries: Vec<(String, String, String)> = deployments
        .values()
        .map(|d| (d.id.clone(), d.project_name.clone(), d.compose_dir.clone()))
        .collect();
    drop(deployments);

    for (dep_id, project_name, compose_dir) in entries {
        eprintln!("dd-agent: stopping deployment {dep_id}...");

        if let Err(e) = run_compose_down(&compose_dir, &project_name).await {
            eprintln!("dd-agent: failed to stop deployment {dep_id}: {e}");
        }

        let _ = report_deployment_status(http, cp_url, &dep_id, "stopped", None).await;

        // Clean up deployment directory
        let _ = tokio::fs::remove_dir_all(&compose_dir).await;
    }

    active_deployments.lock().await.clear();
}

// ── Control-plane mode ─────────────────────────────────────────────────────

fn run_control_plane_mode(cfg: AgentRuntimeConfig) {
    eprintln!("dd-agent: starting control plane (dd-cp)");

    let mut cmd = std::process::Command::new("dd-cp");

    // Forward relevant configuration as environment variables.
    if let Some(ref dc) = cfg.datacenter {
        cmd.env("DD_DATACENTER", dc);
    }
    if let Some(ref key) = cfg.intel_api_key {
        cmd.env("DD_INTEL_API_KEY", key);
    }
    if let Some(ref port) = cfg.port {
        cmd.env("DD_PORT", port.to_string());
    }

    // Forward raw key-value pairs.
    for (k, v) in &cfg.raw_kv {
        cmd.env(k, v);
    }

    match cmd.status() {
        Ok(status) => {
            if !status.success() {
                eprintln!("dd-agent: dd-cp exited with {status}");
                std::process::exit(status.code().unwrap_or(1));
            }
        }
        Err(e) => {
            eprintln!("dd-agent: failed to start dd-cp: {e}");
            std::process::exit(1);
        }
    }
}

// ── Helpers ────────────────────────────────────────────────────────────────

/// Best-effort hostname for this VM.
fn hostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .unwrap_or_else(|_| "unknown".into())
        .trim()
        .to_string()
}

async fn backoff_sleep(attempt: u32) {
    let secs = std::cmp::min(5 * 2u64.saturating_pow(attempt.saturating_sub(1)), 60);
    tokio::time::sleep(std::time::Duration::from_secs(secs)).await;
}
