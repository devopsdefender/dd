mod config;
mod measure;
mod oci;

use config::{AgentMode, AgentRuntimeConfig};
use dd_agent::api::{AgentChallengeResponse, AgentRegisterResponse};

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
    let cp_url = match &cfg.control_plane_url {
        Some(url) => url.clone(),
        None => {
            eprintln!("dd-agent: DD_CP_URL / control_plane_url not set");
            std::process::exit(1);
        }
    };

    // 1. Build an HTTP client.
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

    // 2–4. Challenge → attest → register (with retry + backoff).
    let max_retries = 30u32;
    let mut registration = None;

    for attempt in 1..=max_retries {
        // 2. Obtain a challenge nonce from the control plane.
        let challenge = match fetch_challenge(&http, &cp_url).await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("dd-agent: challenge failed (attempt {attempt}/{max_retries}): {e}");
                backoff_sleep(attempt).await;
                continue;
            }
        };

        eprintln!(
            "dd-agent: received nonce (expires in {}s)",
            challenge.expires_in_seconds
        );

        // 3. Generate a TDX quote embedding the nonce as report data.
        // skip_attestation is only settable via agent.json (not env vars) to prevent
        // accidental bypass in production. Staging sets this to true via Ansible.
        let quote_b64 = if cfg.skip_attestation {
            eprintln!("dd-agent: skip_attestation=true (non-TDX host), skipping quote generation");
            String::new()
        } else {
            match dd_agent::attestation::tsm::generate_tdx_quote_base64() {
                Ok(q) => q,
                Err(e) => {
                    eprintln!("dd-agent: TDX quote generation failed (attempt {attempt}/{max_retries}): {e}");
                    backoff_sleep(attempt).await;
                    continue;
                }
            }
        };

        // 4. Register with the control plane.
        match register_agent(&http, &cp_url, &challenge.nonce, &quote_b64, &cfg).await {
            Ok(r) => {
                registration = Some(r);
                break;
            }
            Err(e) => {
                eprintln!("dd-agent: registration failed (attempt {attempt}/{max_retries}): {e}");
                backoff_sleep(attempt).await;
            }
        }
    }

    let registration = match registration {
        Some(r) => r,
        None => {
            eprintln!("dd-agent: registration failed after {max_retries} attempts, exiting");
            std::process::exit(1);
        }
    };

    eprintln!(
        "dd-agent: registered as {} at {}",
        registration.agent_id, registration.hostname
    );

    // 5. Start cloudflared tunnel.
    if let Err(e) = start_cloudflared(&registration.tunnel_token).await {
        eprintln!("dd-agent: cloudflared start failed: {e}");
        // Non-fatal: continue to workload.
    }

    // 6. Run workload containers.
    if let Err(e) = run_workloads(&cfg).await {
        eprintln!("dd-agent: workload launch failed: {e}");
    }

    // 7. Heartbeat / reconciliation loop.
    let agent_id = registration.agent_id.clone();
    heartbeat_loop(&http, &cp_url, &agent_id).await;
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

async fn heartbeat_loop(http: &reqwest::Client, cp_url: &str, agent_id: &str) {
    let url = format!("{cp_url}/api/v1/agents/{agent_id}/heartbeat");
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));

    loop {
        interval.tick().await;

        match http.post(&url).send().await {
            Ok(resp) if resp.status().is_success() => {
                // Heartbeat acknowledged.
            }
            Ok(resp) => {
                eprintln!(
                    "dd-agent: heartbeat rejected (status {}), attempting re-registration",
                    resp.status()
                );
                // In a full implementation we would re-register here.
                // For now just log and continue.
            }
            Err(e) => {
                eprintln!("dd-agent: heartbeat failed: {e}");
            }
        }

        // Check cloudflared is still running.
        check_cloudflared().await;
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

// ── Control-plane mode ─────────────────────────────────────────────────────

fn run_control_plane_mode(cfg: AgentRuntimeConfig) {
    eprintln!("dd-agent: starting control plane (dd-cp)");

    // Use absolute path so the binary is found regardless of systemd PATH restrictions.
    let dd_cp = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("dd-cp")))
        .filter(|p| p.exists())
        .unwrap_or_else(|| std::path::PathBuf::from("/usr/local/bin/dd-cp"));
    let mut cmd = std::process::Command::new(&dd_cp);

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

/// Exponential backoff: 5s, 10s, 20s, … capped at 60s.
async fn backoff_sleep(attempt: u32) {
    let secs = std::cmp::min(5 * 2u64.saturating_pow(attempt.saturating_sub(1)), 60);
    tokio::time::sleep(std::time::Duration::from_secs(secs)).await;
}

/// Best-effort hostname for this VM.
fn hostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .unwrap_or_else(|_| "unknown".into())
        .trim()
        .to_string()
}
