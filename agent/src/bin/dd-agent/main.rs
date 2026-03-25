mod config;
mod oci;

use config::{AgentMode, AgentRuntimeConfig};
use dd_agent::api::{
    AgentChallengeResponse, AgentDeploymentResponse, AgentDeploymentStatusRequest,
    AgentRegisterResponse,
};

#[derive(Debug)]
struct RunningDeployment {
    deployment_id: String,
}

#[tokio::main]
async fn main() {
    if std::env::args().any(|arg| arg == "--measure") {
        run_measure_mode();
        return;
    }

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
        AgentMode::BootstrapCp => run_bootstrap_cp_mode(cfg),
    }
}

async fn run_agent_mode(cfg: AgentRuntimeConfig) {
    let cp_url = cfg
        .control_plane_url
        .clone()
        .expect("agent mode requires control_plane_url");

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

    deployment_loop(&http, &cp_url, &registration.agent_id, cfg.port).await;
}

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

        let quote_b64 = match dd_agent::attestation::tsm::generate_tdx_quote_base64(Some(
            challenge.nonce.as_bytes(),
        )) {
            Ok(q) => q,
            Err(e) => {
                eprintln!(
                    "dd-agent: TDX quote generation failed (attempt {attempt}/{max_retries}): {e}"
                );
                backoff_sleep(attempt).await;
                continue;
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
    raw_quote_b64: &str,
    cfg: &AgentRuntimeConfig,
) -> Result<AgentRegisterResponse, String> {
    let url = format!("{cp_url}/api/v1/agents/register");

    let body = serde_json::json!({
        "nonce": nonce,
        "intel_ta_token": raw_quote_b64,
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

async fn deployment_loop(http: &reqwest::Client, cp_url: &str, agent_id: &str, port: Option<u16>) {
    let runtime = match oci::NativeOciRuntime::new() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("dd-agent: failed to initialize OCI runtime: {e}");
            std::process::exit(1);
        }
    };

    let heartbeat_interval = std::time::Duration::from_secs(30);
    let mut running: Option<RunningDeployment> = None;

    loop {
        if let Err(e) = send_heartbeat(http, cp_url, agent_id).await {
            eprintln!("dd-agent: heartbeat failed: {e}");
        }

        check_cloudflared().await;

        if let Some(current) = &running {
            match runtime.try_wait() {
                Ok(Some(exit)) => {
                    eprintln!(
                        "dd-agent: deployment {} exited success={} code={:?}",
                        current.deployment_id, exit.success, exit.exit_code
                    );
                    let status = if exit.success { "stopped" } else { "failed" };
                    if let Err(e) = report_deployment_status(
                        http,
                        cp_url,
                        agent_id,
                        &current.deployment_id,
                        status,
                        exit.exit_code,
                    )
                    .await
                    {
                        eprintln!("dd-agent: failed to report deployment exit: {e}");
                    }
                    running = None;
                }
                Ok(None) => {
                    tokio::time::sleep(heartbeat_interval).await;
                    continue;
                }
                Err(e) => {
                    eprintln!("dd-agent: failed waiting for workload exit: {e}");
                    tokio::time::sleep(heartbeat_interval).await;
                    continue;
                }
            }
        }

        match fetch_deployment(http, cp_url, agent_id).await {
            Ok(Some(dep)) => match pull_and_run(&runtime, &dep, port).await {
                Ok(pid) => {
                    eprintln!(
                        "dd-agent: deployment {} running as pid {}",
                        dep.deployment_id, pid
                    );
                    if let Err(e) = report_deployment_status(
                        http,
                        cp_url,
                        agent_id,
                        &dep.deployment_id,
                        "running",
                        None,
                    )
                    .await
                    {
                        eprintln!("dd-agent: failed to report running deployment: {e}");
                    }
                    running = Some(RunningDeployment {
                        deployment_id: dep.deployment_id,
                    });
                }
                Err(e) => {
                    eprintln!("dd-agent: deployment start failed: {e}");
                    if let Err(report_err) = report_deployment_status(
                        http,
                        cp_url,
                        agent_id,
                        &dep.deployment_id,
                        "failed",
                        None,
                    )
                    .await
                    {
                        eprintln!("dd-agent: failed to report deployment failure: {report_err}");
                    }
                }
            },
            Ok(None) => {}
            Err(e) => eprintln!("dd-agent: deployment poll failed: {e}"),
        }

        tokio::time::sleep(heartbeat_interval).await;
    }
}

async fn send_heartbeat(
    http: &reqwest::Client,
    cp_url: &str,
    agent_id: &str,
) -> Result<(), String> {
    let url = format!("{cp_url}/api/v1/agents/{agent_id}/heartbeat");
    let resp = http
        .post(&url)
        .send()
        .await
        .map_err(|e| format!("POST {url}: {e}"))?;

    if resp.status().is_success() {
        Ok(())
    } else {
        Err(format!("POST {url}: status {}", resp.status()))
    }
}

async fn fetch_deployment(
    http: &reqwest::Client,
    cp_url: &str,
    agent_id: &str,
) -> Result<Option<AgentDeploymentResponse>, String> {
    let url = format!("{cp_url}/api/v1/agents/{agent_id}/deployment");
    let resp = http
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("GET {url}: {e}"))?;

    match resp.status() {
        reqwest::StatusCode::OK => resp
            .json::<AgentDeploymentResponse>()
            .await
            .map(Some)
            .map_err(|e| format!("parse deployment response: {e}")),
        reqwest::StatusCode::NO_CONTENT => Ok(None),
        status => {
            let body = resp.text().await.unwrap_or_default();
            Err(format!("GET {url}: status {status}: {body}"))
        }
    }
}

async fn pull_and_run(
    runtime: &oci::NativeOciRuntime,
    dep: &AgentDeploymentResponse,
    port: Option<u16>,
) -> Result<i32, String> {
    eprintln!("dd-agent: pulling image {}", dep.image);
    runtime.pull_image(&dep.image).await?;

    let mut ports = Vec::new();
    if let Some(port) = port {
        ports.push(oci::PortMapping {
            host_port: port,
            container_port: port,
            protocol: "tcp".into(),
        });
    }

    let req = oci::LaunchRequest {
        image: dep.image.clone(),
        name: Some(format!("dd-workload-{}", dep.deployment_id)),
        env: dep.env.clone(),
        ports,
        cmd: dep.cmd.clone(),
    };

    runtime.create_and_start(&req).await
}

async fn report_deployment_status(
    http: &reqwest::Client,
    cp_url: &str,
    agent_id: &str,
    deployment_id: &str,
    status: &str,
    exit_code: Option<i32>,
) -> Result<(), String> {
    let url = format!("{cp_url}/api/v1/agents/{agent_id}/deployment/{deployment_id}/status");
    let body = AgentDeploymentStatusRequest {
        status: status.to_string(),
        exit_code,
    };
    let resp = http
        .post(&url)
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("POST {url}: {e}"))?;

    if resp.status().is_success() {
        Ok(())
    } else {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        Err(format!("POST {url}: status {status}: {body}"))
    }
}

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
        Ok(None) => Ok(()),
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

fn run_bootstrap_cp_mode(cfg: AgentRuntimeConfig) {
    use std::os::unix::process::CommandExt;

    let quote_b64 = match dd_agent::attestation::tsm::generate_tdx_quote_base64(None) {
        Ok(quote) => quote,
        Err(e) => {
            eprintln!("dd-agent: bootstrap CP quote generation failed: {e}");
            std::process::exit(1);
        }
    };
    let dd_env = match std::env::var("DD_ENV") {
        Ok(value) => value,
        Err(_) => {
            eprintln!("dd-agent: bootstrap CP mode requires DD_ENV to be set");
            std::process::exit(1);
        }
    };

    let dd_cp = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("dd-cp")))
        .filter(|p| p.exists())
        .unwrap_or_else(|| std::path::PathBuf::from("/usr/local/bin/dd-cp"));

    let mut cmd = std::process::Command::new(&dd_cp);
    cmd.env("DD_ENV", dd_env);
    if let Some(port) = cfg.port {
        cmd.env("DD_PORT", port.to_string());
    }
    if let Some(dc) = cfg.datacenter {
        cmd.env("DD_DATACENTER", dc);
    }
    cmd.env("DD_SELF_QUOTE_B64", quote_b64);

    let err = cmd.exec();
    eprintln!("dd-agent: failed to exec dd-cp: {err}");
    std::process::exit(1);
}

fn run_measure_mode() {
    eprintln!("dd-agent: entering measure mode");

    match dd_agent::attestation::tsm::generate_tdx_quote_base64(None) {
        Ok(b64_quote) => match dd_agent::attestation::tsm::parse_tdx_quote_base64(&b64_quote) {
            Ok(parsed) => {
                println!("mrtd:        {}", parsed.mrtd_hex());
                println!("rtmr0:       {}", parsed.rtmr_hex(0));
                println!("rtmr1:       {}", parsed.rtmr_hex(1));
                println!("rtmr2:       {}", parsed.rtmr_hex(2));
                println!("rtmr3:       {}", parsed.rtmr_hex(3));
                println!("report_data: {}", parsed.report_data_hex());
                println!("quote_b64:   {b64_quote}");
            }
            Err(e) => {
                eprintln!("failed to parse generated quote: {e}");
                std::process::exit(1);
            }
        },
        Err(e) => {
            eprintln!("failed to generate TDX quote: {e}");
            eprintln!("(this is expected when not running inside a TDX VM)");
            std::process::exit(1);
        }
    }
}

async fn backoff_sleep(attempt: u32) {
    let secs = std::cmp::min(5 * 2u64.saturating_pow(attempt.saturating_sub(1)), 60);
    tokio::time::sleep(std::time::Duration::from_secs(secs)).await;
}

fn hostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .unwrap_or_else(|_| "unknown".into())
        .trim()
        .to_string()
}
