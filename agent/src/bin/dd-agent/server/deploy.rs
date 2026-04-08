use axum::extract::{OriginalUri, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

use super::{require_browser_token, verify_owner, AgentState};

#[derive(Debug, Clone, Serialize)]
pub struct PostDeployStep {
    pub cmd: Vec<String>,
    pub exit_code: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub stdout: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub stderr: String,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeploymentInfo {
    pub id: String,
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_id: Option<String>,
    pub app_name: String,
    pub image: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    pub started_at: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub post_deploy_steps: Vec<PostDeployStep>,
}

pub type Deployments = Arc<Mutex<HashMap<String, DeploymentInfo>>>;

/// Per-process I/O handles for interactive sessions.
pub struct ProcessIO {
    pub stdin: tokio::process::ChildStdin,
    pub stdout_tx: tokio::sync::broadcast::Sender<Vec<u8>>,
}

pub type ProcessHandles = Arc<Mutex<HashMap<String, ProcessIO>>>;

#[derive(Debug, Clone, Deserialize)]
pub struct ExecRequest {
    pub cmd: Vec<String>,
    #[serde(default = "default_exec_timeout")]
    pub timeout_secs: u64,
}

fn default_exec_timeout() -> u64 {
    30
}

#[derive(Debug, Clone, Serialize)]
pub struct ExecResponse {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DeployRequest {
    #[serde(default)]
    pub cmd: Vec<String>,
    #[serde(default)]
    pub image: Option<String>,
    #[serde(default)]
    pub env: Option<Vec<String>>,
    #[serde(default)]
    pub volumes: Option<Vec<String>>,
    #[serde(default)]
    pub app_name: Option<String>,
    #[serde(default)]
    pub tty: bool,
    /// Commands to exec inside the container after it starts.
    /// Each entry is a list of strings (program + args).
    #[serde(default)]
    pub post_deploy: Option<Vec<Vec<String>>>,
}

pub(super) fn add_routes(
    router: Router<AgentState>,
    browser_ui_enabled: bool,
) -> Router<AgentState> {
    let router = router
        .route("/deploy", post(post_deploy))
        .route("/exec", post(post_exec));
    if browser_ui_enabled {
        router.route("/terminal", post(new_terminal))
    } else {
        router
    }
}

async fn new_terminal(
    State(state): State<AgentState>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
) -> Response {
    if !state.owner.is_empty() {
        match require_browser_token(&state, &headers, None, &uri).await {
            Ok(_) => {}
            Err(response) => return response,
        }
    }

    let name = format!("term-{}", &uuid::Uuid::new_v4().to_string()[..6]);
    let req = DeployRequest {
        cmd: vec!["bash".into()],
        image: None,
        env: None,
        volumes: None,
        app_name: Some(name.clone()),
        tty: true,
        post_deploy: None,
    };

    let (id, _status) =
        execute_deploy_with_handles(&state.deployments, Some(&state.process_handles), req).await;
    eprintln!("dd-agent: new terminal {name} (deploy {id})");

    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    Redirect::to(&format!("/session/{name}")).into_response()
}

async fn post_deploy(
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
    State(state): State<AgentState>,
    headers: HeaderMap,
    Json(req): Json<DeployRequest>,
) -> Response {
    if !addr.ip().is_loopback() && verify_owner(&state, &headers).await.is_err() {
        return (
            axum::http::StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "authentication required"})),
        )
            .into_response();
    }

    let (id, status) = execute_deploy(&state.deployments, req).await;
    Json(serde_json::json!({"id": id, "status": status})).into_response()
}

async fn post_exec(
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
    State(state): State<AgentState>,
    headers: HeaderMap,
    Json(req): Json<ExecRequest>,
) -> Response {
    if !addr.ip().is_loopback() && verify_owner(&state, &headers).await.is_err() {
        return (
            axum::http::StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "authentication required"})),
        )
            .into_response();
    }

    if req.cmd.is_empty() {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "cmd must not be empty"})),
        )
            .into_response();
    }

    let timeout = std::time::Duration::from_secs(req.timeout_secs.min(300));
    let program = &req.cmd[0];
    let args: Vec<&str> = req.cmd[1..].iter().map(|s| s.as_str()).collect();

    let mut cmd = tokio::process::Command::new(program);
    cmd.args(&args);
    cmd.stdin(std::process::Stdio::null());
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    let child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) => {
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("spawn failed: {e}")})),
            )
                .into_response();
        }
    };

    let pid = child.id();

    match tokio::time::timeout(timeout, child.wait_with_output()).await {
        Ok(Ok(output)) => Json(ExecResponse {
            exit_code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
        .into_response(),
        Ok(Err(e)) => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("wait failed: {e}")})),
        )
            .into_response(),
        Err(_) => {
            if let Some(pid) = pid {
                let _ = dd_agent::process::kill_process(pid).await;
            }
            (
                axum::http::StatusCode::REQUEST_TIMEOUT,
                Json(serde_json::json!({"error": format!("command timed out after {}s", timeout.as_secs())})),
            )
                .into_response()
        }
    }
}

pub async fn execute_deploy(deployments: &Deployments, req: DeployRequest) -> (String, String) {
    execute_deploy_with_handles(deployments, None, req).await
}

pub async fn execute_deploy_with_handles(
    deployments: &Deployments,
    handles: Option<&ProcessHandles>,
    req: DeployRequest,
) -> (String, String) {
    let dep_id = uuid::Uuid::new_v4().to_string();
    let app_name = req.app_name.clone().unwrap_or_else(|| "unnamed".into());

    let image_label = if let Some(ref img) = req.image {
        img.clone()
    } else {
        req.cmd.join(" ")
    };

    let info = DeploymentInfo {
        id: dep_id.clone(),
        pid: None,
        container_id: None,
        app_name: app_name.clone(),
        image: image_label,
        status: "deploying".into(),
        error_message: None,
        started_at: chrono::Utc::now().to_rfc3339(),
        post_deploy_steps: Vec::new(),
    };
    deployments.lock().await.insert(dep_id.clone(), info);

    let return_id = dep_id.clone();
    let deployments_clone = deployments.clone();
    let handles_clone = handles.cloned();
    tokio::spawn(async move {
        run_deploy(deployments_clone, handles_clone, dep_id, app_name, req).await;
    });

    (return_id, "deploying".into())
}

async fn run_deploy(
    deployments: Deployments,
    process_handles: Option<ProcessHandles>,
    dep_id: String,
    app_name: String,
    req: DeployRequest,
) {
    {
        let deps = deployments.lock().await;
        let old: Vec<(String, Option<u32>, Option<String>)> = deps
            .values()
            .filter(|d| d.app_name == app_name && d.id != dep_id)
            .map(|d| (d.id.clone(), d.pid, d.container_id.clone()))
            .collect();
        drop(deps);
        for (old_id, old_pid, old_cid) in old {
            if let Some(cid) = old_cid {
                let _ = dd_agent::container::stop(&cid).await;
            } else if let Some(pid) = old_pid {
                let _ = dd_agent::process::kill_process(pid).await;
            }
            deployments.lock().await.remove(&old_id);
        }
    }

    if let Some(ref image) = req.image {
        match dd_agent::container::pull_and_run(image, &app_name, req.env, req.volumes, true).await
        {
            Ok(container_id) => {
                eprintln!("dd-agent: deployment {dep_id} running (container={container_id})");
                let mut deps = deployments.lock().await;
                if let Some(info) = deps.get_mut(&dep_id) {
                    info.container_id = Some(container_id.clone());
                    info.status = "running".into();
                }
                drop(deps);

                if let Some(ref commands) = req.post_deploy {
                    for _ in 0..60 {
                        if dd_agent::container::is_running(&container_id).await {
                            break;
                        }
                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                    }

                    for cmd in commands {
                        if cmd.is_empty() {
                            continue;
                        }
                        eprintln!("dd-agent: post-deploy exec: {}", cmd.join(" "));
                        let started = std::time::Instant::now();
                        let result = dd_agent::container::exec(&app_name, cmd).await;
                        let duration_ms = started.elapsed().as_millis() as u64;
                        match result {
                            Ok((code, stdout, stderr)) => {
                                {
                                    let mut deps = deployments.lock().await;
                                    if let Some(info) = deps.get_mut(&dep_id) {
                                        info.post_deploy_steps.push(PostDeployStep {
                                            cmd: cmd.clone(),
                                            exit_code: code,
                                            stdout: stdout.clone(),
                                            stderr: stderr.clone(),
                                            duration_ms,
                                        });
                                    }
                                }
                                if code != 0 {
                                    eprintln!(
                                        "dd-agent: post-deploy cmd failed (exit {}): {}{}",
                                        code,
                                        stdout.trim(),
                                        if stderr.is_empty() {
                                            String::new()
                                        } else {
                                            format!(" stderr: {}", stderr.trim())
                                        }
                                    );
                                    set_deploy_failed(
                                        &deployments,
                                        &dep_id,
                                        &format!(
                                            "post-deploy failed: {} (exit {code})",
                                            cmd.join(" ")
                                        ),
                                    )
                                    .await;
                                    return;
                                }
                                if !stdout.trim().is_empty() {
                                    eprintln!("dd-agent: post-deploy: {}", stdout.trim());
                                }
                            }
                            Err(e) => {
                                {
                                    let mut deps = deployments.lock().await;
                                    if let Some(info) = deps.get_mut(&dep_id) {
                                        info.post_deploy_steps.push(PostDeployStep {
                                            cmd: cmd.clone(),
                                            exit_code: -1,
                                            stdout: String::new(),
                                            stderr: e.clone(),
                                            duration_ms,
                                        });
                                    }
                                }
                                set_deploy_failed(
                                    &deployments,
                                    &dep_id,
                                    &format!("post-deploy exec error: {e}"),
                                )
                                .await;
                                return;
                            }
                        }
                    }
                    eprintln!("dd-agent: post-deploy commands complete for {app_name}");
                }
            }
            Err(e) => {
                set_deploy_failed(&deployments, &dep_id, &e).await;
            }
        }
    } else if !req.cmd.is_empty() {
        let program = &req.cmd[0];
        let args: Vec<&str> = req.cmd[1..].iter().map(|s| s.as_str()).collect();
        match dd_agent::process::spawn_command(program, &args, req.tty).await {
            Ok(mut child) => {
                let pid = child.id();
                eprintln!("dd-agent: deployment {dep_id} running (pid={pid:?})");
                let mut deps = deployments.lock().await;
                if let Some(info) = deps.get_mut(&dep_id) {
                    info.pid = pid;
                    info.status = "running".into();
                }
                drop(deps);

                if req.tty {
                    if let Some(ref handles) = process_handles {
                        let (stdout_tx, _) = tokio::sync::broadcast::channel::<Vec<u8>>(256);
                        if let Some(stdin) = child.stdin.take() {
                            handles.lock().await.insert(
                                app_name.clone(),
                                ProcessIO {
                                    stdin,
                                    stdout_tx: stdout_tx.clone(),
                                },
                            );
                        }
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
                    }
                }

                tokio::spawn(async move {
                    let _ = child.wait().await;
                });
            }
            Err(e) => {
                set_deploy_failed(&deployments, &dep_id, &e).await;
            }
        }
    } else {
        set_deploy_failed(&deployments, &dep_id, "neither image nor cmd specified").await;
    }
}

async fn set_deploy_failed(deployments: &Deployments, dep_id: &str, error: &str) {
    eprintln!("dd-agent: deployment {dep_id} failed: {error}");
    let mut deps = deployments.lock().await;
    if let Some(info) = deps.get_mut(dep_id) {
        info.status = "failed".into();
        info.error_message = Some(error.to_string());
    }
}

pub async fn execute_stop(deployments: &Deployments, id: &str) -> Result<(), String> {
    let (pid, container_id) = {
        let deps = deployments.lock().await;
        let info = deps.get(id).ok_or("deployment not found")?;
        if info.status != "running" && info.status != "deploying" {
            return Err(format!(
                "cannot stop deployment in '{}' status",
                info.status
            ));
        }
        (info.pid, info.container_id.clone())
    };

    if let Some(cid) = container_id {
        dd_agent::container::stop(&cid).await?;
    } else if let Some(pid) = pid {
        dd_agent::process::kill_process(pid).await?;
    }

    let mut deps = deployments.lock().await;
    if let Some(info) = deps.get_mut(id) {
        info.status = "stopped".into();
    }
    Ok(())
}
