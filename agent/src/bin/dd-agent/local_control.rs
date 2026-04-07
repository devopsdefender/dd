use dd_agent::local_control::{
    socket_path_from_env, LocalControlRequest, LocalControlResponse, LocalDeployRequest,
    LocalDeploymentInfo, LocalStatus,
};
use std::path::Path;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

use crate::server::{self, AgentState};

pub async fn start(state: AgentState, mode: &str) -> Result<String, String> {
    let socket_path = socket_path_from_env();
    let parent = Path::new(&socket_path)
        .parent()
        .ok_or_else(|| format!("invalid control socket path: {socket_path}"))?;

    tokio::fs::create_dir_all(parent)
        .await
        .map_err(|e| format!("create control socket dir {parent:?}: {e}"))?;

    if tokio::fs::metadata(&socket_path).await.is_ok() {
        tokio::fs::remove_file(&socket_path)
            .await
            .map_err(|e| format!("remove stale control socket {socket_path}: {e}"))?;
    }

    let listener =
        UnixListener::bind(&socket_path).map_err(|e| format!("bind {socket_path}: {e}"))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o660);
        std::fs::set_permissions(&socket_path, perms)
            .map_err(|e| format!("chmod {socket_path}: {e}"))?;
    }

    let mode = mode.to_string();
    let listener_socket_path = socket_path.clone();
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("dd-agent: local control accept failed: {e}");
                    continue;
                }
            };

            let state = state.clone();
            let mode = mode.clone();
            let socket_path = listener_socket_path.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_connection(stream, state, &mode, &socket_path).await {
                    eprintln!("dd-agent: local control request failed: {e}");
                }
            });
        }
    });

    Ok(socket_path)
}

async fn handle_connection(
    stream: UnixStream,
    state: AgentState,
    mode: &str,
    socket_path: &str,
) -> Result<(), String> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    let read = reader
        .read_line(&mut line)
        .await
        .map_err(|e| format!("read request: {e}"))?;
    if read == 0 {
        return Ok(());
    }

    let req: LocalControlRequest =
        serde_json::from_str(line.trim()).map_err(|e| format!("parse request: {e}"))?;

    let response = match req {
        LocalControlRequest::Status => LocalControlResponse::Status {
            status: build_status(&state, mode, socket_path).await,
        },
        LocalControlRequest::List => LocalControlResponse::Deployments {
            deployments: list_deployments(&state).await,
        },
        LocalControlRequest::Spawn { request } => spawn_deployment(&state, request).await,
        LocalControlRequest::Stop { id, app_name } => stop_deployments(&state, id, app_name).await,
    };

    let json = serde_json::to_vec(&response).map_err(|e| format!("encode response: {e}"))?;
    writer
        .write_all(&json)
        .await
        .map_err(|e| format!("write response: {e}"))?;
    writer
        .write_all(b"\n")
        .await
        .map_err(|e| format!("write response newline: {e}"))?;
    writer
        .flush()
        .await
        .map_err(|e| format!("flush response: {e}"))?;
    Ok(())
}

async fn build_status(state: &AgentState, mode: &str, socket_path: &str) -> LocalStatus {
    let deployments = list_deployments(state).await;
    LocalStatus {
        ready: true,
        mode: mode.to_string(),
        vm_name: state.vm_name.clone(),
        agent_id: state.agent_id.clone(),
        register_mode: state.register_mode,
        socket_path: socket_path.to_string(),
        deployment_count: deployments.len(),
        deployments,
    }
}

async fn list_deployments(state: &AgentState) -> Vec<LocalDeploymentInfo> {
    let deps = state.deployments.lock().await;
    deps.values().cloned().map(convert_deployment).collect()
}

fn convert_deployment(info: server::DeploymentInfo) -> LocalDeploymentInfo {
    LocalDeploymentInfo {
        id: info.id,
        pid: info.pid,
        container_id: info.container_id,
        app_name: info.app_name,
        image: info.image,
        status: info.status,
        error_message: info.error_message,
        started_at: info.started_at,
    }
}

async fn spawn_deployment(state: &AgentState, request: LocalDeployRequest) -> LocalControlResponse {
    if request.image.is_none() && request.cmd.is_empty() {
        return LocalControlResponse::Error {
            message: "spawn requires either image or cmd".into(),
        };
    }

    let req = server::DeployRequest {
        cmd: request.cmd,
        image: request.image,
        env: if request.env.is_empty() {
            None
        } else {
            Some(request.env)
        },
        volumes: if request.volumes.is_empty() {
            None
        } else {
            Some(request.volumes)
        },
        app_name: request.app_name,
        tty: request.tty,
        post_deploy: None,
    };

    let (id, status) =
        server::execute_deploy_with_handles(&state.deployments, Some(&state.process_handles), req)
            .await;
    LocalControlResponse::Spawned { id, status }
}

async fn stop_deployments(
    state: &AgentState,
    id: Option<String>,
    app_name: Option<String>,
) -> LocalControlResponse {
    let mut ids = Vec::new();
    if let Some(id) = id {
        ids.push(id);
    } else if let Some(app_name) = app_name {
        let deps = state.deployments.lock().await;
        ids.extend(
            deps.values()
                .filter(|d| d.app_name == app_name)
                .map(|d| d.id.clone()),
        );
    } else {
        return LocalControlResponse::Error {
            message: "stop requires id or app_name".into(),
        };
    }

    if ids.is_empty() {
        return LocalControlResponse::Error {
            message: "no matching deployments found".into(),
        };
    }

    let mut stopped = Vec::new();
    let mut errors = Vec::new();
    for id in ids {
        match server::execute_stop(&state.deployments, &id).await {
            Ok(()) => stopped.push(id),
            Err(e) => errors.push(format!("{id}: {e}")),
        }
    }

    if errors.is_empty() {
        LocalControlResponse::Stopped { ids: stopped }
    } else {
        LocalControlResponse::Error {
            message: errors.join("; "),
        }
    }
}
