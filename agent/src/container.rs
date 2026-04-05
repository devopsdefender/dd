//! Container management via bollard (Docker/Podman API).

use bollard::container::{
    Config, CreateContainerOptions, ListContainersOptions, LogsOptions, RemoveContainerOptions,
    StopContainerOptions,
};
use bollard::image::CreateImageOptions;
use bollard::Docker;
use futures_util::StreamExt;
use std::collections::HashMap;

/// Connect to the local Docker/Podman socket.
fn connect() -> Result<Docker, String> {
    // Try podman socket first, then Docker
    for path in &["/run/podman/podman.sock", "/var/run/docker.sock"] {
        if std::path::Path::new(path).exists() {
            return Docker::connect_with_unix(path, 120, bollard::API_DEFAULT_VERSION)
                .map_err(|e| format!("connect {path}: {e}"));
        }
    }
    Docker::connect_with_socket_defaults().map_err(|e| format!("docker connect: {e}"))
}

/// Pull an image, create and start a container. Returns the container ID.
pub async fn pull_and_run(
    image: &str,
    name: &str,
    env: Option<Vec<String>>,
    volumes: Option<Vec<String>>,
    network_host: bool,
) -> Result<String, String> {
    let docker = connect()?;

    // Pull image
    eprintln!("dd-agent: pulling {image}");
    let mut pull_stream = docker.create_image(
        Some(CreateImageOptions {
            from_image: image,
            ..Default::default()
        }),
        None,
        None,
    );
    while let Some(result) = pull_stream.next().await {
        if let Err(e) = result {
            return Err(format!("pull {image}: {e}"));
        }
    }

    // Remove existing container with same name (idempotent redeploy)
    let _ = docker
        .remove_container(
            name,
            Some(RemoveContainerOptions {
                force: true,
                ..Default::default()
            }),
        )
        .await;

    // Create container
    let host_config = bollard::models::HostConfig {
        binds: volumes,
        network_mode: if network_host {
            Some("host".to_string())
        } else {
            None
        },
        restart_policy: Some(bollard::models::RestartPolicy {
            name: Some(bollard::models::RestartPolicyNameEnum::UNLESS_STOPPED),
            ..Default::default()
        }),
        ..Default::default()
    };

    let config = Config {
        image: Some(image.to_string()),
        env: env.as_ref().map(|e| e.to_vec()),
        host_config: Some(host_config),
        ..Default::default()
    };

    let container = docker
        .create_container(
            Some(CreateContainerOptions {
                name,
                ..Default::default()
            }),
            config,
        )
        .await
        .map_err(|e| format!("create container {name}: {e}"))?;

    // Start container
    docker
        .start_container::<String>(&container.id, None)
        .await
        .map_err(|e| format!("start container {name}: {e}"))?;

    eprintln!(
        "dd-agent: container {name} started (id={})",
        &container.id[..12]
    );
    Ok(container.id)
}

/// Execute a command inside a running container. Returns (exit_code, stdout, stderr).
pub async fn exec(container_name: &str, cmd: &[String]) -> Result<(i64, String, String), String> {
    use bollard::exec::{CreateExecOptions, StartExecOptions};

    let docker = connect()?;
    let exec = docker
        .create_exec(
            container_name,
            CreateExecOptions {
                cmd: Some(cmd.to_vec()),
                attach_stdout: Some(true),
                attach_stderr: Some(true),
                ..Default::default()
            },
        )
        .await
        .map_err(|e| format!("create exec: {e}"))?;

    let output = docker
        .start_exec(
            &exec.id,
            Some(StartExecOptions {
                detach: false,
                ..Default::default()
            }),
        )
        .await
        .map_err(|e| format!("start exec: {e}"))?;

    let mut stdout = String::new();
    let mut stderr = String::new();
    if let bollard::exec::StartExecResults::Attached { mut output, .. } = output {
        while let Some(Ok(msg)) = output.next().await {
            match msg {
                bollard::container::LogOutput::StdOut { message } => {
                    stdout.push_str(&String::from_utf8_lossy(&message));
                }
                bollard::container::LogOutput::StdErr { message } => {
                    stderr.push_str(&String::from_utf8_lossy(&message));
                }
                _ => {}
            }
        }
    }

    let inspect = docker
        .inspect_exec(&exec.id)
        .await
        .map_err(|e| format!("inspect exec: {e}"))?;
    let exit_code = inspect.exit_code.unwrap_or(-1);

    Ok((exit_code, stdout, stderr))
}

/// Stop and remove a container.
pub async fn stop(container_id: &str) -> Result<(), String> {
    let docker = connect()?;
    let _ = docker
        .stop_container(container_id, Some(StopContainerOptions { t: 10 }))
        .await;
    let _ = docker
        .remove_container(
            container_id,
            Some(RemoveContainerOptions {
                force: true,
                ..Default::default()
            }),
        )
        .await;
    Ok(())
}

/// Check if a container is running.
pub async fn is_running(container_id: &str) -> bool {
    let docker = match connect() {
        Ok(d) => d,
        Err(_) => return false,
    };
    match docker.inspect_container(container_id, None).await {
        Ok(info) => info.state.and_then(|s| s.running).unwrap_or(false),
        Err(_) => false,
    }
}

/// Get the last N lines of container logs.
pub async fn logs(container_id: &str, tail: usize) -> Result<Vec<String>, String> {
    let docker = connect()?;
    let mut log_stream = docker.logs(
        container_id,
        Some(LogsOptions::<String> {
            stdout: true,
            stderr: true,
            tail: tail.to_string(),
            ..Default::default()
        }),
    );

    let mut lines = Vec::new();
    while let Some(result) = log_stream.next().await {
        match result {
            Ok(output) => lines.push(output.to_string()),
            Err(e) => return Err(format!("logs: {e}")),
        }
    }
    Ok(lines)
}

/// List running containers managed by dd-agent (by label).
pub async fn list_running() -> Result<Vec<String>, String> {
    let docker = connect()?;
    let mut filters = HashMap::new();
    filters.insert("status", vec!["running"]);
    let containers = docker
        .list_containers(Some(ListContainersOptions {
            filters,
            ..Default::default()
        }))
        .await
        .map_err(|e| format!("list containers: {e}"))?;
    Ok(containers.iter().filter_map(|c| c.id.clone()).collect())
}
