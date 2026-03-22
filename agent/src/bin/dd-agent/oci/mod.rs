use bollard::container::{
    Config, CreateContainerOptions, ListContainersOptions, LogsOptions, RemoveContainerOptions,
    StartContainerOptions, StopContainerOptions,
};
use bollard::image::CreateImageOptions;
use bollard::models::{HostConfig, PortBinding};
use bollard::Docker;
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A port mapping from host to container.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortMapping {
    /// Port on the host.
    pub host_port: u16,
    /// Port inside the container.
    pub container_port: u16,
    /// Protocol (tcp or udp).
    #[serde(default = "default_protocol")]
    pub protocol: String,
}

fn default_protocol() -> String {
    "tcp".into()
}

/// Request to launch a container.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LaunchRequest {
    /// OCI image reference (e.g. `ghcr.io/org/image:tag`).
    pub image: String,
    /// Optional container name.
    pub name: Option<String>,
    /// Environment variables.
    #[serde(default)]
    pub env: Vec<String>,
    /// Port mappings.
    #[serde(default)]
    pub ports: Vec<PortMapping>,
    /// Optional command override.
    #[serde(default)]
    pub cmd: Vec<String>,
}

/// OCI runtime backed by the Docker/Podman API via bollard.
#[allow(dead_code)]
pub struct DockerOciRuntime {
    client: Docker,
}

#[allow(dead_code)]
impl DockerOciRuntime {
    /// Connect to the local Docker/Podman socket.
    pub fn new() -> Result<Self, String> {
        let client = Docker::connect_with_local_defaults()
            .map_err(|e| format!("failed to connect to container runtime: {e}"))?;
        Ok(Self { client })
    }

    /// Pull an image from a registry.
    pub async fn pull_image(&self, image: &str) -> Result<(), String> {
        let opts = CreateImageOptions {
            from_image: image,
            ..Default::default()
        };

        let mut stream = self.client.create_image(Some(opts), None, None);
        while let Some(result) = stream.next().await {
            match result {
                Ok(info) => {
                    if let Some(status) = &info.status {
                        eprintln!("pull: {status}");
                    }
                }
                Err(e) => return Err(format!("image pull failed: {e}")),
            }
        }
        Ok(())
    }

    /// Create and start a container from a [`LaunchRequest`].
    pub async fn create_and_start(&self, req: &LaunchRequest) -> Result<String, String> {
        // Build port bindings for the host config.
        let mut port_bindings: HashMap<String, Option<Vec<PortBinding>>> = HashMap::new();
        let mut exposed_port_keys: Vec<String> = Vec::new();

        for pm in &req.ports {
            let container_key = format!("{}/{}", pm.container_port, pm.protocol);
            port_bindings.insert(
                container_key.clone(),
                Some(vec![PortBinding {
                    host_ip: Some("0.0.0.0".into()),
                    host_port: Some(pm.host_port.to_string()),
                }]),
            );
            exposed_port_keys.push(container_key);
        }

        let host_config = HostConfig {
            port_bindings: Some(port_bindings),
            ..Default::default()
        };

        let cmd: Vec<&str> = req.cmd.iter().map(|s| s.as_str()).collect();

        // Build exposed_ports with borrowed keys.
        let exposed_ports: HashMap<&str, HashMap<(), ()>> = exposed_port_keys
            .iter()
            .map(|k| (k.as_str(), HashMap::new()))
            .collect();

        let config = Config {
            image: Some(req.image.as_str()),
            env: Some(req.env.iter().map(|s| s.as_str()).collect()),
            cmd: if cmd.is_empty() { None } else { Some(cmd) },
            exposed_ports: if exposed_ports.is_empty() {
                None
            } else {
                Some(exposed_ports)
            },
            host_config: Some(host_config),
            ..Default::default()
        };

        let create_opts = req.name.as_ref().map(|n| CreateContainerOptions {
            name: n.as_str(),
            platform: None,
        });

        let container = self
            .client
            .create_container(create_opts, config)
            .await
            .map_err(|e| format!("create container failed: {e}"))?;

        self.client
            .start_container(&container.id, None::<StartContainerOptions<String>>)
            .await
            .map_err(|e| format!("start container failed: {e}"))?;

        Ok(container.id)
    }

    /// Stop a running container.
    pub async fn stop_container(&self, container_id: &str) -> Result<(), String> {
        self.client
            .stop_container(container_id, Some(StopContainerOptions { t: 10 }))
            .await
            .map_err(|e| format!("stop container failed: {e}"))?;
        Ok(())
    }

    /// Remove a container (force).
    pub async fn remove_container(&self, container_id: &str) -> Result<(), String> {
        self.client
            .remove_container(
                container_id,
                Some(RemoveContainerOptions {
                    force: true,
                    ..Default::default()
                }),
            )
            .await
            .map_err(|e| format!("remove container failed: {e}"))?;
        Ok(())
    }

    /// Retrieve recent logs from a container.
    pub async fn logs(&self, container_id: &str, tail: usize) -> Result<Vec<String>, String> {
        let opts = LogsOptions::<String> {
            stdout: true,
            stderr: true,
            tail: tail.to_string(),
            ..Default::default()
        };

        let mut stream = self.client.logs(container_id, Some(opts));
        let mut lines = Vec::new();

        while let Some(result) = stream.next().await {
            match result {
                Ok(output) => lines.push(output.to_string()),
                Err(e) => return Err(format!("logs failed: {e}")),
            }
        }

        Ok(lines)
    }

    /// List containers, optionally filtering by label.
    pub async fn list_containers(&self, label_filter: Option<&str>) -> Result<Vec<String>, String> {
        let mut filters = HashMap::new();
        if let Some(label) = label_filter {
            filters.insert("label", vec![label]);
        }

        let opts = ListContainersOptions {
            all: true,
            filters,
            ..Default::default()
        };

        let containers = self
            .client
            .list_containers(Some(opts))
            .await
            .map_err(|e| format!("list containers failed: {e}"))?;

        Ok(containers.into_iter().filter_map(|c| c.id).collect())
    }
}
