use serde::{Deserialize, Serialize};

pub const DEFAULT_SOCKET_PATH: &str = "/run/dd-agent/control.sock";

pub fn socket_path_from_env() -> String {
    std::env::var("DD_CONTROL_SOCK")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_SOCKET_PATH.to_string())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalDeploymentInfo {
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
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LocalDeployRequest {
    #[serde(default)]
    pub cmd: Vec<String>,
    #[serde(default)]
    pub image: Option<String>,
    #[serde(default)]
    pub env: Vec<String>,
    #[serde(default)]
    pub volumes: Vec<String>,
    #[serde(default)]
    pub app_name: Option<String>,
    #[serde(default)]
    pub tty: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalStatus {
    pub ready: bool,
    pub mode: String,
    pub vm_name: String,
    pub agent_id: String,
    pub register_mode: bool,
    pub socket_path: String,
    pub deployment_count: usize,
    pub deployments: Vec<LocalDeploymentInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum LocalControlRequest {
    Status,
    List,
    Spawn {
        request: LocalDeployRequest,
    },
    Stop {
        #[serde(default)]
        id: Option<String>,
        #[serde(default)]
        app_name: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum LocalControlResponse {
    Status {
        status: LocalStatus,
    },
    Deployments {
        deployments: Vec<LocalDeploymentInfo>,
    },
    Spawned {
        id: String,
        status: String,
    },
    Stopped {
        ids: Vec<String>,
    },
    Error {
        message: String,
    },
}
