use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct AgentChallengeResponse {
    pub nonce: String,
    pub expires_in_seconds: u64,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct AgentRegisterResponse {
    pub agent_id: String,
    pub tunnel_token: String,
    pub hostname: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct PendingDeployment {
    pub id: String,
    #[serde(default)]
    pub image: Option<String>,
    #[serde(default)]
    pub env: Option<String>,
    #[serde(default)]
    pub cmd: Option<String>,
    #[serde(default)]
    pub ports: Option<String>,
    #[serde(default)]
    pub config: Option<String>,
    #[serde(default)]
    pub app_name: Option<String>,
    #[serde(default)]
    pub app_version: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct HeartbeatResponse {
    pub ok: bool,
    #[serde(default)]
    pub pending_deployments: Vec<PendingDeployment>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UpdateDeploymentStatusRequest {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
}

/// Sent to a new CP when heartbeat returns 404 (CP doesn't know this agent).
/// Includes currently running deployments so the CP can track them.
#[derive(Debug, Clone, Serialize)]
pub struct AgentReattachRequest {
    pub vm_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_size: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub datacenter: Option<String>,
    pub running_deployments: Vec<RunningDeploymentReport>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RunningDeploymentReport {
    pub deployment_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    pub status: String,
}

/// Response from the reattach endpoint — same shape as register response.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct AgentReattachResponse {
    pub agent_id: String,
    pub tunnel_token: String,
    pub hostname: String,
}
