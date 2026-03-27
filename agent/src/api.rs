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
    pub compose: String,
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
