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
pub struct AgentDeploymentResponse {
    pub image: String,
    pub env: Vec<String>,
    pub cmd: Vec<String>,
    pub deployment_id: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct AgentDeploymentStatusRequest {
    pub status: String,
    pub exit_code: Option<i32>,
}
