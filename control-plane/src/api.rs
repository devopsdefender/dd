use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::types::{AccountType, DeploymentStatus};

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HealthResponse {
    pub ok: bool,
    pub boot_id: String,
    pub git_sha: String,
}

// ---------------------------------------------------------------------------
// Agent challenge / registration
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentChallengeResponse {
    pub nonce: String,
    pub expires_in_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentRegisterRequest {
    pub intel_ta_token: String,
    pub vm_name: String,
    pub nonce: String,
    #[serde(default)]
    pub node_size: Option<String>,
    #[serde(default)]
    pub datacenter: Option<String>,
    #[serde(default)]
    pub github_owner: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentRegisterResponse {
    pub agent_id: Uuid,
    pub tunnel_token: String,
    pub hostname: String,
}

// ---------------------------------------------------------------------------
// Deploy
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DeployRequest {
    pub compose: String,
    #[serde(default)]
    pub config: Option<String>,
    #[serde(default)]
    pub app_name: Option<String>,
    #[serde(default)]
    pub app_version: Option<String>,
    #[serde(default)]
    pub agent_name: Option<String>,
    #[serde(default)]
    pub node_size: Option<String>,
    #[serde(default)]
    pub datacenter: Option<String>,
    #[serde(default)]
    pub dry_run: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DeployResponse {
    pub deployment_id: Uuid,
    pub agent_id: Uuid,
    pub status: DeploymentStatus,
}

// ---------------------------------------------------------------------------
// Agent heartbeat
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HeartbeatResponse {
    pub ok: bool,
    pub pending_deployments: Vec<PendingDeployment>,
}

// ---------------------------------------------------------------------------
// Deployment status update
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UpdateDeploymentStatusRequest {
    pub status: DeploymentStatus,
    #[serde(default)]
    pub error_message: Option<String>,
}

// ---------------------------------------------------------------------------
// Agent health check ingestion
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentCheckIngestRequest {
    #[serde(default)]
    pub app_name: Option<String>,
    pub health_ok: bool,
    pub attestation_ok: bool,
    #[serde(default)]
    pub failure_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentCheckIngestResponse {
    pub app_name: String,
    pub check_ok: bool,
    pub deployment_exempt: bool,
    pub counted_down: bool,
    pub imperfect_now: bool,
    pub consecutive_failures: i64,
    pub consecutive_successes: i64,
}

// ---------------------------------------------------------------------------
// Accounts
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CreateAccountRequest {
    pub name: String,
    pub account_type: AccountType,
    #[serde(default)]
    pub github_login: Option<String>,
    #[serde(default)]
    pub github_org: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CreateAccountResponse {
    pub account_id: Uuid,
    pub api_key: String,
}

// ---------------------------------------------------------------------------
// Admin auth
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AdminLoginRequest {
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AdminLoginResponse {
    pub token: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthMeResponse {
    pub auth_method: String,
    #[serde(default)]
    pub github_login: Option<String>,
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
}

// ---------------------------------------------------------------------------
// Error response
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ApiErrorResponse {
    pub code: String,
    pub message: String,
    #[serde(default)]
    pub request_id: Option<String>,
}

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RecentAppStat {
    pub app_name: String,
    pub total_checks: i64,
    pub healthy_checks: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RecentAppStatsResponse {
    pub stats: Vec<RecentAppStat>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RecentAgentStat {
    pub agent_id: Uuid,
    pub vm_name: String,
    pub total_checks: i64,
    pub healthy_checks: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RecentAgentStatsResponse {
    pub stats: Vec<RecentAgentStat>,
}
