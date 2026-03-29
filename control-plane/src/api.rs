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
    #[serde(default)]
    pub compose: Option<String>,
    #[serde(default)]
    pub image: Option<String>,
    #[serde(default)]
    pub env: Option<Vec<String>>,
    #[serde(default)]
    pub cmd: Option<Vec<String>>,
    #[serde(default)]
    pub ports: Option<Vec<String>>,
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
    #[serde(default)]
    pub compose: Option<String>,
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
// Migration
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MigrationStatusResponse {
    pub can_export: bool,
    pub can_import: bool,
    pub agent_count: usize,
    pub deployment_count: usize,
    /// If proxying is active, the target URL.
    pub proxy_target: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MigrationImportResponse {
    pub imported: bool,
    pub summary: crate::services::migration::SeedConfigSummary,
}

/// Request to deploy a new CP instance on an agent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DeployCpRequest {
    /// The OCI image for the control-plane container.
    pub image: String,
    /// Target agent ID to deploy the CP on.
    /// If not set, picks an available agent.
    #[serde(default)]
    pub agent_id: Option<String>,
    /// Optional node_size filter when auto-selecting an agent.
    #[serde(default)]
    pub node_size: Option<String>,
    /// Optional datacenter filter when auto-selecting an agent.
    #[serde(default)]
    pub datacenter: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DeployCpResponse {
    pub deployment_id: Uuid,
    pub agent_id: Uuid,
    pub status: DeploymentStatus,
    pub seed_config_included: bool,
}

/// Readiness report: how many agents have re-registered with the new CP.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MigrationReadinessResponse {
    pub ready: bool,
    pub agents_registered: usize,
    pub agents_expected: usize,
    pub agents_missing: Vec<String>,
}

/// Request to start proxying all traffic to a new CP during migration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProxyStartRequest {
    /// URL of the new CP to proxy traffic to (e.g. "http://10.0.0.5:8080").
    pub target_url: String,
}

/// Agent re-registration request — sent when an agent heartbeats a new CP
/// that doesn't know about it yet.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentReattachRequest {
    pub vm_name: String,
    #[serde(default)]
    pub node_size: Option<String>,
    #[serde(default)]
    pub datacenter: Option<String>,
    /// Deployments currently running on this agent.
    #[serde(default)]
    pub running_deployments: Vec<RunningDeploymentReport>,
}

/// A deployment the agent is currently running (reported during reattach).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RunningDeploymentReport {
    pub deployment_id: String,
    pub app_name: Option<String>,
    pub image: Option<String>,
    pub status: String,
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
