use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::config::Config;

/// Point-in-time snapshot of a single agent, populated by the collector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentSnapshot {
    pub agent_id: String,
    pub hostname: String,
    pub vm_name: String,
    pub attestation_type: String,
    pub status: String,
    pub last_seen: chrono::DateTime<chrono::Utc>,
    pub deployment_count: usize,
    pub deployment_names: Vec<String>,
    pub cpu_percent: u64,
    pub memory_used_mb: u64,
    pub memory_total_mb: u64,
}

pub type AgentStore = Arc<Mutex<HashMap<String, AgentSnapshot>>>;

/// Browser session for local cookie-based auth.
#[derive(Debug, Clone)]
pub struct BrowserSession {
    pub token: String,
    pub expires_at: Instant,
}

pub type BrowserSessions = Arc<Mutex<HashMap<String, BrowserSession>>>;

/// Pending OAuth state for CSRF protection.
#[derive(Debug, Clone)]
pub struct PendingOauthState {
    pub next_path: String,
    pub expires_at: Instant,
}

pub type PendingOauthStates = Arc<Mutex<HashMap<String, PendingOauthState>>>;

/// Shared application state for the dd-web service.
#[derive(Clone)]
pub struct WebState {
    pub config: Arc<Config>,
    pub agents: AgentStore,
    pub sessions: BrowserSessions,
    pub pending_oauth_states: PendingOauthStates,
    pub signing_key: jsonwebtoken::EncodingKey,
    pub decoding_key: jsonwebtoken::DecodingKey,
    pub started_at: Instant,
}
