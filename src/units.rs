//! Canonical managed-unit inventory shared by agent, CP, and shell views.
//!
//! Security mode is agent-scoped. Units inherit the containing agent's
//! read-only/read-write boundary and add UX role/capability metadata.

use serde::{Deserialize, Serialize};

use crate::oracle::OracleStatus;
use crate::taint::IntegrityState;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentMode {
    ReadOnly,
    ReadWrite,
}

impl AgentMode {
    pub fn from_confidential(confidential: bool) -> Self {
        if confidential {
            Self::ReadOnly
        } else {
            Self::ReadWrite
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnly => "read_only",
            Self::ReadWrite => "read_write",
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnitKind {
    Agent,
    Shell,
    Tunnel,
    Storage,
    Runtime,
    Workload,
}

impl UnitKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Agent => "agent",
            Self::Shell => "shell",
            Self::Tunnel => "tunnel",
            Self::Storage => "storage",
            Self::Runtime => "runtime",
            Self::Workload => "workload",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnitRef {
    pub kind: String,
    pub label: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagedUnit {
    pub id: String,
    pub app_name: String,
    pub title: String,
    pub kind: UnitKind,
    pub agent_mode: AgentMode,
    pub agent_integrity_state: IntegrityState,
    pub status: String,
    pub image: Option<String>,
    pub started_at: Option<String>,
    pub error_message: Option<String>,
    pub source: Option<String>,
    pub log_line_count: usize,
    pub capabilities: Vec<String>,
    pub refs: Vec<UnitRef>,
    pub oracle: Option<OracleStatus>,
}

pub fn kind_for_app(app: &str) -> UnitKind {
    match app {
        "dd-agent" => UnitKind::Agent,
        "dd-shell" | "confidential-shell" | "codex-podman-shell" => UnitKind::Shell,
        "cloudflared" => UnitKind::Tunnel,
        "mount-data" => UnitKind::Storage,
        app if app.starts_with("podman-") => UnitKind::Runtime,
        _ => UnitKind::Workload,
    }
}

pub fn title_for_app(app: &str) -> String {
    match app {
        "dd-agent" => "Agent API".into(),
        "dd-shell" => "Shell service".into(),
        "cloudflared" => "Cloudflare tunnel".into(),
        "mount-data" => "Persistent data mount".into(),
        "podman-static" => "Podman release asset".into(),
        "podman-bootstrap" => "Podman runtime bootstrap".into(),
        _ => app.to_string(),
    }
}

pub fn source_for_app(app: &str) -> Option<String> {
    match app {
        "dd-agent" | "dd-management" => Some(format!("apps/{app}/workload.json.tmpl")),
        _ => Some(format!("apps/{app}/workload.json")),
    }
}

pub fn base_capabilities(kind: UnitKind) -> Vec<String> {
    match kind {
        UnitKind::Agent => vec!["health".into()],
        UnitKind::Shell => vec!["shell".into(), "history".into(), "sessions".into()],
        UnitKind::Tunnel => vec!["tunnel".into(), "ingress".into()],
        UnitKind::Storage => vec!["storage".into()],
        UnitKind::Runtime => vec!["runtime".into()],
        UnitKind::Workload => Vec::new(),
    }
}

pub fn ref_item(kind: &str, label: impl Into<String>, value: impl Into<String>) -> UnitRef {
    UnitRef {
        kind: kind.into(),
        label: label.into(),
        value: value.into(),
    }
}
