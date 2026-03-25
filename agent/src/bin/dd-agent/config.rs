use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// The two operational modes the agent binary can run in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AgentMode {
    Agent,
    BootstrapCp,
}

/// Runtime configuration for the dd-agent binary.
///
/// Loaded from a JSON config file with environment variable overrides.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRuntimeConfig {
    /// Operating mode determined from bootstrap_cp / control_plane_url.
    #[serde(skip, default = "default_mode")]
    pub mode: AgentMode,

    /// Base URL of the control plane the agent registers with.
    #[serde(default)]
    pub control_plane_url: Option<String>,

    /// Run as the bootstrap control plane instead of an attached agent.
    #[serde(default)]
    pub bootstrap_cp: bool,

    /// Nominal size of this node (informational label).
    #[serde(default)]
    pub node_size: Option<String>,

    /// Datacenter / region label.
    #[serde(default)]
    pub datacenter: Option<String>,

    /// Port the workload should listen on.
    #[serde(default)]
    pub port: Option<u16>,
}

fn default_mode() -> AgentMode {
    AgentMode::Agent
}

impl Default for AgentRuntimeConfig {
    fn default() -> Self {
        Self {
            mode: AgentMode::Agent,
            control_plane_url: None,
            bootstrap_cp: false,
            node_size: None,
            datacenter: None,
            port: None,
        }
    }
}

impl AgentRuntimeConfig {
    /// Default path to the on-disk configuration file.
    pub const DEFAULT_CONFIG_PATH: &'static str = "/etc/devopsdefender/agent.json";

    /// Load configuration by reading the config file and then applying
    /// environment variable overrides.
    pub fn load() -> Result<Self, String> {
        let config_path =
            std::env::var("DD_CONFIG").unwrap_or_else(|_| Self::DEFAULT_CONFIG_PATH.to_string());

        let mut cfg = Self::load_from_file(&config_path)?;
        cfg.apply_env_overrides()?;
        cfg.mode = cfg.detect_mode()?;
        Ok(cfg)
    }

    fn load_from_file(path: &str) -> Result<Self, String> {
        let pb = PathBuf::from(path);
        if !pb.exists() {
            eprintln!("config file not found at {path}, using defaults");
            return Ok(Self::default());
        }
        let text = std::fs::read_to_string(&pb)
            .map_err(|e| format!("failed to read config file {path}: {e}"))?;
        serde_json::from_str(&text).map_err(|e| format!("failed to parse config file {path}: {e}"))
    }

    fn apply_env_overrides(&mut self) -> Result<(), String> {
        if let Ok(val) = std::env::var("DD_CP_URL") {
            self.control_plane_url = Some(val);
        }

        if let Ok(val) = std::env::var("DD_BOOTSTRAP_CP") {
            self.bootstrap_cp = parse_bool_env(&val)
                .map_err(|_| format!("DD_BOOTSTRAP_CP must be a boolean, got {val:?}"))?;
        }

        if let Ok(val) = std::env::var("AGENT_NODE_SIZE") {
            self.node_size = Some(val);
        }

        if let Ok(val) = std::env::var("DD_DATACENTER") {
            self.datacenter = Some(val);
        }

        if let Ok(val) = std::env::var("DD_PORT") {
            if let Ok(p) = val.parse::<u16>() {
                self.port = Some(p);
            }
        }

        Ok(())
    }

    fn detect_mode(&self) -> Result<AgentMode, String> {
        match (self.bootstrap_cp, self.control_plane_url.as_ref()) {
            (true, Some(_)) => Err(
                "DD_BOOTSTRAP_CP=true cannot be combined with DD_CP_URL/control_plane_url".into(),
            ),
            (true, None) => Ok(AgentMode::BootstrapCp),
            (false, Some(_)) => Ok(AgentMode::Agent),
            (false, None) => {
                Err("either DD_CP_URL/control_plane_url or DD_BOOTSTRAP_CP=true must be set".into())
            }
        }
    }
}

fn parse_bool_env(val: &str) -> Result<bool, String> {
    match val.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(format!("invalid boolean value {val:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_agent_mode() {
        let cfg = AgentRuntimeConfig::default();
        assert_eq!(cfg.mode, AgentMode::Agent);
    }

    #[test]
    fn detect_mode_prefers_bootstrap_cp() {
        let cfg = AgentRuntimeConfig {
            bootstrap_cp: true,
            ..AgentRuntimeConfig::default()
        };
        assert_eq!(cfg.detect_mode().unwrap(), AgentMode::BootstrapCp);
    }

    #[test]
    fn detect_mode_agent_requires_cp_url() {
        let cfg = AgentRuntimeConfig {
            control_plane_url: Some("https://cp.example".into()),
            ..AgentRuntimeConfig::default()
        };
        assert_eq!(cfg.detect_mode().unwrap(), AgentMode::Agent);
    }

    #[test]
    fn detect_mode_rejects_ambiguous_config() {
        let cfg = AgentRuntimeConfig {
            bootstrap_cp: true,
            control_plane_url: Some("https://cp.example".into()),
            ..AgentRuntimeConfig::default()
        };
        assert!(cfg.detect_mode().is_err());
    }

    #[test]
    fn parse_bool_env_accepts_common_values() {
        assert!(parse_bool_env("true").unwrap());
        assert!(parse_bool_env("1").unwrap());
        assert!(!parse_bool_env("false").unwrap());
        assert!(parse_bool_env("wat").is_err());
    }
}
