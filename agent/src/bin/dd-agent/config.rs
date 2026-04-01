use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// The three operational modes the agent binary can run in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AgentMode {
    Agent,
    Register,
    Scraper,
    ControlPlane,
    Measure,
}

impl AgentMode {
    fn from_str_loose(s: &str) -> Option<Self> {
        match s.to_lowercase().replace('_', "-").as_str() {
            "agent" => Some(Self::Agent),
            "register" => Some(Self::Register),
            "scraper" => Some(Self::Scraper),
            "control-plane" | "controlplane" | "cp" => Some(Self::ControlPlane),
            "measure" => Some(Self::Measure),
            _ => None,
        }
    }
}

/// Which provided application the agent should manage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProvidedApp {
    ControlPlane,
    Measure,
}

/// Runtime configuration for the dd-agent binary.
///
/// Loaded from a JSON config file with environment variable overrides.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRuntimeConfig {
    /// Operating mode (agent / control-plane / measure).
    #[serde(default = "default_mode")]
    pub mode: AgentMode,

    /// Base URL of the control plane the agent registers with.
    #[serde(default)]
    pub control_plane_url: Option<String>,

    /// Nominal size of this node (informational label).
    #[serde(default)]
    pub node_size: Option<String>,

    /// Datacenter / region label.
    #[serde(default)]
    pub datacenter: Option<String>,

    /// Intel Trust Authority API key used for attestation token retrieval.
    #[serde(default)]
    pub intel_api_key: Option<String>,

    /// OCI image reference for the control-plane workload.
    #[serde(default)]
    pub control_plane_image: Option<String>,

    /// OCI image reference for the measure workload.
    #[serde(default)]
    pub measure_app_image: Option<String>,

    /// Which provided application to run, if any.
    #[serde(default)]
    pub provided_app: Option<ProvidedApp>,

    /// Port the workload should listen on.
    #[serde(default)]
    pub port: Option<u16>,

    /// Catch-all key/value pairs forwarded as environment variables.
    #[serde(default)]
    pub raw_kv: HashMap<String, String>,
}

fn default_mode() -> AgentMode {
    AgentMode::Agent
}

impl Default for AgentRuntimeConfig {
    fn default() -> Self {
        Self {
            mode: AgentMode::Agent,
            control_plane_url: None,
            node_size: None,
            datacenter: None,
            intel_api_key: None,
            control_plane_image: None,
            measure_app_image: None,
            provided_app: None,
            port: None,
            raw_kv: HashMap::new(),
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
        cfg.apply_env_overrides();
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

    fn apply_env_overrides(&mut self) {
        if let Ok(val) = std::env::var("DD_AGENT_MODE") {
            if let Some(mode) = AgentMode::from_str_loose(&val) {
                self.mode = mode;
            }
        }

        // Control plane URL: prefer DD_CP_URL, fall back to AGENT_CP_URL.
        if let Ok(val) = std::env::var("DD_CP_URL") {
            self.control_plane_url = Some(val);
        } else if let Ok(val) = std::env::var("AGENT_CP_URL") {
            self.control_plane_url = Some(val);
        }

        if let Ok(val) = std::env::var("AGENT_NODE_SIZE") {
            self.node_size = Some(val);
        }

        if let Ok(val) = std::env::var("DD_DATACENTER") {
            self.datacenter = Some(val);
        }

        if let Ok(val) = std::env::var("DD_INTEL_API_KEY") {
            self.intel_api_key = Some(val);
        }

        if let Ok(val) = std::env::var("DD_CP_IMAGE") {
            self.control_plane_image = Some(val);
        }

        if let Ok(val) = std::env::var("DD_MEASURE_IMAGE") {
            self.measure_app_image = Some(val);
        }

        if let Ok(val) = std::env::var("DD_PORT") {
            if let Ok(p) = val.parse::<u16>() {
                self.port = Some(p);
            }
        }
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
    fn mode_from_str_loose() {
        assert_eq!(AgentMode::from_str_loose("agent"), Some(AgentMode::Agent));
        assert_eq!(
            AgentMode::from_str_loose("control-plane"),
            Some(AgentMode::ControlPlane)
        );
        assert_eq!(
            AgentMode::from_str_loose("control_plane"),
            Some(AgentMode::ControlPlane)
        );
        assert_eq!(
            AgentMode::from_str_loose("cp"),
            Some(AgentMode::ControlPlane)
        );
        assert_eq!(
            AgentMode::from_str_loose("measure"),
            Some(AgentMode::Measure)
        );
        assert_eq!(AgentMode::from_str_loose("bogus"), None);
    }
}
