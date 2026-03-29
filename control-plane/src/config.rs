use std::collections::HashMap;

/// The operational mode of the control plane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CpMode {
    /// Bootstrap mode: a lightweight CP that runs on bare infrastructure,
    /// registers agents, and can deploy the portable CP as a workload.
    /// Does not create its own CF tunnel by default.
    Bootstrap,
    /// Portable mode: the full CP running as a container workload on an agent.
    /// Supports state export/import for migration between nodes.
    Portable,
}

impl CpMode {
    fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "bootstrap" => Self::Bootstrap,
            "portable" => Self::Portable,
            _ => Self::Portable,
        }
    }
}

/// Control plane configuration, loaded from environment variables.
#[derive(Debug, Clone)]
pub struct CpConfig {
    pub bind_addr: String,
    pub database_url: String,
    pub admin_password: Option<String>,
    pub tcb_enforcement_mode: String,
    pub rtmr_enforcement_mode: String,
    pub nonce_enforcement_mode: String,
    /// Bootstrap or portable mode.
    pub cp_mode: CpMode,
    /// Path to a state bundle JSON file to import on startup.
    /// When set, the CP will restore state from this file before serving.
    pub import_state_path: Option<String>,
}

impl CpConfig {
    /// Load configuration from process environment variables.
    pub fn from_env() -> Self {
        let mut map = HashMap::new();
        for (k, v) in std::env::vars() {
            map.insert(k, v);
        }
        Self::from_map(&map)
    }

    /// Load configuration from an arbitrary key-value map (useful for testing).
    pub fn from_map(map: &HashMap<String, String>) -> Self {
        Self {
            bind_addr: map
                .get("DD_CP_BIND_ADDR")
                .cloned()
                .unwrap_or_else(|| "0.0.0.0:8080".to_string()),
            database_url: map
                .get("DD_CP_DATABASE_URL")
                .cloned()
                .unwrap_or_else(|| "sqlite://devopsdefender.db?mode=rwc".to_string()),
            admin_password: map.get("DD_CP_ADMIN_PASSWORD").cloned(),
            tcb_enforcement_mode: map
                .get("DD_CP_TCB_ENFORCEMENT_MODE")
                .cloned()
                .unwrap_or_else(|| "strict".to_string()),
            rtmr_enforcement_mode: map
                .get("DD_CP_RTMR_ENFORCEMENT_MODE")
                .cloned()
                .unwrap_or_else(|| "strict".to_string()),
            nonce_enforcement_mode: map
                .get("DD_CP_NONCE_ENFORCEMENT_MODE")
                .cloned()
                .unwrap_or_else(|| "required".to_string()),
            cp_mode: map
                .get("DD_CP_MODE")
                .map(|s| CpMode::from_str(s))
                .unwrap_or(CpMode::Portable),
            import_state_path: map.get("DD_CP_IMPORT_STATE").cloned(),
        }
    }

    pub fn is_bootstrap(&self) -> bool {
        self.cp_mode == CpMode::Bootstrap
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_apply_correctly() {
        let map = HashMap::new();
        let cfg = CpConfig::from_map(&map);
        assert_eq!(cfg.bind_addr, "0.0.0.0:8080");
        assert_eq!(cfg.database_url, "sqlite://devopsdefender.db?mode=rwc");
        assert!(cfg.admin_password.is_none());
        assert_eq!(cfg.tcb_enforcement_mode, "strict");
        assert_eq!(cfg.rtmr_enforcement_mode, "strict");
        assert_eq!(cfg.nonce_enforcement_mode, "required");
        assert_eq!(cfg.cp_mode, CpMode::Portable);
        assert!(cfg.import_state_path.is_none());
    }

    #[test]
    fn bootstrap_mode_from_env() {
        let mut map = HashMap::new();
        map.insert("DD_CP_MODE".into(), "bootstrap".into());
        let cfg = CpConfig::from_map(&map);
        assert_eq!(cfg.cp_mode, CpMode::Bootstrap);
        assert!(cfg.is_bootstrap());
    }

    #[test]
    fn import_state_path_from_env() {
        let mut map = HashMap::new();
        map.insert("DD_CP_IMPORT_STATE".into(), "/tmp/state.json".into());
        let cfg = CpConfig::from_map(&map);
        assert_eq!(cfg.import_state_path, Some("/tmp/state.json".to_string()));
    }
}
