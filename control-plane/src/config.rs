use std::collections::HashMap;

/// Control plane configuration, loaded from environment variables.
#[derive(Debug, Clone)]
pub struct CpConfig {
    pub bind_addr: String,
    pub database_url: String,
    pub admin_password: Option<String>,
    pub tcb_enforcement_mode: String,
    pub rtmr_enforcement_mode: String,
    pub nonce_enforcement_mode: String,
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
        }
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
    }
}
