use crate::db::Db;
use crate::services::attestation::AttestationService;
use crate::services::github_oidc::GithubOidcService;
use crate::services::nonce::NonceService;
use crate::services::tunnel::TunnelService;
use crate::stores::setting::SettingsStore;

/// Shared application state available to all route handlers.
#[derive(Clone)]
pub struct AppState {
    pub boot_id: String,
    pub git_sha: String,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub admin_password: Option<String>,
    pub db: Db,
    pub settings: SettingsStore,
    pub nonce: NonceService,
    pub attestation: AttestationService,
    pub github_oidc: GithubOidcService,
    pub tunnel: TunnelService,
    pub check_ingest_token: Option<String>,
    pub heartbeat_interval_seconds: u64,
    pub check_timeout_seconds: u64,
    pub down_after_failures: i64,
    pub recover_after_successes: i64,
    pub attestation_recheck_seconds: u64,
    pub agent_health_path: String,
    pub agent_attestation_path: String,
    pub stale_agent_timeout_seconds: u64,
}

impl AppState {
    /// Build AppState from environment variables and a connected DB.
    pub fn from_env(db: Db) -> Self {
        let env = |key: &str, default: &str| -> String {
            std::env::var(key).unwrap_or_else(|_| default.to_string())
        };
        let env_u64 = |key: &str, default: u64| -> u64 {
            std::env::var(key)
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(default)
        };
        let env_i64 = |key: &str, default: i64| -> i64 {
            std::env::var(key)
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(default)
        };

        Self {
            boot_id: uuid::Uuid::new_v4().to_string(),
            git_sha: env("DD_CP_GIT_SHA", "unknown"),
            started_at: chrono::Utc::now(),
            admin_password: std::env::var("DD_CP_ADMIN_PASSWORD").ok(),
            db: db.clone(),
            settings: SettingsStore::new(db),
            nonce: NonceService::new(env_u64("DD_CP_NONCE_TTL_SECONDS", 300)),
            attestation: AttestationService::insecure_for_tests(),
            github_oidc: GithubOidcService::disabled_for_tests(),
            tunnel: TunnelService::disabled_for_tests(),
            check_ingest_token: std::env::var("DD_CP_CHECK_INGEST_TOKEN").ok(),
            heartbeat_interval_seconds: env_u64("DD_CP_HEARTBEAT_INTERVAL_SECONDS", 30),
            check_timeout_seconds: env_u64("DD_CP_CHECK_TIMEOUT_SECONDS", 10),
            down_after_failures: env_i64("DD_CP_DOWN_AFTER_FAILURES", 3),
            recover_after_successes: env_i64("DD_CP_RECOVER_AFTER_SUCCESSES", 2),
            attestation_recheck_seconds: env_u64("DD_CP_ATTESTATION_RECHECK_SECONDS", 3600),
            agent_health_path: env("DD_CP_AGENT_HEALTH_PATH", "/health"),
            agent_attestation_path: env("DD_CP_AGENT_ATTESTATION_PATH", "/attestation"),
            stale_agent_timeout_seconds: env_u64("DD_CP_STALE_AGENT_TIMEOUT_SECONDS", 300),
        }
    }

    /// Build AppState suitable for testing with an in-memory DB.
    pub fn for_testing(db: Db) -> Self {
        Self {
            boot_id: "test-boot-id".into(),
            git_sha: "test-sha".into(),
            started_at: chrono::Utc::now(),
            admin_password: Some("test-admin-password".into()),
            db: db.clone(),
            settings: SettingsStore::new(db),
            nonce: NonceService::new(300),
            attestation: AttestationService::insecure_for_tests(),
            github_oidc: GithubOidcService::disabled_for_tests(),
            tunnel: TunnelService::disabled_for_tests(),
            check_ingest_token: Some("test-ingest-token".into()),
            heartbeat_interval_seconds: 30,
            check_timeout_seconds: 10,
            down_after_failures: 3,
            recover_after_successes: 2,
            attestation_recheck_seconds: 3600,
            agent_health_path: "/health".into(),
            agent_attestation_path: "/attestation".into(),
            stale_agent_timeout_seconds: 300,
        }
    }
}
