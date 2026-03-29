use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::common::error::{AppError, AppResult};
use crate::db::{self, Db};

// ── Seed Config ─────────────────────────────────────────────────────────────
//
// Lightweight configuration state that MUST be transferred when migrating the
// CP to a new node.  Agent and deployment state is NOT included — agents
// re-register naturally when they heartbeat the new CP and get a 404.

/// Tables that form the "seed config" — small, essential, cannot be
/// rediscovered from agents.
const SEED_TABLES: &[&str] = &[
    "accounts",
    "settings",
    "trusted_mrtds",
    "apps",
    "app_versions",
];

/// Lightweight config needed to seed a new portable CP.
///
/// Does NOT contain agent or deployment data — those come over naturally when
/// agents re-register with the new CP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeedConfig {
    /// Schema version for forward compatibility.
    pub version: u32,
    /// ISO 8601 timestamp of when this was created.
    pub exported_at: String,
    /// Git SHA of the CP that created this.
    pub git_sha: String,
    /// Seed database tables (accounts, settings, trusted_mrtds, apps, app_versions).
    pub tables: serde_json::Map<String, serde_json::Value>,
}

impl SeedConfig {
    pub const CURRENT_VERSION: u32 = 1;

    /// Export the seed config from the current database.
    pub fn export(db: &Db, git_sha: &str) -> AppResult<Self> {
        let all_tables = db::export_all_tables(db)
            .map_err(|e| AppError::External(format!("database export failed: {e}")))?;

        let mut tables = serde_json::Map::new();
        for &name in SEED_TABLES {
            if let Some(data) = all_tables.get(name) {
                tables.insert(name.to_string(), data.clone());
            }
        }

        Ok(Self {
            version: Self::CURRENT_VERSION,
            exported_at: chrono::Utc::now().to_rfc3339(),
            git_sha: git_sha.to_string(),
            tables,
        })
    }

    /// Import seed config into the database.  Only touches the seed tables.
    pub fn import(&self, db: &Db) -> AppResult<()> {
        if self.version > Self::CURRENT_VERSION {
            return Err(AppError::InvalidInput(format!(
                "seed config version {} is newer than supported version {}",
                self.version,
                Self::CURRENT_VERSION
            )));
        }

        db::import_all_tables(db, &self.tables)
            .map_err(|e| AppError::External(format!("seed config import failed: {e}")))?;

        Ok(())
    }

    pub fn summary(&self) -> SeedConfigSummary {
        let mut table_counts = HashMap::new();
        for (table, rows) in &self.tables {
            if let Some(arr) = rows.as_array() {
                table_counts.insert(table.clone(), arr.len());
            }
        }
        SeedConfigSummary {
            version: self.version,
            exported_at: self.exported_at.clone(),
            git_sha: self.git_sha.clone(),
            table_counts,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SeedConfigSummary {
    pub version: u32,
    pub exported_at: String,
    pub git_sha: String,
    pub table_counts: HashMap<String, usize>,
}

// ── Full State Bundle ───────────────────────────────────────────────────────
//
// Optional: a full database snapshot including agents and deployments.
// Useful for instant cutover when you don't want to wait for agents to
// re-register.

// Full export uses db::EXPORTABLE_TABLES (defined in db.rs) which includes
// all tables.  No separate constant needed here.

/// Full state snapshot — seed config + all agent/deployment state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateBundle {
    pub version: u32,
    pub exported_at: String,
    pub git_sha: String,
    /// Configuration secrets (env var values).
    pub secrets: HashMap<String, String>,
    /// Full database dump.
    pub database: serde_json::Map<String, serde_json::Value>,
}

/// Env vars captured in the secrets section.
pub const SECRET_ENV_VARS: &[&str] = &[
    "DD_CP_ADMIN_PASSWORD",
    "DD_CP_CF_API_TOKEN",
    "DD_CP_CF_ACCOUNT_ID",
    "DD_CP_CF_ZONE_ID",
    "DD_CP_CF_DOMAIN",
    "DD_CP_PUBLIC_HOSTNAME",
    "DD_CP_ITA_JWKS_URL",
    "DD_CP_ITA_ISSUER",
    "DD_CP_ITA_AUDIENCE",
    "DD_CP_GITHUB_OIDC_AUDIENCE",
    "DD_CP_CHECK_INGEST_TOKEN",
    "DD_ENV",
];

impl StateBundle {
    pub const CURRENT_VERSION: u32 = 1;

    pub fn export(db: &Db, git_sha: &str) -> AppResult<Self> {
        let database = db::export_all_tables(db)
            .map_err(|e| AppError::External(format!("database export failed: {e}")))?;

        let mut secrets = HashMap::new();
        for &key in SECRET_ENV_VARS {
            if let Ok(val) = std::env::var(key) {
                secrets.insert(key.to_string(), val);
            }
        }

        Ok(Self {
            version: Self::CURRENT_VERSION,
            exported_at: chrono::Utc::now().to_rfc3339(),
            git_sha: git_sha.to_string(),
            secrets,
            database,
        })
    }

    pub fn import(&self, db: &Db) -> AppResult<()> {
        if self.version > Self::CURRENT_VERSION {
            return Err(AppError::InvalidInput(format!(
                "state bundle version {} is newer than supported version {}",
                self.version,
                Self::CURRENT_VERSION
            )));
        }

        db::import_all_tables(db, &self.database)
            .map_err(|e| AppError::External(format!("database import failed: {e}")))?;

        Ok(())
    }

    pub fn apply_secrets_to_env(&self) {
        for (key, value) in &self.secrets {
            std::env::set_var(key, value);
        }
    }

    pub fn to_json(&self) -> AppResult<Vec<u8>> {
        serde_json::to_vec_pretty(self)
            .map_err(|e| AppError::External(format!("serialize state bundle: {e}")))
    }

    pub fn from_json(data: &[u8]) -> AppResult<Self> {
        serde_json::from_slice(data)
            .map_err(|e| AppError::InvalidInput(format!("invalid state bundle: {e}")))
    }

    pub fn summary(&self) -> StateBundleSummary {
        let mut table_counts = HashMap::new();
        for (table, rows) in &self.database {
            if let Some(arr) = rows.as_array() {
                table_counts.insert(table.clone(), arr.len());
            }
        }
        StateBundleSummary {
            version: self.version,
            exported_at: self.exported_at.clone(),
            git_sha: self.git_sha.clone(),
            secret_count: self.secrets.len(),
            table_counts,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StateBundleSummary {
    pub version: u32,
    pub exported_at: String,
    pub git_sha: String,
    pub secret_count: usize,
    pub table_counts: HashMap<String, usize>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;

    fn setup_db() -> Db {
        db::connect_and_migrate("sqlite://:memory:").unwrap()
    }

    // ── SeedConfig tests ────────────────────────────────────────────────────

    #[test]
    fn seed_config_exports_only_seed_tables() {
        let db = setup_db();
        {
            let conn = db.lock().unwrap();
            conn.execute(
                "INSERT INTO agents (id, vm_name, status, registration_state, created_at) \
                 VALUES ('a1', 'vm-1', 'undeployed', 'ready', '2025-01-01T00:00:00Z')",
                [],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO settings (key, value) VALUES ('test-key', 'test-value')",
                [],
            )
            .unwrap();
        }

        let seed = SeedConfig::export(&db, "sha").unwrap();

        // Settings should be included
        let settings = seed.tables.get("settings").unwrap().as_array().unwrap();
        assert_eq!(settings.len(), 1);

        // Agents should NOT be included (they re-register naturally)
        assert!(!seed.tables.contains_key("agents"));
    }

    #[test]
    fn seed_config_roundtrip() {
        let db1 = setup_db();
        {
            let conn = db1.lock().unwrap();
            conn.execute("INSERT INTO settings (key, value) VALUES ('k1', 'v1')", [])
                .unwrap();
        }

        let seed = SeedConfig::export(&db1, "sha").unwrap();
        let json = serde_json::to_vec(&seed).unwrap();
        let restored: SeedConfig = serde_json::from_slice(&json).unwrap();

        let db2 = setup_db();
        restored.import(&db2).unwrap();

        let conn = db2.lock().unwrap();
        let val: String = conn
            .query_row("SELECT value FROM settings WHERE key = 'k1'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(val, "v1");
    }

    // ── StateBundle tests ───────────────────────────────────────────────────

    #[test]
    fn export_empty_db() {
        let db = setup_db();
        let bundle = StateBundle::export(&db, "test-sha").unwrap();
        assert_eq!(bundle.version, StateBundle::CURRENT_VERSION);
        assert!(bundle.database.contains_key("agents"));
    }

    #[test]
    fn full_bundle_roundtrip() {
        let db1 = setup_db();
        {
            let conn = db1.lock().unwrap();
            conn.execute(
                "INSERT INTO agents (id, vm_name, status, registration_state, created_at) \
                 VALUES ('a1', 'vm-1', 'undeployed', 'ready', '2025-01-01T00:00:00Z')",
                [],
            )
            .unwrap();
        }

        let bundle = StateBundle::export(&db1, "sha-abc").unwrap();
        let json = bundle.to_json().unwrap();
        let restored = StateBundle::from_json(&json).unwrap();

        let db2 = setup_db();
        restored.import(&db2).unwrap();

        let conn = db2.lock().unwrap();
        let vm: String = conn
            .query_row("SELECT vm_name FROM agents WHERE id = 'a1'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(vm, "vm-1");
    }

    #[test]
    fn reject_future_version() {
        let db = setup_db();
        let mut bundle = StateBundle::export(&db, "sha").unwrap();
        bundle.version = 999;
        assert!(bundle.import(&db).is_err());
    }
}
