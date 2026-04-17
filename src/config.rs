//! Environment-derived configuration for both modes.

use crate::error::{Error, Result};

#[derive(Clone)]
pub struct CfCreds {
    pub api_token: String,
    pub account_id: String,
    pub zone_id: String,
    pub domain: String,
}

impl CfCreds {
    pub fn from_env() -> Result<Self> {
        let get = |k: &str| std::env::var(k).map_err(|_| Error::Internal(format!("{k} not set")));
        Ok(Self {
            api_token: get("DD_CF_API_TOKEN")?,
            account_id: get("DD_CF_ACCOUNT_ID")?,
            zone_id: get("DD_CF_ZONE_ID")?,
            domain: get("DD_CF_DOMAIN")?,
        })
    }
}

/// Configuration shared between modes.
pub struct Common {
    pub env_label: String,
    pub port: u16,
    pub owner: String,
    pub vm_name: String,
}

impl Common {
    pub fn from_env() -> Result<Self> {
        let env_label = std::env::var("DD_ENV").map_err(|_| {
            Error::Internal("DD_ENV required (dev / staging / production / pr-*)".into())
        })?;
        let port = std::env::var("DD_PORT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(8080);
        let owner = std::env::var("DD_OWNER")
            .map_err(|_| Error::Internal("DD_OWNER required (GitHub user or org)".into()))?;
        let vm_name = std::env::var("DD_VM_NAME").unwrap_or_else(|_| {
            std::fs::read_to_string("/etc/hostname")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "unknown".into())
        });
        Ok(Self {
            env_label,
            port,
            owner,
            vm_name,
        })
    }
}

/// ITA (Intel Trust Authority) configuration. All fields required —
/// attestation is mandatory in both modes.
#[derive(Clone)]
pub struct Ita {
    /// URL for Intel's ITA mint endpoint, e.g. `https://api.trustauthority.intel.com`.
    pub base_url: String,
    /// API key for the mint endpoint.
    pub api_key: String,
    /// JWKS endpoint for verifier.
    pub jwks_url: String,
    /// Expected `iss` claim.
    pub issuer: String,
}

impl Ita {
    pub fn from_env() -> Result<Self> {
        let get = |k: &str| {
            std::env::var(k)
                .ok()
                .filter(|s| !s.is_empty())
                .ok_or_else(|| Error::Internal(format!("{k} required")))
        };
        Ok(Self {
            base_url: get("DD_ITA_BASE_URL")?,
            api_key: get("DD_ITA_API_KEY")?,
            jwks_url: get("DD_ITA_JWKS_URL")?,
            issuer: get("DD_ITA_ISSUER")?,
        })
    }
}

/// Control-plane-mode config.
pub struct Cp {
    pub common: Common,
    pub cf: CfCreds,
    pub hostname: String,
    pub scrape_interval_secs: u64,
    pub ita: Ita,
}

impl Cp {
    pub fn from_env() -> Result<Self> {
        let common = Common::from_env()?;
        let cf = CfCreds::from_env()?;
        let hostname = std::env::var("DD_HOSTNAME")
            .map_err(|_| Error::Internal("DD_HOSTNAME required in CP mode".into()))?;
        let scrape_interval_secs = std::env::var("DD_SCRAPE_INTERVAL")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(30);
        Ok(Self {
            common,
            cf,
            hostname,
            scrape_interval_secs,
            ita: Ita::from_env()?,
        })
    }
}

/// Agent-mode config.
pub struct Agent {
    pub common: Common,
    pub cp_url: String,
    pub pat: String,
    pub ee_socket: String,
    pub ita: Ita,
}

impl Agent {
    pub fn from_env() -> Result<Self> {
        let common = Common::from_env()?;
        let cp_url = std::env::var("DD_CP_URL").map_err(|_| {
            Error::Internal("DD_CP_URL required (e.g. https://app.devopsdefender.com)".into())
        })?;
        let pat = std::env::var("DD_PAT")
            .map_err(|_| Error::Internal("DD_PAT required (GitHub PAT for owner check)".into()))?;
        let ee_socket = std::env::var("EE_SOCKET_PATH")
            .unwrap_or_else(|_| "/var/lib/easyenclave/agent.sock".into());
        Ok(Self {
            common,
            cp_url,
            pat,
            ee_socket,
            ita: Ita::from_env()?,
        })
    }
}
