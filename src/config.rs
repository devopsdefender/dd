//! Environment-derived configuration for both modes.
//!
//! Auth model: CF Access is gone. The CP hosts the GitHub OAuth flow
//! itself and mints HS256 JWT cookies scoped to the fleet domain.
//! Agents verify those cookies with the same shared secret. CI →
//! agent/CP still uses GitHub Actions OIDC; agent → CP still uses
//! Intel Trust Authority tokens. No PATs, no service tokens, no
//! Cloudflare Access.

use crate::error::{Error, Result};
use crate::gh_oidc::{Principal, PrincipalKind};

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

/// GitHub OAuth App credentials (CP only).
///
/// Created once per fleet in the `DD_OWNER` GitHub org. Callback URL is
/// `https://app.<DD_CF_DOMAIN>/oauth/callback`.
#[derive(Clone)]
pub struct GhOauth {
    pub client_id: String,
    pub client_secret: String,
}

impl GhOauth {
    pub fn from_env() -> Result<Self> {
        let get = |k: &str| std::env::var(k).map_err(|_| Error::Internal(format!("{k} not set")));
        Ok(Self {
            client_id: get("DD_GH_OAUTH_CLIENT_ID")?,
            client_secret: get("DD_GH_OAUTH_CLIENT_SECRET")?,
        })
    }
}

/// Configuration shared between modes.
pub struct Common {
    pub env_label: String,
    pub port: u16,
    pub owner: Principal,
    pub vm_name: String,
    /// HS256 secret used to sign + verify the `dd_session` JWT cookie.
    /// Required in both modes — CP signs, agents verify.
    pub fleet_jwt_secret: String,
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
        let owner_name =
            std::env::var("DD_OWNER").map_err(|_| Error::Internal("DD_OWNER required".into()))?;
        let owner_id: u64 = std::env::var("DD_OWNER_ID")
            .map_err(|_| Error::Internal("DD_OWNER_ID required (numeric GitHub id)".into()))?
            .parse()
            .map_err(|e| Error::Internal(format!("DD_OWNER_ID parse: {e}")))?;
        let owner_kind = PrincipalKind::parse(
            &std::env::var("DD_OWNER_KIND")
                .map_err(|_| Error::Internal("DD_OWNER_KIND required (user|org|repo)".into()))?,
        )?;
        let owner = Principal::from_parts(owner_name, owner_id, owner_kind)?;
        let vm_name = std::env::var("DD_VM_NAME").unwrap_or_else(|_| {
            std::fs::read_to_string("/etc/hostname")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "unknown".into())
        });
        let fleet_jwt_secret = std::env::var("DD_FLEET_JWT_SECRET").map_err(|_| {
            Error::Internal(
                "DD_FLEET_JWT_SECRET required (32-byte hex; generate once per fleet)".into(),
            )
        })?;
        if fleet_jwt_secret.len() < 32 {
            return Err(Error::Internal(
                "DD_FLEET_JWT_SECRET must be >= 32 bytes".into(),
            ));
        }
        Ok(Self {
            env_label,
            port,
            owner,
            vm_name,
            fleet_jwt_secret,
        })
    }
}

/// ITA (Intel Trust Authority) configuration. All fields required —
/// attestation is mandatory in both modes.
#[derive(Clone)]
pub struct Ita {
    pub base_url: String,
    pub api_key: String,
    pub jwks_url: String,
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
    pub gh_oauth: GhOauth,
    /// Break-glass admin email accepted by `/oauth/callback` even when
    /// the GitHub user isn't a member of `DD_OWNER` (org). Required so
    /// the operator has a way in if org membership checks break.
    pub admin_email: String,
    pub hostname: String,
    pub scrape_interval_secs: u64,
    pub ita: Ita,
}

impl Cp {
    pub fn from_env() -> Result<Self> {
        let common = Common::from_env()?;
        let cf = CfCreds::from_env()?;
        let gh_oauth = GhOauth::from_env()?;
        let admin_email = std::env::var("DD_ADMIN_EMAIL")
            .map_err(|_| Error::Internal("DD_ADMIN_EMAIL required (break-glass login)".into()))?
            .trim()
            .to_string();
        if admin_email.is_empty() || !admin_email.contains('@') {
            return Err(Error::Internal(
                "DD_ADMIN_EMAIL must be a valid email address".into(),
            ));
        }
        let hostname = std::env::var("DD_HOSTNAME")
            .map_err(|_| Error::Internal("DD_HOSTNAME required in CP mode".into()))?;
        let scrape_interval_secs = std::env::var("DD_SCRAPE_INTERVAL")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(30);
        Ok(Self {
            common,
            cf,
            gh_oauth,
            admin_email,
            hostname,
            scrape_interval_secs,
            ita: Ita::from_env()?,
        })
    }
}

/// Agent-mode config. Authenticates to the CP with ITA at /register;
/// verifies human cookies with the shared `DD_FLEET_JWT_SECRET`;
/// verifies CI requests with GitHub Actions OIDC.
pub struct Agent {
    pub common: Common,
    pub cp_url: String,
    pub ee_socket: String,
    pub ita: Ita,
}

impl Agent {
    pub fn from_env() -> Result<Self> {
        let common = Common::from_env()?;
        let cp_url = std::env::var("DD_CP_URL").map_err(|_| {
            Error::Internal("DD_CP_URL required (e.g. https://app.devopsdefender.com)".into())
        })?;
        let ee_socket = std::env::var("EE_SOCKET_PATH")
            .unwrap_or_else(|_| "/var/lib/easyenclave/agent.sock".into());
        Ok(Self {
            common,
            cp_url,
            ee_socket,
            ita: Ita::from_env()?,
        })
    }
}
