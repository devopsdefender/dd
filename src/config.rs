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
        // DD_OWNER must be a GitHub **organization** login — the CF
        // Access policy uses the `github-organization` include rule,
        // which is member-of-org only. A personal-user login here
        // would produce a policy that silently matches nobody.
        let owner = std::env::var("DD_OWNER")
            .map_err(|_| Error::Internal("DD_OWNER required (GitHub organization login)".into()))?;
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

/// CF Access configuration — one email that's always allowed in
/// alongside GitHub org members. Required so the operator has a
/// break-glass login path if org membership checks break.
#[derive(Clone)]
pub struct CfAccess {
    pub admin_email: String,
}

impl CfAccess {
    pub fn from_env() -> Result<Self> {
        let admin_email = std::env::var("DD_ACCESS_ADMIN_EMAIL")
            .map_err(|_| {
                Error::Internal(
                    "DD_ACCESS_ADMIN_EMAIL required (break-glass human login for CF Access)".into(),
                )
            })?
            .trim()
            .to_string();
        if admin_email.is_empty() || !admin_email.contains('@') {
            return Err(Error::Internal(
                "DD_ACCESS_ADMIN_EMAIL must be a valid email address".into(),
            ));
        }
        Ok(Self { admin_email })
    }
}

/// Control-plane-mode config.
pub struct Cp {
    pub common: Common,
    pub cf: CfCreds,
    pub access: CfAccess,
    pub hostname: String,
    pub scrape_interval_secs: u64,
    pub ita: Ita,
}

impl Cp {
    pub fn from_env() -> Result<Self> {
        let common = Common::from_env()?;
        let cf = CfCreds::from_env()?;
        let access = CfAccess::from_env()?;
        let hostname = std::env::var("DD_HOSTNAME")
            .map_err(|_| Error::Internal("DD_HOSTNAME required in CP mode".into()))?;
        let scrape_interval_secs = std::env::var("DD_SCRAPE_INTERVAL")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(30);
        Ok(Self {
            common,
            cf,
            access,
            hostname,
            scrape_interval_secs,
            ita: Ita::from_env()?,
        })
    }
}

/// Agent-mode config. No PAT — the agent authenticates to the CP with
/// ITA attestation at /register and the CF Access service token
/// (received in the register response) on subsequent calls.
pub struct Agent {
    pub common: Common,
    pub cp_url: String,
    pub ee_socket: String,
    pub ita: Ita,
    /// Auto per-agent ingress rules from `DD_EXTRA_INGRESS` —
    /// entries like `label:port`. Each becomes the URL
    /// `<agent-base>-<label>.<domain>` after register.
    pub extra_ingress: Vec<(String, u16)>,
    /// Vanity claim ingress rules from `DD_EXTRA_INGRESS` — entries
    /// like `@name:port`. Each is a zone-apex claim the agent tries
    /// to lock at register time; the first agent to ask wins, others
    /// get 409 from the CP. Useful for stable short URLs
    /// (`nvidia-smi.<domain>`) independent of any specific agent's
    /// UUID.
    pub claims: Vec<(String, u16)>,
}

impl Agent {
    pub fn from_env() -> Result<Self> {
        let common = Common::from_env()?;
        let cp_url = std::env::var("DD_CP_URL").map_err(|_| {
            Error::Internal("DD_CP_URL required (e.g. https://app.devopsdefender.com)".into())
        })?;
        let ee_socket = std::env::var("EE_SOCKET_PATH")
            .unwrap_or_else(|_| "/var/lib/easyenclave/agent.sock".into());
        let (extra_ingress, claims) = parse_extra_ingress()?;
        Ok(Self {
            common,
            cp_url,
            ee_socket,
            ita: Ita::from_env()?,
            extra_ingress,
            claims,
        })
    }
}

/// Parse `DD_EXTRA_INGRESS` as a comma-separated list of entries,
/// each either `label:port` (auto per-agent ingress) or
/// `@claim:port` (vanity zone-apex claim). Returns a (extras,
/// claims) pair. Chosen over JSON to sidestep `"`-escaping when
/// the value is substituted into the dd-agent workload template's
/// `"DD_EXTRA_INGRESS=${…}"` env entry.
///
/// Empty / unset → two empty Vecs.
#[allow(clippy::type_complexity)]
fn parse_extra_ingress() -> Result<(Vec<(String, u16)>, Vec<(String, u16)>)> {
    let raw = match std::env::var("DD_EXTRA_INGRESS") {
        Ok(s) if !s.trim().is_empty() => s,
        _ => return Ok((Vec::new(), Vec::new())),
    };
    let mut extras = Vec::new();
    let mut claims = Vec::new();
    for entry in raw.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let (is_claim, rest) = match entry.strip_prefix('@') {
            Some(r) => (true, r),
            None => (false, entry),
        };
        let (name, port_s) = rest.split_once(':').ok_or_else(|| {
            Error::Internal(format!(
                "DD_EXTRA_INGRESS entry {entry:?}: expected label:port or @claim:port"
            ))
        })?;
        let port: u16 = port_s.parse().map_err(|e| {
            Error::Internal(format!(
                "DD_EXTRA_INGRESS entry {entry:?}: port must be u16 ({e})"
            ))
        })?;
        if name.is_empty() {
            return Err(Error::Internal(format!(
                "DD_EXTRA_INGRESS entry {entry:?}: empty name"
            )));
        }
        if is_claim {
            claims.push((name.to_string(), port));
        } else {
            extras.push((name.to_string(), port));
        }
    }
    Ok((extras, claims))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    #[allow(clippy::type_complexity)]
    fn parse(s: &str) -> Result<(Vec<(String, u16)>, Vec<(String, u16)>)> {
        let _guard = ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        unsafe {
            std::env::set_var("DD_EXTRA_INGRESS", s);
        }
        let r = parse_extra_ingress();
        unsafe {
            std::env::remove_var("DD_EXTRA_INGRESS");
        }
        r
    }

    #[test]
    fn empty_parses_to_empty_vec() {
        let (e, c) = parse("").unwrap();
        assert!(e.is_empty() && c.is_empty());
        let (e, c) = parse("   ").unwrap();
        assert!(e.is_empty() && c.is_empty());
    }

    #[test]
    fn single_auto_entry() {
        let (e, c) = parse("gpu:8081").unwrap();
        assert_eq!(e, vec![("gpu".into(), 8081)]);
        assert!(c.is_empty());
    }

    #[test]
    fn single_claim_entry() {
        let (e, c) = parse("@nvidia-smi:8081").unwrap();
        assert!(e.is_empty());
        assert_eq!(c, vec![("nvidia-smi".into(), 8081)]);
    }

    #[test]
    fn mixed_entries() {
        let (e, c) = parse("gpu:8081,@nvidia-smi:8081,web:9000").unwrap();
        assert_eq!(e, vec![("gpu".into(), 8081), ("web".into(), 9000)]);
        assert_eq!(c, vec![("nvidia-smi".into(), 8081)]);
    }

    #[test]
    fn tolerates_whitespace_and_trailing_commas() {
        let (e, c) = parse("gpu:8081, , web:9000,").unwrap();
        assert_eq!(e, vec![("gpu".into(), 8081), ("web".into(), 9000)]);
        assert!(c.is_empty());
    }

    #[test]
    fn bad_port_errors() {
        assert!(parse("gpu:notaport").is_err());
        assert!(parse("gpu:99999").is_err()); // > u16
    }

    #[test]
    fn missing_colon_errors() {
        assert!(parse("gpu").is_err());
        assert!(parse("@claim").is_err());
    }

    #[test]
    fn empty_name_errors() {
        assert!(parse(":8081").is_err());
        assert!(parse("@:8081").is_err());
    }
}
