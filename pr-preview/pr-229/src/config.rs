//! Environment-derived configuration for both modes.

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

/// Configuration shared between modes.
pub struct Common {
    pub env_label: String,
    pub port: u16,
    pub owner: Principal,
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
        // DD_OWNER + DD_OWNER_ID + DD_OWNER_KIND together describe the
        // principal authorized to deploy to this agent.
        //
        //   kind=user|org → DD_OWNER is a GitHub login (no '/'). The
        //                   verifier matches tokens whose
        //                   repository_owner == DD_OWNER and
        //                   repository_owner_id == DD_OWNER_ID. The
        //                   two kinds differ only at CF Access:
        //                   kind=org maps to a github-organization
        //                   include rule; kind=user falls back to
        //                   admin_email-only for the dashboard.
        //   kind=repo     → DD_OWNER is "<owner>/<repo>" (one '/'),
        //                   verifier matches repository == DD_OWNER
        //                   and repository_id == DD_OWNER_ID.
        //                   Dashboard CF Access falls back to
        //                   admin_email-only.
        //
        // DD_OWNER_ID defeats login-squat — a deleted/transferred
        // account whose login is later re-registered will produce
        // tokens with a different numeric id and be rejected.
        //
        // All three are required at boot. Existing agents from before
        // this change must be re-provisioned.
        let owner_name = std::env::var("DD_OWNER")
            .map_err(|_| Error::Internal("DD_OWNER required".into()))?;
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
    /// Source-of-truth file for the device registry (JSON). Survives
    /// CP restart; mutations fsync through to disk.
    pub devices_path: std::path::PathBuf,
    /// Where the Noise gateway persists its X25519 static private key
    /// (tmpfs). Fresh per-boot when missing.
    pub noise_key_path: std::path::PathBuf,
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
        // `/tmp/` (tmpfs) is the only universally-writable path in the
        // EE workload sandbox — the root FS is RO, and `/var/lib/` +
        // `/data/` are both unavailable on the CP VM (no mount-data
        // in the CP boot set; root FS read-only for workloads).
        // Ephemeral across CP restarts is OK: the zero-downtime
        // boot hydrates devices from the predecessor CP via
        // `/api/v1/admin/export` before flipping DNS, so the on-disk
        // copy is a cache, not source of truth.
        let devices_path = std::env::var("DD_CP_DEVICES_PATH")
            .unwrap_or_else(|_| "/tmp/devopsdefender/devices.json".into())
            .into();
        let noise_key_path = std::env::var("DD_NOISE_KEY_PATH")
            .unwrap_or_else(|_| "/run/devopsdefender/noise.key".into())
            .into();
        Ok(Self {
            common,
            cf,
            access,
            hostname,
            scrape_interval_secs,
            ita: Ita::from_env()?,
            devices_path,
            noise_key_path,
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
    /// Extra cloudflared ingress rules requested at register time,
    /// parsed from `DD_EXTRA_INGRESS` (a comma-separated list of
    /// `label:port` pairs, e.g. `gpu:8081,web:9000`). The boot-workload
    /// builder (`apps/_infra/local-agents.sh`) collects these from
    /// `expose` hints on individual workload specs. Empty is fine —
    /// the agent just gets the default dashboard rule.
    pub extra_ingress: Vec<(String, u16)>,
    /// Confidential-mode flag from `DD_CONFIDENTIAL`. When true, the
    /// agent omits `/deploy`, `/exec`, and `/owner` from its router —
    /// no one (not tenant, not ops) can mutate the running workload
    /// post-boot. `/logs` + `/health` + attestation stay open. Used by
    /// Sats for Compute's "confidential mode" product variant for
    /// oracle / bot-oracle workloads where the operator proves to
    /// third parties that the code is sealed. Backward-compatible:
    /// unset = default (mutation endpoints enabled).
    pub confidential: bool,
}

impl Agent {
    pub fn from_env() -> Result<Self> {
        let common = Common::from_env()?;
        let cp_url = std::env::var("DD_CP_URL").map_err(|_| {
            Error::Internal("DD_CP_URL required (e.g. https://app.devopsdefender.com)".into())
        })?;
        let ee_socket = std::env::var("EE_SOCKET_PATH")
            .unwrap_or_else(|_| "/var/lib/easyenclave/agent.sock".into());
        let extra_ingress = parse_extra_ingress()?;
        let confidential = parse_truthy("DD_CONFIDENTIAL");
        Ok(Self {
            common,
            cp_url,
            ee_socket,
            ita: Ita::from_env()?,
            extra_ingress,
            confidential,
        })
    }
}

/// Best-effort bool parser for env flags. Treats any of
/// `1 / true / yes / on` (case-insensitive) as true; everything else
/// (including empty and absent) as false.
fn parse_truthy(key: &str) -> bool {
    std::env::var(key)
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

/// Parse `DD_EXTRA_INGRESS` as a comma-separated list of `label:port`
/// pairs — e.g. `"gpu:8081"` or `"gpu:8081,web:9000"`. Chosen over
/// JSON to sidestep `"`-escaping when the value is substituted into
/// the dd-agent workload template's `"DD_EXTRA_INGRESS=${…}"` env
/// entry (embedded quotes would close the outer JSON string early).
/// Empty / unset → empty Vec.
fn parse_extra_ingress() -> Result<Vec<(String, u16)>> {
    let raw = match std::env::var("DD_EXTRA_INGRESS") {
        Ok(s) if !s.trim().is_empty() => s,
        _ => return Ok(Vec::new()),
    };
    let mut out = Vec::new();
    for entry in raw.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let (label, port_s) = entry.split_once(':').ok_or_else(|| {
            Error::Internal(format!(
                "DD_EXTRA_INGRESS entry {entry:?}: expected label:port"
            ))
        })?;
        let port: u16 = port_s.parse().map_err(|e| {
            Error::Internal(format!(
                "DD_EXTRA_INGRESS entry {entry:?}: port must be u16 ({e})"
            ))
        })?;
        if label.is_empty() {
            return Err(Error::Internal(format!(
                "DD_EXTRA_INGRESS entry {entry:?}: empty label"
            )));
        }
        out.push((label.to_string(), port));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    fn parse(s: &str) -> Result<Vec<(String, u16)>> {
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
        assert!(parse("").unwrap().is_empty());
        assert!(parse("   ").unwrap().is_empty());
    }

    #[test]
    fn single_entry() {
        assert_eq!(parse("gpu:8081").unwrap(), vec![("gpu".into(), 8081)]);
    }

    #[test]
    fn multiple_entries() {
        assert_eq!(
            parse("gpu:8081,web:9000").unwrap(),
            vec![("gpu".into(), 8081), ("web".into(), 9000)]
        );
    }

    #[test]
    fn tolerates_whitespace_and_trailing_commas() {
        assert_eq!(
            parse("gpu:8081, , web:9000,").unwrap(),
            vec![("gpu".into(), 8081), ("web".into(), 9000)]
        );
    }

    #[test]
    fn bad_port_errors() {
        assert!(parse("gpu:notaport").is_err());
        assert!(parse("gpu:99999").is_err()); // > u16
    }

    #[test]
    fn missing_colon_errors() {
        assert!(parse("gpu").is_err());
    }

    #[test]
    fn empty_label_errors() {
        assert!(parse(":8081").is_err());
    }
}
