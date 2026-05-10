//! Environment-derived configuration for both modes.

use crate::error::{Error, Result};
use crate::gh_oidc::{Principal, PrincipalKind};
use base64::Engine as _;

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
        //                   repository_owner_id == DD_OWNER_ID.
        //   kind=repo     → DD_OWNER is "<owner>/<repo>" (one '/'),
        //                   verifier matches repository == DD_OWNER
        //                   and repository_id == DD_OWNER_ID.
        //                   Dashboard browser auth is handled by
        //                   DD's GitHub App OAuth flow.
        //
        // DD_OWNER_ID defeats login-squat — a deleted/transferred
        // account whose login is later re-registered will produce
        // tokens with a different numeric id and be rejected.
        //
        // All three are required at boot. Existing agents from before
        // this change must be re-provisioned.
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
        Ok(Self {
            env_label,
            port,
            owner,
            vm_name,
        })
    }
}

/// ITA (Intel Trust Authority) configuration. Production uses Intel ITA.
/// Local PR previews may use a signed local token so they can test the
/// Mini boot/deploy path when the host's Intel PCCS collateral is absent.
#[derive(Clone)]
pub struct Ita {
    pub mode: ItaMode,
    /// URL for Intel's ITA mint endpoint, e.g. `https://api.trustauthority.intel.com`.
    pub base_url: String,
    /// API key for Intel mode; shared signing key for local mode.
    pub api_key: String,
    /// JWKS endpoint for verifier.
    pub jwks_url: String,
    /// Expected `iss` claim.
    pub issuer: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ItaMode {
    Intel,
    Local,
}

impl ItaMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Intel => "intel",
            Self::Local => "local",
        }
    }
}

impl Ita {
    pub fn from_env(env_label: &str) -> Result<Self> {
        let get = |k: &str| {
            std::env::var(k)
                .ok()
                .filter(|s| !s.is_empty())
                .ok_or_else(|| Error::Internal(format!("{k} required")))
        };
        let mode = match std::env::var("DD_ITA_MODE")
            .unwrap_or_else(|_| "intel".into())
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "" | "intel" => ItaMode::Intel,
            "local" => {
                if env_label == "production" || env_label == "staging" {
                    return Err(Error::Internal(
                        "DD_ITA_MODE=local is not allowed for production or staging".into(),
                    ));
                }
                ItaMode::Local
            }
            other => {
                return Err(Error::Internal(format!(
                    "DD_ITA_MODE must be intel or local, got {other}"
                )))
            }
        };
        Ok(Self {
            mode,
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
    pub auth: crate::auth::AuthConfig,
    pub hostname: String,
    pub scrape_interval_secs: u64,
    pub discovery_interval_secs: u64,
    pub scraper_shard_index: u64,
    pub scraper_shard_total: u64,
    pub ita: Ita,
    /// Where the Noise gateway persists its X25519 static private key
    /// (tmpfs). Fresh per-boot when missing.
    pub noise_key_path: std::path::PathBuf,
}

impl Cp {
    pub fn from_env() -> Result<Self> {
        let common = Common::from_env()?;
        let cf = CfCreds::from_env()?;
        let hostname = std::env::var("DD_HOSTNAME")
            .map_err(|_| Error::Internal("DD_HOSTNAME required in CP mode".into()))?;
        let auth = crate::auth::AuthConfig::from_env(&hostname, &cf.domain)?;
        let scrape_interval_secs = std::env::var("DD_SCRAPE_INTERVAL")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(5)
            .max(1);
        let discovery_interval_secs = std::env::var("DD_DISCOVERY_INTERVAL")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(30)
            .max(scrape_interval_secs);
        let scraper_shard_total = std::env::var("DD_SCRAPER_SHARD_TOTAL")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(1)
            .max(1);
        let scraper_shard_index = std::env::var("DD_SCRAPER_SHARD_INDEX")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        if scraper_shard_index >= scraper_shard_total {
            return Err(Error::Internal(format!(
                "DD_SCRAPER_SHARD_INDEX ({scraper_shard_index}) must be less than DD_SCRAPER_SHARD_TOTAL ({scraper_shard_total})"
            )));
        }
        let noise_key_path = std::env::var("DD_NOISE_KEY_PATH")
            .unwrap_or_else(|_| "/run/devopsdefender/noise.key".into())
            .into();
        let ita = Ita::from_env(&common.env_label)?;
        Ok(Self {
            common,
            cf,
            auth,
            hostname,
            scrape_interval_secs,
            discovery_interval_secs,
            scraper_shard_index,
            scraper_shard_total,
            ita,
            noise_key_path,
        })
    }
}

/// Agent-mode config. No PAT — the agent authenticates to the CP with
/// ITA attestation at /register and uses in-code auth for subsequent
/// machine-to-machine calls.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct OracleSpec {
    pub app_name: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub hostname_label: String,
    pub port: u16,
    #[serde(default = "default_oracle_path")]
    pub path: String,
    #[serde(default = "default_oracle_interval_secs")]
    pub interval_secs: u64,
}

fn default_oracle_path() -> String {
    "/oracle.json".into()
}

fn default_oracle_interval_secs() -> u64 {
    10
}

pub struct Agent {
    pub common: Common,
    pub cp_url: String,
    pub ee_socket: String,
    pub ita: Ita,
    pub auth: crate::auth::AuthConfig,
    /// Extra cloudflared ingress rules requested at register time,
    /// parsed from `DD_EXTRA_INGRESS` (a comma-separated list of
    /// `label:port` pairs, e.g. `api:8081,web:9000`). The boot-workload
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
    /// Source-of-truth file for paired-device pubkeys enforced by this
    /// agent's Noise gateway.
    pub devices_path: std::path::PathBuf,
    /// Read-only oracle endpoints baked into the boot workload set.
    /// `apps/_infra/local-agents.sh` extracts DD-level `oracle`
    /// metadata from workload JSON and injects it here as base64 JSON
    /// (`DD_ORACLES_B64`) so the agent can scrape local endpoints and
    /// report oracle health without giving the observer process control.
    pub oracles: Vec<OracleSpec>,
}

impl Agent {
    pub fn from_env() -> Result<Self> {
        let common = Common::from_env()?;
        let domain = std::env::var("DD_CF_DOMAIN")
            .map_err(|_| Error::Internal("DD_CF_DOMAIN required in agent mode".into()))?;
        let hostname = std::env::var("DD_HOSTNAME")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| common.vm_name.clone());
        let auth = crate::auth::AuthConfig::from_env(&hostname, &domain)?;
        let cp_url = std::env::var("DD_CP_URL").map_err(|_| {
            Error::Internal("DD_CP_URL required (e.g. https://app.devopsdefender.com)".into())
        })?;
        let ee_socket = std::env::var("EE_SOCKET_PATH")
            .unwrap_or_else(|_| "/var/lib/easyenclave/agent.sock".into());
        let extra_ingress = parse_extra_ingress()?;
        let confidential = parse_truthy("DD_CONFIDENTIAL");
        let devices_path = std::env::var("DD_AGENT_DEVICES_PATH")
            .unwrap_or_else(|_| "/var/lib/easyenclave/data/dd-agent/devices.json".into())
            .into();
        let oracles = parse_oracles()?;
        let ita = Ita::from_env(&common.env_label)?;
        Ok(Self {
            common,
            cp_url,
            ee_socket,
            ita,
            auth,
            extra_ingress,
            confidential,
            devices_path,
            oracles,
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
/// pairs — e.g. `"api:8081"` or `"api:8081,web:9000"`. Chosen over
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

fn parse_oracles() -> Result<Vec<OracleSpec>> {
    let raw = match std::env::var("DD_ORACLES_B64") {
        Ok(s) if !s.trim().is_empty() => s,
        _ => return Ok(Vec::new()),
    };
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(raw.trim())
        .map_err(|e| Error::Internal(format!("DD_ORACLES_B64 base64 decode: {e}")))?;
    let mut specs: Vec<OracleSpec> = serde_json::from_slice(&bytes)
        .map_err(|e| Error::Internal(format!("DD_ORACLES_B64 JSON parse: {e}")))?;
    for spec in &mut specs {
        spec.app_name = spec.app_name.trim().to_string();
        spec.title = spec.title.trim().to_string();
        spec.hostname_label = spec.hostname_label.trim().to_string();
        spec.path = spec.path.trim().to_string();
        if spec.app_name.is_empty() {
            return Err(Error::Internal(
                "DD_ORACLES_B64 oracle entry has empty app_name".into(),
            ));
        }
        if spec.title.is_empty() {
            spec.title = spec.app_name.clone();
        }
        if spec.port == 0 {
            return Err(Error::Internal(format!(
                "DD_ORACLES_B64 oracle {} has invalid port 0",
                spec.app_name
            )));
        }
        if spec.path.is_empty() {
            spec.path = default_oracle_path();
        }
        if spec.interval_secs == 0 {
            spec.interval_secs = default_oracle_interval_secs();
        }
    }
    Ok(specs)
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

    fn parse_oracles_env(json: &str) -> Result<Vec<OracleSpec>> {
        let _guard = ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let encoded = base64::engine::general_purpose::STANDARD.encode(json);
        unsafe {
            std::env::set_var("DD_ORACLES_B64", encoded);
        }
        let r = parse_oracles();
        unsafe {
            std::env::remove_var("DD_ORACLES_B64");
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
        assert_eq!(parse("api:8081").unwrap(), vec![("api".into(), 8081)]);
    }

    #[test]
    fn multiple_entries() {
        assert_eq!(
            parse("api:8081,web:9000").unwrap(),
            vec![("api".into(), 8081), ("web".into(), 9000)]
        );
    }

    #[test]
    fn tolerates_whitespace_and_trailing_commas() {
        assert_eq!(
            parse("api:8081, , web:9000,").unwrap(),
            vec![("api".into(), 8081), ("web".into(), 9000)]
        );
    }

    #[test]
    fn bad_port_errors() {
        assert!(parse("api:notaport").is_err());
        assert!(parse("api:99999").is_err()); // > u16
    }

    #[test]
    fn missing_colon_errors() {
        assert!(parse("api").is_err());
    }

    #[test]
    fn empty_label_errors() {
        assert!(parse(":8081").is_err());
    }

    #[test]
    fn oracle_metadata_decodes_from_base64_json() {
        let got = parse_oracles_env(
            r#"[{"app_name":"human-readonly","title":"Human Oracle","hostname_label":"oracle","port":8082,"path":"oracle.json","interval_secs":5}]"#,
        )
        .unwrap();
        assert_eq!(
            got,
            vec![OracleSpec {
                app_name: "human-readonly".into(),
                title: "Human Oracle".into(),
                hostname_label: "oracle".into(),
                port: 8082,
                path: "oracle.json".into(),
                interval_secs: 5,
            }]
        );
    }

    #[test]
    fn oracle_metadata_defaults_title_path_and_interval() {
        let got = parse_oracles_env(r#"[{"app_name":"oracle-readonly","port":8082}]"#).unwrap();
        assert_eq!(got[0].title, "oracle-readonly");
        assert_eq!(got[0].path, "/oracle.json");
        assert_eq!(got[0].interval_secs, 10);
    }
}
