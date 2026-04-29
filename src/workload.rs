//! Typed workload schema.
//!
//! Every workload that runs on a dd-agent is one of four kinds:
//! `oracle`, `llm`, `shell`, or `bot`. The `kind` discriminates a
//! `KindConfig` enum with kind-specific fields. The full spec is what
//! the CP POSTs to the agent's `/deploy` endpoint and what the agent
//! forwards (minus dd-specific fields) to EE.
//!
//! This is the *closed* schema replacing the earlier open
//! `apps/*/workload.json` shape. Unknown fields are rejected at
//! deserialization (we use `deny_unknown_fields` on every variant).

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Oracle,
    Llm,
    Shell,
    Bot,
}

impl Kind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Kind::Oracle => "oracle",
            Kind::Llm => "llm",
            Kind::Shell => "shell",
            Kind::Bot => "bot",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GithubRelease {
    pub repo: String,
    pub asset: String,
    pub tag: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Expose {
    pub label: String,
    pub port: u16,
    /// `public` (anyone can hit the URL) or `owner` (cookie required).
    /// Defaults to `public` because that's the headline shape — most
    /// kind URLs are meant to be hit by users / on-chain consumers.
    #[serde(default = "default_auth")]
    pub auth: ExposeAuth,
}

fn default_auth() -> ExposeAuth {
    ExposeAuth::Public
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExposeAuth {
    Public,
    Owner,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LlmMode {
    /// Local inference (Ollama / vLLM). The container exposes its own
    /// inference server on `expose[].port`.
    Local,
    /// Reverse-proxy upstream LLM (Claude, ChatGPT). The agent runs an
    /// in-process forwarder that injects `key_env` from the workload
    /// env on each outbound request, never logging it.
    Proxy,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct HistoryConfig {
    /// base64 X25519 public key (32 raw bytes).
    pub client_pubkey: String,
    /// Optional auto-prune horizon. None = keep forever (segment
    /// rotation still applies, see history.rs).
    #[serde(default)]
    pub retention_secs: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
pub enum KindConfig {
    Oracle {
        /// Optional cron-like schedule (e.g. `every 60s`). The agent
        /// runs a tokio interval that pokes the workload's
        /// `/tick` endpoint at this cadence; absent → workload runs
        /// its own loop.
        #[serde(default)]
        schedule: Option<String>,
        /// Documentation-only: which env var holds the chain key.
        /// Surfaced in `/manifest` so verifiers know which env is the
        /// signer.
        #[serde(default)]
        signer_env: Option<String>,
        /// Enable signed public NDJSON log at `<vanity>/log`.
        #[serde(default)]
        public_log: bool,
    },
    Llm {
        mode: LlmMode,
        /// Required when `mode = Proxy`. The HTTPS URL the in-process
        /// forwarder targets.
        #[serde(default)]
        upstream: Option<String>,
        /// Required when `mode = Proxy`. Name of the env var carrying
        /// the upstream API key. Workload must expose the env, dd-agent
        /// reads it.
        #[serde(default)]
        key_env: Option<String>,
        /// Optional client-encrypted chat history. Absent = no
        /// persisted history.
        #[serde(default)]
        history: Option<HistoryConfig>,
    },
    Shell {
        /// Hard ceiling on a session's duration (seconds).
        #[serde(default = "default_session_ttl")]
        session_ttl_secs: u64,
        /// GitHub logins that may open a session. Empty = any user
        /// logged in to the fleet (org membership already enforced by
        /// the cookie).
        #[serde(default)]
        allowed_users: Vec<String>,
        #[serde(default)]
        history: Option<HistoryConfig>,
    },
    Bot {
        /// Optional cron-like schedule for the bot's wake loop.
        #[serde(default)]
        wake_schedule: Option<String>,
        /// Named persistent volume the agent passes to EE so the bot's
        /// session state (Signal/WhatsApp tokens, chat history)
        /// survives container restarts.
        #[serde(default)]
        state_volume: Option<String>,
        #[serde(default)]
        history: Option<HistoryConfig>,
    },
}

fn default_session_ttl() -> u64 {
    30 * 60
}

impl KindConfig {
    pub fn kind(&self) -> Kind {
        match self {
            KindConfig::Oracle { .. } => Kind::Oracle,
            KindConfig::Llm { .. } => Kind::Llm,
            KindConfig::Shell { .. } => Kind::Shell,
            KindConfig::Bot { .. } => Kind::Bot,
        }
    }
}

/// A workload spec. Either `image` (OCI image, pulled by EE) or
/// `github_release` (binary asset fetched by EE) must be set.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Workload {
    pub name: String,
    /// Kind discriminator (must match `kind_config.kind`). Carried
    /// alongside `kind_config` so callers can read the kind without
    /// matching on the inner enum.
    pub kind: Kind,
    #[serde(default)]
    pub image: Option<String>,
    #[serde(default)]
    pub github_release: Option<GithubRelease>,
    #[serde(default)]
    pub expose: Vec<Expose>,
    #[serde(default)]
    pub env: Vec<String>,
    #[serde(default)]
    pub post_deploy: Option<Vec<String>>,
    pub kind_config: KindConfig,
}

impl Workload {
    /// Validate the workload spec. Called from `POST /cp/deployments`
    /// before persisting and at agent boot for boot-workloads.
    pub fn validate(&self) -> Result<()> {
        if self.name.is_empty() {
            return Err(Error::BadRequest("workload.name is empty".into()));
        }
        if self.kind != self.kind_config.kind() {
            return Err(Error::BadRequest(format!(
                "workload.kind = {:?} but kind_config has {:?}",
                self.kind,
                self.kind_config.kind()
            )));
        }
        if self.image.is_none() && self.github_release.is_none() {
            return Err(Error::BadRequest(
                "workload requires `image` or `github_release`".into(),
            ));
        }
        // Each expose label must be unique (we map them to ingress
        // hostnames; collisions would silently overwrite each other).
        let mut seen = std::collections::HashSet::new();
        for e in &self.expose {
            if !seen.insert(e.label.clone()) {
                return Err(Error::BadRequest(format!(
                    "duplicate expose label: {}",
                    e.label
                )));
            }
        }
        Ok(())
    }

    /// The label of the primary user-facing port — the one a vanity
    /// CNAME should resolve to. Defaults to the first expose entry, or
    /// `"api"` if none is declared.
    pub fn primary_label(&self) -> &str {
        self.expose
            .first()
            .map(|e| e.label.as_str())
            .unwrap_or("api")
    }

    /// The port behind the primary expose, used by the agent when
    /// adding the deployment's vanity hostname to its tunnel ingress.
    pub fn primary_port(&self) -> u16 {
        self.expose.first().map(|e| e.port).unwrap_or(8080)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_oracle_minimal() {
        let s = r#"{
            "name": "myoracle",
            "kind": "oracle",
            "image": "ghcr.io/example/oracle:latest",
            "expose": [{"label": "api", "port": 8080}],
            "kind_config": {"kind": "oracle"}
        }"#;
        let w: Workload = serde_json::from_str(s).unwrap();
        assert_eq!(w.kind, Kind::Oracle);
        w.validate().unwrap();
    }

    #[test]
    fn parses_llm_proxy() {
        let s = r#"{
            "name": "claude-proxy",
            "kind": "llm",
            "image": "ghcr.io/example/llm-proxy:latest",
            "expose": [{"label": "api", "port": 8080, "auth": "owner"}],
            "kind_config": {
                "kind": "llm",
                "mode": "proxy",
                "upstream": "https://api.anthropic.com",
                "key_env": "ANTHROPIC_API_KEY"
            }
        }"#;
        let w: Workload = serde_json::from_str(s).unwrap();
        assert_eq!(w.kind, Kind::Llm);
        w.validate().unwrap();
    }

    #[test]
    fn parses_bot_with_history() {
        let s = r#"{
            "name": "openclaw",
            "kind": "bot",
            "image": "ghcr.io/example/openclaw:latest",
            "expose": [{"label": "api", "port": 8080}],
            "kind_config": {
                "kind": "bot",
                "wake_schedule": "every 60s",
                "state_volume": "openclaw-state",
                "history": {
                    "client_pubkey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
                }
            }
        }"#;
        let w: Workload = serde_json::from_str(s).unwrap();
        assert_eq!(w.kind, Kind::Bot);
        w.validate().unwrap();
    }

    #[test]
    fn rejects_unknown_field() {
        let s = r#"{
            "name": "x",
            "kind": "oracle",
            "image": "x",
            "kind_config": {"kind": "oracle"},
            "fishhook": true
        }"#;
        let r: std::result::Result<Workload, _> = serde_json::from_str(s);
        assert!(r.is_err());
    }

    #[test]
    fn rejects_kind_mismatch() {
        let s = r#"{
            "name": "x",
            "kind": "oracle",
            "image": "x",
            "kind_config": {"kind": "bot"}
        }"#;
        let w: Workload = serde_json::from_str(s).unwrap();
        assert!(w.validate().is_err());
    }

    #[test]
    fn rejects_missing_source() {
        let s = r#"{
            "name": "x",
            "kind": "oracle",
            "kind_config": {"kind": "oracle"}
        }"#;
        let w: Workload = serde_json::from_str(s).unwrap();
        assert!(w.validate().is_err());
    }
}
