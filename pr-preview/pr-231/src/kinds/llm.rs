//! LLM kind.
//!
//! Two modes:
//!
//!   - `Local`: container exposes its own inference server on
//!     `expose[].port`. Nothing kind-specific in the agent — the
//!     workload looks like any other oracle/bot from the runtime
//!     perspective.
//!
//!   - `Proxy`: the agent runs an in-process forwarder that injects
//!     the upstream API key from `kind_config.key_env` (read from the
//!     workload's env) on each request. The key never leaves the
//!     enclave's RAM. Adds `X-DD-Attestation: <ITA-token>` so the
//!     upstream can verify, if it cares, that the proxy is in TDX.

use std::sync::Arc;

use crate::workload::{KindConfig, LlmMode, Workload};

#[derive(Clone)]
pub struct ProxyState {
    pub http: reqwest::Client,
    pub upstream: String,
    pub key: String,
    pub ita_token: Arc<tokio::sync::RwLock<Option<String>>>,
}

impl ProxyState {
    /// Construct from a workload + the agent's running ITA token.
    /// Returns None if the workload isn't `Llm { mode: Proxy, ... }`,
    /// the upstream is missing, or the keyed env is missing.
    pub fn from_workload(
        http: reqwest::Client,
        w: &Workload,
        ita_token: Arc<tokio::sync::RwLock<Option<String>>>,
    ) -> Option<Self> {
        let (mode, upstream, key_env) = match &w.kind_config {
            KindConfig::Llm {
                mode,
                upstream,
                key_env,
                ..
            } => (mode, upstream.as_deref()?, key_env.as_deref()?),
            _ => return None,
        };
        if !matches!(mode, LlmMode::Proxy) {
            return None;
        }
        let key = w.env.iter().find_map(|kv| {
            let (k, v) = kv.split_once('=')?;
            (k == key_env).then(|| v.to_string())
        })?;
        Some(Self {
            http,
            upstream: upstream.to_string(),
            key,
            ita_token,
        })
    }
}

/// Identify whether a workload should hook the `/llm/*` proxy.
pub fn workload_is_proxy(w: &Workload) -> bool {
    matches!(
        &w.kind_config,
        KindConfig::Llm {
            mode: LlmMode::Proxy,
            ..
        }
    )
}
