//! Deployment primitive.
//!
//! A Deployment is a CP-side controller object that owns a vanity DNS
//! name, picks a healthy host agent, and repoints the CNAME on
//! failover. Cloudflare DNS + EE on each agent are the source of
//! truth — this module is a thin controller layer over them.
//!
//! Recovery: there isn't one. The CP is stateless. Every read
//! (`GET /cp/deployments`) is a fresh `cf::list_records` call;
//! restarting the CP doesn't lose Deployments because they live in
//! DNS.

use std::collections::HashMap;
use std::time::Duration;

use reqwest::Client;
use serde::{Deserialize, Serialize};

use crate::cf::{self};
use crate::config::CfCreds;
use crate::error::{Error, Result};
use crate::workload::Workload;

pub const TXT_PREFIX: &str = "_dd.";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FailoverPolicy {
    #[serde(default = "FailoverPolicy::default_enabled")]
    pub enabled: bool,
    #[serde(default = "FailoverPolicy::default_miss_threshold")]
    pub miss_threshold: u32,
    #[serde(default = "FailoverPolicy::default_slow_threshold_ms")]
    pub slow_threshold_ms: u64,
    #[serde(default = "FailoverPolicy::default_cooldown_secs")]
    pub cooldown_secs: u64,
}

impl Default for FailoverPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            miss_threshold: 3,
            slow_threshold_ms: 5_000,
            cooldown_secs: 60,
        }
    }
}

impl FailoverPolicy {
    fn default_enabled() -> bool {
        true
    }
    fn default_miss_threshold() -> u32 {
        3
    }
    fn default_slow_threshold_ms() -> u64 {
        5_000
    }
    fn default_cooldown_secs() -> u64 {
        60
    }

    pub fn cooldown(&self) -> Duration {
        Duration::from_secs(self.cooldown_secs)
    }
}

/// Compact JSON written to the TXT record at `_dd.<vanity>`. Only
/// non-default values are stored; an absent record means "use
/// defaults."
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct FailoverPolicyTxt {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub m: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub s: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub c: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub off: Option<bool>,
}

impl FailoverPolicyTxt {
    pub fn from_policy(p: &FailoverPolicy) -> Self {
        let d = FailoverPolicy::default();
        Self {
            m: (p.miss_threshold != d.miss_threshold).then_some(p.miss_threshold),
            s: (p.slow_threshold_ms != d.slow_threshold_ms).then_some(p.slow_threshold_ms),
            c: (p.cooldown_secs != d.cooldown_secs).then_some(p.cooldown_secs),
            off: (!p.enabled).then_some(true),
        }
    }
    pub fn into_policy(self) -> FailoverPolicy {
        let d = FailoverPolicy::default();
        FailoverPolicy {
            enabled: !self.off.unwrap_or(false),
            miss_threshold: self.m.unwrap_or(d.miss_threshold),
            slow_threshold_ms: self.s.unwrap_or(d.slow_threshold_ms),
            cooldown_secs: self.c.unwrap_or(d.cooldown_secs),
        }
    }
    pub fn is_empty(&self) -> bool {
        self.m.is_none() && self.s.is_none() && self.c.is_none() && self.off.is_none()
    }
}

/// One Deployment, reconstructed from CF state on every read.
#[derive(Debug, Clone, Serialize)]
pub struct Deployment {
    pub name: String,
    pub vanity: String,
    pub host_hostname: String,
    pub failover: FailoverPolicy,
}

/// Request body for `POST /cp/deployments`.
#[derive(Debug, Deserialize)]
pub struct CreateDeployment {
    pub name: String,
    pub vanity: String,
    pub workload: Workload,
    #[serde(default)]
    pub failover: Option<FailoverPolicy>,
}

/// List all Deployments by reading CNAMEs in the fleet zone whose
/// targets match the agent-tunnel pattern.
pub async fn list(http: &Client, cf: &CfCreds) -> Result<Vec<Deployment>> {
    let records = cf::list_cnames(http, cf).await?;
    let txt_records = cf::list_txt(http, cf, TXT_PREFIX).await.unwrap_or_default();
    let txt_map: HashMap<String, FailoverPolicyTxt> = txt_records
        .into_iter()
        .filter_map(|(name, content)| {
            let stripped = name.strip_prefix(TXT_PREFIX)?.to_string();
            let parsed: FailoverPolicyTxt = serde_json::from_str(&content).unwrap_or_default();
            Some((stripped, parsed))
        })
        .collect();

    let mut deployments = Vec::new();
    for (name, target) in records {
        // Skip CP/agent system hostnames — only vanity claims pointing
        // at agent tunnels are Deployments.
        if !is_agent_tunnel_target(&target) {
            continue;
        }
        let host_hostname = strip_cf_argo_suffix(&target).to_string();
        let policy = txt_map
            .get(&name)
            .map(|t| t.clone_into_policy())
            .unwrap_or_default();
        deployments.push(Deployment {
            name: name.clone(),
            vanity: name,
            host_hostname,
            failover: policy,
        });
    }
    Ok(deployments)
}

impl FailoverPolicyTxt {
    fn clone_into_policy(&self) -> FailoverPolicy {
        let d = FailoverPolicy::default();
        FailoverPolicy {
            enabled: !self.off.unwrap_or(false),
            miss_threshold: self.m.unwrap_or(d.miss_threshold),
            slow_threshold_ms: self.s.unwrap_or(d.slow_threshold_ms),
            cooldown_secs: self.c.unwrap_or(d.cooldown_secs),
        }
    }
}

fn is_agent_tunnel_target(target: &str) -> bool {
    // Agent tunnels are CNAMEs to `<tunnel_id>.cfargotunnel.com`; the
    // CP's tunnel CNAMEs are the same shape but live under the well-
    // known fleet hostname (e.g. `app.devopsdefender.com`). A vanity
    // claim is any CNAME whose target ends in `.cfargotunnel.com`
    // *and* whose source name is not the well-known CP host.
    target.ends_with(".cfargotunnel.com")
}

fn strip_cf_argo_suffix(target: &str) -> &str {
    target.strip_suffix(".cfargotunnel.com").unwrap_or(target)
}

/// Probe a deployment's vanity URL. Returns Ok(latency) on a 2xx,
/// Err(()) otherwise. The agent's `/health` is a separate signal used
/// for *scheduling* (don't pick a sick agent as a failover target),
/// not for *triggering* failover.
pub async fn probe_vanity(http: &Client, vanity: &str) -> std::result::Result<Duration, ()> {
    let url = format!("https://{vanity}/health");
    let started = std::time::Instant::now();
    match http.get(&url).timeout(Duration::from_secs(10)).send().await {
        Ok(resp) if resp.status().is_success() => Ok(started.elapsed()),
        _ => Err(()),
    }
}

pub fn delete_deployment_vanity_records(_d: &Deployment) -> Result<()> {
    // Deletion happens at higher level — see cp.rs handler. This
    // function is a no-op placeholder retained so callers don't drift
    // on signature.
    Err(Error::Internal("call cf::delete_cname directly".into()))
}
