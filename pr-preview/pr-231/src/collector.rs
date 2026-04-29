//! Background collector — DNS-driven Deployment monitor.
//!
//! WIP. The full failover loop (probe vanity URLs, pick a new host on
//! miss/slow, repoint CNAME, re-deploy) lands in a follow-up. This
//! skeleton just exposes the CF-driven enumeration entry points so the
//! collector can be plugged into `cp::run` later.

use crate::config::CfCreds;
use crate::deployment::{self, Deployment};
use crate::error::Result;

/// One reconciliation tick: list deployments, probe each vanity, decide
/// failover. v1 stub: list + probe only; failover is a follow-up.
pub async fn tick(http: &reqwest::Client, cf: &CfCreds) -> Result<Vec<TickReport>> {
    let deployments = deployment::list(http, cf).await?;
    let mut out = Vec::with_capacity(deployments.len());
    for d in deployments {
        let probe = deployment::probe_vanity(http, &d.vanity).await;
        out.push(TickReport {
            deployment: d,
            healthy: probe.is_ok(),
            latency_ms: probe.ok().map(|d| d.as_millis() as u64),
        });
    }
    Ok(out)
}

#[derive(Debug)]
pub struct TickReport {
    pub deployment: Deployment,
    pub healthy: bool,
    pub latency_ms: Option<u64>,
}
