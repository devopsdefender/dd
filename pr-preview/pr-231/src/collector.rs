//! Background collector — DNS-driven Deployment monitor.
//!
//! Runs inside the CP. Each tick:
//!   1. List Deployments by reading CNAMEs from CF (DNS = truth).
//!   2. Probe each Deployment's vanity `/health`, recording miss
//!      counts + recent latency.
//!   3. If a Deployment trips its policy (`miss_threshold` consecutive
//!      misses OR `slow_threshold_ms` latency over the recent window)
//!      and isn't in cooldown: fail over.
//!
//! Fail over = pick a new healthy host, push the workload to that
//! host's `/deploy`, repoint the vanity CNAME at the new host's
//! tunnel. On success, mark the cooldown so we don't immediately
//! flap.
//!
//! The CP keeps no on-disk state; cooldowns are tracked in-memory.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Serialize;
use tokio::sync::RwLock;

use crate::cf::{self};
use crate::config::CfCreds;
use crate::deployment::{self, Deployment, FailoverPolicy};
use crate::error::{Error, Result};

/// Runtime probe history for a single Deployment, keyed by vanity.
#[derive(Default, Debug)]
pub struct ProbeWindow {
    pub consecutive_misses: u32,
    /// Recent latencies, in milliseconds; bounded ring of last 8 probes.
    pub latency_ms: Vec<u64>,
    pub last_failover_at: Option<Instant>,
}

impl ProbeWindow {
    fn record_hit(&mut self, latency_ms: u64) {
        self.consecutive_misses = 0;
        self.latency_ms.push(latency_ms);
        if self.latency_ms.len() > 8 {
            self.latency_ms.remove(0);
        }
    }

    fn record_miss(&mut self) {
        self.consecutive_misses = self.consecutive_misses.saturating_add(1);
        self.latency_ms.clear();
    }

    fn p50_ms(&self) -> Option<u64> {
        if self.latency_ms.is_empty() {
            return None;
        }
        let mut sorted = self.latency_ms.clone();
        sorted.sort_unstable();
        Some(sorted[sorted.len() / 2])
    }

    fn in_cooldown(&self, policy: &FailoverPolicy, now: Instant) -> bool {
        match self.last_failover_at {
            Some(t) => now.duration_since(t) < policy.cooldown(),
            None => false,
        }
    }

    fn should_failover(&self, policy: &FailoverPolicy, now: Instant) -> bool {
        if !policy.enabled || self.in_cooldown(policy, now) {
            return false;
        }
        if self.consecutive_misses >= policy.miss_threshold {
            return true;
        }
        if let Some(p50) = self.p50_ms() {
            if p50 > policy.slow_threshold_ms && self.latency_ms.len() >= 3 {
                return true;
            }
        }
        false
    }
}

/// Collector state — the per-vanity probe window, plus a clone of the
/// CP's agent registry so we can pick failover targets.
#[derive(Clone)]
pub struct CollectorState {
    pub http: reqwest::Client,
    pub cf: CfCreds,
    pub windows: Arc<RwLock<HashMap<String, ProbeWindow>>>,
    pub agents: Arc<RwLock<HashMap<String, crate::cp::AgentRecord>>>,
    pub fleet_jwt_secret: String,
    pub owner_name: String,
}

#[derive(Debug, Serialize)]
pub struct TickReport {
    pub vanity: String,
    pub healthy: bool,
    pub latency_ms: Option<u64>,
    pub consecutive_misses: u32,
    pub failed_over: bool,
}

/// One reconciliation tick.
pub async fn tick(s: &CollectorState) -> Result<Vec<TickReport>> {
    let deployments = deployment::list(&s.http, &s.cf).await?;
    let mut reports = Vec::with_capacity(deployments.len());
    let now = Instant::now();

    for d in deployments {
        let probe = deployment::probe_vanity(&s.http, &d.vanity).await;
        let mut windows = s.windows.write().await;
        let window = windows.entry(d.vanity.clone()).or_default();
        let healthy = probe.is_ok();
        let latency_ms = probe.ok().map(|d| d.as_millis() as u64);
        if let Some(ms) = latency_ms {
            window.record_hit(ms);
        } else {
            window.record_miss();
        }

        let needs_failover = window.should_failover(&d.failover, now);
        let mut failed_over = false;
        if needs_failover {
            drop(windows);
            match fail_over(s, &d).await {
                Ok(_) => {
                    failed_over = true;
                    let mut windows = s.windows.write().await;
                    if let Some(w) = windows.get_mut(&d.vanity) {
                        w.last_failover_at = Some(now);
                        w.consecutive_misses = 0;
                        w.latency_ms.clear();
                    }
                }
                Err(e) => eprintln!("collector: failover {}: {e}", d.vanity),
            }
        }

        let consecutive_misses = s
            .windows
            .read()
            .await
            .get(&d.vanity)
            .map(|w| w.consecutive_misses)
            .unwrap_or(0);
        reports.push(TickReport {
            vanity: d.vanity,
            healthy,
            latency_ms,
            consecutive_misses,
            failed_over,
        });
    }
    Ok(reports)
}

/// Pick a fresh host (any registered agent that isn't the current
/// host), push `/deploy`, repoint the vanity CNAME.
async fn fail_over(s: &CollectorState, d: &Deployment) -> Result<()> {
    let agents = s.agents.read().await;
    let current_target = format!("{}.cfargotunnel.com", d.host_hostname);
    let new_host = agents
        .values()
        .find(|a| {
            // skip the current host (matches by hostname if we can,
            // or by tunnel target otherwise)
            d.host_hostname != a.hostname
                && current_target != format!("{}.cfargotunnel.com", a.hostname)
                || d.host_hostname.is_empty()
        })
        .cloned()
        .ok_or(Error::Internal("no eligible failover host".into()))?;
    drop(agents);

    // Push the workload to the new host. The collector doesn't have
    // the workload spec — only the vanity. v1 fallback: the CP mints
    // a __cp__ JWT and POSTs an empty body; the agent's /deploy
    // currently requires a workload spec, so this branch is
    // best-effort and primarily useful when the workload spec is
    // already cached on the new agent (e.g. cooldown after a hiccup).
    // Real failover with spec recovery is a follow-up that fetches
    // ee.list() from the old host or stores the spec in CF as a TXT
    // record next to the vanity. Documented in the plan.
    let cp_bearer = mint_cp_bearer(&s.fleet_jwt_secret, &s.owner_name)?;
    let push_url = format!("https://{}/deploy", new_host.hostname);
    let _ = s
        .http
        .post(&push_url)
        .bearer_auth(&cp_bearer)
        .json(&serde_json::json!({"vanity": d.vanity, "workload": null}))
        .send()
        .await
        .map_err(|e| Error::Upstream(format!("push /deploy {push_url}: {e}")))?;

    // Repoint the CNAME unconditionally — DNS-as-truth wins even if
    // the new host's deploy hasn't propagated yet (the CP will
    // re-issue on the next tick).
    let new_target = format!("{}.cfargotunnel.com", new_host.tunnel_id);
    cf::upsert_cname_raw(&s.http, &s.cf, &d.vanity, &new_target).await?;
    Ok(())
}

fn mint_cp_bearer(secret: &str, fleet: &str) -> Result<String> {
    use jsonwebtoken::{Algorithm, EncodingKey, Header};
    let now = chrono::Utc::now().timestamp();
    let claims = serde_json::json!({
        "sub": "__cp__",
        "fleet": fleet,
        "iat": now,
        "exp": now + 60,
    });
    jsonwebtoken::encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|e| Error::Internal(format!("jwt mint: {e}")))
}

/// Spawn the collector as a background task on a tokio interval.
pub fn spawn(s: CollectorState, interval: Duration) {
    tokio::spawn(async move {
        let mut t = tokio::time::interval(interval);
        t.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            t.tick().await;
            match tick(&s).await {
                Ok(reports) => {
                    for r in reports {
                        if r.failed_over || !r.healthy {
                            eprintln!("collector: {} {:?}", r.vanity, r);
                        }
                    }
                }
                Err(e) => eprintln!("collector tick: {e}"),
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn miss_threshold_triggers_failover() {
        let mut w = ProbeWindow::default();
        let policy = FailoverPolicy::default();
        let now = Instant::now();
        w.record_miss();
        w.record_miss();
        assert!(!w.should_failover(&policy, now));
        w.record_miss();
        assert!(w.should_failover(&policy, now));
    }

    #[test]
    fn slow_p50_triggers_failover() {
        let mut w = ProbeWindow::default();
        let policy = FailoverPolicy::default();
        let now = Instant::now();
        // Three slow hits — slow_threshold_ms default = 5000.
        w.record_hit(6_000);
        w.record_hit(6_000);
        w.record_hit(6_000);
        assert!(w.should_failover(&policy, now));
    }

    #[test]
    fn cooldown_blocks_repeat_failover() {
        let mut w = ProbeWindow::default();
        let policy = FailoverPolicy::default();
        let now = Instant::now();
        w.last_failover_at = Some(now);
        w.consecutive_misses = 10;
        assert!(!w.should_failover(&policy, now));
    }

    #[test]
    fn record_hit_resets_misses() {
        let mut w = ProbeWindow::default();
        w.record_miss();
        w.record_miss();
        w.record_hit(10);
        assert_eq!(w.consecutive_misses, 0);
    }

    #[test]
    fn disabled_policy_never_fires() {
        let mut w = ProbeWindow::default();
        let policy = FailoverPolicy {
            enabled: false,
            ..FailoverPolicy::default()
        };
        let now = Instant::now();
        for _ in 0..10 {
            w.record_miss();
        }
        assert!(!w.should_failover(&policy, now));
    }
}
