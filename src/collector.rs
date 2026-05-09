//! Background collector — discovers agents, scrapes `/health`, GC's dead tunnels.
//!
//! Every agent entry in the store carries freshly-verified ITA claims. The
//! collector scrapes `/health`, extracts the `ita_token` field, and runs
//! it through the CP's verifier; agents whose tokens are missing, expired,
//! or mis-signed don't enter the store. Known registered agents are scraped
//! frequently from the CP store; Cloudflare tunnel discovery runs on a slower
//! interval for new/unknown tunnels and orphan cleanup. One discovery pass:
//!
//!   1. List CF tunnels whose name starts with `dd-{env}-agent-`.
//!   2. Scrape `https://dd-{env}-api-{uuid}.{domain}/health` in parallel.
//!   3. Verify the `ita_token` field from each /health body.
//!   4. Insert on success, including tunnel id and reported ingress.
//!   5. Mark dead / GC tunnel on repeated scrape failures.
//!   6. Refresh the `control-plane` entry (its claims come from CP startup).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, Notify};
use tokio::time::MissedTickBehavior;

use crate::cf;
use crate::config::CfCreds;
use crate::ee::Ee;
use crate::ita;
use crate::taint::IntegrityState;
use crate::units::{AgentMode, ManagedUnit};

// Keep this longer than the relaunch-agent CI registration window
// (10 minutes). Freshly-created Cloudflare hostnames can fail early
// scrape attempts while DNS/edge state is still converging; deleting
// the tunnel inside that window makes a slow-but-healthy agent
// unrecoverable before CI can observe it.
const DEAD_THRESHOLD_SECS: i64 = 900;
const UNKNOWN_TUNNEL_SCRAPE_DELAY_SECS: i64 = 120;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Agent {
    pub agent_id: String,
    pub hostname: String,
    pub vm_name: String,
    pub attestation_type: String,
    pub status: String,
    pub last_seen: DateTime<Utc>,
    pub agent_mode: AgentMode,
    pub integrity_state: IntegrityState,
    pub deployment_count: usize,
    pub deployment_names: Vec<String>,
    pub unit_count: usize,
    pub units: Vec<ManagedUnit>,
    pub cpu_percent: u64,
    pub memory_used_mb: u64,
    pub memory_total_mb: u64,
    #[serde(default)]
    pub nets: Vec<crate::metrics::NetStats>,
    #[serde(default)]
    pub disks: Vec<crate::metrics::DiskStats>,
    /// Intel-verified ITA claims. Required — agents without a valid
    /// token don't enter the store.
    pub ita: ita::Claims,
    /// CF tunnel ID (not name) — needed to re-PUT ingress at runtime
    /// when a POSTed workload declares `expose`. Empty for the
    /// `control-plane` pseudo-entry which doesn't take runtime slop.
    #[serde(default)]
    pub tunnel_id: String,
    /// Currently-active per-workload ingress rules for this agent's
    /// tunnel. Seeded at /register from the boot-workload `expose`
    /// set; appended on each runtime /ingress/replace call. If the
    /// agent relaunches, the CP re-seeds from the new register's
    /// `extra_ingress` field. If only the CP restarts, the collector
    /// recovers this list from the agent's `/health` response.
    #[serde(default)]
    pub extras: Vec<(String, u16)>,
    /// Read-only oracle scrape status reported by dd-agent health.
    #[serde(default)]
    pub oracles: Vec<crate::oracle::OracleStatus>,
}

pub type Store = Arc<Mutex<HashMap<String, Agent>>>;

#[derive(Debug, Clone)]
struct Orphan {
    name: String,
    host: String,
    extras: Vec<(String, u16)>,
}

#[derive(Debug, Clone)]
struct ScrapeTarget {
    name: String,
    tunnel_id: String,
    host: String,
    created_at: Option<DateTime<Utc>>,
    known: bool,
}

#[allow(clippy::too_many_arguments)]
pub async fn run(
    store: Store,
    cf: CfCreds,
    env_label: String,
    cp_hostname: String,
    ee: Arc<Ee>,
    verifier: Arc<ita::Verifier>,
    wake: Arc<Notify>,
    scrape_interval: Duration,
    discovery_interval: Duration,
    shard_index: u64,
    shard_total: u64,
) -> ! {
    let prefix = cf::agent_prefix(&env_label);
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());

    eprintln!(
        "cp: collector starting (prefix={prefix}*, scrape={}s, discovery={}s, shard={}/{})",
        scrape_interval.as_secs(),
        discovery_interval.as_secs(),
        shard_index + 1,
        shard_total
    );

    let mut ticker = tokio::time::interval(scrape_interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut next_discovery = tokio::time::Instant::now();
    loop {
        tokio::select! {
            _ = ticker.tick() => {}
            _ = wake.notified() => {}
        }
        let now = tokio::time::Instant::now();
        let discover = now >= next_discovery;
        if discover {
            next_discovery = now + discovery_interval;
        }
        tick(
            &store,
            &http,
            &cf,
            &prefix,
            &ee,
            &verifier,
            &env_label,
            &cp_hostname,
            discover,
            shard_index,
            shard_total,
        )
        .await;
    }
}

#[allow(clippy::too_many_arguments)]
async fn tick(
    store: &Store,
    http: &reqwest::Client,
    cf: &CfCreds,
    prefix: &str,
    ee: &Arc<Ee>,
    verifier: &Arc<ita::Verifier>,
    env_label: &str,
    cp_hostname: &str,
    discover: bool,
    shard_index: u64,
    shard_total: u64,
) {
    let mut targets = if discover {
        discover_targets(store, http, cf, prefix).await
    } else {
        known_targets(store).await
    };
    targets.retain(|t| should_scrape_key(&t.name, shard_index, shard_total));

    let now = Utc::now();
    let scrapes = targets.iter().map(|target| {
        let http = http.clone();
        let target = target.clone();
        async move {
            if !target.known && unknown_tunnel_should_wait_for_registration(target.created_at, now)
            {
                return (
                    target.name,
                    target.tunnel_id,
                    target.host,
                    target.created_at,
                    None,
                    Some("fresh unknown tunnel pending registration".into()),
                );
            }
            let health_host = cf::agent_api_hostname(&target.host);
            let r = http
                .get(format!("https://{health_host}/health"))
                .send()
                .await;
            match r {
                Ok(resp) if resp.status().is_success() => {
                    let body = resp.json::<serde_json::Value>().await.ok();
                    (
                        target.name,
                        target.tunnel_id,
                        target.host,
                        target.created_at,
                        body,
                        None,
                    )
                }
                Ok(resp) => (
                    target.name,
                    target.tunnel_id,
                    target.host,
                    target.created_at,
                    None,
                    Some(format!("status {}", resp.status())),
                ),
                Err(e) => (
                    target.name,
                    target.tunnel_id,
                    target.host,
                    target.created_at,
                    None,
                    Some(format!("{e:?}")),
                ),
            }
        }
    });
    let results = futures_util::future::join_all(scrapes).await;

    let mut orphans: Vec<Orphan> = Vec::new();
    let mut verified = 0usize;

    for (name, tunnel_id, host, created_at, body, err) in &results {
        let Some(h) = body else {
            mark_stale_or_orphan(store, host, name, *created_at, err, now, &mut orphans).await;
            continue;
        };
        let Some(token) = h["ita_token"].as_str() else {
            eprintln!("cp: collector: {name} /health lacks ita_token — skipping");
            continue;
        };
        let claims = match verifier.verify(token).await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("cp: collector: {name} ITA verify failed: {e}");
                continue;
            }
        };
        // Store key is the tunnel name (authoritative on the CP side),
        // NOT the agent's self-reported agent_id.
        let mut s = store.lock().await;
        let extras = parse_extra_ingress(h)
            .unwrap_or_else(|| s.get(name).map(|a| a.extras.clone()).unwrap_or_default());
        s.insert(
            name.clone(),
            Agent {
                agent_id: name.clone(),
                hostname: host.clone(),
                vm_name: h["vm_name"].as_str().unwrap_or("unknown").to_string(),
                attestation_type: h["attestation_type"]
                    .as_str()
                    .unwrap_or("unknown")
                    .to_string(),
                status: "healthy".into(),
                last_seen: now,
                agent_mode: serde_json::from_value(h["agent_mode"].clone())
                    .unwrap_or(AgentMode::ReadWrite),
                integrity_state: serde_json::from_value(h["integrity_state"].clone())
                    .unwrap_or(IntegrityState::Controlled),
                deployment_count: h["deployment_count"].as_u64().unwrap_or(0) as usize,
                deployment_names: h["deployments"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_default(),
                unit_count: h["unit_count"].as_u64().unwrap_or(0) as usize,
                units: serde_json::from_value(h["units"].clone()).unwrap_or_default(),
                cpu_percent: h["cpu_percent"].as_u64().unwrap_or(0),
                memory_used_mb: h["memory_used_mb"].as_u64().unwrap_or(0),
                memory_total_mb: h["memory_total_mb"].as_u64().unwrap_or(0),
                nets: serde_json::from_value(h["nets"].clone()).unwrap_or_default(),
                disks: serde_json::from_value(h["disks"].clone()).unwrap_or_default(),
                ita: claims,
                tunnel_id: tunnel_id.clone(),
                extras,
                oracles: serde_json::from_value(h["oracles"].clone()).unwrap_or_default(),
            },
        );
        drop(s);
        verified += 1;
    }

    // Collect + delete dead entries from the store.
    let dead: Vec<String> = {
        let s = store.lock().await;
        s.iter()
            .filter(|(_, a)| a.status == "dead")
            .map(|(k, _)| k.clone())
            .collect()
    };
    for k in &dead {
        store.lock().await.remove(k);
    }

    if !orphans.is_empty() {
        for orphan in &orphans {
            eprintln!("cp: GC dead tunnel {}", orphan.name);
            cf::delete_by_name(http, cf, &orphan.name).await;
            let _ = cf::delete_cname(http, cf, &orphan.host).await;
            let _ = cf::delete_cname(http, cf, &cf::agent_api_hostname(&orphan.host)).await;
            for (label, _) in &orphan.extras {
                let _ = cf::delete_cname(http, cf, &cf::extra_hostname(&orphan.host, label)).await;
            }
            // Sweep legacy Cloudflare Access apps for this agent so
            // stale exact host/path apps cannot intercept future
            // DNS+tunnel routes.
            cf::delete_access_apps_for_agent(http, cf, &orphan.host).await;
        }
    }

    // Refresh the CP's own entry. Its ITA claims were seeded at CP
    // startup and are preserved here across ticks; everything else
    // (status, workloads, attestation) gets refreshed from EE.
    let (deployments, attestation) = match ee.list().await {
        Ok(deps) => {
            let names: Vec<String> = deps["deployments"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v["app_name"].as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            let att = ee
                .health()
                .await
                .ok()
                .and_then(|h| h["attestation_type"].as_str().map(String::from))
                .unwrap_or_else(|| "tdx".into());
            (names, att)
        }
        Err(_) => (vec![], "tdx".into()),
    };
    let count = deployments.len();
    let mut store_lock = store.lock().await;
    if let Some(cp) = store_lock.get_mut("control-plane") {
        cp.hostname = cp_hostname.to_string();
        cp.vm_name = format!("dd-{env_label}-cp");
        cp.attestation_type = attestation;
        cp.status = "healthy".into();
        cp.last_seen = now;
        cp.deployment_count = count;
        cp.deployment_names = deployments;
    }
    drop(store_lock);

    eprintln!(
        "cp: scraped {} {} ({verified} verified, {} orphans GC'd)",
        results.len(),
        if discover {
            "discovered targets"
        } else {
            "known agents"
        },
        orphans.len()
    );
}

async fn discover_targets(
    store: &Store,
    http: &reqwest::Client,
    cf: &CfCreds,
    prefix: &str,
) -> Vec<ScrapeTarget> {
    let known_hosts: std::collections::HashSet<String> = {
        let s = store.lock().await;
        s.values().map(|a| a.hostname.clone()).collect()
    };
    cf::list(http, cf)
        .await
        .unwrap_or_default()
        .into_iter()
        .filter_map(|t| {
            let name = t["name"].as_str()?;
            let id = t["id"].as_str()?;
            if !name.starts_with(prefix) {
                return None;
            }
            let hostname = format!("{name}.{}", cf.domain);
            let created_at = t["created_at"]
                .as_str()
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .map(|dt| dt.with_timezone(&Utc));
            Some(ScrapeTarget {
                name: name.to_string(),
                tunnel_id: id.to_string(),
                known: known_hosts.contains(&hostname),
                host: hostname,
                created_at,
            })
        })
        .collect()
}

async fn known_targets(store: &Store) -> Vec<ScrapeTarget> {
    let s = store.lock().await;
    s.iter()
        .filter(|(name, a)| name.as_str() != "control-plane" && !a.tunnel_id.is_empty())
        .map(|(name, a)| ScrapeTarget {
            name: name.clone(),
            tunnel_id: a.tunnel_id.clone(),
            host: a.hostname.clone(),
            created_at: None,
            known: true,
        })
        .collect()
}

fn parse_extra_ingress(h: &serde_json::Value) -> Option<Vec<(String, u16)>> {
    h.get("extra_ingress")?.as_array().map(|items| {
        items
            .iter()
            .filter_map(|item| {
                let label = item.get("hostname_label")?.as_str()?;
                let port = item.get("port")?.as_u64()?;
                if label.is_empty() || port == 0 || port > u16::MAX as u64 {
                    return None;
                }
                Some((label.to_string(), port as u16))
            })
            .collect()
    })
}

async fn mark_stale_or_orphan(
    store: &Store,
    host: &str,
    name: &str,
    created_at: Option<DateTime<Utc>>,
    err: &Option<String>,
    now: DateTime<Utc>,
    orphans: &mut Vec<Orphan>,
) {
    let mut s = store.lock().await;
    if let Some(a) = s.values_mut().find(|a| a.hostname == *host) {
        let age = now.signed_duration_since(a.last_seen).num_seconds();
        if age > DEAD_THRESHOLD_SECS && scrape_failure_is_dead_signal(err) {
            let extras = a.extras.clone();
            a.status = "dead".into();
            orphans.push(Orphan {
                name: name.to_string(),
                host: host.to_string(),
                extras,
            });
        } else {
            a.status = "stale".into();
            eprintln!(
                "cp: collector: {name} scrape failed: {}",
                err.as_deref().unwrap_or("unknown error")
            );
        }
    } else if unknown_tunnel_is_gc_candidate(created_at, err, now) {
        eprintln!(
            "cp: collector: {name} unknown stale tunnel failed scrape; GC'ing: {}",
            err.as_deref().unwrap_or("unknown error")
        );
        orphans.push(Orphan {
            name: name.to_string(),
            host: host.to_string(),
            extras: Vec::new(),
        });
    } else if let Some(e) = err {
        eprintln!(
            "cp: collector: {name} not in store yet; preserving tunnel after scrape error: {e}"
        );
    }
}

fn unknown_tunnel_is_gc_candidate(
    created_at: Option<DateTime<Utc>>,
    err: &Option<String>,
    now: DateTime<Utc>,
) -> bool {
    let Some(created_at) = created_at else {
        return false;
    };
    now.signed_duration_since(created_at).num_seconds() > DEAD_THRESHOLD_SECS
        && scrape_failure_is_dead_signal(err)
}

fn unknown_tunnel_should_wait_for_registration(
    created_at: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> bool {
    created_at.is_some_and(|created_at| {
        now.signed_duration_since(created_at).num_seconds() < UNKNOWN_TUNNEL_SCRAPE_DELAY_SECS
    })
}

fn should_scrape_key(key: &str, shard_index: u64, shard_total: u64) -> bool {
    if shard_total <= 1 {
        return true;
    }
    rendezvous_shard(key, shard_total) == shard_index
}

fn rendezvous_shard(key: &str, shard_total: u64) -> u64 {
    let mut best_shard = 0;
    let mut best_score = 0;
    for shard in 0..shard_total.max(1) {
        let mut bytes = Vec::with_capacity(key.len() + 8);
        bytes.extend_from_slice(key.as_bytes());
        bytes.extend_from_slice(&shard.to_le_bytes());
        let score = fnv1a64(&bytes);
        if shard == 0 || score > best_score {
            best_score = score;
            best_shard = shard;
        }
    }
    best_shard
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn scrape_failure_is_dead_signal(err: &Option<String>) -> bool {
    let Some(err) = err.as_deref() else {
        return false;
    };
    !matches!(
        err,
        "status 301 Moved Permanently"
            | "status 302 Found"
            | "status 303 See Other"
            | "status 307 Temporary Redirect"
            | "status 308 Permanent Redirect"
            | "status 401 Unauthorized"
            | "status 403 Forbidden"
    )
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, Utc};

    use super::{
        parse_extra_ingress, rendezvous_shard, scrape_failure_is_dead_signal, should_scrape_key,
        unknown_tunnel_is_gc_candidate, unknown_tunnel_should_wait_for_registration,
    };

    #[test]
    fn missing_extra_ingress_preserves_existing_state() {
        let h = serde_json::json!({});

        assert_eq!(parse_extra_ingress(&h), None);
    }

    #[test]
    fn parses_valid_extra_ingress() {
        let h = serde_json::json!({
            "extra_ingress": [
                {"hostname_label": "api", "port": 8081},
                {"hostname_label": "web", "port": 9000}
            ]
        });

        assert_eq!(
            parse_extra_ingress(&h),
            Some(vec![("api".into(), 8081), ("web".into(), 9000)])
        );
    }

    #[test]
    fn drops_malformed_extra_ingress_entries() {
        let h = serde_json::json!({
            "extra_ingress": [
                {"hostname_label": "api", "port": 8081},
                {"hostname_label": "", "port": 8082},
                {"hostname_label": "bad-zero", "port": 0},
                {"hostname_label": "bad-wide", "port": 70000},
                {"hostname_label": "bad-string", "port": "8083"}
            ]
        });

        assert_eq!(parse_extra_ingress(&h), Some(vec![("api".into(), 8081)]));
    }

    #[test]
    fn auth_gate_scrape_failures_are_not_dead_signals() {
        for err in [
            None,
            Some("status 302 Found".to_string()),
            Some("status 401 Unauthorized".to_string()),
            Some("status 403 Forbidden".to_string()),
        ] {
            assert!(!scrape_failure_is_dead_signal(&err));
        }
    }

    #[test]
    fn origin_scrape_failures_are_dead_signals() {
        for err in [
            Some("status 530 <unknown status code>".to_string()),
            Some("error sending request".to_string()),
        ] {
            assert!(scrape_failure_is_dead_signal(&err));
        }
    }

    #[test]
    fn unknown_tunnels_gc_only_after_grace_window() {
        let now = Utc::now();
        let err = Some("error sending request".to_string());

        assert!(!unknown_tunnel_is_gc_candidate(None, &err, now));
        assert!(!unknown_tunnel_is_gc_candidate(
            Some(now - Duration::seconds(60)),
            &err,
            now
        ));
        assert!(unknown_tunnel_is_gc_candidate(
            Some(now - Duration::seconds(1200)),
            &err,
            now
        ));
    }

    #[test]
    fn unknown_tunnels_keep_auth_gate_failures() {
        let now = Utc::now();
        let err = Some("status 403 Forbidden".to_string());

        assert!(!unknown_tunnel_is_gc_candidate(
            Some(now - Duration::seconds(1200)),
            &err,
            now
        ));
    }

    #[test]
    fn fresh_unknown_tunnels_are_not_scraped_immediately() {
        let now = Utc::now();

        assert!(unknown_tunnel_should_wait_for_registration(
            Some(now - Duration::seconds(30)),
            now
        ));
        assert!(!unknown_tunnel_should_wait_for_registration(
            Some(now - Duration::seconds(180)),
            now
        ));
        assert!(!unknown_tunnel_should_wait_for_registration(None, now));
    }

    #[test]
    fn rendezvous_shards_assign_each_key_once() {
        for key in ["agent-a", "agent-b", "agent-c", "agent-d"] {
            let assigned = (0..4)
                .filter(|idx| should_scrape_key(key, *idx, 4))
                .collect::<Vec<_>>();
            assert_eq!(assigned.len(), 1);
            assert_eq!(assigned[0], rendezvous_shard(key, 4));
        }
    }

    #[test]
    fn single_shard_scrapes_every_key() {
        assert!(should_scrape_key("agent-a", 0, 1));
        assert!(should_scrape_key("agent-a", 7, 0));
    }
}
