//! Background collector — discovers agents, scrapes `/health`, GC's dead tunnels.
//!
//! Every agent entry in the store carries freshly-verified ITA claims. The
//! collector scrapes `/health`, extracts the `ita_token` field, and runs
//! it through the CP's verifier; agents whose tokens are missing, expired,
//! or mis-signed don't enter the store. One tick:
//!
//!   1. List CF tunnels whose name starts with `dd-{env}-agent-`.
//!   2. Scrape `https://{tunnel-name}.{domain}/health` in parallel.
//!   3. Verify the `ita_token` field from each /health body.
//!   4. Insert on success, including tunnel id and reported ingress.
//!   5. Mark dead / GC tunnel on repeated scrape failures.
//!   6. Refresh the `control-plane` entry (its claims come from CP startup).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::cf;
use crate::config::CfCreds;
use crate::ee::Ee;
use crate::ita;

const DEAD_THRESHOLD_SECS: i64 = 300;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Agent {
    pub agent_id: String,
    pub hostname: String,
    pub vm_name: String,
    pub attestation_type: String,
    pub status: String,
    pub last_seen: DateTime<Utc>,
    pub deployment_count: usize,
    pub deployment_names: Vec<String>,
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
}

pub type Store = Arc<Mutex<HashMap<String, Agent>>>;

#[allow(clippy::too_many_arguments)]
pub async fn run(
    store: Store,
    cf: CfCreds,
    env_label: String,
    cp_hostname: String,
    ee: Arc<Ee>,
    verifier: Arc<ita::Verifier>,
    interval: Duration,
) -> ! {
    let prefix = cf::agent_prefix(&env_label);
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());

    eprintln!(
        "cp: collector starting (prefix={prefix}*, interval={}s)",
        interval.as_secs()
    );

    let mut ticker = tokio::time::interval(interval);
    loop {
        ticker.tick().await;
        tick(
            &store,
            &http,
            &cf,
            &prefix,
            &ee,
            &verifier,
            &env_label,
            &cp_hostname,
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
) {
    let tunnels: Vec<(String, String, String)> = cf::list(http, cf)
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
            Some((name.to_string(), id.to_string(), hostname))
        })
        .collect();

    let scrapes = tunnels.iter().map(|(name, tunnel_id, host)| {
        let http = http.clone();
        let name = name.clone();
        let tunnel_id = tunnel_id.clone();
        let host = host.clone();
        async move {
            let r = http.get(format!("https://{host}/health")).send().await;
            match r {
                Ok(resp) if resp.status().is_success() => {
                    let body = resp.json::<serde_json::Value>().await.ok();
                    (name, tunnel_id, host, body, None)
                }
                Ok(resp) => (
                    name,
                    tunnel_id,
                    host,
                    None,
                    Some(format!("status {}", resp.status())),
                ),
                Err(e) => (name, tunnel_id, host, None, Some(e.to_string())),
            }
        }
    });
    let results = futures_util::future::join_all(scrapes).await;

    let now = Utc::now();
    let mut orphans: Vec<(String, String)> = Vec::new();
    let mut verified = 0usize;

    for (name, tunnel_id, host, body, err) in &results {
        let Some(h) = body else {
            mark_stale_or_orphan(store, host, name, err, now, &mut orphans).await;
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
                deployment_count: h["deployment_count"].as_u64().unwrap_or(0) as usize,
                deployment_names: h["deployments"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_default(),
                cpu_percent: h["cpu_percent"].as_u64().unwrap_or(0),
                memory_used_mb: h["memory_used_mb"].as_u64().unwrap_or(0),
                memory_total_mb: h["memory_total_mb"].as_u64().unwrap_or(0),
                nets: serde_json::from_value(h["nets"].clone()).unwrap_or_default(),
                disks: serde_json::from_value(h["disks"].clone()).unwrap_or_default(),
                ita: claims,
                tunnel_id: tunnel_id.clone(),
                extras,
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
        for (name, host) in &orphans {
            eprintln!("cp: GC dead tunnel {name}");
            cf::delete_by_name(http, cf, name).await;
            let _ = cf::delete_cname(http, cf, host).await;
            // Sweep the agent's CF Access apps — its human dashboard
            // app and every workload-URL bypass under this hostname.
            // Without this the account accumulates dead apps every
            // STONITH cycle.
            cf::delete_access_apps_for(http, cf, host).await;
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
        "cp: scraped {} tunnels ({verified} verified, {} orphans GC'd)",
        results.len(),
        orphans.len()
    );
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
    err: &Option<String>,
    now: DateTime<Utc>,
    orphans: &mut Vec<(String, String)>,
) {
    let mut s = store.lock().await;
    if let Some(a) = s.values_mut().find(|a| a.hostname == *host) {
        let age = now.signed_duration_since(a.last_seen).num_seconds();
        if age > DEAD_THRESHOLD_SECS {
            a.status = "dead".into();
            orphans.push((name.to_string(), host.to_string()));
        } else {
            a.status = "stale".into();
        }
    } else if err
        .as_ref()
        .is_some_and(|e| e.contains("connect") || e.contains("timed out"))
    {
        orphans.push((name.to_string(), host.to_string()));
    }
}

#[cfg(test)]
mod tests {
    use super::parse_extra_ingress;

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
}
