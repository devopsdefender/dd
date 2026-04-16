//! Background collector — discovers agents, scrapes `/health`, GC's dead tunnels.
//!
//! One tick:
//!   1. List CF tunnels whose name starts with `dd-{env}-agent-` (CP tunnels
//!      use a different prefix, so they can't be misidentified as agents —
//!      previous design needed an ingress-config round-trip to distinguish
//!      and got this wrong once, PR #103).
//!   2. Scrape `https://{tunnel-name}.{domain}/health` in parallel.
//!   3. Mark dead if scrape fails for >5 min; delete tunnel+DNS for dead.
//!   4. Insert a `control-plane` entry for ourselves so the fleet view
//!      lists the CP too.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::cf;
use crate::config::CfCreds;
use crate::ee::Ee;

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
}

pub type Store = Arc<Mutex<HashMap<String, Agent>>>;

pub async fn run(
    store: Store,
    cf: CfCreds,
    env_label: String,
    cp_hostname: String,
    ee: Arc<Ee>,
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
        tick(&store, &http, &cf, &prefix, &ee, &env_label, &cp_hostname).await;
    }
}

async fn tick(
    store: &Store,
    http: &reqwest::Client,
    cf: &CfCreds,
    prefix: &str,
    ee: &Arc<Ee>,
    env_label: &str,
    cp_hostname: &str,
) {
    // Discover agents by name prefix only — no ingress round-trip.
    let tunnels: Vec<(String, String)> = cf::list(http, cf)
        .await
        .unwrap_or_default()
        .into_iter()
        .filter_map(|t| {
            let name = t["name"].as_str()?;
            if !name.starts_with(prefix) {
                return None;
            }
            let hostname = format!("{name}.{}", cf.domain);
            Some((name.to_string(), hostname))
        })
        .collect();

    let scrapes = tunnels.iter().map(|(name, host)| {
        let http = http.clone();
        let name = name.clone();
        let host = host.clone();
        async move {
            let r = http.get(format!("https://{host}/health")).send().await;
            match r {
                Ok(resp) if resp.status().is_success() => {
                    let body = resp.json::<serde_json::Value>().await.ok();
                    (name, host, body, None)
                }
                Ok(resp) => (name, host, None, Some(format!("status {}", resp.status()))),
                Err(e) => (name, host, None, Some(e.to_string())),
            }
        }
    });
    let results = futures_util::future::join_all(scrapes).await;

    let now = Utc::now();
    let mut orphans: Vec<(String, String)> = Vec::new();

    {
        let mut s = store.lock().await;
        for (name, host, body, err) in &results {
            if let Some(h) = body {
                let agent_id = h["agent_id"].as_str().unwrap_or(name).to_string();
                s.insert(
                    agent_id.clone(),
                    Agent {
                        agent_id,
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
                    },
                );
            } else {
                let existing = s.values_mut().find(|a| a.hostname == *host);
                if let Some(a) = existing {
                    let age = now.signed_duration_since(a.last_seen).num_seconds();
                    if age > DEAD_THRESHOLD_SECS {
                        a.status = "dead".into();
                        orphans.push((name.clone(), host.clone()));
                    } else {
                        a.status = "stale".into();
                    }
                } else if err
                    .as_ref()
                    .is_some_and(|e| e.contains("connect") || e.contains("timed out"))
                {
                    orphans.push((name.clone(), host.clone()));
                }
            }
        }

        let dead: Vec<String> = s
            .iter()
            .filter(|(_, a)| a.status == "dead")
            .map(|(k, _)| k.clone())
            .collect();
        for k in &dead {
            s.remove(k);
        }
    }

    if !orphans.is_empty() {
        for (name, host) in &orphans {
            eprintln!("cp: GC dead tunnel {name}");
            cf::delete_by_name(http, cf, name).await;
            let _ = cf::delete_cname(http, cf, host).await;
        }
    }

    // Insert ourselves into the store so the fleet list includes the CP.
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
    store.lock().await.insert(
        "control-plane".into(),
        Agent {
            agent_id: "control-plane".into(),
            hostname: cp_hostname.to_string(),
            vm_name: format!("dd-{env_label}-cp"),
            attestation_type: attestation,
            status: "healthy".into(),
            last_seen: now,
            deployment_count: count,
            deployment_names: deployments,
            cpu_percent: 0,
            memory_used_mb: 0,
            memory_total_mb: 0,
        },
    );

    let healthy = results.iter().filter(|r| r.2.is_some()).count();
    eprintln!(
        "cp: scraped {} agents ({healthy} healthy, {} orphans GC'd)",
        results.len(),
        orphans.len()
    );
}
