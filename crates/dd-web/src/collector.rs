//! Background collector task -- discovers agents from CF tunnels and scrapes /health.

use crate::state::{AgentSnapshot, WebState};
use dd_common::tunnel;

/// Run the collector loop as an in-process background task.
///
/// Every `scrape_interval_secs`:
/// 1. List CF tunnels matching `dd-{env}-*`
/// 2. For each tunnel hostname, GET /health
/// 3. Update AgentStore with results (healthy/stale/dead)
/// 4. Clean up dead agents: remove from store + delete CF tunnel + DNS
pub async fn run_collector(state: WebState) {
    let env_label = &state.config.env_label;
    let tunnel_prefix = format!("dd-{env_label}-");
    let scrape_interval = std::time::Duration::from_secs(state.config.scrape_interval_secs);
    let scrape_timeout = std::time::Duration::from_secs(5);

    let http = reqwest::Client::builder()
        .timeout(scrape_timeout)
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());

    // Number of consecutive failures before a tunnel is considered dead and cleaned up.
    const DEAD_THRESHOLD_SECS: i64 = 300; // 5 minutes

    eprintln!(
        "dd-web: collector starting (prefix={tunnel_prefix}*, interval={}s)",
        state.config.scrape_interval_secs
    );

    let mut ticker = tokio::time::interval(scrape_interval);
    loop {
        ticker.tick().await;

        // List CF tunnels (excludes this CP's own tunnel via ingress-hostname match)
        let tunnels = list_agent_tunnels(
            &http,
            &state.config.cf,
            &tunnel_prefix,
            &state.config.hostname,
        )
        .await;
        eprintln!(
            "dd-web: collector found {} tunnels matching {tunnel_prefix}*",
            tunnels.len()
        );

        // Scrape all agents concurrently
        let scrape_futures: Vec<_> = tunnels
            .iter()
            .map(|(name, hostname)| {
                let http = http.clone();
                let hostname = hostname.clone();
                let name = name.clone();
                async move {
                    let url = format!("https://{hostname}/health");
                    match http.get(&url).send().await {
                        Ok(resp) if resp.status().is_success() => {
                            let health: serde_json::Value = resp.json().await.unwrap_or_default();
                            (name, hostname, true, Some(health), None)
                        }
                        Ok(resp) => (
                            name,
                            hostname,
                            false,
                            None,
                            Some(format!("status {}", resp.status())),
                        ),
                        Err(e) => (name, hostname, false, None, Some(e.to_string())),
                    }
                }
            })
            .collect();

        let results = futures_util::future::join_all(scrape_futures).await;

        // Update agent store
        let now = chrono::Utc::now();
        let mut store = state.agents.lock().await;
        let mut orphan_tunnels: Vec<(String, String)> = Vec::new();

        for (tunnel_name, hostname, healthy, health, error) in &results {
            if *healthy {
                if let Some(h) = health {
                    let agent_id = h
                        .get("agent_id")
                        .and_then(|v| v.as_str())
                        .unwrap_or(tunnel_name)
                        .to_string();

                    let deployment_names: Vec<String> = h
                        .get("deployments")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(String::from))
                                .collect()
                        })
                        .unwrap_or_default();

                    store.insert(
                        agent_id.clone(),
                        AgentSnapshot {
                            agent_id,
                            hostname: hostname.clone(),
                            vm_name: h
                                .get("vm_name")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown")
                                .to_string(),
                            attestation_type: h
                                .get("attestation_type")
                                .and_then(|v| v.as_str())
                                .unwrap_or("none")
                                .to_string(),
                            status: "healthy".to_string(),
                            last_seen: now,
                            deployment_count: h
                                .get("deployment_count")
                                .and_then(|v| v.as_u64())
                                .unwrap_or(0)
                                as usize,
                            deployment_names,
                            cpu_percent: h.get("cpu_percent").and_then(|v| v.as_u64()).unwrap_or(0),
                            memory_used_mb: h
                                .get("memory_used_mb")
                                .and_then(|v| v.as_u64())
                                .unwrap_or(0),
                            memory_total_mb: h
                                .get("memory_total_mb")
                                .and_then(|v| v.as_u64())
                                .unwrap_or(0),
                        },
                    );
                }
            } else {
                // Mark as stale if we already know this agent, or track for cleanup
                let existing = store.values_mut().find(|a| a.hostname == *hostname);

                if let Some(agent) = existing {
                    let age = now.signed_duration_since(agent.last_seen).num_seconds();
                    if age > DEAD_THRESHOLD_SECS {
                        agent.status = "dead".to_string();
                        orphan_tunnels.push((tunnel_name.clone(), hostname.clone()));
                    } else {
                        agent.status = "stale".to_string();
                    }
                } else if error
                    .as_ref()
                    .is_some_and(|e| e.contains("connect") || e.contains("timed out"))
                {
                    // Never-seen tunnel that can't connect -- orphan
                    orphan_tunnels.push((tunnel_name.clone(), hostname.clone()));
                }
            }
        }

        // Remove dead agents from the store
        let dead_ids: Vec<String> = store
            .iter()
            .filter(|(_, a)| a.status == "dead")
            .map(|(id, _)| id.clone())
            .collect();
        for id in &dead_ids {
            store.remove(id);
        }
        drop(store);

        // Clean up orphan tunnels (delete CF tunnel + DNS)
        if !orphan_tunnels.is_empty() {
            let cleanup_http = reqwest::Client::new();
            for (tunnel_name, hostname) in &orphan_tunnels {
                eprintln!("dd-web: collector cleaning up dead tunnel {tunnel_name}");
                let _ = tunnel::delete_tunnel_by_name(&cleanup_http, &state.config.cf, tunnel_name)
                    .await;
                let _ = tunnel::delete_dns_record(&cleanup_http, &state.config.cf, hostname).await;
            }
        }

        // Re-register sweep: for agents bootstrapped from CF tunnels that
        // haven't registered with the current dd-register (status "discovered"),
        // trigger re-registration so they migrate to the new register instance.
        {
            let store = state.agents.lock().await;
            let discovered: Vec<String> = store
                .values()
                .filter(|a| a.status == "discovered" || a.status == "stale")
                .filter(|a| a.agent_id != "control-plane")
                .map(|a| a.hostname.clone())
                .collect();
            drop(store);

            for hostname in &discovered {
                let url = format!("https://{hostname}/re-register");
                match http.post(&url).send().await {
                    Ok(resp) if resp.status().is_success() => {
                        eprintln!("dd-web: collector triggered re-register on {hostname}");
                    }
                    _ => {} // Agent may not support re-register yet; ignore errors.
                }
            }
        }

        // Self-check: query local easyenclave + localhost health to register
        // the control plane in the fleet dashboard.
        let self_healthy = matches!(
            http.get(format!("http://localhost:{}/health", state.config.port))
                .send()
                .await,
            Ok(resp) if resp.status().is_success()
        );

        // Pull real workload info from the local easyenclave socket.
        let (deployment_names, deployment_count, attestation_type) =
            match state.ee_client.list().await {
                Ok(deps) => {
                    let names: Vec<String> = deps["deployments"]
                        .as_array()
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v["app_name"].as_str().map(String::from))
                                .collect()
                        })
                        .unwrap_or_default();
                    let count = names.len();
                    // Also grab attestation from easyenclave health
                    let att = state
                        .ee_client
                        .health()
                        .await
                        .ok()
                        .and_then(|h| h["attestation_type"].as_str().map(String::from))
                        .unwrap_or_else(|| "tdx".into());
                    (names, count, att)
                }
                Err(_) => (vec!["dd-management".into()], 1, "tdx".into()),
            };

        {
            let mut store = state.agents.lock().await;
            store.insert(
                "control-plane".to_string(),
                AgentSnapshot {
                    agent_id: "control-plane".to_string(),
                    hostname: state.config.hostname.clone(),
                    vm_name: format!("dd-{env_label}-cp"),
                    attestation_type,
                    status: if self_healthy { "healthy" } else { "stale" }.to_string(),
                    last_seen: now,
                    deployment_count,
                    deployment_names,
                    cpu_percent: 0,
                    memory_used_mb: 0,
                    memory_total_mb: 0,
                },
            );
        }

        let healthy_count = results.iter().filter(|r| r.2).count();
        let unhealthy_count = results.iter().filter(|r| !r.2).count();
        eprintln!(
            "dd-web: collector scraped {} agents ({healthy_count} healthy, {unhealthy_count} unhealthy, {} orphans cleaned)",
            results.len(),
            orphan_tunnels.len(),
        );
    }
}

/// List CF tunnels whose name starts with the given prefix, returning (name, hostname) pairs.
async fn list_agent_tunnels(
    client: &reqwest::Client,
    cf: &tunnel::CfConfig,
    prefix: &str,
    cp_hostname: &str,
) -> Vec<(String, String)> {
    let url = format!(
        "https://api.cloudflare.com/client/v4/accounts/{}/cfd_tunnel?is_deleted=false",
        cf.account_id
    );

    let resp = match client
        .get(&url)
        .header("Authorization", format!("Bearer {}", cf.api_token))
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("dd-web: collector CF API error: {e}");
            return Vec::new();
        }
    };

    let body: serde_json::Value = resp.json().await.unwrap_or_default();
    let mut tunnels = Vec::new();

    let Some(results) = body["result"].as_array() else {
        return tunnels;
    };
    for t in results {
        let Some(name) = t["name"].as_str() else {
            continue;
        };
        if !name.starts_with(prefix) {
            continue;
        }
        let Some(tunnel_id) = t["id"].as_str() else {
            continue;
        };

        // Resolve the tunnel's real ingress hostname instead of synthesising
        // `{name}.{domain}`. Agent tunnels' names do match their hostnames,
        // but the CP's own tunnel is named `dd-{env}-{vm-id}` while its real
        // ingress is `app.{domain}` — synthesising would make the collector
        // treat itself as an unreachable agent and orphan-delete its own
        // tunnel (~5 min → self-STONITH). Fail closed on lookup error or
        // empty ingress so a CF flake can't resurrect that bug.
        let hostnames = match tunnel::tunnel_ingress_hostnames(client, cf, tunnel_id).await {
            Ok(h) => h,
            Err(e) => {
                eprintln!("dd-web: ingress lookup failed for {name}: {e} — skipping this cycle");
                continue;
            }
        };
        if hostnames.is_empty() {
            continue;
        }
        if hostnames.iter().any(|h| h == cp_hostname) {
            continue; // our own tunnel — never scrape or orphan-delete
        }
        let Some(hostname) = hostnames.into_iter().next() else {
            continue;
        };
        tunnels.push((name.to_string(), hostname));
    }

    tunnels
}
