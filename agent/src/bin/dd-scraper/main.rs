//! dd-scraper — discovers agents from Cloudflare tunnels and reports health to the register.

#[tokio::main]
async fn main() {
    let cf = dd_agent::tunnel::CfConfig::from_env().unwrap_or_else(|e| {
        eprintln!("dd-scraper: CF config required: {e}");
        std::process::exit(1);
    });

    let register_url = std::env::var("DD_REGISTER_URL").unwrap_or_else(|_| {
        eprintln!("dd-scraper: DD_REGISTER_URL required");
        std::process::exit(1);
    });

    let env_label = std::env::var("DD_ENV").unwrap_or_else(|_| "dev".into());
    let tunnel_prefix = format!("dd-{env_label}-");
    let scrape_interval = std::time::Duration::from_secs(30);
    let scrape_timeout = std::time::Duration::from_secs(3);
    let report_url = fleet_report_url(&register_url);

    eprintln!("dd-scraper: starting (env={env_label}, report_url={report_url})");

    let http = reqwest::Client::builder()
        .timeout(scrape_timeout)
        .build()
        .unwrap_or_else(|e| {
            eprintln!("dd-scraper: http client: {e}");
            std::process::exit(1);
        });

    let mut ticker = tokio::time::interval(scrape_interval);
    loop {
        ticker.tick().await;
        if let Err(e) = scrape_once(&http, &report_url, &cf, &tunnel_prefix).await {
            eprintln!("dd-scraper: error: {e}");
        }
    }
}

async fn scrape_once(
    http: &reqwest::Client,
    report_url: &str,
    cf: &dd_agent::tunnel::CfConfig,
    tunnel_prefix: &str,
) -> Result<(), String> {
    let tunnels = list_cf_tunnels(http, cf, tunnel_prefix).await;
    eprintln!(
        "dd-scraper: found {} tunnels matching {tunnel_prefix}*",
        tunnels.len()
    );

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

    let mut agents = Vec::new();
    let mut orphan_tunnels = Vec::new();

    for (tunnel_name, hostname, healthy, health, error) in &results {
        if *healthy {
            if let Some(h) = health {
                agents.push(serde_json::json!({
                    "hostname": hostname,
                    "healthy": true,
                    "agent_id": h.get("agent_id").and_then(|v| v.as_str()),
                    "vm_name": h.get("vm_name").and_then(|v| v.as_str()),
                    "attestation_type": h.get("attestation_type").and_then(|v| v.as_str()),
                    "deployment_count": h.get("deployment_count").and_then(|v| v.as_u64()),
                    "cpu_percent": h.get("cpu_percent").and_then(|v| v.as_u64()),
                    "memory_used_mb": h.get("memory_used_mb").and_then(|v| v.as_u64()),
                    "memory_total_mb": h.get("memory_total_mb").and_then(|v| v.as_u64()),
                    "deployments": h.get("deployments"),
                }));
            }
        } else {
            agents.push(serde_json::json!({
                "hostname": hostname,
                "healthy": false,
                "error": error,
            }));
            if error
                .as_ref()
                .is_some_and(|e| e.contains("connect") || e.contains("timed out"))
            {
                orphan_tunnels.push(tunnel_name.clone());
            }
        }
    }

    let report = serde_json::json!({
        "agents": agents,
        "orphan_tunnels": orphan_tunnels,
    });

    eprintln!(
        "dd-scraper: reporting {} agents ({} healthy, {} unhealthy, {} orphans)",
        results.len(),
        results.iter().filter(|r| r.2).count(),
        results.iter().filter(|r| !r.2).count(),
        orphan_tunnels.len(),
    );

    let response = http
        .post(report_url)
        .json(&report)
        .send()
        .await
        .map_err(|e| format!("post fleet report: {e}"))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("fleet report rejected: {status} {body}"));
    }

    Ok(())
}

fn fleet_report_url(register_url: &str) -> String {
    let normalized = register_url
        .replace("wss://", "https://")
        .replace("ws://", "http://");

    if normalized.ends_with("/api/fleet/report") {
        normalized
    } else if normalized.ends_with("/register") {
        format!(
            "{}/api/fleet/report",
            normalized.trim_end_matches("/register")
        )
    } else if normalized.ends_with("/scraper") {
        format!(
            "{}/api/fleet/report",
            normalized.trim_end_matches("/scraper")
        )
    } else {
        format!("{}/api/fleet/report", normalized.trim_end_matches('/'))
    }
}

async fn list_cf_tunnels(
    client: &reqwest::Client,
    cf: &dd_agent::tunnel::CfConfig,
    prefix: &str,
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
            eprintln!("dd-scraper: CF API error: {e}");
            return Vec::new();
        }
    };

    let body: serde_json::Value = resp.json().await.unwrap_or_default();
    let mut tunnels = Vec::new();

    if let Some(results) = body["result"].as_array() {
        for t in results {
            if let Some(name) = t["name"].as_str() {
                if name.starts_with(prefix) {
                    let hostname = format!("{name}.{}", cf.domain);
                    tunnels.push((name.to_string(), hostname));
                }
            }
        }
    }

    tunnels
}

#[cfg(test)]
mod tests {
    use super::fleet_report_url;

    #[test]
    fn report_url_converts_register_websocket() {
        assert_eq!(
            fleet_report_url("wss://app.devopsdefender.com/register"),
            "https://app.devopsdefender.com/api/fleet/report"
        );
    }

    #[test]
    fn report_url_converts_scraper_websocket() {
        assert_eq!(
            fleet_report_url("ws://localhost:8080/scraper"),
            "http://localhost:8080/api/fleet/report"
        );
    }

    #[test]
    fn report_url_preserves_explicit_http_endpoint() {
        assert_eq!(
            fleet_report_url("http://localhost:8080/api/fleet/report"),
            "http://localhost:8080/api/fleet/report"
        );
    }
}
