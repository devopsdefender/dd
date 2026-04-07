//! dd-scraper — discovers agents from Cloudflare tunnels and reports health to the register.

use std::sync::Arc;

use axum::extract::State;
use axum::response::Html;
use axum::routing::get;
use axum::{Json, Router};
use tokio::sync::RwLock;

#[derive(Clone, Debug, Default, serde::Serialize)]
struct ScraperStatus {
    env_label: String,
    report_url: String,
    tunnel_prefix: String,
    last_scrape_at: Option<String>,
    last_report_ok_at: Option<String>,
    last_error: Option<String>,
    tunnels_found: usize,
    healthy_agents: usize,
    unhealthy_agents: usize,
    orphan_tunnels: usize,
    recent_hostnames: Vec<String>,
}

type SharedStatus = Arc<RwLock<ScraperStatus>>;

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
    let report_token = std::env::var("DD_SCRAPER_REPORT_TOKEN")
        .ok()
        .filter(|value| !value.is_empty());
    let status = Arc::new(RwLock::new(ScraperStatus {
        env_label: env_label.clone(),
        report_url: report_url.clone(),
        tunnel_prefix: tunnel_prefix.clone(),
        ..ScraperStatus::default()
    }));

    eprintln!("dd-scraper: starting (env={env_label}, report_url={report_url})");

    let http = reqwest::Client::builder()
        .timeout(scrape_timeout)
        .build()
        .unwrap_or_else(|e| {
            eprintln!("dd-scraper: http client: {e}");
            std::process::exit(1);
        });

    start_status_server(status.clone());

    let mut ticker = tokio::time::interval(scrape_interval);
    loop {
        ticker.tick().await;
        if let Err(e) = scrape_once(
            &http,
            &report_url,
            report_token.as_deref(),
            &cf,
            &tunnel_prefix,
            &status,
        )
        .await
        {
            eprintln!("dd-scraper: error: {e}");
            let mut guard = status.write().await;
            guard.last_scrape_at = Some(now_rfc3339());
            guard.last_error = Some(e);
        }
    }
}

fn start_status_server(status: SharedStatus) {
    let bind_addr = std::env::var("DD_SCRAPER_BIND_ADDR").unwrap_or_else(|_| "0.0.0.0".to_string());
    let port = std::env::var("DD_SCRAPER_PORT")
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(8082);
    let addr = format!("{bind_addr}:{port}");

    tokio::spawn(async move {
        let app = Router::new()
            .route("/", get(scraper_dashboard))
            .route("/health", get(scraper_health))
            .route("/api/status", get(scraper_status))
            .with_state(status);

        match tokio::net::TcpListener::bind(&addr).await {
            Ok(listener) => {
                eprintln!("dd-scraper: status server listening on {addr}");
                if let Err(error) = axum::serve(listener, app).await {
                    eprintln!("dd-scraper: status server error: {error}");
                }
            }
            Err(error) => {
                eprintln!("dd-scraper: failed to bind status server {addr}: {error}");
            }
        }
    });
}

async fn scraper_health(State(status): State<SharedStatus>) -> Json<serde_json::Value> {
    let snapshot = status.read().await.clone();
    Json(serde_json::json!({
        "ok": true,
        "service": "dd-scraper",
        "env": snapshot.env_label,
        "report_url": snapshot.report_url,
        "last_report_ok_at": snapshot.last_report_ok_at,
        "last_error": snapshot.last_error,
        "healthy_agents": snapshot.healthy_agents,
        "unhealthy_agents": snapshot.unhealthy_agents,
        "orphan_tunnels": snapshot.orphan_tunnels,
    }))
}

async fn scraper_status(State(status): State<SharedStatus>) -> Json<ScraperStatus> {
    Json(status.read().await.clone())
}

async fn scraper_dashboard(State(status): State<SharedStatus>) -> Html<String> {
    let snapshot = status.read().await.clone();
    let error_class = if snapshot.last_error.is_some() {
        "error"
    } else {
        ""
    };
    let last_error = snapshot
        .last_error
        .clone()
        .unwrap_or_else(|| "none".to_string());
    let recent = if snapshot.recent_hostnames.is_empty() {
        "<div class=\"empty\">No hostnames scraped yet</div>".to_string()
    } else {
        snapshot
            .recent_hostnames
            .iter()
            .map(|hostname| format!("<li>{hostname}</li>"))
            .collect::<Vec<_>>()
            .join("")
    };

    Html(format!(
        r#"<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>DD Scraper</title>
<style>
body {{ margin: 0; background: #111827; color: #e5e7eb; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; padding: 24px; }}
h1 {{ margin: 0 0 6px; color: #f9fafb; font-size: 22px; }}
.sub {{ color: #9ca3af; margin-bottom: 20px; }}
.grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin-bottom: 20px; }}
.card {{ background: #1f2937; border: 1px solid #374151; border-radius: 12px; padding: 14px; }}
.label {{ color: #9ca3af; font-size: 12px; text-transform: uppercase; margin-bottom: 8px; }}
.value {{ color: #f9fafb; font-size: 20px; }}
.meta {{ margin-bottom: 16px; color: #d1d5db; }}
.error {{ color: #fca5a5; }}
.empty {{ color: #9ca3af; }}
ul {{ margin: 0; padding-left: 20px; }}
</style>
</head>
<body>
<h1>DD Scraper</h1>
<div class="sub">{env} &middot; prefix {prefix}</div>
<div class="meta">Report URL: {report_url}</div>
<div class="meta">Last scrape: {last_scrape}</div>
<div class="meta">Last successful report: {last_ok}</div>
<div class="meta {error_class}">Last error: {last_error}</div>
<div class="grid">
  <div class="card"><div class="label">Tunnels Found</div><div class="value">{tunnels_found}</div></div>
  <div class="card"><div class="label">Healthy Agents</div><div class="value">{healthy_agents}</div></div>
  <div class="card"><div class="label">Unhealthy Agents</div><div class="value">{unhealthy_agents}</div></div>
  <div class="card"><div class="label">Orphan Tunnels</div><div class="value">{orphan_tunnels}</div></div>
</div>
<div class="card">
  <div class="label">Recent Hostnames</div>
  <ul>{recent}</ul>
</div>
</body>
</html>"#,
        env = snapshot.env_label,
        prefix = snapshot.tunnel_prefix,
        report_url = snapshot.report_url,
        last_scrape = snapshot
            .last_scrape_at
            .unwrap_or_else(|| "never".to_string()),
        last_ok = snapshot
            .last_report_ok_at
            .unwrap_or_else(|| "never".to_string()),
        last_error = last_error,
        error_class = error_class,
        tunnels_found = snapshot.tunnels_found,
        healthy_agents = snapshot.healthy_agents,
        unhealthy_agents = snapshot.unhealthy_agents,
        orphan_tunnels = snapshot.orphan_tunnels,
        recent = recent,
    ))
}

async fn scrape_once(
    http: &reqwest::Client,
    report_url: &str,
    report_token: Option<&str>,
    cf: &dd_agent::tunnel::CfConfig,
    tunnel_prefix: &str,
    status: &SharedStatus,
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
    let healthy_agents = results.iter().filter(|result| result.2).count();
    let unhealthy_agents = results.len().saturating_sub(healthy_agents);

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
        healthy_agents,
        unhealthy_agents,
        orphan_tunnels.len(),
    );

    let mut request = http.post(report_url).json(&report);
    if let Some(token) = report_token {
        request = request.bearer_auth(token);
    }
    let response = request
        .send()
        .await
        .map_err(|e| format!("post fleet report: {e}"))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("fleet report rejected: {status} {body}"));
    }

    {
        let mut guard = status.write().await;
        guard.last_scrape_at = Some(now_rfc3339());
        guard.last_report_ok_at = guard.last_scrape_at.clone();
        guard.last_error = None;
        guard.tunnels_found = tunnels.len();
        guard.healthy_agents = healthy_agents;
        guard.unhealthy_agents = unhealthy_agents;
        guard.orphan_tunnels = orphan_tunnels.len();
        guard.recent_hostnames = results
            .iter()
            .map(|(_, hostname, _, _, _)| hostname.clone())
            .take(12)
            .collect();
    }

    Ok(())
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
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
