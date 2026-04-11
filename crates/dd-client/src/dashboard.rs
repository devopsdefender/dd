//! Dashboard and workload detail pages.

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Response};
use dd_common::error::AppError;

use crate::auth::{require_browser_token, DashQuery};
use crate::AppState;

// ── Catppuccin Mocha CSS ────────────────────────────────────────────────

const CATPPUCCIN_CSS: &str = r#"
  * { box-sizing:border-box; margin:0; padding:0; }
  body { background:#1e1e2e; color:#cdd6f4; font-family:'JetBrains Mono',ui-monospace,monospace; }
  a { color:#89b4fa; text-decoration:none; } a:hover { text-decoration:underline; }
  nav { display:flex; align-items:center; gap:16px; padding:12px 24px; border-bottom:1px solid #313244; }
  nav .brand { color:#89b4fa; font-weight:700; font-size:14px; }
  nav a { color:#a6adc8; font-size:13px; } nav a:hover, nav a.active { color:#cdd6f4; }
  nav .spacer { flex:1; }
  main { max-width:960px; margin:0 auto; padding:24px; }
  h1 { color:#89b4fa; font-size:20px; margin-bottom:4px; }
  .sub { color:#585b70; font-size:12px; margin-bottom:16px; }
  .meta { color:#a6adc8; font-size:13px; margin-bottom:24px; }
  .meta .ok { color:#a6e3a1; }
  .section { color:#a6adc8; font-size:12px; text-transform:uppercase; margin:20px 0 8px; }
  .cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:12px; margin-bottom:16px; }
  .card { background:#181825; border:1px solid #313244; border-radius:8px; padding:16px; }
  .card .label { color:#a6adc8; font-size:11px; text-transform:uppercase; }
  .card .value { font-size:20px; margin-top:4px; }
  .card .value.green { color:#a6e3a1; }
  .card .value.blue { color:#89b4fa; }
  .card .value.peach { color:#fab387; }
  .card .value.mauve { color:#cba6f7; }
  .row { display:flex; justify-content:space-between; padding:8px 0; border-bottom:1px solid #313244; }
  .row:last-child { border-bottom:none; }
  table { border-collapse:collapse; width:100%; }
  th { text-align:left; color:#a6adc8; font-weight:normal; font-size:12px; text-transform:uppercase; padding:8px 12px; border-bottom:1px solid #313244; }
  td { padding:8px 12px; border-bottom:1px solid #313244; font-size:14px; }
  .pill { display:inline-block; padding:2px 8px; border-radius:4px; font-size:12px; font-weight:600; }
  .pill.healthy, .pill.running { background:#a6e3a122; color:#a6e3a1; }
  .pill.stale, .pill.deploying { background:#fab38722; color:#fab387; }
  .pill.dead, .pill.failed, .pill.exited { background:#f38ba822; color:#f38ba8; }
  .pill.idle { background:#31324488; color:#a6adc8; }
  .empty { color:#585b70; padding:24px; text-align:center; }
  .dim { color:#585b70; }
  .back { font-size:13px; margin-bottom:20px; }
  @media(max-width:640px) { main { padding:16px; } .cards { grid-template-columns:1fr 1fr; } }
"#;

fn page_shell(title: &str, nav_html: &str, content: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title>
<style>{css}</style></head><body>
{nav}
<main>{content}</main>
</body></html>"#,
        title = title,
        css = CATPPUCCIN_CSS,
        nav = nav_html,
        content = content,
    )
}

fn nav_bar(items: &[(&str, &str, bool)]) -> String {
    let mut html = String::from(r#"<nav><span class="brand">DD</span>"#);
    for (label, href, active) in items {
        if *active {
            html.push_str(&format!(r#"<a href="{href}" class="active">{label}</a>"#));
        } else {
            html.push_str(&format!(r#"<a href="{href}">{label}</a>"#));
        }
    }
    html.push_str(r#"<span class="spacer"></span><a href="/auth/logout">log out</a></nav>"#);
    html
}

fn format_uptime(secs: u64) -> String {
    if secs > 3600 {
        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
    } else if secs > 60 {
        format!("{}m", secs / 60)
    } else {
        format!("{secs}s")
    }
}

// ── System metrics (from /proc) ─────────────────────────────────────────

struct SystemMetrics {
    cpu_pct: u64,
    mem_used: String,
    mem_total: String,
    disk_used: String,
    disk_total: String,
    load_1m: String,
}

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1_073_741_824 {
        format!("{:.1}G", bytes as f64 / 1_073_741_824.0)
    } else if bytes >= 1_048_576 {
        format!("{:.0}M", bytes as f64 / 1_048_576.0)
    } else {
        format!("{:.0}K", bytes as f64 / 1024.0)
    }
}

async fn collect_metrics() -> SystemMetrics {
    let mut metrics = SystemMetrics {
        cpu_pct: 0,
        mem_used: "?".into(),
        mem_total: "?".into(),
        disk_used: "?".into(),
        disk_total: "?".into(),
        load_1m: "?".into(),
    };

    // Memory from /proc/meminfo
    if let Ok(meminfo) = tokio::fs::read_to_string("/proc/meminfo").await {
        let mut total_kb = 0u64;
        let mut available_kb = 0u64;
        for line in meminfo.lines() {
            if let Some(val) = line.strip_prefix("MemTotal:") {
                total_kb = val
                    .split_whitespace()
                    .next()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0);
            }
            if let Some(val) = line.strip_prefix("MemAvailable:") {
                available_kb = val
                    .split_whitespace()
                    .next()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0);
            }
        }
        if total_kb > 0 {
            let used_kb = total_kb.saturating_sub(available_kb);
            metrics.mem_total = format_bytes(total_kb * 1024);
            metrics.mem_used = format_bytes(used_kb * 1024);
        }
    }

    // Load average
    if let Ok(loadavg) = tokio::fs::read_to_string("/proc/loadavg").await {
        if let Some(load_1m) = loadavg.split_whitespace().next() {
            metrics.load_1m = load_1m.to_string();
        }
    }

    // CPU from /proc/stat
    if let Ok(stat) = tokio::fs::read_to_string("/proc/stat").await {
        if let Some(cpu_line) = stat.lines().next() {
            let vals: Vec<u64> = cpu_line
                .split_whitespace()
                .skip(1)
                .filter_map(|v| v.parse().ok())
                .collect();
            if vals.len() >= 4 {
                let total: u64 = vals.iter().sum();
                let idle = vals[3];
                if total > 0 {
                    metrics.cpu_pct = 100u64.saturating_sub((idle * 100) / total);
                }
            }
        }
    }

    // Disk from df
    if let Ok(output) = tokio::process::Command::new("df")
        .arg("-B1")
        .arg("/")
        .output()
        .await
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if let Some(line) = stdout.lines().nth(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                let total: u64 = parts[1].parse().unwrap_or(0);
                let used: u64 = parts[2].parse().unwrap_or(0);
                if total > 0 {
                    metrics.disk_total = format_bytes(total);
                    metrics.disk_used = format_bytes(used);
                }
            }
        }
    }

    metrics
}

// ── Dashboard handler ───────────────────────────────────────────────────

pub async fn dashboard(
    State(state): State<AppState>,
    axum::extract::Query(query): axum::extract::Query<DashQuery>,
    headers: HeaderMap,
    axum::extract::OriginalUri(uri): axum::extract::OriginalUri,
) -> Result<Response, AppError> {
    if !state.config.owner.is_empty() {
        match require_browser_token(&state, &headers, query.token.as_deref(), &uri).await {
            Ok(_) => {}
            Err(response) => return Ok(response),
        }
    }

    let metrics = collect_metrics().await;

    // Get workloads from easyenclave
    let list_resp = state.ee_client.list().await.unwrap_or_default();
    let deployments: Vec<&serde_json::Value> = list_resp["deployments"]
        .as_array()
        .map(|a| a.iter().collect())
        .unwrap_or_default();

    let mut rows = String::new();
    for d in &deployments {
        let status_class = match d["status"].as_str().unwrap_or("") {
            "running" => "running",
            "deploying" => "deploying",
            "failed" | "exited" => "failed",
            _ => "idle",
        };
        let id = d["id"].as_str().unwrap_or("");
        let app_name = d["app_name"].as_str().unwrap_or("unnamed");
        let status = d["status"].as_str().unwrap_or("unknown");
        let image = d["image"].as_str().unwrap_or("");
        let started = d["started_at"].as_str().unwrap_or("");
        let started_short = started.split('T').next().unwrap_or(started);

        let terminal_link = if status == "running" {
            format!(r#"<a href="/session/{app_name}">open session</a>"#)
        } else {
            r#"<span class="dim">—</span>"#.to_string()
        };
        rows.push_str(&format!(
            r#"<tr>
                <td><a href="/workload/{id}">{app_name}</a></td>
                <td><span class="pill {status_class}">{status}</span></td>
                <td class="dim">{image}</td>
                <td>{started_short}</td>
                <td>{terminal_link}</td>
            </tr>"#,
        ));
    }

    let uptime_str = format_uptime(state.started_at.elapsed().as_secs());
    let nav = nav_bar(&[("Dashboard", "/", true)]);
    let hostname = state
        .config
        .hostname
        .as_deref()
        .unwrap_or(&state.config.vm_name);

    let table = if deployments.is_empty() {
        r#"<div class="empty">No workloads running</div>"#.to_string()
    } else {
        format!(
            r#"<table><tr><th>app</th><th>status</th><th>image</th><th>started</th><th>session</th></tr>{rows}</table>"#
        )
    };

    // Get attestation type from easyenclave health
    let ee_health = state.ee_client.health().await.unwrap_or_default();
    let att = ee_health["attestation_type"].as_str().unwrap_or("unknown");

    let content = format!(
        r#"<h1>{hostname}</h1>
<div class="sub">{vm_name} &middot; {att}</div>
<div class="meta"><span class="ok">healthy</span> &middot; uptime {uptime} &middot; {count} workload(s)</div>

<div class="cards">
  <div class="card"><div class="label">CPU</div><div class="value green">{cpu}%</div></div>
  <div class="card"><div class="label">Memory</div><div class="value blue">{mem_used} / {mem_total}</div></div>
  <div class="card"><div class="label">Disk</div><div class="value peach">{disk_used} / {disk_total}</div></div>
  <div class="card"><div class="label">Load</div><div class="value mauve">{load}</div></div>
</div>

<div class="section">Workloads</div>
{table}"#,
        hostname = hostname,
        vm_name = &state.config.vm_name,
        att = att,
        uptime = uptime_str,
        count = deployments.len(),
        cpu = metrics.cpu_pct,
        mem_used = metrics.mem_used,
        mem_total = metrics.mem_total,
        disk_used = metrics.disk_used,
        disk_total = metrics.disk_total,
        load = metrics.load_1m,
        table = table,
    );

    Ok(Html(page_shell(
        &format!("DD — {}", state.config.vm_name),
        &nav,
        &content,
    ))
    .into_response())
}

// ── Workload detail page ────────────────────────────────────────────────

pub async fn workload_page(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    axum::extract::OriginalUri(uri): axum::extract::OriginalUri,
) -> Result<Response, AppError> {
    if !state.config.owner.is_empty() {
        match require_browser_token(&state, &headers, None, &uri).await {
            Ok(_) => {}
            Err(response) => return Ok(response),
        }
    }

    // Get all deployments, find the one matching this id
    let list_resp = state.ee_client.list().await.map_err(AppError::External)?;
    let deployments: Vec<&serde_json::Value> = list_resp["deployments"]
        .as_array()
        .map(|a| a.iter().collect())
        .unwrap_or_default();
    let d = deployments
        .iter()
        .find(|d| d["id"].as_str() == Some(id.as_str()))
        .ok_or(AppError::NotFound)?;

    let app_name = d["app_name"].as_str().unwrap_or("unnamed");
    let status = d["status"].as_str().unwrap_or("unknown");
    let image = d["image"].as_str().unwrap_or("");
    let started = d["started_at"].as_str().unwrap_or("");
    let error_message = d["error_message"].as_str().unwrap_or("");

    let status_class = match status {
        "running" => "running",
        "deploying" => "deploying",
        "failed" | "exited" => "failed",
        _ => "idle",
    };

    let session_link = if status == "running" {
        format!(r#"<a href="/session/{app_name}">Open terminal session</a>"#,)
    } else {
        String::new()
    };

    let error_row = if !error_message.is_empty() {
        format!(
            r#"<div class="row"><span class="label">Error</span><span style="color:#f38ba8">{error_message}</span></div>"#
        )
    } else {
        String::new()
    };

    // Get logs from easyenclave
    let logs_resp = state.ee_client.logs(&id).await.unwrap_or_default();
    let logs = if let Some(lines) = logs_resp["lines"].as_array() {
        lines
            .iter()
            .filter_map(|v| v.as_str())
            .map(|l| {
                l.replace('&', "&amp;")
                    .replace('<', "&lt;")
                    .replace('>', "&gt;")
            })
            .collect::<Vec<_>>()
            .join("\n")
    } else {
        String::new()
    };

    let nav = nav_bar(&[("Dashboard", "/", false)]);
    let content = format!(
        r#"<div class="back"><a href="/">&larr; dashboard</a></div>
<h1>{name}</h1>
<div class="sub">{id}</div>

<div class="card">
  <div class="row"><span class="label">Status</span><span class="pill {status_class}">{status}</span></div>
  <div class="row"><span class="label">Image</span><span>{image}</span></div>
  <div class="row"><span class="label">Started</span><span>{started}</span></div>
  {error_row}
</div>

{session_link}

<div class="section">Logs (last 200 lines)</div>
<pre style="background:#11111b;border:1px solid #313244;border-radius:8px;padding:16px;overflow-x:auto;font-size:12px;line-height:1.5;max-height:60vh;overflow-y:auto;color:#a6adc8">{logs}</pre>"#,
        name = app_name,
        id = id,
        status_class = status_class,
        status = status,
        image = image,
        started = started,
        error_row = error_row,
        session_link = session_link,
        logs = if logs.is_empty() {
            "<span class=\"dim\">No logs available</span>".into()
        } else {
            logs
        },
    );

    Ok(Html(page_shell(&format!("DD — {}", app_name), &nav, &content)).into_response())
}
