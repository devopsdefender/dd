use axum::extract::State;
use axum::response::{Html, IntoResponse};
use axum::routing::get;
use axum::{Json, Router};
use std::sync::Arc;

#[derive(Clone)]
struct AdminState {
    register_fleet_url: String,
    http: reqwest::Client,
}

#[tokio::main]
async fn main() {
    let bind_addr = std::env::var("DD_ADMIN_BIND_ADDR").unwrap_or_else(|_| "0.0.0.0".into());
    let port = std::env::var("DD_ADMIN_PORT")
        .ok()
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(9090);
    let register_fleet_url = register_fleet_url();
    let state = Arc::new(AdminState {
        register_fleet_url: register_fleet_url.clone(),
        http: reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("failed to build dd-admin HTTP client"),
    });

    let app = Router::new()
        .route("/", get(index))
        .route("/health", get(health))
        .route("/api/fleet", get(api_fleet))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(format!("{bind_addr}:{port}"))
        .await
        .expect("failed to bind dd-admin");

    eprintln!("dd-admin: listening on {}:{}", bind_addr, port);
    eprintln!("dd-admin: fleet source {}", register_fleet_url);
    if let Err(error) = axum::serve(listener, app).await {
        eprintln!("dd-admin: server error: {error}");
        std::process::exit(1);
    }
}

async fn index(State(state): State<Arc<AdminState>>) -> Html<String> {
    Html(format!(
        r#"<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>DD Admin</title>
    <style>
      body {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; background: #0b1020; color: #eef2ff; margin: 0; padding: 32px; }}
      h1 {{ margin: 0 0 8px; font-size: 30px; }}
      .sub {{ color: #93c5fd; margin-bottom: 20px; }}
      .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin-bottom: 20px; }}
      .card {{ background: #121936; border: 1px solid #22305f; border-radius: 16px; padding: 18px; }}
      .label {{ color: #94a3b8; font-size: 12px; text-transform: uppercase; margin-bottom: 8px; }}
      .value {{ font-size: 24px; }}
      table {{ width: 100%; border-collapse: collapse; background: #121936; border: 1px solid #22305f; border-radius: 16px; overflow: hidden; }}
      th, td {{ text-align: left; padding: 12px 14px; border-bottom: 1px solid #22305f; }}
      th {{ color: #93c5fd; font-size: 12px; text-transform: uppercase; }}
      td {{ color: #e2e8f0; vertical-align: top; }}
      .pill {{ display: inline-block; padding: 3px 8px; border-radius: 999px; font-size: 12px; }}
      .healthy {{ background: rgba(34,197,94,0.15); color: #86efac; }}
      .stale {{ background: rgba(245,158,11,0.15); color: #fcd34d; }}
      .dead {{ background: rgba(239,68,68,0.15); color: #fca5a5; }}
      .muted {{ color: #94a3b8; }}
      .error {{ color: #fca5a5; margin-top: 14px; }}
    </style>
  </head>
  <body>
    <h1>DD Admin</h1>
    <div class="sub">Fleet source: <code>{fleet_source}</code></div>
    <div id="summary" class="grid"></div>
    <table>
      <thead>
        <tr>
          <th>Hostname</th>
          <th>VM</th>
          <th>Status</th>
          <th>Workloads</th>
          <th>CPU</th>
          <th>Memory</th>
          <th>Last Seen</th>
        </tr>
      </thead>
      <tbody id="fleet-rows">
        <tr><td colspan="7" class="muted">Loading fleet snapshot…</td></tr>
      </tbody>
    </table>
    <div id="error" class="error"></div>
    <script>
      function renderSummary(snapshot) {{
        const cards = [
          ['Environment', snapshot.env],
          ['Agents', snapshot.total_agents],
          ['Healthy', snapshot.healthy_agents],
          ['Stale', snapshot.stale_agents],
          ['Dead', snapshot.dead_agents],
        ];
        document.getElementById('summary').innerHTML = cards.map(([label, value]) =>
          `<div class="card"><div class="label">${{label}}</div><div class="value">${{value}}</div></div>`
        ).join('');
      }}

      function renderRows(snapshot) {{
        const rows = snapshot.agents.map(agent => {{
          const workloads = (agent.deployment_names || []).length
            ? agent.deployment_names.join('<br />')
            : String(agent.deployment_count || 0);
          const memory = agent.memory_total_mb
            ? `${{agent.memory_used_mb}}M / ${{agent.memory_total_mb}}M`
            : '—';
          return `<tr>
            <td>${{agent.hostname}}</td>
            <td>${{agent.vm_name}}</td>
            <td><span class="pill ${{agent.status}}">${{agent.status}}</span></td>
            <td>${{workloads}}</td>
            <td>${{agent.cpu_percent ?? '—'}}%</td>
            <td>${{memory}}</td>
            <td>${{agent.last_seen || agent.registered_at || '—'}}</td>
          </tr>`;
        }});
        document.getElementById('fleet-rows').innerHTML = rows.length
          ? rows.join('')
          : '<tr><td colspan="7" class="muted">No agents registered</td></tr>';
      }}

      async function refresh() {{
        const error = document.getElementById('error');
        error.textContent = '';
        try {{
          const response = await fetch('/api/fleet');
          if (!response.ok) {{
            throw new Error(`fleet request failed: ${{response.status}}`);
          }}
          const snapshot = await response.json();
          renderSummary(snapshot);
          renderRows(snapshot);
        }} catch (err) {{
          error.textContent = err.message;
        }}
      }}

      refresh();
      setInterval(refresh, 10000);
    </script>
  </body>
</html>"#,
        fleet_source = state.register_fleet_url,
    ))
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "ok": true,
        "service": "dd-admin",
    }))
}

async fn api_fleet(State(state): State<Arc<AdminState>>) -> impl IntoResponse {
    match state.http.get(&state.register_fleet_url).send().await {
        Ok(response) if response.status().is_success() => match response.text().await {
            Ok(body) => (
                axum::http::StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, "application/json")],
                body,
            )
                .into_response(),
            Err(error) => (
                axum::http::StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({"error": format!("read fleet body: {error}")})),
            )
                .into_response(),
        },
        Ok(response) => (
            axum::http::StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({"error": format!("register returned {}", response.status())})),
        )
            .into_response(),
        Err(error) => (
            axum::http::StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({"error": format!("fetch fleet: {error}")})),
        )
            .into_response(),
    }
}

fn register_fleet_url() -> String {
    if let Ok(url) = std::env::var("DD_REGISTER_ADMIN_URL") {
        return normalize_register_base_url(&url);
    }
    let register_url = std::env::var("DD_REGISTER_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:8080/register".to_string());
    normalize_register_base_url(&register_url)
}

fn normalize_register_base_url(url: &str) -> String {
    let normalized = url
        .replace("wss://", "https://")
        .replace("ws://", "http://");
    if normalized.ends_with("/api/fleet") {
        normalized
    } else if normalized.ends_with("/register") {
        format!("{}/api/fleet", normalized.trim_end_matches("/register"))
    } else {
        format!("{}/api/fleet", normalized.trim_end_matches('/'))
    }
}
