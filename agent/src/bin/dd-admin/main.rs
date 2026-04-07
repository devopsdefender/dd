use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{Form, Query, State};
use axum::http::header::{COOKIE, SET_COOKIE};
use axum::http::{HeaderMap, HeaderValue};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::{Json, Router};
use tokio::sync::Mutex;

#[derive(Clone)]
struct AdminState {
    register_fleet_url: String,
    register_api_token: Option<String>,
    http: reqwest::Client,
    auth_password: Option<String>,
    secure_cookies: bool,
    sessions: BrowserSessions,
}

type BrowserSessions = Arc<Mutex<HashMap<String, BrowserSession>>>;

#[derive(Clone)]
struct BrowserSession {
    expires_at: Instant,
}

#[derive(serde::Deserialize)]
struct LoginQuery {
    next: Option<String>,
    error: Option<String>,
}

#[derive(serde::Deserialize)]
struct LoginForm {
    password: String,
    next: Option<String>,
}

const SESSION_COOKIE: &str = "dd_admin_session";
const SESSION_TTL: Duration = Duration::from_secs(8 * 60 * 60);

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
        register_api_token: std::env::var("DD_ADMIN_API_TOKEN")
            .ok()
            .filter(|value| !value.is_empty()),
        http: reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("failed to build dd-admin HTTP client"),
        auth_password: std::env::var("DD_ADMIN_PASSWORD")
            .ok()
            .filter(|value| !value.is_empty())
            .or_else(|| {
                std::env::var("DD_PASSWORD")
                    .ok()
                    .filter(|value| !value.is_empty())
            }),
        secure_cookies: std::env::var("DD_ADMIN_SECURE_COOKIES")
            .ok()
            .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
            .unwrap_or(false),
        sessions: Arc::new(Mutex::new(HashMap::new())),
    });

    let app = Router::new()
        .route("/", get(index))
        .route("/health", get(health))
        .route("/api/fleet", get(api_fleet))
        .route("/auth/login", get(login_page).post(login_submit))
        .route("/auth/logout", get(logout))
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

async fn index(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    query: Query<LoginQuery>,
) -> Response {
    if let Some(response) = require_session(&state, &headers, query.next.as_deref()).await {
        return response;
    }

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
      .toolbar {{ margin-bottom: 20px; display: flex; justify-content: space-between; gap: 12px; align-items: center; }}
      .toolbar a {{ color: #93c5fd; text-decoration: none; }}
      .toolbar a:hover {{ text-decoration: underline; }}
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
    <div class="toolbar">
      <div>
        <h1>DD Admin</h1>
        <div class="sub">Fleet source: <code>{fleet_source}</code></div>
      </div>
      <a href="/auth/logout">Log out</a>
    </div>
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
          if (response.status === 401) {{
            window.location.href = '/auth/login';
            return;
          }}
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
    .into_response()
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "ok": true,
        "service": "dd-admin",
    }))
}

async fn api_fleet(State(state): State<Arc<AdminState>>, headers: HeaderMap) -> impl IntoResponse {
    if let Some(response) = require_session(&state, &headers, Some("/")).await {
        return response;
    }

    let mut request = state.http.get(&state.register_fleet_url);
    if let Some(token) = state.register_api_token.as_deref() {
        request = request.bearer_auth(token);
    }

    match request.send().await {
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

async fn login_page(State(state): State<Arc<AdminState>>, query: Query<LoginQuery>) -> Response {
    if state.auth_password.is_none() {
        return Redirect::to("/").into_response();
    }

    let next = sanitize_next_path(query.next.as_deref());
    let error = query
        .error
        .as_deref()
        .map(|value| format!(r#"<div class="error">{value}</div>"#))
        .unwrap_or_default();

    Html(format!(
        r#"<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>DD Admin Login</title>
    <style>
      body {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; background: #0b1020; color: #eef2ff; margin: 0; min-height: 100vh; display: grid; place-items: center; }}
      .card {{ width: min(420px, calc(100vw - 32px)); background: #121936; border: 1px solid #22305f; border-radius: 16px; padding: 24px; }}
      h1 {{ margin: 0 0 8px; font-size: 28px; }}
      p {{ color: #c7d2fe; line-height: 1.5; }}
      input {{ width: 100%; margin-top: 12px; padding: 12px; border-radius: 10px; border: 1px solid #334155; background: #0f172a; color: #eef2ff; font: inherit; }}
      button {{ width: 100%; margin-top: 16px; padding: 12px; border: none; border-radius: 10px; background: #38bdf8; color: #082f49; font: inherit; font-weight: 700; cursor: pointer; }}
      .error {{ margin-top: 12px; color: #fca5a5; }}
    </style>
  </head>
  <body>
    <form class="card" method="post" action="/auth/login">
      <h1>DD Admin</h1>
      <p>Enter the admin password to access the fleet UI.</p>
      {error}
      <input type="hidden" name="next" value="{next}" />
      <input type="password" name="password" placeholder="Password" autofocus />
      <button type="submit">Log In</button>
    </form>
  </body>
</html>"#,
        error = error,
        next = next,
    ))
    .into_response()
}

async fn login_submit(
    State(state): State<Arc<AdminState>>,
    Form(form): Form<LoginForm>,
) -> Response {
    let expected = match state.auth_password.as_deref() {
        Some(password) => password,
        None => return Redirect::to("/").into_response(),
    };

    if !secure_eq(form.password.as_bytes(), expected.as_bytes()) {
        let next = sanitize_next_path(form.next.as_deref());
        return Redirect::to(&format!("/auth/login?next={next}&error=invalid-password"))
            .into_response();
    }

    let session_id = uuid::Uuid::new_v4().simple().to_string();
    state.sessions.lock().await.insert(
        session_id.clone(),
        BrowserSession {
            expires_at: Instant::now() + SESSION_TTL,
        },
    );

    let next = sanitize_next_path(form.next.as_deref());
    response_with_cookie(
        Redirect::to(&next),
        build_session_cookie(&state, &session_id, SESSION_TTL.as_secs()),
    )
}

async fn logout(State(state): State<Arc<AdminState>>, headers: HeaderMap) -> Response {
    if let Some(session_id) = extract_cookie(&headers, SESSION_COOKIE) {
        state.sessions.lock().await.remove(&session_id);
    }
    response_with_cookie(
        Redirect::to("/auth/login"),
        build_session_cookie(&state, "", 0),
    )
}

async fn require_session(
    state: &AdminState,
    headers: &HeaderMap,
    next: Option<&str>,
) -> Option<Response> {
    state.auth_password.as_ref()?;

    let session_id = extract_cookie(headers, SESSION_COOKIE);
    let mut sessions = state.sessions.lock().await;
    let now = Instant::now();
    sessions.retain(|_, session| session.expires_at > now);
    if session_id
        .as_ref()
        .and_then(|id| sessions.get(id))
        .is_some()
    {
        return None;
    }

    let next = sanitize_next_path(next);
    Some(Redirect::to(&format!("/auth/login?next={next}")).into_response())
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

fn extract_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let cookies = headers.get(COOKIE)?.to_str().ok()?;
    for cookie in cookies.split(';') {
        let mut parts = cookie.trim().splitn(2, '=');
        let key = parts.next()?.trim();
        let value = parts.next()?.trim();
        if key == name {
            return Some(value.to_string());
        }
    }
    None
}

fn build_session_cookie(state: &AdminState, session_id: &str, max_age: u64) -> String {
    let mut cookie =
        format!("{SESSION_COOKIE}={session_id}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}");
    if state.secure_cookies {
        cookie.push_str("; Secure");
    }
    cookie
}

fn response_with_cookie(response: impl IntoResponse, cookie: String) -> Response {
    let mut response = response.into_response();
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        response.headers_mut().append(SET_COOKIE, value);
    }
    response
}

fn sanitize_next_path(next: Option<&str>) -> String {
    match next {
        Some(path) if path.starts_with('/') && !path.starts_with("//") => path.to_string(),
        _ => "/".to_string(),
    }
}

fn secure_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (l, r) in left.iter().zip(right.iter()) {
        diff |= l ^ r;
    }
    diff == 0
}
