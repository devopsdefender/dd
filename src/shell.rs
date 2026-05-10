//! Multi-session shell sidecar.
//!
//! Transitional browser shell proxy.
//!
//! Native clients in `devopsdefender/dd-client` are the primary shell/session
//! workflow. This sidecar keeps only the minimal browser attach surface while
//! forwarding session state and PTY bytes to local `dd-sessiond`.

use std::time::Duration;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path as AxPath, Query, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use futures_util::{SinkExt, StreamExt};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::error::{Error, Result};
use crate::html;

const DEFAULT_PORT: u16 = 7681;

#[derive(Clone)]
struct App {
    http: reqwest::Client,
    sessiond_http_url: String,
    sessiond_attach_addr: String,
    owner: crate::gh_oidc::Principal,
    auth: crate::auth::AuthConfig,
    hostname: String,
}

#[derive(Deserialize, Serialize)]
struct CreateSession {
    name: Option<String>,
    recipe_id: Option<String>,
    command: Option<String>,
    cwd: Option<String>,
}

#[derive(Deserialize, Serialize)]
struct ResizeSession {
    cols: u16,
    rows: u16,
}

pub async fn run() -> Result<()> {
    let common = crate::config::Common::from_env()?;
    let domain = std::env::var("DD_CF_DOMAIN")
        .map_err(|_| Error::Internal("DD_CF_DOMAIN required in shell mode".into()))?;
    let hostname = std::env::var("DD_HOSTNAME")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| common.vm_name.clone());
    let auth = crate::auth::AuthConfig::from_env(&hostname, &domain)?;
    let port = std::env::var("DD_SHELL_PORT")
        .ok()
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(DEFAULT_PORT);
    let sessiond_http_url =
        std::env::var("DD_SESSIOND_HTTP_URL").unwrap_or_else(|_| "http://127.0.0.1:7683".into());
    let sessiond_attach_addr =
        std::env::var("DD_SESSIOND_ATTACH_ADDR").unwrap_or_else(|_| "127.0.0.1:7684".into());

    let app_state = App {
        http: reqwest::Client::builder()
            .timeout(Duration::from_secs(3))
            .no_hickory_dns()
            .build()
            .unwrap_or_else(|_| crate::system_http_client()),
        sessiond_http_url,
        sessiond_attach_addr,
        owner: common.owner,
        auth,
        hostname,
    };

    let app = Router::new()
        .route("/", get(index))
        .route("/favicon.ico", get(favicon))
        .route("/assets/xterm/xterm.css", get(xterm_css))
        .route("/assets/xterm/xterm.js", get(xterm_js))
        .route("/assets/xterm/addon-fit.js", get(xterm_fit_js))
        .route("/api/recipes", get(list_recipes))
        .route("/api/sessions", get(list_sessions).post(create_session))
        .route("/api/sessions/{id}/replay", get(replay_session))
        .route("/api/sessions/{id}/resize", post(resize_session))
        .route("/api/sessions/{id}/close", post(close_session))
        .route("/ws/sessions/{id}", get(attach_session))
        .with_state(app_state);

    let addr = format!("0.0.0.0:{port}");
    eprintln!("dd-shell: listening on {addr}");
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app.into_make_service())
        .await
        .map_err(|e| Error::Internal(e.to_string()))
}

fn shell_path_and_query(uri: &Uri) -> &str {
    uri.path_and_query().map(|p| p.as_str()).unwrap_or("/")
}

fn require_shell_auth(app: &App, headers: &HeaderMap, uri: &Uri) -> Option<Response> {
    if app.auth.verify_session(&app.owner, headers).is_some() {
        None
    } else {
        let return_to =
            crate::auth::absolute_url(headers, &app.hostname, shell_path_and_query(uri));
        Some(crate::auth::unauthorized_or_redirect(
            &app.auth, headers, &return_to,
        ))
    }
}

fn ensure_shell_auth(app: &App, headers: &HeaderMap, uri: &Uri) -> Result<()> {
    if require_shell_auth(app, headers, uri).is_some() {
        Err(Error::Unauthorized)
    } else {
        Ok(())
    }
}

async fn index(State(app): State<App>, headers: HeaderMap, uri: Uri) -> Response {
    if let Some(resp) = require_shell_auth(&app, &headers, &uri) {
        return resp;
    }
    Html(html::shell("DD Shell", "", SHELL_HTML)).into_response()
}

async fn favicon() -> StatusCode {
    StatusCode::NO_CONTENT
}

async fn xterm_css() -> impl IntoResponse {
    (
        [
            ("content-type", "text/css; charset=utf-8"),
            ("cache-control", "public, max-age=31536000, immutable"),
        ],
        XTERM_CSS,
    )
}

async fn xterm_js() -> impl IntoResponse {
    (
        [
            ("content-type", "application/javascript; charset=utf-8"),
            ("cache-control", "public, max-age=31536000, immutable"),
        ],
        XTERM_JS,
    )
}

async fn xterm_fit_js() -> impl IntoResponse {
    (
        [
            ("content-type", "application/javascript; charset=utf-8"),
            ("cache-control", "public, max-age=31536000, immutable"),
        ],
        XTERM_FIT_JS,
    )
}

async fn list_recipes(
    State(app): State<App>,
    headers: HeaderMap,
    uri: Uri,
) -> Result<Json<Vec<crate::sessiond::Recipe>>> {
    ensure_shell_auth(&app, &headers, &uri)?;
    sessiond_get(&app, "/api/recipes").await.map(Json)
}

async fn list_sessions(
    State(app): State<App>,
    headers: HeaderMap,
    uri: Uri,
) -> Result<Json<Vec<crate::sessiond::SessionMeta>>> {
    ensure_shell_auth(&app, &headers, &uri)?;
    sessiond_get(&app, "/api/sessions").await.map(Json)
}

async fn create_session(
    State(app): State<App>,
    headers: HeaderMap,
    uri: Uri,
    Json(req): Json<CreateSession>,
) -> Result<Json<crate::sessiond::CreateSessionResponse>> {
    ensure_shell_auth(&app, &headers, &uri)?;
    sessiond_post(&app, "/api/sessions", &req).await.map(Json)
}

async fn replay_session(
    State(app): State<App>,
    headers: HeaderMap,
    uri: Uri,
    AxPath(id): AxPath<String>,
) -> Result<Json<crate::sessiond::ReplayResponse>> {
    ensure_shell_auth(&app, &headers, &uri)?;
    sessiond_get(&app, &format!("/api/sessions/{id}/replay"))
        .await
        .map(Json)
}

async fn sessiond_get<T: DeserializeOwned>(app: &App, path: &str) -> Result<T> {
    let url = format!("{}{}", app.sessiond_http_url.trim_end_matches('/'), path);
    let resp = app.http.get(url).send().await?;
    decode_sessiond_response(path, resp).await
}

async fn sessiond_post<T: DeserializeOwned, B: Serialize>(
    app: &App,
    path: &str,
    body: &B,
) -> Result<T> {
    let url = format!("{}{}", app.sessiond_http_url.trim_end_matches('/'), path);
    let resp = app.http.post(url).json(body).send().await?;
    decode_sessiond_response(path, resp).await
}

async fn sessiond_post_empty(app: &App, path: &str) -> Result<StatusCode> {
    let url = format!("{}{}", app.sessiond_http_url.trim_end_matches('/'), path);
    let resp = app.http.post(url).send().await?;
    decode_sessiond_empty(path, resp).await
}

async fn sessiond_post_empty_json<B: Serialize>(
    app: &App,
    path: &str,
    body: &B,
) -> Result<StatusCode> {
    let url = format!("{}{}", app.sessiond_http_url.trim_end_matches('/'), path);
    let resp = app.http.post(url).json(body).send().await?;
    decode_sessiond_empty(path, resp).await
}

async fn decode_sessiond_response<T: DeserializeOwned>(
    path: &str,
    resp: reqwest::Response,
) -> Result<T> {
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(Error::Upstream(format!(
            "sessiond {path}: HTTP {status}: {body}"
        )));
    }
    Ok(resp.json().await?)
}

async fn decode_sessiond_empty(path: &str, resp: reqwest::Response) -> Result<StatusCode> {
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(Error::Upstream(format!(
            "sessiond {path}: HTTP {status}: {body}"
        )));
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn close_session(
    State(app): State<App>,
    headers: HeaderMap,
    uri: Uri,
    AxPath(id): AxPath<String>,
) -> Result<StatusCode> {
    ensure_shell_auth(&app, &headers, &uri)?;
    sessiond_post_empty(&app, &format!("/api/sessions/{id}/close")).await
}

async fn resize_session(
    State(app): State<App>,
    headers: HeaderMap,
    uri: Uri,
    AxPath(id): AxPath<String>,
    Json(req): Json<ResizeSession>,
) -> Result<StatusCode> {
    ensure_shell_auth(&app, &headers, &uri)?;
    sessiond_post_empty_json(&app, &format!("/api/sessions/{id}/resize"), &req).await
}

async fn attach_session(
    State(app): State<App>,
    headers: HeaderMap,
    uri: Uri,
    AxPath(id): AxPath<String>,
    Query(query): Query<AttachQuery>,
    ws: WebSocketUpgrade,
) -> Result<Response> {
    ensure_shell_auth(&app, &headers, &uri)?;
    let attach_addr = app.sessiond_attach_addr.clone();
    Ok(ws.on_upgrade(move |socket| async move {
        if let Err(e) = attach(socket, attach_addr, id, query.tail.unwrap_or(true)).await {
            eprintln!("dd-shell: attach ended: {e:#}");
        }
    }))
}

#[derive(Debug, Deserialize)]
struct AttachQuery {
    tail: Option<bool>,
}

async fn attach(
    socket: WebSocket,
    attach_addr: String,
    id: String,
    tail: bool,
) -> anyhow::Result<()> {
    let mut stream = TcpStream::connect(&attach_addr).await?;
    let tail_arg = if tail { "tail" } else { "notail" };
    stream
        .write_all(format!("{id} {tail_arg}\n").as_bytes())
        .await?;
    let (mut tcp_rx, mut tcp_tx) = stream.into_split();
    let (mut ws_tx, mut ws_rx) = socket.split();

    let output = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            let n = match tcp_rx.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };
            if ws_tx
                .send(Message::Binary(buf[..n].to_vec().into()))
                .await
                .is_err()
            {
                break;
            }
        }
    });

    while let Some(msg) = ws_rx.next().await {
        match msg? {
            Message::Binary(bytes) => {
                tcp_tx.write_all(&bytes).await?;
            }
            Message::Text(text) => {
                tcp_tx.write_all(text.as_bytes()).await?;
            }
            Message::Close(_) => break,
            Message::Ping(_) | Message::Pong(_) => {}
        }
    }
    output.abort();
    Ok(())
}

const XTERM_CSS: &str = include_str!("../assets/xterm/xterm.css");
const XTERM_JS: &str = include_str!("../assets/xterm/xterm.js");
const XTERM_FIT_JS: &str = include_str!("../assets/xterm/addon-fit.js");

const SHELL_HTML: &str = r##"
<link rel="stylesheet" href="/assets/xterm/xterm.css">
<style>
body { background:#0b0d12; color:#d7deea; overflow:hidden; }
main { max-width:none; padding:0; height:100dvh; display:grid; grid-template-columns:280px 1fr; }
.sidebar { border-right:1px solid #252a36; background:#111520; overflow:auto; min-height:0; }
.sidebar-top { padding:16px; border-bottom:1px solid #252a36; }
.sidebar-scroll { padding:16px; }
.terminal-wrap { height:100dvh; display:flex; flex-direction:column; min-width:0; }
.toolbar { min-height:48px; border-bottom:1px solid #252a36; display:flex; align-items:center; gap:8px; padding:0 12px; background:#111520; }
.term { flex:1; min-height:0; background:#05070a; overflow:hidden; padding:8px; }
.term .xterm { height:100%; }
.term .xterm-viewport { background:#05070a !important; }
.group-title { color:#8791a5; font-size:11px; font-weight:700; letter-spacing:0; text-transform:uppercase; margin:18px 0 8px; }
.group-title:first-child { margin-top:0; }
.sessions { display:flex; flex-direction:column; gap:8px; }
.session { text-align:left; color:#d7deea; background:#171c29; border:1px solid #2b3242; border-radius:6px; padding:10px; cursor:pointer; }
.session.active { border-color:#7aa2f7; }
.session .name { font-weight:700; font-size:13px; }
.session .meta { margin:3px 0 0; font-size:11px; color:#8791a5; }
.recipe-launcher { display:grid; grid-template-columns:1fr auto; gap:8px; }
.recipe-select { min-width:0; background:#0b0d12; color:#d7deea; border:1px solid #2b3242; border-radius:6px; padding:9px 10px; font:inherit; font-size:13px; }
.recipe-summary { margin-top:8px; color:#8791a5; font-size:11px; line-height:1.4; }
.status { color:#8791a5; font-size:12px; margin-left:auto; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
.empty-mini { color:#8791a5; font-size:12px; padding:8px 2px; }
button.secondary { background:#252a36; color:#d7deea; }
.mobile-toggle { display:none; }
@media (max-width:860px) {
  main { display:block; height:100dvh; }
  .terminal-wrap { height:100dvh; padding-bottom:env(safe-area-inset-bottom); }
  .toolbar { min-height:44px; padding:0 8px; gap:6px; }
  .toolbar button { padding:8px 10px; font-size:12px; }
  .term { padding:4px; }
  .sidebar { position:fixed; left:0; right:0; bottom:0; z-index:20; height:min(58dvh,460px); border-right:0; border-top:1px solid #252a36; border-radius:10px 10px 0 0; transform:translateY(105%); transition:transform .16s ease; box-shadow:0 -16px 40px #0008; }
  .sidebar.open { transform:translateY(0); }
  .mobile-toggle { display:inline-flex; }
}
</style>
<div class="sidebar" id="sidebar">
  <div class="sidebar-top">
    <h1>Shell</h1>
    <div class="sub">Transitional browser attach. Use dd-client for the native workflow.</div>
  </div>
  <div class="sidebar-scroll">
    <div class="group-title">New session</div>
    <div class="recipe-launcher">
      <select class="recipe-select" id="recipe-select"></select>
      <button class="secondary" id="launch-recipe">Start</button>
    </div>
    <div class="recipe-summary" id="recipe-summary"></div>
    <div class="group-title">Sessions</div>
    <div class="sessions" id="sessions"></div>
  </div>
</div>
<div class="terminal-wrap">
  <div class="toolbar">
    <button class="secondary mobile-toggle" id="panels">Sessions</button>
    <button class="secondary" id="detach">Detach</button>
    <button class="secondary" id="close">Close session</button>
    <span class="status" id="status">No session</span>
  </div>
  <div class="term" id="terminal"></div>
</div>
<script src="/assets/xterm/xterm.js"></script>
<script src="/assets/xterm/addon-fit.js"></script>
<script>
const terminalEl = document.getElementById("terminal");
const term = new Terminal({
  cursorBlink: true,
  convertEol: false,
  fontFamily: '"JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Consolas, monospace',
  fontSize: 13,
  macOptionIsMeta: true,
  scrollback: 10000,
  theme: {
    background: "#05070a",
    foreground: "#d7deea",
    cursor: "#d7deea",
    black: "#111520",
    blue: "#7aa2f7",
    cyan: "#7dcfff",
    green: "#9ece6a",
    magenta: "#bb9af7",
    red: "#f7768e",
    white: "#d7deea",
    yellow: "#e0af68"
  }
});
const fitAddon = new FitAddon.FitAddon();
term.loadAddon(fitAddon);
term.open(terminalEl);
terminalEl.addEventListener("click", () => term.focus());
let current = null;
let ws = null;
let resizeTimer = null;
let cachedRecipes = [];

async function api(path, opts) {
  const res = await fetch(path, opts);
  if (!res.ok) throw new Error(await res.text());
  if (res.status === 204) return null;
  return res.json();
}

async function refresh() {
  const [recipes, sessions] = await Promise.all([
    api("/api/recipes").catch(() => []),
    api("/api/sessions").catch(() => [])
  ]);
  cachedRecipes = recipes;
  renderRecipes();
  renderSessions(sessions);
}

function renderRecipes() {
  const select = document.getElementById("recipe-select");
  const summary = document.getElementById("recipe-summary");
  const selected = select.value;
  select.innerHTML = "";
  if (!cachedRecipes.length) {
    select.innerHTML = `<option value="">No recipes</option>`;
    select.disabled = true;
    document.getElementById("launch-recipe").disabled = true;
    summary.textContent = "";
    return;
  }
  select.disabled = false;
  document.getElementById("launch-recipe").disabled = false;
  cachedRecipes.forEach(recipe => {
    const option = document.createElement("option");
    option.value = recipe.id;
    option.textContent = recipe.title || recipe.id;
    select.appendChild(option);
  });
  if (selected && cachedRecipes.some(r => r.id === selected)) select.value = selected;
  renderRecipeSummary();
}

function renderRecipeSummary() {
  const select = document.getElementById("recipe-select");
  const recipe = cachedRecipes.find(r => r.id === select.value);
  document.getElementById("recipe-summary").textContent = recipe ? (recipe.description || recipe.command || recipe.id) : "";
}

function renderSessions(sessions) {
  const root = document.getElementById("sessions");
  root.innerHTML = "";
  if (!sessions.length) {
    root.innerHTML = `<div class="empty-mini">No sessions</div>`;
    return;
  }
  sessions.forEach(s => {
    const el = document.createElement("button");
    el.className = "session" + (s.id === current ? " active" : "");
    const recipe = s.recipe_title || s.recipe_id || "Shell";
    el.innerHTML = `<div class="name">${escapeHtml(s.name)}</div><div class="meta">${escapeHtml(recipe)} - ${escapeHtml(s.status)} - ${new Date(s.updated_at*1000).toLocaleString()}</div>`;
    el.onclick = () => attach(s.id);
    root.appendChild(el);
  });
}

async function createSession(recipeId) {
  const body = recipeId ? {recipe_id: recipeId} : {};
  const r = await api("/api/sessions", {method:"POST", headers:{"content-type":"application/json"}, body:JSON.stringify(body)});
  closePanels();
  await refresh();
  attach(r.id);
}

async function attach(id) {
  detach();
  current = id;
  term.reset();
  fitAndResize();
  term.focus();
  setStatus("Loading history");
  const history = await api(`/api/sessions/${id}/replay`).catch(() => null);
  if (current !== id) return;
  if (history) await writeTerminal(base64Bytes(history.bytes_b64));
  term.scrollToBottom();
  setStatus("Connecting");
  ws = new WebSocket(`${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/ws/sessions/${id}?tail=false`);
  ws.binaryType = "arraybuffer";
  ws.onopen = () => {
    setStatus("Attached");
    fitAndResize();
    term.focus();
  };
  ws.onmessage = ev => term.write(typeof ev.data === "string" ? ev.data : new Uint8Array(ev.data));
  ws.onclose = () => {
    if (ws) ws = null;
    setStatus(current ? "Detached" : "No session");
  };
  refresh();
}

function detach() {
  if (ws) {
    const closing = ws;
    ws = null;
    closing.close();
  }
  setStatus(current ? "Detached" : "No session");
}

async function closeCurrent() {
  if (!current) return;
  const id = current;
  detach();
  current = null;
  await api(`/api/sessions/${id}/close`, {method:"POST"});
  term.reset();
  setStatus("Session closed");
  await refresh();
}

term.onData(data => {
  if (ws && ws.readyState === WebSocket.OPEN) ws.send(data);
});

function fitAndResize() {
  try { fitAddon.fit(); } catch (_) {}
  if (!current || !ws || ws.readyState !== WebSocket.OPEN) return;
  clearTimeout(resizeTimer);
  resizeTimer = setTimeout(sendResize, 50);
}

async function sendResize() {
  if (!current || term.cols < 2 || term.rows < 1) return;
  await fetch(`/api/sessions/${current}/resize`, {
    method: "POST",
    headers: {"content-type": "application/json"},
    body: JSON.stringify({cols: term.cols, rows: term.rows})
  }).catch(() => {});
}

function openPanels() {
  document.getElementById("sidebar").classList.add("open");
}

function closePanels() {
  document.getElementById("sidebar").classList.remove("open");
}

function base64Bytes(value) {
  const raw = atob(value);
  const bytes = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
  return bytes;
}

function writeTerminal(data) {
  return new Promise(resolve => term.write(data, resolve));
}

function setStatus(value) {
  document.getElementById("status").textContent = value;
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

document.getElementById("recipe-select").onchange = renderRecipeSummary;
document.getElementById("launch-recipe").onclick = () => {
  const id = document.getElementById("recipe-select").value;
  if (id) createSession(id);
};
document.getElementById("panels").onclick = openPanels;
document.getElementById("detach").onclick = detach;
document.getElementById("close").onclick = closeCurrent;
window.addEventListener("resize", fitAndResize);
new ResizeObserver(fitAndResize).observe(terminalEl);
refresh();
fitAndResize();
term.focus();
</script>
"##;
