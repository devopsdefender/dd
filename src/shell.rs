//! Multi-session shell sidecar.
//!
//! One process per VM, multiple reconnectable PTY sessions, read-only workload
//! terminals, and encrypted append-only transcripts on disk.

use std::cmp::Reverse;
use std::collections::{HashMap, VecDeque};
use std::fs::File as StdFile;
use std::os::fd::{AsRawFd, FromRawFd};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path as AxPath, Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine as _;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use futures_util::{SinkExt, StreamExt};
use rand::RngCore;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::fs::File as TokioFile;
use tokio::fs::OpenOptions;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, Command};
use tokio::sync::{broadcast, Mutex, RwLock};
use uuid::Uuid;

use crate::ee::Ee;
use crate::error::{Error, Result};
use crate::html;
use crate::oracle::OracleStatus;
use crate::taint::IntegrityState;
use crate::units::{self, AgentMode, ManagedUnit, UnitKind};

const DEFAULT_PORT: u16 = 7681;
const DEFAULT_DIR: &str = "/var/lib/devopsdefender/shell";
const RING_LIMIT: usize = 256 * 1024;

#[derive(Clone)]
struct App {
    sessions: Arc<RwLock<HashMap<String, Arc<Session>>>>,
    store: TranscriptStore,
    ee: Arc<Ee>,
    http: reqwest::Client,
    agent_api: String,
    default_shell: String,
}

struct Session {
    meta: RwLock<SessionMeta>,
    input: Mutex<TokioFile>,
    master_fd: i32,
    child: Mutex<Child>,
    pgid: i32,
    tx: broadcast::Sender<Vec<u8>>,
    ring: Mutex<VecDeque<u8>>,
}

#[derive(Clone, Serialize)]
struct SessionMeta {
    id: String,
    name: String,
    command: String,
    cwd: String,
    terminal_mode: TerminalMode,
    integrity_state: IntegrityState,
    integrity_reason: &'static str,
    created_at: i64,
    updated_at: i64,
    status: SessionStatus,
    exit_code: Option<i32>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "snake_case")]
enum TerminalMode {
    ReadWrite,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "snake_case")]
enum SessionStatus {
    Running,
    Exited,
}

#[derive(Deserialize)]
struct CreateSession {
    name: Option<String>,
    command: Option<String>,
    cwd: Option<String>,
}

#[derive(Serialize)]
struct CreateSessionResponse {
    id: String,
}

#[derive(Deserialize)]
struct ResizeSession {
    cols: u16,
    rows: u16,
}

#[derive(Clone)]
struct TranscriptStore {
    dir: PathBuf,
    key: [u8; 32],
}

#[derive(Serialize, Deserialize)]
struct TranscriptRecord {
    ts: i64,
    kind: String,
    data_b64: String,
}

#[derive(Serialize)]
struct ReplayResponse {
    id: String,
    bytes_b64: String,
}

#[derive(Serialize)]
struct SystemProbe {
    ok: bool,
    status: String,
    detail: Option<String>,
    data: Option<serde_json::Value>,
}

#[derive(Serialize)]
struct SystemStatus {
    ee: SystemProbe,
    agent: SystemProbe,
}

pub async fn run() -> Result<()> {
    let port = std::env::var("DD_SHELL_PORT")
        .ok()
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(DEFAULT_PORT);
    let dir = std::env::var("DD_SHELL_DIR").unwrap_or_else(|_| DEFAULT_DIR.into());
    let default_shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".into());
    let ee_socket = std::env::var("DD_SHELL_EE_SOCKET")
        .unwrap_or_else(|_| "/var/lib/easyenclave/agent.sock".into());
    let agent_api = std::env::var("DD_SHELL_AGENT_API_URL")
        .unwrap_or_else(|_| format!("http://127.0.0.1:{}", crate::cf::AGENT_API_PORT));
    let store = TranscriptStore::new(PathBuf::from(dir)).await?;

    let app_state = App {
        sessions: Arc::new(RwLock::new(HashMap::new())),
        store,
        ee: Arc::new(Ee::new(ee_socket)),
        http: reqwest::Client::builder()
            .timeout(Duration::from_secs(3))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new()),
        agent_api,
        default_shell,
    };

    let app = Router::new()
        .route("/", get(index))
        .route("/favicon.ico", get(favicon))
        .route("/assets/xterm/xterm.css", get(xterm_css))
        .route("/assets/xterm/xterm.js", get(xterm_js))
        .route("/assets/xterm/addon-fit.js", get(xterm_fit_js))
        .route("/api/sessions", get(list_sessions).post(create_session))
        .route("/api/sessions/{id}/replay", get(replay_session))
        .route("/api/sessions/{id}/resize", post(resize_session))
        .route("/api/sessions/{id}/close", post(close_session))
        .route("/api/system", get(system_status))
        .route("/api/oracles", get(list_oracles))
        .route("/api/workloads", get(list_workloads))
        .route("/api/workloads/{app}/replay", get(replay_workload))
        .route("/ws/sessions/{id}", get(attach_session))
        .with_state(app_state);

    let addr = format!("0.0.0.0:{port}");
    eprintln!("dd-shell: listening on {addr}");
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app.into_make_service())
        .await
        .map_err(|e| Error::Internal(e.to_string()))
}

async fn index() -> Html<String> {
    Html(html::shell("DD Shell", "", SHELL_HTML))
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

async fn list_sessions(State(app): State<App>) -> Json<Vec<SessionMeta>> {
    let sessions: Vec<Arc<Session>> = app.sessions.read().await.values().cloned().collect();
    let mut out = Vec::with_capacity(sessions.len());
    for s in sessions {
        out.push(s.meta.read().await.clone());
    }
    out.sort_by_key(|s| Reverse(s.updated_at));
    Json(out)
}

async fn create_session(
    State(app): State<App>,
    Json(req): Json<CreateSession>,
) -> Result<Json<CreateSessionResponse>> {
    let id = Uuid::new_v4().to_string();
    let command = req.command.unwrap_or_else(|| app.default_shell.clone());
    let cwd = req.cwd.unwrap_or_else(|| "/".into());
    let name = req.name.unwrap_or_else(|| short_name(&id));
    let now = unix_ts();

    let (child, output, input, pgid) = spawn_pty(&command, &cwd)?;
    let master_fd = input.as_raw_fd();
    let (tx, _) = broadcast::channel(512);

    let meta = SessionMeta {
        id: id.clone(),
        name,
        command,
        cwd,
        terminal_mode: TerminalMode::ReadWrite,
        integrity_state: IntegrityState::Controlled,
        integrity_reason: "interactive_pty_control",
        created_at: now,
        updated_at: now,
        status: SessionStatus::Running,
        exit_code: None,
    };
    app.store.append_meta(&meta).await?;

    let session = Arc::new(Session {
        meta: RwLock::new(meta),
        input: Mutex::new(input),
        master_fd,
        child: Mutex::new(child),
        pgid,
        tx,
        ring: Mutex::new(VecDeque::with_capacity(RING_LIMIT)),
    });

    app.sessions
        .write()
        .await
        .insert(id.clone(), session.clone());
    spawn_reader(app.store.clone(), session.clone(), output, "pty");
    spawn_waiter(app.store.clone(), session.clone());

    Ok(Json(CreateSessionResponse { id }))
}

fn spawn_pty(command: &str, cwd: &str) -> Result<(Child, TokioFile, TokioFile, i32)> {
    let mut master = -1;
    let mut slave = -1;
    let winsize = libc::winsize {
        ws_row: 24,
        ws_col: 80,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    let open_rc = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null(),
            &winsize,
        )
    };
    if open_rc != 0 {
        return Err(Error::Internal(format!(
            "openpty: {}",
            std::io::Error::last_os_error()
        )));
    }

    let master = unsafe { StdFile::from_raw_fd(master) };
    let output = TokioFile::from_std(
        master
            .try_clone()
            .map_err(|e| Error::Internal(format!("pty master clone: {e}")))?,
    );
    let input = TokioFile::from_std(master);
    let slave = unsafe { StdFile::from_raw_fd(slave) };
    let slave_fd = slave.as_raw_fd();

    let dup_slave = || -> std::io::Result<StdFile> {
        let fd = unsafe { libc::dup(slave_fd) };
        if fd < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(unsafe { StdFile::from_raw_fd(fd) })
        }
    };

    let mut cmd = Command::new(command);
    cmd.current_dir(cwd)
        .env("TERM", "xterm-256color")
        .env("COLORTERM", "truecolor")
        .stdin(Stdio::from(
            dup_slave().map_err(|e| Error::Internal(format!("pty stdin dup: {e}")))?,
        ))
        .stdout(Stdio::from(
            dup_slave().map_err(|e| Error::Internal(format!("pty stdout dup: {e}")))?,
        ))
        .stderr(Stdio::from(
            dup_slave().map_err(|e| Error::Internal(format!("pty stderr dup: {e}")))?,
        ));
    unsafe {
        cmd.pre_exec(move || {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::ioctl(slave_fd, libc::TIOCSCTTY, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = cmd
        .spawn()
        .map_err(|e| Error::BadRequest(format!("spawn {command}: {e}")))?;
    let pgid = child.id().map(|pid| pid as i32).unwrap_or_default();
    drop(slave);
    Ok((child, output, input, pgid))
}

async fn replay_session(
    State(app): State<App>,
    AxPath(id): AxPath<String>,
) -> Result<Json<ReplayResponse>> {
    let bytes = app.store.replay(&id).await?;
    Ok(Json(ReplayResponse {
        id,
        bytes_b64: base64::engine::general_purpose::STANDARD.encode(bytes),
    }))
}

async fn list_workloads(State(app): State<App>) -> Result<Json<Vec<ManagedUnit>>> {
    if let Ok(units) = agent_get(&app, "/api/units").await {
        return Ok(Json(units));
    }

    let oracles = load_oracles(&app).await;
    let mut oracle_by_app: HashMap<String, OracleStatus> = oracles
        .into_iter()
        .map(|oracle| (oracle.app_name.clone(), oracle))
        .collect();
    let mut workloads = Vec::new();

    match app.ee.list().await {
        Ok(list) => {
            if let Some(deployments) = list["deployments"].as_array() {
                for d in deployments {
                    let Some(app_name) = d["app_name"].as_str() else {
                        continue;
                    };
                    let id = d["id"].as_str().unwrap_or(app_name).to_string();
                    let oracle = oracle_by_app.remove(app_name);
                    let kind = units::kind_for_app(app_name);
                    let mut capabilities = units::base_capabilities(kind);
                    capabilities.push("logs".into());
                    if oracle.is_some() {
                        capabilities.push("oracle".into());
                    }
                    workloads.push(ManagedUnit {
                        id: id.clone(),
                        app_name: app_name.to_string(),
                        title: units::title_for_app(app_name),
                        kind,
                        agent_mode: AgentMode::ReadWrite,
                        agent_integrity_state: IntegrityState::Controlled,
                        status: d["status"].as_str().unwrap_or("unknown").to_string(),
                        image: non_empty_string(&d["image"]),
                        started_at: non_empty_string(&d["started_at"]),
                        error_message: non_empty_string(&d["error_message"]),
                        source: units::source_for_app(app_name),
                        log_line_count: workload_log_line_count(&app.ee, &id).await,
                        capabilities,
                        refs: fallback_refs(app_name, kind, oracle.as_ref()),
                        oracle,
                    });
                }
            }
        }
        Err(e) => {
            eprintln!("dd-shell: ee workload probe unavailable: {e}");
        }
    }

    workloads.extend(oracle_by_app.into_values().map(|oracle| ManagedUnit {
        id: oracle.app_name.clone(),
        app_name: oracle.app_name.clone(),
        title: oracle.title.clone(),
        kind: UnitKind::Workload,
        agent_mode: AgentMode::ReadWrite,
        agent_integrity_state: IntegrityState::Controlled,
        status: oracle.status.clone(),
        image: None,
        started_at: None,
        error_message: oracle.last_error.clone(),
        source: units::source_for_app(&oracle.app_name),
        log_line_count: 0,
        capabilities: vec!["oracle".into()],
        refs: fallback_refs(&oracle.app_name, UnitKind::Workload, Some(&oracle)),
        oracle: Some(oracle),
    }));
    workloads.sort_by(|a, b| a.app_name.cmp(&b.app_name));
    Ok(Json(workloads))
}

async fn workload_log_line_count(ee: &Ee, id: &str) -> usize {
    match ee.logs(id).await {
        Ok(logs) => logs["lines"].as_array().map(|a| a.len()).unwrap_or(0),
        Err(e) => {
            eprintln!("dd-shell: workload log probe unavailable for {id}: {e}");
            0
        }
    }
}

fn fallback_refs(
    app_name: &str,
    _kind: UnitKind,
    oracle: Option<&OracleStatus>,
) -> Vec<units::UnitRef> {
    let mut refs = units::source_for_app(app_name)
        .map(|source| vec![units::ref_item("source", "source", source)])
        .unwrap_or_default();
    if let Some(oracle) = oracle {
        if let Some(url) = &oracle.vanity_url {
            refs.push(units::ref_item("url", "oracle", url.clone()));
        }
        refs.push(units::ref_item(
            "url",
            "oracle-local",
            oracle.local_url.clone(),
        ));
    }
    refs
}

fn non_empty_string(value: &serde_json::Value) -> Option<String> {
    value
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
}

async fn list_oracles(State(app): State<App>) -> Json<Vec<OracleStatus>> {
    Json(load_oracles(&app).await)
}

async fn load_oracles(app: &App) -> Vec<OracleStatus> {
    match agent_get(app, "/api/oracles").await {
        Ok(oracles) => oracles,
        Err(e) => {
            eprintln!("dd-shell: agent oracle probe unavailable: {e}");
            Vec::new()
        }
    }
}

async fn system_status(State(app): State<App>) -> Json<SystemStatus> {
    let ee = match app.ee.health().await {
        Ok(data) => SystemProbe {
            ok: true,
            status: "healthy".into(),
            detail: None,
            data: Some(data),
        },
        Err(e) => SystemProbe {
            ok: false,
            status: "unavailable".into(),
            detail: Some(e.to_string()),
            data: None,
        },
    };
    let agent = match agent_get(&app, "/health").await {
        Ok(data) => SystemProbe {
            ok: true,
            status: "healthy".into(),
            detail: None,
            data: Some(data),
        },
        Err(e) => SystemProbe {
            ok: false,
            status: "unavailable".into(),
            detail: Some(e.to_string()),
            data: None,
        },
    };
    Json(SystemStatus { ee, agent })
}

async fn agent_get<T: DeserializeOwned>(app: &App, path: &str) -> Result<T> {
    let url = format!("{}{}", app.agent_api.trim_end_matches('/'), path);
    let resp = app.http.get(url).send().await?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(Error::Upstream(format!(
            "agent api {path}: HTTP {status}: {body}"
        )));
    }
    Ok(resp.json().await?)
}

async fn replay_workload(
    State(app): State<App>,
    AxPath(name): AxPath<String>,
) -> Result<Json<ReplayResponse>> {
    let list = app.ee.list().await?;
    let id = list["deployments"]
        .as_array()
        .and_then(|a| {
            a.iter()
                .find(|d| d["app_name"].as_str() == Some(name.as_str()))
        })
        .and_then(|d| d["id"].as_str())
        .map(String::from)
        .ok_or(Error::NotFound)?;
    let logs = app.ee.logs(&id).await?;
    let bytes = workload_log_bytes(&logs);
    Ok(Json(ReplayResponse {
        id: name,
        bytes_b64: base64::engine::general_purpose::STANDARD.encode(bytes),
    }))
}

async fn close_session(State(app): State<App>, AxPath(id): AxPath<String>) -> Result<StatusCode> {
    let Some(session) = app.sessions.write().await.remove(&id) else {
        return Err(Error::NotFound);
    };
    let pgid = session.pgid;
    mark_session_exited(&app.store, &session, None).await;
    terminate_process_group(id, pgid);
    Ok(StatusCode::NO_CONTENT)
}

fn terminate_process_group(id: String, pgid: i32) {
    if pgid <= 0 {
        return;
    }
    tokio::spawn(async move {
        for (signal, delay) in [
            (libc::SIGHUP, Duration::from_millis(250)),
            (libc::SIGTERM, Duration::from_millis(1500)),
            (libc::SIGKILL, Duration::ZERO),
        ] {
            let rc = unsafe { libc::kill(-pgid, signal) };
            if rc != 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() != Some(libc::ESRCH) {
                    eprintln!("dd-shell: signal {signal} for {id}: {err}");
                }
                break;
            }
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
        }
    });
}

fn workload_log_bytes(logs: &serde_json::Value) -> Vec<u8> {
    let mut out = Vec::new();
    if let Some(lines) = logs["lines"].as_array() {
        for line in lines.iter().filter_map(|v| v.as_str()) {
            out.extend_from_slice(line.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
    }
    out
}

async fn resize_session(
    State(app): State<App>,
    AxPath(id): AxPath<String>,
    Json(req): Json<ResizeSession>,
) -> Result<StatusCode> {
    if req.cols == 0 || req.rows == 0 {
        return Err(Error::BadRequest("terminal size must be non-zero".into()));
    }
    let Some(session) = app.sessions.read().await.get(&id).cloned() else {
        return Err(Error::NotFound);
    };
    let winsize = libc::winsize {
        ws_row: req.rows,
        ws_col: req.cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    let rc = unsafe { libc::ioctl(session.master_fd, libc::TIOCSWINSZ, &winsize) };
    if rc != 0 {
        return Err(Error::Internal(format!(
            "resize pty: {}",
            std::io::Error::last_os_error()
        )));
    }
    if session.pgid > 0 {
        unsafe {
            libc::kill(-session.pgid, libc::SIGWINCH);
        }
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn attach_session(
    State(app): State<App>,
    AxPath(id): AxPath<String>,
    Query(query): Query<AttachQuery>,
    ws: WebSocketUpgrade,
) -> Result<Response> {
    let Some(session) = app.sessions.read().await.get(&id).cloned() else {
        return Err(Error::NotFound);
    };
    Ok(ws.on_upgrade(move |socket| async move {
        if let Err(e) = attach(socket, session, query.tail.unwrap_or(true)).await {
            eprintln!("dd-shell: attach ended: {e:#}");
        }
    }))
}

#[derive(Debug, Deserialize)]
struct AttachQuery {
    tail: Option<bool>,
}

async fn attach(socket: WebSocket, session: Arc<Session>, tail: bool) -> anyhow::Result<()> {
    let (mut ws_tx, mut ws_rx) = socket.split();

    if tail {
        let ring = session.ring.lock().await;
        if !ring.is_empty() {
            let bytes: Vec<u8> = ring.iter().copied().collect();
            ws_tx.send(Message::Binary(bytes.into())).await?;
        }
    }

    let mut output_rx = session.tx.subscribe();
    let output = tokio::spawn(async move {
        while let Ok(bytes) = output_rx.recv().await {
            if ws_tx.send(Message::Binary(bytes.into())).await.is_err() {
                break;
            }
        }
    });

    while let Some(msg) = ws_rx.next().await {
        match msg? {
            Message::Binary(bytes) => {
                session.input.lock().await.write_all(&bytes).await?;
            }
            Message::Text(text) => {
                session
                    .input
                    .lock()
                    .await
                    .write_all(text.as_bytes())
                    .await?;
            }
            Message::Close(_) => break,
            Message::Ping(_) | Message::Pong(_) => {}
        }
    }
    output.abort();
    Ok(())
}

fn spawn_reader<R>(store: TranscriptStore, session: Arc<Session>, mut reader: R, kind: &'static str)
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let id = session.meta.read().await.id.clone();
        let mut buf = [0u8; 4096];
        loop {
            match reader.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    let bytes = buf[..n].to_vec();
                    push_ring(&session, &bytes).await;
                    let _ = session.tx.send(bytes.clone());
                    if let Err(e) = store.append_bytes(&id, kind, &bytes).await {
                        eprintln!("dd-shell: transcript append failed: {e}");
                    }
                    session.meta.write().await.updated_at = unix_ts();
                }
                Err(e) => {
                    eprintln!("dd-shell: {kind} read failed: {e}");
                    break;
                }
            }
        }
    });
}

fn spawn_waiter(store: TranscriptStore, session: Arc<Session>) {
    tokio::spawn(async move {
        let status = {
            let mut child = session.child.lock().await;
            child.wait().await
        };
        mark_session_exited(&store, &session, status.ok().and_then(|s| s.code())).await;
    });
}

async fn mark_session_exited(store: &TranscriptStore, session: &Session, exit_code: Option<i32>) {
    let mut meta = session.meta.write().await;
    if matches!(meta.status, SessionStatus::Exited) {
        return;
    }
    meta.updated_at = unix_ts();
    meta.status = SessionStatus::Exited;
    meta.exit_code = exit_code;
    if let Err(e) = store.append_meta(&meta).await {
        eprintln!("dd-shell: exit meta append failed: {e}");
    }
}

async fn push_ring(session: &Session, bytes: &[u8]) {
    let mut ring = session.ring.lock().await;
    for b in bytes {
        if ring.len() >= RING_LIMIT {
            ring.pop_front();
        }
        ring.push_back(*b);
    }
}

impl TranscriptStore {
    async fn new(dir: PathBuf) -> Result<Self> {
        tokio::fs::create_dir_all(&dir).await?;
        let key = history_key(&dir).await?;
        Ok(Self { dir, key })
    }

    async fn append_meta(&self, meta: &SessionMeta) -> Result<()> {
        let bytes = serde_json::to_vec(meta).map_err(|e| Error::Internal(e.to_string()))?;
        self.append_bytes(&meta.id, "meta", &bytes).await
    }

    async fn append_bytes(&self, id: &str, kind: &str, bytes: &[u8]) -> Result<()> {
        let record = TranscriptRecord {
            ts: unix_ts(),
            kind: kind.to_string(),
            data_b64: base64::engine::general_purpose::STANDARD.encode(bytes),
        };
        let plain = serde_json::to_vec(&record).map_err(|e| Error::Internal(e.to_string()))?;
        let line = self.encrypt_line(&plain)?;
        let path = self.path(id);
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .await?;
        f.write_all(line.as_bytes()).await?;
        f.write_all(b"\n").await?;
        Ok(())
    }

    async fn replay(&self, id: &str) -> Result<Vec<u8>> {
        let path = self.path(id);
        if !Path::new(&path).exists() {
            return Err(Error::NotFound);
        }
        let text = tokio::fs::read_to_string(path).await?;
        let mut out = Vec::new();
        for line in text.lines().filter(|l| !l.trim().is_empty()) {
            let plain = self.decrypt_line(line)?;
            let record: TranscriptRecord =
                serde_json::from_slice(&plain).map_err(|e| Error::Internal(e.to_string()))?;
            if record.kind == "pty" || record.kind == "stdout" || record.kind == "stderr" {
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(record.data_b64)
                    .map_err(|e| Error::Internal(e.to_string()))?;
                out.extend_from_slice(&bytes);
            }
        }
        Ok(out)
    }

    fn path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.log.enc"))
    }

    fn encrypt_line(&self, plain: &[u8]) -> Result<String> {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key));
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), plain)
            .map_err(|e| Error::Internal(format!("encrypt transcript: {e}")))?;
        let mut packed = nonce.to_vec();
        packed.extend_from_slice(&ciphertext);
        Ok(base64::engine::general_purpose::STANDARD.encode(packed))
    }

    fn decrypt_line(&self, line: &str) -> Result<Vec<u8>> {
        let packed = base64::engine::general_purpose::STANDARD
            .decode(line)
            .map_err(|e| Error::Internal(e.to_string()))?;
        if packed.len() < 13 {
            return Err(Error::Internal("truncated transcript record".into()));
        }
        let (nonce, ciphertext) = packed.split_at(12);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key));
        cipher
            .decrypt(Nonce::from_slice(nonce), ciphertext)
            .map_err(|e| Error::Internal(format!("decrypt transcript: {e}")))
    }
}

async fn history_key(dir: &Path) -> Result<[u8; 32]> {
    if let Ok(raw) = std::env::var("DD_SHELL_HISTORY_KEY") {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(raw.trim())
            .or_else(|_| hex::decode(raw.trim()))
            .map_err(|_| Error::BadRequest("DD_SHELL_HISTORY_KEY must be base64 or hex".into()))?;
        if bytes.len() != 32 {
            return Err(Error::BadRequest(
                "DD_SHELL_HISTORY_KEY must decode to 32 bytes".into(),
            ));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        return Ok(key);
    }

    let key_path = dir.join("history.key");
    if let Ok(bytes) = tokio::fs::read(&key_path).await {
        if bytes.len() == 32 {
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes);
            return Ok(key);
        }
    }

    let mut material = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut material);
    tokio::fs::write(&key_path, material).await?;
    let mut hasher = Sha256::new();
    hasher.update(material);
    hasher.update(b"dd-shell-history-v1");
    Ok(hasher.finalize().into())
}

fn unix_ts() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs() as i64
}

fn short_name(id: &str) -> String {
    format!("shell-{}", &id[..8])
}

const XTERM_CSS: &str = include_str!("../assets/xterm/xterm.css");
const XTERM_JS: &str = include_str!("../assets/xterm/xterm.js");
const XTERM_FIT_JS: &str = include_str!("../assets/xterm/addon-fit.js");

const SHELL_HTML: &str = r##"
<link rel="stylesheet" href="/assets/xterm/xterm.css">
<style>
body { background:#0b0d12; color:#d7deea; }
main { max-width:none; padding:0; height:100vh; display:grid; grid-template-columns:280px 1fr; }
.sidebar { border-right:1px solid #252a36; background:#111520; overflow:auto; min-height:0; }
.sidebar-top { position:sticky; top:0; z-index:5; background:#111520; padding:16px 16px 12px; border-bottom:1px solid #252a36; }
.sidebar-scroll { padding:0 16px 16px; }
.terminal-wrap { height:100vh; display:flex; flex-direction:column; min-width:0; }
.toolbar { height:48px; border-bottom:1px solid #252a36; display:flex; align-items:center; gap:8px; padding:0 12px; background:#111520; }
.term { flex:1; min-height:0; background:#05070a; overflow:hidden; padding:8px; }
.term .xterm { height:100%; }
.term .xterm-viewport { background:#05070a !important; }
.groups { display:flex; flex-direction:column; gap:18px; }
.group-title { position:sticky; top:126px; z-index:4; color:#8791a5; font-size:11px; font-weight:700; letter-spacing:0; text-transform:uppercase; margin:0 -16px 8px; padding:8px 16px; background:#111520; border-bottom:1px solid #202634; }
.sessions { display:flex; flex-direction:column; gap:8px; }
.session { text-align:left; color:#d7deea; background:#171c29; border:1px solid #2b3242; border-radius:6px; padding:10px; cursor:pointer; }
.session.active { border-color:#7aa2f7; }
.session .name { font-weight:700; font-size:13px; }
.session .meta { margin:3px 0 0; font-size:11px; color:#8791a5; }
.session.readonly { background:#131720; border-style:dashed; }
.badges { display:flex; flex-wrap:wrap; gap:5px; margin-top:7px; }
.badge { border:1px solid #2b3242; border-radius:999px; padding:1px 6px; color:#8791a5; font-size:10px; }
.badge.ok { color:#9ece6a; border-color:#334b35; }
.badge.bad { color:#f7768e; border-color:#57323d; }
.system { display:flex; flex-direction:column; gap:8px; }
.probe { color:#d7deea; background:#171c29; border:1px solid #2b3242; border-radius:6px; padding:10px; }
.probe .row { display:flex; align-items:center; justify-content:space-between; gap:8px; }
.probe .name { font-weight:700; font-size:13px; }
.probe .meta { margin-top:3px; color:#8791a5; font-size:11px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
.pill { border:1px solid #2b3242; border-radius:999px; padding:2px 7px; color:#8791a5; font-size:11px; }
.pill.ok { color:#9ece6a; border-color:#334b35; }
.pill.bad { color:#f7768e; border-color:#57323d; }
.new { width:100%; }
.filter { width:100%; margin-top:10px; box-sizing:border-box; background:#0b0d12; color:#d7deea; border:1px solid #2b3242; border-radius:6px; padding:9px 10px; font:inherit; font-size:13px; }
.filter:focus { outline:1px solid #7aa2f7; border-color:#7aa2f7; }
.empty-mini { color:#8791a5; font-size:12px; padding:8px 2px; }
.status { color:#8791a5; font-size:12px; margin-left:auto; }
button.secondary { background:#252a36; color:#d7deea; }
@media (max-width:760px) { main { grid-template-columns:1fr; grid-template-rows:240px 1fr; } .sidebar { height:240px; border-right:0; border-bottom:1px solid #252a36; } .group-title { top:126px; } .terminal-wrap { height:calc(100vh - 240px); } }
</style>
<div class="sidebar">
  <div class="sidebar-top">
    <h1>Shell</h1>
    <div class="sub">Observed logs and controlled PTYs</div>
    <button class="new" id="new-session">New session</button>
    <input class="filter" id="workload-filter" type="search" placeholder="Filter workloads">
  </div>
  <div class="sidebar-scroll">
    <div class="groups">
      <div>
        <div class="group-title">System</div>
        <div class="system" id="system"></div>
      </div>
      <div>
        <div class="group-title">Read-write sessions</div>
        <div class="sessions" id="sessions"></div>
      </div>
      <div>
        <div class="group-title">Read-only workloads</div>
        <div class="sessions" id="workloads"></div>
      </div>
    </div>
  </div>
</div>
<div class="terminal-wrap">
  <div class="toolbar">
    <button class="secondary" id="close">Close session</button>
    <button class="secondary" id="notify" title="Enable desktop notifications">Notify</button>
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
let currentKind = null;
let ws = null;
let resizeTimer = null;
let workloadTimer = null;
let notifyMode = localStorage.getItem("dd-shell-notify") || "always";
let oscBuffer = "";
let cachedWorkloads = [];
const decoder = new TextDecoder();

async function api(path, opts) {
  const res = await fetch(path, opts);
  if (!res.ok) throw new Error(await res.text());
  if (res.status === 204) return null;
  return res.json();
}

async function refresh() {
  const [system, sessions, workloads] = await Promise.all([
    api("/api/system").catch(() => null),
    api("/api/sessions").catch(() => []),
    api("/api/workloads").catch(() => [])
  ]);
  renderSystem(system);
  cachedWorkloads = workloads;
  const root = document.getElementById("sessions");
  root.innerHTML = "";
  sessions.forEach(s => {
    const el = document.createElement("button");
    el.className = "session" + (currentKind === "session" && s.id === current ? " active" : "");
    el.innerHTML = `<div class="name">${escapeHtml(s.name)}</div><div class="meta">read-write - controlled - ${s.status} - ${new Date(s.updated_at*1000).toLocaleString()}</div>`;
    el.onclick = () => attach(s.id);
    root.appendChild(el);
  });
  renderWorkloads();
}

function renderWorkloads() {
  const workloadRoot = document.getElementById("workloads");
  const query = document.getElementById("workload-filter").value.trim().toLowerCase();
  const workloads = cachedWorkloads.filter(w => workloadSearchText(w).includes(query));
  workloadRoot.innerHTML = "";
  if (workloads.length === 0) {
    workloadRoot.innerHTML = `<div class="empty-mini">${query ? "No matching workloads" : "No workloads"}</div>`;
    return;
  }
  workloads.forEach(w => {
    const el = document.createElement("button");
    el.className = "session readonly" + (currentKind === "workload" && w.app_name === current ? " active" : "");
    el.innerHTML = workloadButtonHtml(w);
    el.onclick = () => attachWorkload(w.app_name);
    workloadRoot.appendChild(el);
  });
}

function workloadSearchText(w) {
  const caps = Array.isArray(w.capabilities) ? w.capabilities.join(" ") : "";
  const refs = Array.isArray(w.refs) ? w.refs.map(r => `${r.label} ${r.value}`).join(" ") : "";
  return `${w.title || ""} ${w.app_name || ""} ${w.kind || ""} ${w.status || ""} ${caps} ${refs}`.toLowerCase();
}

function renderSystem(system) {
  const root = document.getElementById("system");
  if (!system) {
    root.innerHTML = `<div class="probe"><div class="row"><span class="name">Shell</span><span class="pill bad">unknown</span></div><div class="meta">system probe unavailable</div></div>`;
    return;
  }
  root.innerHTML = [
    probeHtml("EasyEnclave", system.ee),
    probeHtml("Agent API", system.agent)
  ].join("");
}

function probeHtml(name, probe) {
  const ok = probe && probe.ok;
  const status = probe ? probe.status : "unknown";
  const detail = probeSummary(probe);
  return `<div class="probe"><div class="row"><span class="name">${escapeHtml(name)}</span><span class="pill ${ok ? "ok" : "bad"}">${escapeHtml(status)}</span></div><div class="meta">${escapeHtml(detail)}</div></div>`;
}

function probeSummary(probe) {
  if (!probe) return "no data";
  if (!probe.ok) return probe.detail || "unavailable";
  const data = probe.data || {};
  const count = data.workload_count ?? data.deployment_count ?? (Array.isArray(data.deployments) ? data.deployments.length : null);
  const oracleCount = data.oracle_count ?? (Array.isArray(data.oracles) ? data.oracles.length : null);
  const parts = [];
  if (count !== null) parts.push(`${count} workload(s)`);
  if (oracleCount !== null) parts.push(`${oracleCount} oracle(s)`);
  if (data.integrity_state) parts.push(data.integrity_state);
  if (data.vm_name) parts.push(data.vm_name);
  return parts.length ? parts.join(" - ") : "reachable";
}

async function createSession() {
  const r = await api("/api/sessions", {method:"POST", headers:{"content-type":"application/json"}, body:JSON.stringify({})});
  await refresh();
  attach(r.id);
}

async function attach(id) {
  if (ws) ws.close();
  stopWorkloadRefresh();
  current = id;
  currentKind = "session";
  term.reset();
  fitAndResize();
  term.focus();
  document.getElementById("close").disabled = false;
  document.getElementById("status").textContent = "Loading history";
  const history = await api(`/api/sessions/${id}/replay`).catch(() => null);
  if (current !== id) return;
  if (history) await writeTerminal(base64Bytes(history.bytes_b64));
  term.scrollToBottom();
  document.getElementById("status").textContent = "Connecting";
  ws = new WebSocket(`${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/ws/sessions/${id}?tail=false`);
  ws.binaryType = "arraybuffer";
  ws.onopen = () => {
    document.getElementById("status").textContent = "Controlled PTY";
    fitAndResize();
    term.focus();
  };
  ws.onmessage = ev => {
    if (typeof ev.data === "string") {
      scanNotifications(ev.data);
      term.write(ev.data);
    } else {
      const bytes = new Uint8Array(ev.data);
      scanNotifications(bytes);
      term.write(bytes);
    }
  };
  ws.onclose = () => document.getElementById("status").textContent = "Detached";
  refresh();
  setTimeout(() => term.focus(), 0);
}

async function attachWorkload(name) {
  if (ws) ws.close();
  ws = null;
  stopWorkloadRefresh();
  current = name;
  currentKind = "workload";
  await loadWorkload(name);
  workloadTimer = setInterval(() => loadWorkload(name), 2000);
}

async function loadWorkload(name) {
  if (currentKind !== "workload" || current !== name) return;
  term.reset();
  term.focus();
  document.getElementById("close").disabled = true;
  document.getElementById("status").textContent = "Loading read-only workload";
  const [workloads, history] = await Promise.all([
    api("/api/workloads").catch(() => []),
    api(`/api/workloads/${encodeURIComponent(name)}/replay`).catch(() => null)
  ]);
  if (currentKind !== "workload" || current !== name) return;
  const workload = workloads.find(w => w.app_name === name);
  if (workload) await writeTerminal(workloadText(workload));
  const logBytes = history ? base64Bytes(history.bytes_b64) : new Uint8Array();
  if (logBytes.length) await writeTerminal(logBytes);
  else await writeTerminal("No logs yet\r\n");
  term.scrollToBottom();
  document.getElementById("status").textContent = "Observed read-only";
  refresh();
}

function stopWorkloadRefresh() {
  if (workloadTimer) clearInterval(workloadTimer);
  workloadTimer = null;
}

term.onData(data => {
  if (currentKind === "session" && ws && ws.readyState === WebSocket.OPEN) ws.send(data);
});

document.getElementById("new-session").onclick = createSession;
document.getElementById("workload-filter").oninput = renderWorkloads;
document.getElementById("close").onclick = async () => {
  if (!current || currentKind !== "session") return;
  await api(`/api/sessions/${current}/close`, {method:"POST"});
  if (ws) ws.close();
  await refresh();
};
document.getElementById("notify").onclick = async () => {
  if (!("Notification" in window)) {
    document.getElementById("status").textContent = "Notifications unavailable";
    return;
  }
  const permission = Notification.permission === "default" ? await Notification.requestPermission() : Notification.permission;
  if (permission === "granted") {
    notifyMode = "always";
    localStorage.setItem("dd-shell-notify", notifyMode);
    document.getElementById("status").textContent = "Notifications enabled";
  } else {
    notifyMode = "off";
    localStorage.setItem("dd-shell-notify", notifyMode);
    document.getElementById("status").textContent = "Notifications blocked";
  }
};
function base64Bytes(value) {
  const raw = atob(value);
  const bytes = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
  return bytes;
}
function writeTerminal(data) {
  return new Promise(resolve => term.write(data, resolve));
}

function workloadButtonHtml(w) {
  const oracle = w.oracle;
  const caps = Array.isArray(w.capabilities) ? w.capabilities : [];
  const badges = caps.map(cap => {
    const cls = cap === "oracle" && oracle && oracle.status === "healthy" ? " ok" : cap === "oracle" && oracle && oracle.status === "error" ? " bad" : "";
    return `<span class="badge${cls}">${escapeHtml(cap)}</span>`;
  }).join("");
  const status = oracle ? `${w.status} / oracle ${oracle.status}` : w.status;
  const kind = String(w.kind || "workload").replaceAll("_", " ");
  const logs = Number.isFinite(w.log_line_count) ? `${w.log_line_count} log line(s)` : "logs unknown";
  return `<div class="name">${escapeHtml(w.title || w.app_name)}</div><div class="meta">${escapeHtml(kind)} - ${escapeHtml(w.agent_mode || "unknown")} - ${escapeHtml(w.agent_integrity_state || "unknown")} - ${escapeHtml(status)} - ${escapeHtml(logs)}</div><div class="badges">${badges}</div>`;
}

function workloadText(w) {
  const lines = [
    `${w.title || w.app_name}`,
    `app: ${w.app_name}`,
    `kind: ${w.kind || "workload"}`,
    `agent mode: ${w.agent_mode || "unknown"}`,
    `agent integrity: ${w.agent_integrity_state || "unknown"}`,
    `status: ${w.status}`,
    `deployment id: ${w.id || "unknown"}`,
    `source: ${w.source || "unknown"}`,
    `image: ${w.image || "none"}`,
    `started: ${w.started_at || "unknown"}`,
    `log lines: ${w.log_line_count ?? 0}`
  ];
  if (w.error_message) lines.push(`error: ${w.error_message}`);
  const refs = Array.isArray(w.refs) ? w.refs : [];
  if (refs.length) {
    lines.push("", "refs:");
    refs.forEach(ref => lines.push(`${ref.label}: ${ref.value}`));
  }
  const o = w.oracle;
  if (!o) {
    lines.push("", "logs:");
    return lines.join("\r\n") + "\r\n";
  }
  lines.push(
    "",
    "oracle:",
    `title: ${o.title || o.app_name}`,
    `status: ${o.status}`,
    `last ok: ${o.last_ok || "never"}`,
    `local: ${o.local_url || "unknown"}`
  );
  if (o.vanity_url) lines.push(`vanity: ${o.vanity_url}`);
  if (o.last_error) lines.push(`error: ${o.last_error}`);
  if (o.sample !== null && o.sample !== undefined) {
    lines.push("", "sample:", JSON.stringify(o.sample, null, 2));
  }
  lines.push("", "logs:");
  return lines.join("\r\n") + "\r\n";
}
function fitAndResize() {
  try { fitAddon.fit(); } catch (_) {}
  if (!current || currentKind !== "session") return;
  clearTimeout(resizeTimer);
  resizeTimer = setTimeout(sendResize, 50);
}
async function sendResize() {
  if (!current || currentKind !== "session" || term.cols < 2 || term.rows < 1) return;
  await fetch(`/api/sessions/${current}/resize`, {
    method: "POST",
    headers: {"content-type": "application/json"},
    body: JSON.stringify({cols: term.cols, rows: term.rows})
  }).catch(() => {});
}
function scanNotifications(data) {
  const text = typeof data === "string" ? data : decoder.decode(data, {stream:true});
  oscBuffer += text;
  const pattern = /\x1b\](9;([^\x07\x1b]*?)|777;notify;([^\x07\x1b]*?);([^\x07\x1b]*?))(\x07|\x1b\\)/g;
  let match;
  let consumed = 0;
  while ((match = pattern.exec(oscBuffer))) {
    consumed = pattern.lastIndex;
    if (match[2] !== undefined) notify("Shell", match[2]);
    else notify(match[3] || "Shell", match[4] || "");
  }
  if (consumed > 0) oscBuffer = oscBuffer.slice(consumed);
  if (oscBuffer.length > 8192) oscBuffer = oscBuffer.slice(-1024);
}
function notify(title, body) {
  if (!("Notification" in window) || Notification.permission !== "granted") return;
  if (notifyMode !== "always" && document.hasFocus()) return;
  const n = new Notification(title || "Shell", {
    body: body || "",
    tag: current ? `dd-shell-${current}` : "dd-shell"
  });
  n.onclick = () => {
    window.focus();
    term.focus();
    n.close();
  };
}
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
window.addEventListener("resize", fitAndResize);
new ResizeObserver(fitAndResize).observe(terminalEl);
refresh();
fitAndResize();
term.focus();
</script>
"##;
