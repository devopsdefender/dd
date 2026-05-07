//! Multi-session shell sidecar.
//!
//! This is the replacement target for the current ttyd workload: one process
//! per agent VM, multiple reconnectable PTY sessions, and encrypted append-only
//! transcripts on disk.

use std::cmp::Reverse;
use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path as AxPath, State};
use axum::http::StatusCode;
use axum::response::{Html, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine as _;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use futures_util::{SinkExt, StreamExt};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::fs::OpenOptions;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, ChildStdin, Command};
use tokio::sync::{broadcast, Mutex, RwLock};
use uuid::Uuid;

use crate::error::{Error, Result};
use crate::html;

const DEFAULT_PORT: u16 = 7681;
const DEFAULT_DIR: &str = "/var/lib/devopsdefender/shell";
const RING_LIMIT: usize = 256 * 1024;

#[derive(Clone)]
struct App {
    sessions: Arc<RwLock<HashMap<String, Arc<Session>>>>,
    store: TranscriptStore,
    default_shell: String,
}

struct Session {
    meta: RwLock<SessionMeta>,
    stdin: Mutex<ChildStdin>,
    child: Mutex<Child>,
    tx: broadcast::Sender<Vec<u8>>,
    ring: Mutex<VecDeque<u8>>,
}

#[derive(Clone, Serialize)]
struct SessionMeta {
    id: String,
    name: String,
    command: String,
    cwd: String,
    created_at: i64,
    updated_at: i64,
    status: SessionStatus,
    exit_code: Option<i32>,
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

pub async fn run() -> Result<()> {
    let port = std::env::var("DD_SHELL_PORT")
        .ok()
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(DEFAULT_PORT);
    let dir = std::env::var("DD_SHELL_DIR").unwrap_or_else(|_| DEFAULT_DIR.into());
    let default_shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".into());
    let store = TranscriptStore::new(PathBuf::from(dir)).await?;

    let app_state = App {
        sessions: Arc::new(RwLock::new(HashMap::new())),
        store,
        default_shell,
    };

    let app = Router::new()
        .route("/", get(index))
        .route("/favicon.ico", get(favicon))
        .route("/api/sessions", get(list_sessions).post(create_session))
        .route("/api/sessions/{id}/replay", get(replay_session))
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

async fn index() -> Html<String> {
    Html(html::shell("DD Shell", "", SHELL_HTML))
}

async fn favicon() -> StatusCode {
    StatusCode::NO_CONTENT
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

    let mut cmd = Command::new(&command);
    cmd.current_dir(&cwd)
        .env("TERM", "xterm-256color")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd
        .spawn()
        .map_err(|e| Error::BadRequest(format!("spawn {command}: {e}")))?;

    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| Error::Internal("child stdin unavailable".into()))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| Error::Internal("child stdout unavailable".into()))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| Error::Internal("child stderr unavailable".into()))?;
    let (tx, _) = broadcast::channel(512);

    let meta = SessionMeta {
        id: id.clone(),
        name,
        command,
        cwd,
        created_at: now,
        updated_at: now,
        status: SessionStatus::Running,
        exit_code: None,
    };
    app.store.append_meta(&meta).await?;

    let session = Arc::new(Session {
        meta: RwLock::new(meta),
        stdin: Mutex::new(stdin),
        child: Mutex::new(child),
        tx,
        ring: Mutex::new(VecDeque::with_capacity(RING_LIMIT)),
    });

    app.sessions
        .write()
        .await
        .insert(id.clone(), session.clone());
    spawn_reader(app.store.clone(), session.clone(), stdout, "stdout");
    spawn_reader(app.store.clone(), session.clone(), stderr, "stderr");
    spawn_waiter(app.store.clone(), session.clone());

    Ok(Json(CreateSessionResponse { id }))
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

async fn close_session(State(app): State<App>, AxPath(id): AxPath<String>) -> Result<StatusCode> {
    let Some(session) = app.sessions.read().await.get(&id).cloned() else {
        return Err(Error::NotFound);
    };
    let mut child = session.child.lock().await;
    if let Err(e) = child.kill().await {
        eprintln!("dd-shell: kill {id}: {e}");
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn attach_session(
    State(app): State<App>,
    AxPath(id): AxPath<String>,
    ws: WebSocketUpgrade,
) -> Result<Response> {
    let Some(session) = app.sessions.read().await.get(&id).cloned() else {
        return Err(Error::NotFound);
    };
    Ok(ws.on_upgrade(move |socket| async move {
        if let Err(e) = attach(socket, session).await {
            eprintln!("dd-shell: attach ended: {e:#}");
        }
    }))
}

async fn attach(socket: WebSocket, session: Arc<Session>) -> anyhow::Result<()> {
    let (mut ws_tx, mut ws_rx) = socket.split();

    {
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
                session.stdin.lock().await.write_all(&bytes).await?;
            }
            Message::Text(text) => {
                session
                    .stdin
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
        let mut meta = session.meta.write().await;
        meta.updated_at = unix_ts();
        meta.status = SessionStatus::Exited;
        meta.exit_code = status.ok().and_then(|s| s.code());
        if let Err(e) = store.append_meta(&meta).await {
            eprintln!("dd-shell: exit meta append failed: {e}");
        }
    });
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
            if record.kind == "stdout" || record.kind == "stderr" {
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

const SHELL_HTML: &str = r##"
<style>
body { background:#0b0d12; color:#d7deea; }
main { max-width:none; padding:0; height:100vh; display:grid; grid-template-columns:280px 1fr; }
.sidebar { border-right:1px solid #252a36; padding:16px; background:#111520; overflow:auto; }
.terminal-wrap { height:100vh; display:flex; flex-direction:column; min-width:0; }
.toolbar { height:48px; border-bottom:1px solid #252a36; display:flex; align-items:center; gap:8px; padding:0 12px; background:#111520; }
.term { flex:1; min-height:0; background:#05070a; overflow:auto; }
.fallback-term { min-height:100%; padding:12px; white-space:pre-wrap; overflow-wrap:anywhere; outline:none; color:#d7deea; font:13px/1.45 "JetBrains Mono", ui-monospace, monospace; }
.fallback-term:focus { box-shadow:inset 0 0 0 1px #7aa2f7; }
.sessions { display:flex; flex-direction:column; gap:8px; margin-top:14px; }
.session { text-align:left; color:#d7deea; background:#171c29; border:1px solid #2b3242; border-radius:6px; padding:10px; cursor:pointer; }
.session.active { border-color:#7aa2f7; }
.session .name { font-weight:700; font-size:13px; }
.session .meta { margin:3px 0 0; font-size:11px; color:#8791a5; }
.new { width:100%; }
.status { color:#8791a5; font-size:12px; margin-left:auto; }
button.secondary { background:#252a36; color:#d7deea; }
@media (max-width:760px) { main { grid-template-columns:1fr; } .sidebar { height:220px; border-right:0; border-bottom:1px solid #252a36; } }
</style>
<div class="sidebar">
  <h1>Shell</h1>
  <div class="sub">Reconnectable sessions on this agent</div>
  <button class="new" id="new-session">New session</button>
  <div class="sessions" id="sessions"></div>
</div>
<div class="terminal-wrap">
  <div class="toolbar">
    <button class="secondary" id="replay">Replay history</button>
    <button class="secondary" id="close">Close session</button>
    <span class="status" id="status">No session</span>
  </div>
  <div class="term" id="terminal"></div>
</div>
<script>
function makeTerminal() {
  let onData = () => {};
  let screen = null;
  let text = "";
  const clean = s => String(s)
    .replace(/\x1b\[[0-?]*[ -/]*[@-~]/g, "")
    .replace(/\x1b\][^\x07]*(\x07|\x1b\\)/g, "");
  const render = () => {
    screen.textContent = text;
    screen.parentElement.scrollTop = screen.parentElement.scrollHeight;
  };
  return {
    open(parent) {
      screen = document.createElement("div");
      screen.className = "fallback-term";
      screen.tabIndex = 0;
      parent.appendChild(screen);
      screen.addEventListener("keydown", ev => {
        let data = "";
        if (ev.ctrlKey && ev.key.length === 1) data = String.fromCharCode(ev.key.toUpperCase().charCodeAt(0) - 64);
        else if (ev.key === "Enter") data = "\r";
        else if (ev.key === "Backspace") data = "\x7f";
        else if (ev.key === "Tab") data = "\t";
        else if (ev.key.length === 1) data = ev.key;
        if (data) { ev.preventDefault(); onData(data); }
      });
      screen.addEventListener("paste", ev => {
        const data = ev.clipboardData.getData("text");
        if (data) { ev.preventDefault(); onData(data); }
      });
      screen.focus();
    },
    write(data) {
      if (data instanceof Uint8Array) data = new TextDecoder().decode(data);
      text += clean(data).replace(/\r\n/g, "\n").replace(/\r/g, "\n");
      render();
    },
    clear() {
      text = "";
      render();
    },
    onData(fn) {
      onData = fn;
    }
  };
}
const term = makeTerminal();
term.open(document.getElementById("terminal"));
let current = null;
let ws = null;

async function api(path, opts) {
  const res = await fetch(path, opts);
  if (!res.ok) throw new Error(await res.text());
  if (res.status === 204) return null;
  return res.json();
}

async function refresh() {
  const sessions = await api("/api/sessions");
  const root = document.getElementById("sessions");
  root.innerHTML = "";
  sessions.forEach(s => {
    const el = document.createElement("button");
    el.className = "session" + (s.id === current ? " active" : "");
    el.innerHTML = `<div class="name">${escapeHtml(s.name)}</div><div class="meta">${s.status} · ${new Date(s.updated_at*1000).toLocaleString()}</div>`;
    el.onclick = () => attach(s.id);
    root.appendChild(el);
  });
}

async function createSession() {
  const r = await api("/api/sessions", {method:"POST", headers:{"content-type":"application/json"}, body:JSON.stringify({})});
  await refresh();
  attach(r.id);
}

function attach(id) {
  if (ws) ws.close();
  current = id;
  term.clear();
  document.getElementById("status").textContent = "Attached";
  ws = new WebSocket(`${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/ws/sessions/${id}`);
  ws.binaryType = "arraybuffer";
  ws.onmessage = ev => {
    if (typeof ev.data === "string") term.write(ev.data);
    else term.write(new Uint8Array(ev.data));
  };
  ws.onclose = () => document.getElementById("status").textContent = "Detached";
  refresh();
}

term.onData(data => {
  if (ws && ws.readyState === WebSocket.OPEN) ws.send(data);
});

document.getElementById("new-session").onclick = createSession;
document.getElementById("replay").onclick = async () => {
  if (!current) return;
  const r = await api(`/api/sessions/${current}/replay`);
  term.clear();
  term.write(Uint8Array.from(atob(r.bytes_b64), c => c.charCodeAt(0)));
};
document.getElementById("close").onclick = async () => {
  if (!current) return;
  await api(`/api/sessions/${current}/close`, {method:"POST"});
  if (ws) ws.close();
  await refresh();
};
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
refresh();
</script>
"##;
