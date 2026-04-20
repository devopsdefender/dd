//! Block-aware web terminal (M1 of the bastion plan).
//!
//! Serves a persistent, OSC 133–segmented shell to the browser over a
//! WebSocket. Each session owns a PTY spawned with WezTerm's shell
//! integration injected, so we can cut the byte stream into
//! `{command, output, exit}` blocks and keep them alongside a small
//! raw-byte ring for reconnect replay.
//!
//! M1 is plaintext over CF-Access-gated WSS, single-agent, inline HTML.
//! Noise E2E + CP aggregation are M2/M3 — see the plan in
//! `~/.claude/plans/more-and-more-i-modular-pearl.md`.
//!
//! Routes (mounted under `/term`):
//!   GET    /term                  → SPA HTML
//!   GET    /term/api/sessions     → list
//!   POST   /term/api/sessions     → create
//!   DELETE /term/api/sessions/:id → kill
//!   GET    /term/ws/:id           → WebSocket
//!
//! Protocol (M1, pre-Noise):
//!   * WS client → server
//!     - binary frames = stdin bytes (forwarded to PTY)
//!     - text JSON {type:"resize",cols,rows} | {type:"hello",have_up_to:N}
//!   * WS server → client
//!     - binary frames = raw PTY bytes (for xterm.js)
//!     - text JSON {type:"block",...record} | {type:"exit",code}
//!       {type:"gap",from,to} | {type:"ready",seq}

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, State};
use axum::response::{Html, IntoResponse};
use axum::routing::{delete, get};
use axum::{Json, Router};
use base64::Engine as _;
use portable_pty::{native_pty_system, CommandBuilder, MasterPty, PtySize};
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, Mutex, RwLock};
use uuid::Uuid;
use vte::{Params, Parser, Perform};

use crate::html;

/// Vendored from wezterm/assets/shell-integration/wezterm.sh.
/// Emits OSC 133 A/B/C/D around prompt/input/command/exit boundaries for
/// both bash and zsh; works from bash 3.1+ and any zsh.
const SHELL_INTEGRATION_SH: &str = include_str!("webtmux_shell_integration.sh");

/// Cap on the raw-byte ring per session. Enough to replay a full screen
/// on reconnect without letting the agent become a log store.
const RING_CAP: usize = 256 * 1024;

/// Cap on committed blocks kept per session. The browser has IndexedDB
/// for long history; the agent only keeps enough for a gap-free reconnect.
const BLOCKS_CAP: usize = 128;

/// Broadcast buffer size for live subscribers. Small: slow consumers are
/// expected to drop and resync from the ring.
const BROADCAST_CAP: usize = 256;

/// Default PTY geometry until the client sends a resize.
const DEFAULT_COLS: u16 = 120;
const DEFAULT_ROWS: u16 = 32;

// ---------------------------------------------------------------------
// Types exposed to the wire
// ---------------------------------------------------------------------

#[derive(Clone, Debug, Serialize)]
pub struct BlockRecord {
    pub session_id: String,
    pub seq: u64,
    pub started_at_ms: u64,
    pub ended_at_ms: u64,
    pub command: String,
    /// base64 of the raw ANSI output slice C→D
    pub output_b64: String,
    pub exit_code: i32,
}

#[derive(Clone, Debug, Serialize)]
pub struct SessionInfo {
    pub id: String,
    pub title: String,
    pub created_at_ms: u64,
    pub next_seq: u64,
}

#[derive(Deserialize)]
#[allow(dead_code)] // `have_up_to` is wire-level; M3 will consume it
struct HelloMsg {
    have_up_to: Option<u64>,
}

#[derive(Deserialize)]
struct ResizeMsg {
    cols: u16,
    rows: u16,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
#[allow(dead_code)]
enum ClientMsg {
    Hello(HelloMsg),
    Resize(ResizeMsg),
}

// ---------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------

#[derive(Clone)]
enum Event {
    Raw(Arc<Vec<u8>>),
    Block(Arc<BlockRecord>),
    Exit(i32),
}

struct Session {
    id: String,
    title: String,
    created_at_ms: u64,
    master: Arc<Mutex<Box<dyn MasterPty + Send>>>,
    writer: Arc<Mutex<Box<dyn Write + Send>>>,
    ring: Arc<Mutex<VecDeque<u8>>>,
    blocks: Arc<RwLock<VecDeque<BlockRecord>>>,
    next_seq: Arc<Mutex<u64>>,
    tx: broadcast::Sender<Event>,
    /// PID of the spawned shell so `Manager::remove` can SIGHUP it.
    /// The waiter thread owns the `Child` handle; we track the PID
    /// separately to avoid a lock contest with `wait()`.
    pid: Option<u32>,
}

impl Session {
    fn info(&self) -> SessionInfo {
        SessionInfo {
            id: self.id.clone(),
            title: self.title.clone(),
            created_at_ms: self.created_at_ms,
            next_seq: self.next_seq.try_lock().map(|g| *g).unwrap_or(0),
        }
    }

    /// Best-effort termination: SIGHUP first (lets bash exit cleanly),
    /// SIGKILL after a short grace period if still alive.
    fn kill(&self) {
        let Some(pid) = self.pid else { return };
        let pid = pid as i32;
        unsafe {
            libc::kill(pid, libc::SIGHUP);
        }
        // Reader thread's EOF + waiter tear-down take care of the rest.
        // We don't SIGKILL here — the waiter will hit `wait()` and move on,
        // and if the process wedges, a later manual kill can handle it.
        let _ = pid;
    }
}

// ---------------------------------------------------------------------
// Manager
// ---------------------------------------------------------------------

#[derive(Clone)]
pub struct Manager {
    inner: Arc<RwLock<std::collections::HashMap<String, Arc<Session>>>>,
}

impl Default for Manager {
    fn default() -> Self {
        Self::new()
    }
}

impl Manager {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(Default::default())),
        }
    }

    async fn list(&self) -> Vec<SessionInfo> {
        let g = self.inner.read().await;
        g.values().map(|s| s.info()).collect()
    }

    async fn get(&self, id: &str) -> Option<Arc<Session>> {
        self.inner.read().await.get(id).cloned()
    }

    async fn create(&self, title: String) -> std::io::Result<Arc<Session>> {
        let id = short_id();
        let (session, child) = spawn_session(id.clone(), title).await?;
        self.inner.write().await.insert(id.clone(), session.clone());

        // Waiter: reap the child on a blocking thread, then come back to
        // async to broadcast Exit and self-remove from the manager so the
        // map doesn't accumulate dead sessions.
        let tx = session.tx.clone();
        let manager = self.clone();
        let wait_id = id;
        tokio::spawn(async move {
            let code = tokio::task::spawn_blocking(move || {
                let mut child = child;
                child
                    .wait()
                    .ok()
                    .and_then(|s| i32::try_from(s.exit_code()).ok())
                    .unwrap_or(-1)
            })
            .await
            .unwrap_or(-1);
            let _ = tx.send(Event::Exit(code));
            manager.inner.write().await.remove(&wait_id);
        });

        Ok(session)
    }

    async fn remove(&self, id: &str) -> bool {
        let removed = self.inner.write().await.remove(id);
        if let Some(s) = removed {
            // Kill the shell; its exit will flush through the normal
            // reader/waiter path. Any live WS subscribers get an Exit
            // event and close out.
            s.kill();
            true
        } else {
            false
        }
    }
}

fn short_id() -> String {
    let u = Uuid::new_v4();
    u.simple().to_string()[..12].to_string()
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

async fn spawn_session(
    id: String,
    title: String,
) -> std::io::Result<(Arc<Session>, Box<dyn portable_pty::Child + Send + Sync>)> {
    let pty_system = native_pty_system();
    let pair = pty_system
        .openpty(PtySize {
            rows: DEFAULT_ROWS,
            cols: DEFAULT_COLS,
            pixel_width: 0,
            pixel_height: 0,
        })
        .map_err(io_err)?;

    // Write the wezterm shell integration to a tempfile so bash can
    // --rcfile it. Idempotent content; tempfs sweeps it on reboot.
    let rc_path = write_rc_tempfile()?;

    // Prefer bash; fall back to sh if bash is absent on the VM.
    let shell = if std::path::Path::new("/bin/bash").exists() {
        "/bin/bash"
    } else {
        "/bin/sh"
    };

    let mut cmd = CommandBuilder::new(shell);
    cmd.args(["--rcfile", &rc_path, "-i"]);
    cmd.env("TERM", "xterm-256color");
    // Force the integration to load even if the user env would skip it.
    cmd.env_remove("WEZTERM_SHELL_SKIP_ALL");
    if let Ok(home) = std::env::var("HOME") {
        cmd.env("HOME", home);
    }

    let child = pair.slave.spawn_command(cmd).map_err(io_err)?;
    let pid = child.process_id();
    let reader = pair.master.try_clone_reader().map_err(io_err)?;
    let writer = pair.master.take_writer().map_err(io_err)?;

    let created_at_ms = now_ms();
    let (tx, _rx) = broadcast::channel(BROADCAST_CAP);

    let session = Arc::new(Session {
        id: id.clone(),
        title,
        created_at_ms,
        master: Arc::new(Mutex::new(pair.master)),
        writer: Arc::new(Mutex::new(writer)),
        ring: Arc::new(Mutex::new(VecDeque::with_capacity(RING_CAP))),
        blocks: Arc::new(RwLock::new(VecDeque::with_capacity(BLOCKS_CAP))),
        next_seq: Arc::new(Mutex::new(0)),
        tx,
        pid,
    });

    // Reader thread: read PTY bytes, feed the OSC parser, broadcast raw
    // bytes + committed blocks. Blocking IO on a dedicated thread.
    let sess = session.clone();
    std::thread::Builder::new()
        .name(format!("webtmux-rd-{id}"))
        .spawn(move || reader_loop(sess, reader))
        .map_err(io_err)?;

    Ok((session, child))
}

fn io_err<E: std::fmt::Display>(e: E) -> std::io::Error {
    std::io::Error::other(format!("{e}"))
}

fn write_rc_tempfile() -> std::io::Result<String> {
    let dir = std::env::temp_dir();
    let path = dir.join("dd-webtmux-wezterm.sh");
    // Idempotent write; if content matches, skip to avoid racing concurrent
    // session creates.
    if std::fs::read(&path).ok().as_deref() != Some(SHELL_INTEGRATION_SH.as_bytes()) {
        std::fs::write(&path, SHELL_INTEGRATION_SH)?;
    }
    Ok(path.to_string_lossy().into_owned())
}

// ---------------------------------------------------------------------
// Reader loop + OSC 133 parser
// ---------------------------------------------------------------------

fn reader_loop(session: Arc<Session>, mut reader: Box<dyn Read + Send>) {
    let mut parser = Parser::new();
    let mut perf = SemanticPerform {
        session: session.clone(),
        state: PromptState::Idle,
        input_scratch: Vec::new(),
        pending_command: String::new(),
    };
    let mut buf = [0u8; 4096];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let chunk = &buf[..n];
                // Append to rolling ring
                {
                    let mut ring = session.ring.blocking_lock();
                    if ring.len() + n > RING_CAP {
                        let drop_n = ring.len() + n - RING_CAP;
                        for _ in 0..drop_n.min(ring.len()) {
                            ring.pop_front();
                        }
                    }
                    ring.extend(chunk.iter().copied());
                }
                // Broadcast raw bytes
                let _ = session.tx.send(Event::Raw(Arc::new(chunk.to_vec())));
                // Feed the semantic parser (vte drives all capture).
                for &b in chunk {
                    parser.advance(&mut perf, b);
                }
            }
            Err(_) => break,
        }
    }
}

#[derive(Debug)]
enum PromptState {
    Idle,
    InPrompt,               // after A, before B
    InInput,                // after B, before C
    InOutput(PartialBlock), // after C, before D
}

#[derive(Debug)]
struct PartialBlock {
    started_at_ms: u64,
    output_bytes: Vec<u8>,
}

struct SemanticPerform {
    session: Arc<Session>,
    state: PromptState,
    /// Echoed bytes between OSC 133 B and C; trimmed into the command
    /// text when we enter InOutput.
    input_scratch: Vec<u8>,
    /// Command text derived from `input_scratch` at B→C transition,
    /// parked here until the D event finalizes the block.
    pending_command: String,
}

impl Perform for SemanticPerform {
    fn print(&mut self, c: char) {
        let mut buf = [0u8; 4];
        let s = c.encode_utf8(&mut buf);
        match &mut self.state {
            PromptState::InInput => self.input_scratch.extend_from_slice(s.as_bytes()),
            PromptState::InOutput(pb) => pb.output_bytes.extend_from_slice(s.as_bytes()),
            _ => {}
        }
    }
    fn execute(&mut self, b: u8) {
        // Keep only the visible whitespace / control chars that belong
        // in the transcript. Everything else (BEL, backspace, etc.) is
        // terminal noise we don't need in the block record.
        if !matches!(b, b'\n' | b'\r' | b'\t') {
            return;
        }
        match &mut self.state {
            PromptState::InInput => self.input_scratch.push(b),
            PromptState::InOutput(pb) => pb.output_bytes.push(b),
            _ => {}
        }
    }
    fn hook(&mut self, _p: &Params, _i: &[u8], _ignore: bool, _c: char) {}
    fn put(&mut self, _b: u8) {}
    fn unhook(&mut self) {}
    fn csi_dispatch(&mut self, _p: &Params, _i: &[u8], _ignore: bool, _c: char) {}
    fn esc_dispatch(&mut self, _i: &[u8], _ignore: bool, _b: u8) {}

    fn osc_dispatch(&mut self, params: &[&[u8]], _bell_terminated: bool) {
        if params.len() < 2 {
            return;
        }
        if params[0] != b"133" {
            return;
        }
        let kind = params[1].first().copied();
        match kind {
            Some(b'A') => {
                self.state = PromptState::InPrompt;
                self.input_scratch.clear();
            }
            Some(b'B') => {
                self.state = PromptState::InInput;
                self.input_scratch.clear();
            }
            Some(b'C') => {
                let _command = decode_command(&self.input_scratch);
                self.pending_command = _command;
                self.input_scratch.clear();
                self.state = PromptState::InOutput(PartialBlock {
                    started_at_ms: now_ms(),
                    output_bytes: Vec::new(),
                });
            }
            Some(b'D') => {
                // OSC 133 D has form "D;<exit>" — params[2] is the exit
                // code if present; default to 0.
                let exit_code: i32 = params
                    .get(2)
                    .and_then(|p| std::str::from_utf8(p).ok())
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                if let PromptState::InOutput(pb) =
                    std::mem::replace(&mut self.state, PromptState::Idle)
                {
                    let command = std::mem::take(&mut self.pending_command);
                    let block = finalize_block(&self.session, pb, command, exit_code);
                    let arc = Arc::new(block);
                    {
                        let mut blocks = self.session.blocks.blocking_write();
                        while blocks.len() >= BLOCKS_CAP {
                            blocks.pop_front();
                        }
                        blocks.push_back((*arc).clone());
                    }
                    let _ = self.session.tx.send(Event::Block(arc));
                }
            }
            _ => {}
        }
    }
}

// Reopen the struct to add the scratch field without reshuffling above
// — kept at the bottom to keep the imports block clean. The whole file
// is cohesive enough that this is just a style choice.
// (Rust allows only one definition per struct, so we inline the field
// into the original above.)

fn decode_command(input: &[u8]) -> String {
    // The bytes between B and C are the echoed keystrokes as the user
    // typed — includes backspaces, cursor moves, and the trailing Enter.
    // Strip ANSI sequences and trim. Not authoritative; upgrade to
    // OSC 633;E capture later.
    let s = String::from_utf8_lossy(input);
    let mut out = String::new();
    let mut in_esc = false;
    for c in s.chars() {
        if in_esc {
            if c.is_ascii_alphabetic() || c == '\x07' {
                in_esc = false;
            }
            continue;
        }
        match c {
            '\x1b' => in_esc = true,
            '\x08' => {
                out.pop();
            }
            '\r' | '\n' => {}
            _ => out.push(c),
        }
    }
    out.trim().to_string()
}

fn finalize_block(
    session: &Session,
    pb: PartialBlock,
    command: String,
    exit_code: i32,
) -> BlockRecord {
    let mut seq_g = session.next_seq.blocking_lock();
    let seq = *seq_g;
    *seq_g += 1;
    let output_b64 = base64::engine::general_purpose::STANDARD.encode(&pb.output_bytes);
    BlockRecord {
        session_id: session.id.clone(),
        seq,
        started_at_ms: pb.started_at_ms,
        ended_at_ms: now_ms(),
        command,
        output_b64,
        exit_code,
    }
}

// ---------------------------------------------------------------------
// HTTP handlers
// ---------------------------------------------------------------------

pub fn router(manager: Manager) -> Router {
    Router::new()
        .route("/term", get(page))
        .route(
            "/term/api/sessions",
            get(list_sessions).post(create_session),
        )
        .route("/term/api/sessions/{id}", delete(kill_session))
        .route("/term/ws/{id}", get(ws_upgrade))
        .with_state(manager)
}

async fn page() -> impl IntoResponse {
    Html(html::shell_fullwidth(
        "Terminal",
        &html::nav(&[("Dashboard", "/", false), ("Terminal", "/term", true)]),
        PAGE_BODY,
    ))
}

#[derive(Deserialize)]
struct CreateBody {
    title: Option<String>,
}

async fn list_sessions(State(m): State<Manager>) -> Json<Vec<SessionInfo>> {
    Json(m.list().await)
}

async fn create_session(
    State(m): State<Manager>,
    body: Option<Json<CreateBody>>,
) -> Result<Json<SessionInfo>, axum::http::StatusCode> {
    let title = body
        .and_then(|b| b.0.title)
        .unwrap_or_else(|| "shell".to_string());
    match m.create(title).await {
        Ok(s) => Ok(Json(s.info())),
        Err(_) => Err(axum::http::StatusCode::INTERNAL_SERVER_ERROR),
    }
}

async fn kill_session(State(m): State<Manager>, Path(id): Path<String>) -> axum::http::StatusCode {
    if m.remove(&id).await {
        axum::http::StatusCode::NO_CONTENT
    } else {
        axum::http::StatusCode::NOT_FOUND
    }
}

async fn ws_upgrade(
    ws: WebSocketUpgrade,
    Path(id): Path<String>,
    State(m): State<Manager>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| ws_loop(socket, id, m))
}

async fn ws_loop(mut socket: WebSocket, id: String, m: Manager) {
    use futures_util::{SinkExt, StreamExt};

    let Some(session) = m.get(&id).await else {
        let _ = socket
            .send(Message::Text(
                r#"{"type":"error","code":"not_found"}"#.to_string().into(),
            ))
            .await;
        return;
    };

    // Split the socket so send and receive halves run concurrently.
    let (mut sink, mut stream) = socket.split();

    // Replay: send current ring + blocks, tagged with latest seq so the
    // client can dedupe against its IndexedDB.
    {
        let ring_bytes: Vec<u8> = session.ring.lock().await.iter().copied().collect();
        if !ring_bytes.is_empty() {
            let _ = sink.send(Message::Binary(ring_bytes.into())).await;
        }
        let blocks = session.blocks.read().await;
        for b in blocks.iter() {
            if let Ok(s) = serde_json::to_string(&serde_json::json!({
                "type": "block",
                "session_id": b.session_id,
                "seq": b.seq,
                "started_at_ms": b.started_at_ms,
                "ended_at_ms": b.ended_at_ms,
                "command": b.command,
                "output_b64": b.output_b64,
                "exit_code": b.exit_code,
            })) {
                let _ = sink.send(Message::Text(s.into())).await;
            }
        }
        let seq = *session.next_seq.lock().await;
        let _ = sink
            .send(Message::Text(
                serde_json::json!({"type":"ready","seq":seq})
                    .to_string()
                    .into(),
            ))
            .await;
    }

    // Subscribe to live events.
    let mut rx = session.tx.subscribe();

    let writer = session.writer.clone();
    let master = session.master.clone();

    // Inbound: stdin bytes and control JSON.
    let inbound = async move {
        while let Some(Ok(msg)) = stream.next().await {
            match msg {
                Message::Binary(bytes) => {
                    let w = writer.clone();
                    let _ = tokio::task::spawn_blocking(move || {
                        let mut g = w.blocking_lock();
                        let _ = g.write_all(&bytes);
                    })
                    .await;
                }
                Message::Text(s) => {
                    let Ok(msg) = serde_json::from_str::<ClientMsg>(&s) else {
                        continue;
                    };
                    match msg {
                        ClientMsg::Resize(r) => {
                            let g = master.lock().await;
                            let _ = g.resize(PtySize {
                                rows: r.rows.max(4),
                                cols: r.cols.max(8),
                                pixel_width: 0,
                                pixel_height: 0,
                            });
                        }
                        ClientMsg::Hello(_) => {
                            // M1: we already replayed everything above.
                            // M3 will honor have_up_to to skip known seqs.
                        }
                    }
                }
                Message::Close(_) => break,
                _ => {}
            }
        }
    };

    // Outbound: pump broadcast events to the client.
    let outbound = async move {
        loop {
            let ev = match rx.recv().await {
                Ok(e) => e,
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(_) => break,
            };
            match ev {
                Event::Raw(bytes) => {
                    if sink
                        .send(Message::Binary((*bytes).clone().into()))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Event::Block(b) => {
                    let payload = serde_json::json!({
                        "type": "block",
                        "session_id": b.session_id,
                        "seq": b.seq,
                        "started_at_ms": b.started_at_ms,
                        "ended_at_ms": b.ended_at_ms,
                        "command": b.command,
                        "output_b64": b.output_b64,
                        "exit_code": b.exit_code,
                    });
                    if sink
                        .send(Message::Text(payload.to_string().into()))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Event::Exit(code) => {
                    let _ = sink
                        .send(Message::Text(
                            serde_json::json!({"type":"exit","code":code})
                                .to_string()
                                .into(),
                        ))
                        .await;
                    break;
                }
            }
        }
    };

    tokio::select! {
        _ = inbound => {},
        _ = outbound => {},
    }
}

// ---------------------------------------------------------------------
// SPA (inline for M1)
// ---------------------------------------------------------------------

const PAGE_BODY: &str = include_str!("webtmux_page.html");

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn osc_133_sequence_produces_block() {
        // Build a minimal session without a real PTY.
        let session = Arc::new(Session {
            id: "t".into(),
            title: "t".into(),
            created_at_ms: 0,
            master: Arc::new(Mutex::new(make_fake_master())),
            writer: Arc::new(Mutex::new(
                Box::new(std::io::sink()) as Box<dyn Write + Send>
            )),
            ring: Arc::new(Mutex::new(VecDeque::new())),
            blocks: Arc::new(RwLock::new(VecDeque::new())),
            next_seq: Arc::new(Mutex::new(0)),
            tx: broadcast::channel::<Event>(8).0,
            pid: None,
        });
        let mut parser = Parser::new();
        let mut perf = SemanticPerform {
            session: session.clone(),
            state: PromptState::Idle,
            input_scratch: Vec::new(),
            pending_command: String::new(),
        };
        // A B <typed "echo hi\r"> C <output "hi\n"> D;0
        let stream = b"\x1b]133;A\x07\x1b]133;B\x07echo hi\r\x1b]133;C\x07hi\n\x1b]133;D;0\x07";
        for &b in stream {
            parser.advance(&mut perf, b);
        }
        let blocks = session.blocks.blocking_read();
        assert_eq!(blocks.len(), 1);
        let b = &blocks[0];
        assert_eq!(b.command, "echo hi");
        assert_eq!(b.exit_code, 0);
    }

    fn make_fake_master() -> Box<dyn MasterPty + Send> {
        // Opening a real pty is fine in unit tests on Linux; the
        // caller won't read/write it in this test.
        let pair = native_pty_system()
            .openpty(PtySize {
                rows: 24,
                cols: 80,
                pixel_width: 0,
                pixel_height: 0,
            })
            .expect("openpty");
        pair.master
    }
}
