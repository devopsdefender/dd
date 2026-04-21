//! # bastion — block-aware web terminal
//!
//! Serves a persistent, OSC 133–segmented shell to the browser over a
//! WebSocket. Each session owns a PTY spawned with WezTerm's shell
//! integration injected, so the byte stream is cut into
//! `{command, output, exit}` blocks and kept alongside a small raw-byte
//! ring for reconnect replay.
//!
//! ## Quick start
//!
//! ```no_run
//! use axum::Router;
//!
//! # #[tokio::main]
//! # async fn main() -> std::io::Result<()> {
//! let mgr = bastion::Manager::new();
//! let app: Router = Router::new().nest("/term", bastion::router(mgr));
//! let listener = tokio::net::TcpListener::bind("127.0.0.1:7681").await?;
//! axum::serve(listener, app).await.unwrap();
//! # Ok(())
//! # }
//! ```
//!
//! Routes (relative to wherever you mount the router):
//!   - `GET  /`               — SPA HTML
//!   - `GET  /api/sessions`   — list sessions
//!   - `POST /api/sessions`   — create a session
//!   - `DEL  /api/sessions/:id` — kill a session
//!   - `GET  /ws/:id`         — WebSocket
//!
//! ## WebSocket protocol
//!
//! Client → server:
//!   - binary frames = stdin bytes (forwarded to PTY)
//!   - text JSON `{type:"resize",cols,rows}` | `{type:"hello",have_up_to:N}`
//!
//! Server → client:
//!   - binary frames = raw PTY bytes (feed to xterm.js)
//!   - text JSON `{type:"block",...record}` | `{type:"exit",code}` |
//!     `{type:"gap",from,to}` | `{type:"ready",seq}`

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

pub mod capture;
pub mod ee;
pub mod ee_sync;

/// Re-export so `bastion::noise::NoiseStatic` + `bastion::noise_tunnel::*`
/// continue to work after the primitives moved into `dd-common` (shared
/// with the CP / agent m2m path).
pub use dd_common::noise_static as noise;
pub use dd_common::noise_tunnel;

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

/// Vendored from wezterm/assets/shell-integration/wezterm.sh.
/// Emits OSC 133 A/B/C/D around prompt/input/command/exit boundaries for
/// both bash and zsh; works from bash 3.1+ and any zsh.
const SHELL_INTEGRATION_SH: &str = include_str!("shell_integration.sh");

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
    /// "shell" for OSC-133 segmented PTY sessions; "workload" for
    /// process-lifetime records sourced from the easyenclave capture
    /// socket. Discriminator consumed by the SPA sidebar to render the
    /// correct category.
    pub kind: String,
    pub seq: u64,
    pub started_at_ms: u64,
    pub ended_at_ms: u64,
    pub command: String,
    /// base64 of the raw ANSI output slice C→D (shell) or the full
    /// stdout+stderr accumulated over the workload's lifetime (workload).
    pub output_b64: String,
    pub exit_code: i32,
}

#[derive(Clone, Debug, Serialize)]
pub struct SessionInfo {
    pub id: String,
    /// "shell" | "workload" — mirrors `BlockRecord::kind`.
    pub kind: String,
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

pub struct Session {
    pub(crate) id: String,
    /// "shell" for PTY-backed interactive sessions; "workload" for
    /// EE-captured process-lifetime records (no PTY, no stdin).
    pub kind: String,
    pub(crate) title: String,
    pub(crate) created_at_ms: u64,
    /// Present for shell sessions; `None` for workloads (no PTY).
    pub(crate) master: Option<Arc<Mutex<Box<dyn MasterPty + Send>>>>,
    /// Present for shell sessions; `None` for workloads (stdin is
    /// silently dropped, since the workload is already running with
    /// its own stdin from EE).
    pub(crate) writer: Option<Arc<Mutex<Box<dyn Write + Send>>>>,
    pub ring: Arc<Mutex<VecDeque<u8>>>,
    pub blocks: Arc<RwLock<VecDeque<BlockRecord>>>,
    pub(crate) next_seq: Arc<Mutex<u64>>,
    pub(crate) tx: broadcast::Sender<Event>,
    /// Per-lifetime accumulator for workload sessions. Holds the
    /// `argv`, `started_at_ms`, and raw stdout/stderr bytes until
    /// `exit`, when they're finalized into a single `BlockRecord`.
    pub(crate) workload_ctx: Option<Arc<Mutex<WorkloadCtx>>>,
    /// PID of the spawned shell so `Manager::remove` can SIGHUP it.
    /// The waiter thread owns the `Child` handle; we track the PID
    /// separately to avoid a lock contest with `wait()`. `None` for
    /// workload sessions.
    pub(crate) pid: Option<u32>,
}

/// State that a workload session accumulates between `spawn` and
/// `exit` on the EE capture socket. On `exit` this becomes a single
/// `BlockRecord` whose `output_b64` covers the whole lifetime.
struct WorkloadCtx {
    argv: Vec<String>,
    started_at_ms: u64,
    output: Vec<u8>,
}

impl Session {
    fn info(&self) -> SessionInfo {
        SessionInfo {
            id: self.id.clone(),
            kind: self.kind.clone(),
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
    /// Optional CP URL. When set, `GET /` fetches the CP's
    /// `/api/agents` at request time and injects
    /// `window.__DD_AGENTS__` so the SPA fans out to every agent
    /// in the fleet. Absent → single-node fallback.
    cp_url: Option<Arc<str>>,
    http: reqwest::Client,
    /// Long-term Noise static keypair. Clients fetch the pubkey
    /// via `GET /attest` and pin it; Phase 2b runs a Noise_KK
    /// handshake keyed by this + a client static key. Absent in
    /// standalone dev / local-embedder mode — `/attest` then
    /// responds 404.
    noise: Option<Arc<noise::NoiseStatic>>,
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
            cp_url: None,
            http: reqwest::Client::new(),
            noise: None,
        }
    }

    /// Point this bastion at a control-plane so `GET /` serves the
    /// cross-node aggregator SPA instead of single-node. The CP's
    /// `/api/agents` endpoint is CF-Access-bypassed, so no auth
    /// token is needed here. On fetch failure we degrade gracefully
    /// to single-node — no panic, no crash.
    pub fn with_cp_url(mut self, url: impl Into<String>) -> Self {
        let url = url.into();
        if !url.is_empty() {
            self.cp_url = Some(Arc::from(url));
        }
        self
    }

    /// Attach the persistent Noise static keypair. When set, `GET
    /// /attest` returns `{noise_pubkey_hex}` so clients can pin it
    /// before Phase 2b's Noise_KK handshake. Absent → `/attest`
    /// returns 404.
    pub fn with_noise_key(mut self, key: noise::NoiseStatic) -> Self {
        self.noise = Some(Arc::new(key));
        self
    }

    async fn list(&self) -> Vec<SessionInfo> {
        let g = self.inner.read().await;
        g.values().map(|s| s.info()).collect()
    }

    pub(crate) async fn get(&self, id: &str) -> Option<Arc<Session>> {
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

    /// Register a workload session for EE-captured process output.
    ///
    /// Called from [`crate::capture`] on each `spawn` record. The
    /// returned session has no PTY, no writer, and no pid — WebSocket
    /// subscribers get replay + live `Raw` bytes + a final
    /// `BlockRecord` once [`Self::workload_exit`] fires.
    ///
    /// Idempotent on duplicate ids: the existing session is returned
    /// unchanged so a reconnecting capture socket doesn't orphan
    /// state. (The EE side gives each spawn a unique `<app>-<ms>` id
    /// so collisions only happen when something reruns the record.)
    pub async fn register_workload(&self, id: String, argv: Vec<String>, _cwd: Option<String>) {
        {
            let g = self.inner.read().await;
            if g.contains_key(&id) {
                return;
            }
        }
        let (tx, _rx) = broadcast::channel(BROADCAST_CAP);
        let started_at_ms = now_ms();
        let title = argv.first().cloned().unwrap_or_else(|| id.clone());
        let session = Arc::new(Session {
            id: id.clone(),
            kind: "workload".into(),
            title,
            created_at_ms: started_at_ms,
            master: None,
            writer: None,
            ring: Arc::new(Mutex::new(VecDeque::with_capacity(RING_CAP))),
            blocks: Arc::new(RwLock::new(VecDeque::with_capacity(BLOCKS_CAP))),
            next_seq: Arc::new(Mutex::new(0)),
            tx,
            workload_ctx: Some(Arc::new(Mutex::new(WorkloadCtx {
                argv,
                started_at_ms,
                output: Vec::new(),
            }))),
            pid: None,
        });
        self.inner.write().await.insert(id, session);
    }

    /// Append a chunk of captured stdout/stderr bytes to a workload
    /// session: updates the rolling ring so reconnects replay it,
    /// appends to the per-lifetime accumulator (capped at `RING_CAP`
    /// — older bytes drop from the front), and broadcasts raw bytes
    /// to live WS subscribers.
    ///
    /// Silent no-op for unknown ids or shell sessions.
    pub async fn workload_out(&self, id: &str, bytes: &[u8]) {
        let Some(session) = self.get(id).await else {
            return;
        };
        let Some(ctx) = session.workload_ctx.as_ref() else {
            return;
        };
        {
            let mut ring = session.ring.lock().await;
            let n = bytes.len();
            if ring.len() + n > RING_CAP {
                let drop_n = ring.len() + n - RING_CAP;
                for _ in 0..drop_n.min(ring.len()) {
                    ring.pop_front();
                }
            }
            ring.extend(bytes.iter().copied());
        }
        {
            let mut g = ctx.lock().await;
            g.output.extend_from_slice(bytes);
            if g.output.len() > RING_CAP {
                let drop_n = g.output.len() - RING_CAP;
                g.output.drain(..drop_n);
            }
        }
        let _ = session.tx.send(Event::Raw(Arc::new(bytes.to_vec())));
    }

    /// Finalize a workload session: commit one `BlockRecord`
    /// (`kind = "workload"`, `command = argv.join(" ")`) covering the
    /// process lifetime, then broadcast a terminal `Exit`.
    ///
    /// The session remains in the manager so later reconnects can
    /// replay its block; process exit is end-of-writes, not
    /// end-of-readers. Silent no-op for unknown or non-workload ids.
    pub async fn workload_exit(&self, id: &str, code: i32) {
        let Some(session) = self.get(id).await else {
            return;
        };
        let Some(ctx) = session.workload_ctx.as_ref() else {
            return;
        };
        let (command, started_at_ms, output) = {
            let mut g = ctx.lock().await;
            (
                g.argv.join(" "),
                g.started_at_ms,
                std::mem::take(&mut g.output),
            )
        };
        let output_b64 = base64::engine::general_purpose::STANDARD.encode(&output);
        let seq = {
            let mut g = session.next_seq.lock().await;
            let s = *g;
            *g += 1;
            s
        };
        let block = BlockRecord {
            session_id: session.id.clone(),
            kind: "workload".into(),
            seq,
            started_at_ms,
            ended_at_ms: now_ms(),
            command,
            output_b64,
            exit_code: code,
        };
        {
            let mut blocks = session.blocks.write().await;
            while blocks.len() >= BLOCKS_CAP {
                blocks.pop_front();
            }
            blocks.push_back(block.clone());
        }
        let _ = session.tx.send(Event::Block(Arc::new(block)));
        let _ = session.tx.send(Event::Exit(code));
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
        kind: "shell".into(),
        title,
        created_at_ms,
        master: Some(Arc::new(Mutex::new(pair.master))),
        writer: Some(Arc::new(Mutex::new(writer))),
        ring: Arc::new(Mutex::new(VecDeque::with_capacity(RING_CAP))),
        blocks: Arc::new(RwLock::new(VecDeque::with_capacity(BLOCKS_CAP))),
        next_seq: Arc::new(Mutex::new(0)),
        tx,
        workload_ctx: None,
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
        kind: session.kind.clone(),
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

/// Mount point-agnostic. Nest this wherever you want:
///
/// ```no_run
/// # use axum::Router;
/// let app: Router = Router::new()
///     .nest("/term", bastion::router(bastion::Manager::new()));
/// ```
pub fn router(manager: Manager) -> Router {
    // CF Access gates each bastion origin; this layer just tells the
    // browser that cross-origin responses from the CP's `/bastion`
    // aggregator (served on the same `.devopsdefender.com` session
    // domain) are legitimate and the CF Access cookie may ride along.
    let cors = tower_http::cors::CorsLayer::new()
        .allow_credentials(true)
        .allow_headers(tower_http::cors::AllowHeaders::mirror_request())
        .allow_methods(tower_http::cors::AllowMethods::mirror_request())
        .allow_origin(tower_http::cors::AllowOrigin::predicate(|origin, _req| {
            origin
                .to_str()
                .ok()
                .and_then(|s| s.strip_prefix("https://"))
                .is_some_and(|host| host.ends_with(".devopsdefender.com"))
        }));

    Router::new()
        .route("/", get(page))
        .route("/attest", get(attest))
        .route("/api/sessions", get(list_sessions).post(create_session))
        .route("/api/sessions/{id}", delete(kill_session))
        .route("/ws/{id}", get(ws_upgrade))
        .route("/noise/ws", get(noise_ws_upgrade))
        .layer(cors)
        .with_state(manager)
}

/// GET /attest — returns this bastion's long-term Noise static
/// pubkey. Clients pin the returned `noise_pubkey_hex` and use it
/// as the responder key for Phase 2b's Noise_KK handshake. Phase
/// 2d will add the TDX attestation quote to the response body so
/// clients can verify the pubkey came from a genuine enclave.
///
/// 404 when no Noise keypair is configured (standalone dev,
/// embedders that didn't call `Manager::with_noise_key`).
async fn attest(State(m): State<Manager>) -> impl IntoResponse {
    let Some(key) = m.noise.as_ref() else {
        return (
            axum::http::StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "noise key not configured"
            })),
        )
            .into_response();
    };
    Json(serde_json::json!({
        "noise_pubkey_hex": key.public_hex(),
        "source": format!("{:?}", key.source()).to_lowercase(),
    }))
    .into_response()
}

async fn page(State(m): State<Manager>) -> impl IntoResponse {
    // No CP configured → serve the raw single-node SPA. That's the
    // `bastion serve` local-dev path and any embedder that didn't
    // wire `with_cp_url`.
    let Some(cp_url) = m.cp_url.as_deref() else {
        return Html(SPA_HTML.to_string());
    };

    // Try to fetch the live agent catalog. CP's `/api/agents` is
    // CF-Access-bypassed, so no credentials. 2-second ceiling keeps
    // a wedged CP from wedging every page load.
    match fetch_agents(&m.http, cp_url).await {
        Ok(agents) if !agents.is_empty() => Html(aggregator_body(&agents)),
        Ok(_) => Html(SPA_HTML.to_string()), // empty list → single-node fallback
        Err(e) => {
            eprintln!("bastion: fetch CP {cp_url}/api/agents failed: {e} — single-node fallback");
            Html(SPA_HTML.to_string())
        }
    }
}

/// Fetch CP's `/api/agents` and shape it into the `(vm_name, origin)`
/// tuples that [`aggregator_body`] expects. The CP returns objects
/// with a `hostname` field (the agent's own CF-tunneled hostname);
/// bastion's subdomain is `{base}-block.{tld}`, computed via the
/// same label-flatten rule that DD's `cf::label_hostname` uses.
async fn fetch_agents(
    http: &reqwest::Client,
    cp_url: &str,
) -> Result<Vec<(String, String)>, String> {
    let url = format!("{}/api/agents", cp_url.trim_end_matches('/'));
    let resp = http
        .get(&url)
        .timeout(std::time::Duration::from_secs(2))
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("status {}", resp.status()));
    }
    let body: Vec<serde_json::Value> = resp.json().await.map_err(|e| e.to_string())?;
    let mut out: Vec<(String, String)> = body
        .into_iter()
        .filter_map(|a| {
            let vm = a.get("vm_name").and_then(|v| v.as_str())?.to_string();
            let host = a.get("hostname").and_then(|v| v.as_str())?.to_string();
            let block = label_hostname(&host, "block");
            Some((vm, format!("https://{block}")))
        })
        .collect();
    // Sort so rows render in stable order regardless of CP
    // iteration order.
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

/// Turn `("pr-172.devopsdefender.com", "block")` into
/// `"pr-172-block.devopsdefender.com"`. Duplicates the logic from
/// DD's `crates/dd/src/cf.rs::label_hostname` — bastion can't depend
/// on the DD crate (would create a cycle), so the rule is vendored.
fn label_hostname(hostname: &str, label: &str) -> String {
    match hostname.split_once('.') {
        Some((base, rest)) => format!("{base}-{label}.{rest}"),
        None => format!("{hostname}-{label}"),
    }
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
                "kind": b.kind,
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

    // Inbound: stdin bytes and control JSON. For workload sessions,
    // `writer` and `master` are `None`: stdin bytes from the browser
    // are silently dropped, and resize is a no-op. Workloads don't
    // have a PTY; they're view-only.
    let inbound = async move {
        while let Some(Ok(msg)) = stream.next().await {
            match msg {
                Message::Binary(bytes) => {
                    let Some(w) = writer.clone() else { continue };
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
                            let Some(m) = master.as_ref() else { continue };
                            let g = m.lock().await;
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
                        "kind": b.kind,
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
// /noise/ws — Noise_IK-tunneled JSON RPC
// ---------------------------------------------------------------------

/// JSON-over-Noise request/response envelope. Every request carries an
/// `id` so the client can correlate responses on a single multiplexed
/// tunnel. `op` discriminates the call; payload fields are flattened.
///
/// Phase 2b scope: `sessions.list` / `sessions.create` / `sessions.delete`
/// only. Phase 2c will add `shell.open` / `shell.input` / `shell.resize`
/// for tunneling the terminal WS body.
#[derive(Debug, Deserialize)]
struct NoiseReq {
    id: u64,
    #[serde(flatten)]
    body: NoiseReqBody,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum NoiseReqBody {
    SessionsList,
    SessionsCreate {
        title: Option<String>,
    },
    SessionsDelete {
        session_id: String,
    },
    /// Heartbeat — response echoes the current server time. Lets the
    /// client tell "tunnel alive" from "app hung."
    Ping,
}

#[derive(Debug, Serialize)]
struct NoiseResp {
    id: u64,
    #[serde(flatten)]
    body: NoiseRespBody,
}

#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum NoiseRespBody {
    /// Named `sessions` field so serde's `#[serde(tag)]` internal-
    /// tagging works (it can't internally-tag a bare `Vec`).
    Sessions {
        sessions: Vec<SessionInfo>,
    },
    Session {
        session: SessionInfo,
    },
    Ok,
    Err {
        msg: String,
    },
    Pong {
        server_time_ms: u64,
    },
}

async fn noise_ws_upgrade(ws: WebSocketUpgrade, State(m): State<Manager>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| noise_ws_loop(socket, m))
}

async fn noise_ws_loop(mut socket: WebSocket, m: Manager) {
    let Some(noise_key) = m.noise.clone() else {
        // No server key configured. Close with an unencrypted text
        // frame so the client can log a sensible error rather than
        // staring at a silent drop.
        let _ = socket
            .send(Message::Text(
                r#"{"error":"noise_not_configured"}"#.to_string().into(),
            ))
            .await;
        return;
    };

    // Drive the IK handshake first. Client sends msg1, server
    // responds with msg2, both enter transport mode.
    let mut responder = match noise_tunnel::Responder::new(noise_key.secret_bytes()) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("bastion/noise: responder init: {e}");
            return;
        }
    };

    let msg1 = match socket.recv().await {
        Some(Ok(Message::Binary(b))) => b,
        other => {
            eprintln!("bastion/noise: expected binary msg1, got {other:?}");
            return;
        }
    };
    if let Err(e) = responder.read_msg1(&msg1) {
        eprintln!("bastion/noise: msg1 read: {e}");
        return;
    }
    let peer_pub = responder
        .peer_pubkey()
        .map(|p| format!("{}…", &crate::noise::hex_encode(&p)[..16]))
        .unwrap_or_else(|| "?".into());
    let msg2 = match responder.write_msg2(&[]) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("bastion/noise: msg2 write: {e}");
            return;
        }
    };
    if socket.send(Message::Binary(msg2.into())).await.is_err() {
        return;
    }
    let mut transport = match responder.into_transport() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("bastion/noise: transport xition: {e}");
            return;
        }
    };
    eprintln!("bastion/noise: tunnel up (peer={peer_pub})");

    // Serve requests on the encrypted stream. Each inbound binary
    // frame is one decrypted JSON `NoiseReq`; response is one frame.
    while let Some(frame) = socket.recv().await {
        let Ok(Message::Binary(cipher)) = frame else {
            continue;
        };
        let plain = match transport.recv(&cipher) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("bastion/noise: decrypt: {e}");
                break;
            }
        };
        let resp = dispatch_noise_req(&m, &plain).await;
        let resp_bytes = match serde_json::to_vec(&resp) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("bastion/noise: encode resp: {e}");
                break;
            }
        };
        let ct = match transport.send(&resp_bytes) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("bastion/noise: encrypt: {e}");
                break;
            }
        };
        if socket.send(Message::Binary(ct.into())).await.is_err() {
            break;
        }
    }
}

async fn dispatch_noise_req(m: &Manager, plain: &[u8]) -> NoiseResp {
    let req: NoiseReq = match serde_json::from_slice(plain) {
        Ok(r) => r,
        Err(e) => {
            return NoiseResp {
                id: 0,
                body: NoiseRespBody::Err {
                    msg: format!("bad request: {e}"),
                },
            };
        }
    };
    let body = match req.body {
        NoiseReqBody::SessionsList => NoiseRespBody::Sessions {
            sessions: m.list().await,
        },
        NoiseReqBody::SessionsCreate { title } => {
            let t = title.unwrap_or_else(|| "shell".to_string());
            match m.create(t).await {
                Ok(s) => NoiseRespBody::Session { session: s.info() },
                Err(e) => NoiseRespBody::Err {
                    msg: format!("create: {e}"),
                },
            }
        }
        NoiseReqBody::SessionsDelete { session_id } => {
            if m.remove(&session_id).await {
                NoiseRespBody::Ok
            } else {
                NoiseRespBody::Err {
                    msg: "not_found".to_string(),
                }
            }
        }
        NoiseReqBody::Ping => NoiseRespBody::Pong {
            server_time_ms: now_ms(),
        },
    };
    NoiseResp { id: req.id, body }
}

// ---------------------------------------------------------------------
// SPA (Svelte + Vite, single-file bundle)
// ---------------------------------------------------------------------

/// Built SPA — a self-contained HTML document with inlined JS + CSS.
/// The source lives in `crates/bastion/web/`; `npm run build` produces
/// `web/dist/index.html`. Included at compile time so the bastion
/// binary ships with its own frontend, no asset handler required.
const SPA_HTML: &str = include_str!("../web/dist/index.html");

/// Return an HTML page that renders the unified sidebar across every
/// agent in `agents`. Each entry is `(vm_name, origin)` where `origin`
/// is the bastion base URL (e.g. `https://dd-prod-agent-…-block.devopsdefender.com`).
/// The CP's `/bastion` handler calls this with its fleet catalog to
/// produce a one-sidebar, every-node view.
///
/// Injects `window.__DD_AGENTS__ = [...]` before the SPA's `<script>`
/// tag so the SPA enters unified mode instead of the single-node
/// default. If `agents` is empty, the SPA falls back to single-node
/// mode and queries its own origin — identical behaviour to hitting
/// `GET /`.
pub fn aggregator_body(agents: &[(String, String)]) -> String {
    let agents_json = serde_json::to_string(
        &agents
            .iter()
            .map(|(vm, origin)| serde_json::json!({"vm_name": vm, "origin": origin}))
            .collect::<Vec<_>>(),
    )
    .unwrap_or_else(|_| "[]".into());
    let preamble = format!("<script>window.__DD_AGENTS__ = {agents_json};</script>");
    // Vite emits a well-formed `<head>…</head>`; splice the preamble
    // in right before the closing tag so it runs before the SPA
    // module script kicks off its `loadSessions()` fan-out on mount.
    SPA_HTML.replacen("</head>", &format!("{preamble}</head>"), 1)
}

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
            kind: "shell".into(),
            title: "t".into(),
            created_at_ms: 0,
            master: Some(Arc::new(Mutex::new(make_fake_master()))),
            writer: Some(Arc::new(Mutex::new(
                Box::new(std::io::sink()) as Box<dyn Write + Send>
            ))),
            ring: Arc::new(Mutex::new(VecDeque::new())),
            blocks: Arc::new(RwLock::new(VecDeque::new())),
            next_seq: Arc::new(Mutex::new(0)),
            tx: broadcast::channel::<Event>(8).0,
            workload_ctx: None,
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

    #[tokio::test]
    async fn workload_lifecycle_commits_one_block() {
        let m = Manager::new();
        m.register_workload(
            "cloudflared-1".into(),
            vec!["cloudflared".into(), "tunnel".into()],
            None,
        )
        .await;
        m.workload_out("cloudflared-1", b"INF starting\n").await;
        m.workload_out("cloudflared-1", b"INF connected\n").await;
        m.workload_exit("cloudflared-1", 0).await;

        let sessions = m.list().await;
        let w = sessions
            .iter()
            .find(|s| s.id == "cloudflared-1")
            .expect("workload session registered");
        assert_eq!(w.kind, "workload");
        assert_eq!(w.title, "cloudflared");
        assert_eq!(w.next_seq, 1);

        let session = m.get("cloudflared-1").await.expect("session");
        let blocks = session.blocks.read().await;
        assert_eq!(blocks.len(), 1);
        let b = &blocks[0];
        assert_eq!(b.kind, "workload");
        assert_eq!(b.command, "cloudflared tunnel");
        assert_eq!(b.exit_code, 0);
        let output = base64::engine::general_purpose::STANDARD
            .decode(&b.output_b64)
            .unwrap();
        assert_eq!(
            String::from_utf8(output).unwrap(),
            "INF starting\nINF connected\n"
        );
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
