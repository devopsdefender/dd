//! Local interactive session supervisor.
//!
//! `dd-sessiond` owns PTYs and child process groups. Web/API surfaces such as
//! `dd-shell` and `dd-agent` should proxy to this process instead of spawning
//! interactive commands themselves.

use std::cmp::Reverse;
use std::collections::{HashMap, VecDeque};
use std::fs::File as StdFile;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::{Path as AxPath, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine as _;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::fs::File as TokioFile;
use tokio::fs::OpenOptions;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::{Child, Command};
use tokio::sync::{broadcast, Mutex, RwLock};
use uuid::Uuid;

use crate::error::{Error, Result};
use crate::taint::IntegrityState;

const DEFAULT_HTTP_ADDR: &str = "127.0.0.1:7683";
const DEFAULT_ATTACH_ADDR: &str = "127.0.0.1:7684";
const DEFAULT_DIR: &str = "/var/lib/devopsdefender/sessiond";
const EE_DATA_MOUNT: &str = "/var/lib/easyenclave/data";
const DATA_MOUNT_WAIT_SECS: u64 = 60;
const RING_LIMIT: usize = 256 * 1024;

const CODEX_PODMAN_RECIPE: &str = r#"#!/var/lib/easyenclave/bin/busybox sh
set -eu
BB=/var/lib/easyenclave/bin/busybox
BIN=/var/lib/easyenclave/bin
PODMAN=$BIN/podman
SESSION_ID=${DD_SESSION_ID:-manual-$$}
SESSION_DIR=${DD_SESSION_DIR:-/var/lib/easyenclave/data/dd-shell/sessions/$SESSION_ID}
WORKSPACE=${DD_WORKSPACE:-$SESSION_DIR/workspace}
HOME_DIR=${DD_HOME:-$SESSION_DIR/home}
CACHE_DIR=${DD_CACHE:-$SESSION_DIR/cache}
TMP_DIR=${TMPDIR:-$SESSION_DIR/tmp}
until [ -x "$PODMAN" ]; do echo "codex-podman: waiting for podman"; $BB sleep 2; done
$BB mkdir -p "$HOME_DIR" "$WORKSPACE" "$CACHE_DIR" "$TMP_DIR"
$BB chmod 1777 "$TMP_DIR"
SAFE_SESSION=$(printf '%s' "$SESSION_ID" | $BB tr -c 'A-Za-z0-9_.-' '-')
exec "$PODMAN" run --rm --replace -it --pull=missing \
  --cgroups=disabled \
  --network=host \
  --name "codex-shell-$SAFE_SESSION" \
  -e HOME=/root \
  -e TERM=xterm-256color \
  -e COLORTERM=truecolor \
  -e NPM_CONFIG_PREFIX=/root/.npm-global \
  -v "$HOME_DIR:/root" \
  -v "$WORKSPACE:/workspace" \
  -v "$CACHE_DIR:/root/.cache" \
  -v "$TMP_DIR:/tmp" \
  -w /workspace \
  docker.io/library/node:22-bookworm \
  sh -lc 'set -e; mkdir -p "$HOME/.npm-global/bin" "$HOME/.local/bin"; printf "%s\n" "export NPM_CONFIG_PREFIX=\${NPM_CONFIG_PREFIX:-\$HOME/.npm-global}" "export PATH=\"\$HOME/.npm-global/bin:\$HOME/.local/bin:\$PATH\"" > "$HOME/.bashrc"; printf "%s\n" "[ -r \"\$HOME/.bashrc\" ] && . \"\$HOME/.bashrc\"" > "$HOME/.bash_profile"; export PATH="$HOME/.npm-global/bin:$HOME/.local/bin:$PATH"; if ! command -v codex >/dev/null 2>&1; then npm install -g @openai/codex; fi; exec bash -l'
"#;

const PODMAN_UBUNTU_RECIPE: &str = r#"#!/var/lib/easyenclave/bin/busybox sh
set -eu
BB=/var/lib/easyenclave/bin/busybox
BIN=/var/lib/easyenclave/bin
PODMAN=$BIN/podman
SESSION_ID=${DD_SESSION_ID:-manual-$$}
SESSION_DIR=${DD_SESSION_DIR:-/var/lib/easyenclave/data/dd-shell/sessions/$SESSION_ID}
WORKSPACE=${DD_WORKSPACE:-$SESSION_DIR/workspace}
HOME_DIR=${DD_HOME:-$SESSION_DIR/home}
CACHE_DIR=${DD_CACHE:-$SESSION_DIR/cache}
TMP_DIR=${TMPDIR:-$SESSION_DIR/tmp}
until [ -x "$PODMAN" ]; do echo "podman-ubuntu: waiting for podman"; $BB sleep 2; done
$BB mkdir -p "$HOME_DIR" "$WORKSPACE" "$CACHE_DIR" "$TMP_DIR"
$BB chmod 1777 "$TMP_DIR"
SAFE_SESSION=$(printf '%s' "$SESSION_ID" | $BB tr -c 'A-Za-z0-9_.-' '-')
exec "$PODMAN" run --rm --replace -it --pull=missing \
  --cgroups=disabled \
  --network=host \
  --name "ubuntu-shell-$SAFE_SESSION" \
  -e HOME=/root \
  -e TERM=xterm-256color \
  -e COLORTERM=truecolor \
  -v "$HOME_DIR:/root" \
  -v "$WORKSPACE:/workspace" \
  -v "$CACHE_DIR:/root/.cache" \
  -v "$TMP_DIR:/tmp" \
  -w /workspace \
  docker.io/library/ubuntu:24.04 \
  bash -l
"#;

const PODMAN_ALPINE_RECIPE: &str = r#"#!/var/lib/easyenclave/bin/busybox sh
set -eu
BB=/var/lib/easyenclave/bin/busybox
BIN=/var/lib/easyenclave/bin
PODMAN=$BIN/podman
SESSION_ID=${DD_SESSION_ID:-manual-$$}
SESSION_DIR=${DD_SESSION_DIR:-/var/lib/easyenclave/data/dd-shell/sessions/$SESSION_ID}
WORKSPACE=${DD_WORKSPACE:-$SESSION_DIR/workspace}
HOME_DIR=${DD_HOME:-$SESSION_DIR/home}
CACHE_DIR=${DD_CACHE:-$SESSION_DIR/cache}
TMP_DIR=${TMPDIR:-$SESSION_DIR/tmp}
until [ -x "$PODMAN" ]; do echo "podman-alpine: waiting for podman"; $BB sleep 2; done
$BB mkdir -p "$HOME_DIR" "$WORKSPACE" "$CACHE_DIR" "$TMP_DIR"
$BB chmod 1777 "$TMP_DIR"
SAFE_SESSION=$(printf '%s' "$SESSION_ID" | $BB tr -c 'A-Za-z0-9_.-' '-')
exec "$PODMAN" run --rm --replace -it --pull=missing \
  --cgroups=disabled \
  --network=host \
  --name "alpine-shell-$SAFE_SESSION" \
  -e HOME=/root \
  -e TERM=xterm-256color \
  -e COLORTERM=truecolor \
  -v "$HOME_DIR:/root" \
  -v "$WORKSPACE:/workspace" \
  -v "$CACHE_DIR:/root/.cache" \
  -v "$TMP_DIR:/tmp" \
  -w /workspace \
  docker.io/library/alpine:3.20 \
  /bin/sh
"#;

#[derive(Clone)]
struct App {
    sessions: Arc<RwLock<HashMap<String, Arc<Session>>>>,
    store: TranscriptStore,
    recipes: Arc<Vec<Recipe>>,
    scratch_root: PathBuf,
}

struct Session {
    meta: RwLock<SessionMeta>,
    input: Mutex<TokioFile>,
    master_fd: i32,
    child: Mutex<Child>,
    pgid: i32,
    tx: broadcast::Sender<Vec<u8>>,
    ring: Mutex<VecDeque<u8>>,
    scratch_dir: Option<PathBuf>,
    cleanup_scratch_on_exit: bool,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct SessionMeta {
    pub id: String,
    pub name: String,
    pub recipe_id: String,
    pub recipe_title: String,
    pub workspace_policy: WorkspacePolicy,
    pub command: String,
    pub cwd: String,
    pub terminal_mode: TerminalMode,
    pub integrity_state: IntegrityState,
    pub integrity_reason: String,
    pub created_at: i64,
    pub updated_at: i64,
    pub status: SessionStatus,
    pub exit_code: Option<i32>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminalMode {
    ReadWrite,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    Running,
    Exited,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct Recipe {
    pub id: String,
    pub title: String,
    pub description: String,
    pub command: String,
    pub cwd: String,
    pub workspace_policy: WorkspacePolicy,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspacePolicy {
    EphemeralScratch,
}

#[derive(Deserialize, Serialize)]
pub struct CreateSession {
    pub name: Option<String>,
    pub recipe_id: Option<String>,
    pub command: Option<String>,
    pub cwd: Option<String>,
}

#[derive(Deserialize, Serialize)]
pub struct CreateSessionResponse {
    pub id: String,
}

#[derive(Deserialize, Serialize)]
pub struct ResizeSession {
    pub cols: u16,
    pub rows: u16,
}

#[derive(Deserialize, Serialize)]
pub struct ReplayResponse {
    pub id: String,
    pub bytes_b64: String,
}

struct RecipeSeed {
    id: &'static str,
    title: &'static str,
    description: &'static str,
    script_name: &'static str,
    script: &'static str,
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

pub async fn run() -> Result<()> {
    let http_addr =
        std::env::var("DD_SESSIOND_HTTP_ADDR").unwrap_or_else(|_| DEFAULT_HTTP_ADDR.to_string());
    let attach_addr = std::env::var("DD_SESSIOND_ATTACH_ADDR")
        .unwrap_or_else(|_| DEFAULT_ATTACH_ADDR.to_string());
    let dir = std::env::var("DD_SESSIOND_DIR")
        .or_else(|_| std::env::var("DD_SHELL_DIR"))
        .unwrap_or_else(|_| DEFAULT_DIR.into());
    let requested_shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".into());
    let scratch_root = std::env::var("DD_SESSIOND_SCRATCH_DIR")
        .or_else(|_| std::env::var("DD_SHELL_SCRATCH_DIR"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(&dir).join("sessions"));

    let root = PathBuf::from(&dir);
    wait_for_required_mounts(&[root.as_path(), scratch_root.as_path()]).await?;
    let store = TranscriptStore::new(root.clone()).await?;
    tokio::fs::create_dir_all(&scratch_root).await?;
    set_private_dir_permissions(&scratch_root).await?;
    let recipe_dir = root.join("recipes");
    let default_shell = install_default_shell_command(&recipe_dir, &requested_shell).await?;
    let recipe_scripts = install_builtin_recipe_scripts(&recipe_dir).await?;
    let recipes = Arc::new(load_recipes(&default_shell, recipe_scripts));

    let app_state = App {
        sessions: Arc::new(RwLock::new(HashMap::new())),
        store,
        recipes,
        scratch_root,
    };

    {
        let state = app_state.clone();
        let attach_addr = attach_addr.clone();
        tokio::spawn(async move {
            if let Err(e) = run_attach_listener(state, &attach_addr).await {
                eprintln!("dd-sessiond: attach listener exited: {e}");
            }
        });
    }

    let app = Router::new()
        .route("/api/recipes", get(list_recipes))
        .route("/api/sessions", get(list_sessions).post(create_session))
        .route("/api/sessions/{id}/replay", get(replay_session))
        .route("/api/sessions/{id}/resize", post(resize_session))
        .route("/api/sessions/{id}/close", post(close_session))
        .with_state(app_state);

    eprintln!("dd-sessiond: http listening on {http_addr}");
    let listener = TcpListener::bind(&http_addr).await?;
    axum::serve(listener, app.into_make_service())
        .await
        .map_err(|e| Error::Internal(e.to_string()))
}

async fn wait_for_required_mounts(paths: &[&Path]) -> Result<()> {
    let data_mount = Path::new(EE_DATA_MOUNT);
    if !paths.iter().any(|path| path.starts_with(data_mount)) {
        return Ok(());
    }

    for attempt in 0..=DATA_MOUNT_WAIT_SECS {
        if mount_present(data_mount).await? {
            if attempt > 0 {
                eprintln!("dd-sessiond: {EE_DATA_MOUNT} mounted after {attempt}s");
            }
            return Ok(());
        }
        if attempt == 0 {
            eprintln!("dd-sessiond: waiting for {EE_DATA_MOUNT} before initializing storage");
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    Err(Error::Internal(format!(
        "{EE_DATA_MOUNT} did not mount within {DATA_MOUNT_WAIT_SECS}s"
    )))
}

async fn mount_present(target: &Path) -> Result<bool> {
    let mounts = tokio::fs::read_to_string("/proc/mounts").await?;
    let target = target.to_string_lossy();
    Ok(mounts.lines().any(|line| {
        line.split_whitespace()
            .nth(1)
            .is_some_and(|mountpoint| mountpoint == target)
    }))
}

async fn list_recipes(State(app): State<App>) -> Json<Vec<Recipe>> {
    Json((*app.recipes).clone())
}

async fn list_sessions(State(app): State<App>) -> Json<Vec<SessionMeta>> {
    let sessions: Vec<Arc<Session>> = app.sessions.read().await.values().cloned().collect();
    let mut out = Vec::with_capacity(sessions.len());
    for session in sessions {
        out.push(session.meta.read().await.clone());
    }
    out.sort_by_key(|s| Reverse(s.updated_at));
    Json(out)
}

async fn create_session(
    State(app): State<App>,
    Json(req): Json<CreateSession>,
) -> Result<Json<CreateSessionResponse>> {
    let id = Uuid::new_v4().to_string();
    let recipe = select_recipe(&app, req.recipe_id.as_deref(), req.command)?;
    let command = recipe.command.clone();
    let cwd = req.cwd.unwrap_or_else(|| recipe.cwd.clone());
    let name = req.name.unwrap_or_else(|| session_name(&recipe, &id));
    let now = unix_ts();
    let scratch_dir = prepare_scratch_dir(&app, &id, &recipe.workspace_policy).await?;
    let env = session_env(&id, scratch_dir.as_deref());

    let (child, output, input, pgid) = spawn_pty(&command, &cwd, &env)?;
    let master_fd = input.as_raw_fd();
    let (tx, _) = broadcast::channel(512);

    let meta = SessionMeta {
        id: id.clone(),
        name,
        recipe_id: recipe.id,
        recipe_title: recipe.title,
        workspace_policy: recipe.workspace_policy,
        command,
        cwd,
        terminal_mode: TerminalMode::ReadWrite,
        integrity_state: IntegrityState::Controlled,
        integrity_reason: "interactive_pty_control".into(),
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
        scratch_dir,
        cleanup_scratch_on_exit: true,
    });

    app.sessions
        .write()
        .await
        .insert(id.clone(), session.clone());
    spawn_reader(app.store.clone(), session.clone(), output, "pty");
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

async fn close_session(State(app): State<App>, AxPath(id): AxPath<String>) -> Result<StatusCode> {
    let Some(session) = app.sessions.write().await.remove(&id) else {
        return Err(Error::NotFound);
    };
    let pgid = session.pgid;
    mark_session_exited(&app.store, &session, None).await;
    terminate_process_group(id, pgid);
    Ok(StatusCode::NO_CONTENT)
}

async fn run_attach_listener(app: App, addr: &str) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    eprintln!("dd-sessiond: attach listening on {addr}");
    loop {
        let (stream, _) = listener.accept().await?;
        let app = app.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_attach(app, stream).await {
                eprintln!("dd-sessiond: attach failed: {e}");
            }
        });
    }
}

async fn handle_attach(app: App, stream: TcpStream) -> anyhow::Result<()> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).await?;
    let mut parts = line.split_whitespace();
    let id = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing session id"))?;
    let tail = parts.next() != Some("notail");
    let session = app
        .sessions
        .read()
        .await
        .get(id)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("unknown session: {id}"))?;
    let stream = reader.into_inner();
    attach_stream(stream, session, tail).await
}

async fn attach_stream(stream: TcpStream, session: Arc<Session>, tail: bool) -> anyhow::Result<()> {
    let (mut reader, mut writer) = stream.into_split();

    if tail {
        let ring = session.ring.lock().await;
        if !ring.is_empty() {
            let bytes: Vec<u8> = ring.iter().copied().collect();
            writer.write_all(&bytes).await?;
        }
    }

    let mut output_rx = session.tx.subscribe();
    let output = tokio::spawn(async move {
        while let Ok(bytes) = output_rx.recv().await {
            if writer.write_all(&bytes).await.is_err() {
                break;
            }
        }
    });

    let mut buf = [0u8; 4096];
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        session.input.lock().await.write_all(&buf[..n]).await?;
    }
    output.abort();
    Ok(())
}

fn select_recipe(app: &App, recipe_id: Option<&str>, command: Option<String>) -> Result<Recipe> {
    if let Some(command) = command {
        let command = command.trim();
        if command.is_empty() {
            return Err(Error::BadRequest("command must not be empty".into()));
        }
        return Ok(Recipe {
            id: "custom".into(),
            title: "Custom".into(),
            description: "Custom command".into(),
            command: command.into(),
            cwd: "/".into(),
            workspace_policy: WorkspacePolicy::EphemeralScratch,
        });
    }

    let id = recipe_id.unwrap_or("shell");
    app.recipes
        .iter()
        .find(|recipe| recipe.id == id)
        .cloned()
        .ok_or_else(|| Error::BadRequest(format!("unknown recipe: {id}")))
}

async fn install_default_shell_command(dir: &Path, requested_shell: &str) -> Result<String> {
    if executable_exists(requested_shell).await {
        return Ok(requested_shell.into());
    }
    if executable_exists("/bin/sh").await {
        return Ok("/bin/sh".into());
    }
    if executable_exists("/var/lib/easyenclave/bin/busybox").await {
        tokio::fs::create_dir_all(dir).await?;
        set_private_dir_permissions(dir).await?;
        let path = dir.join("plain-shell");
        tokio::fs::write(
            &path,
            "#!/var/lib/easyenclave/bin/busybox sh\nexec /var/lib/easyenclave/bin/busybox sh\n",
        )
        .await?;
        set_private_file_permissions(&path).await?;
        return Ok(path.display().to_string());
    }
    Ok(requested_shell.into())
}

async fn executable_exists(path: &str) -> bool {
    match tokio::fs::metadata(path).await {
        Ok(meta) => meta.is_file() && meta.permissions().mode() & 0o111 != 0,
        Err(_) => false,
    }
}

async fn install_builtin_recipe_scripts(dir: &Path) -> Result<Vec<Recipe>> {
    tokio::fs::create_dir_all(dir).await?;
    set_private_dir_permissions(dir).await?;

    let mut recipes = Vec::new();
    for seed in builtin_recipe_seeds() {
        let path = dir.join(seed.script_name);
        tokio::fs::write(&path, seed.script).await?;
        set_private_file_permissions(&path).await?;
        recipes.push(Recipe {
            id: seed.id.into(),
            title: seed.title.into(),
            description: seed.description.into(),
            command: path.display().to_string(),
            cwd: "/".into(),
            workspace_policy: WorkspacePolicy::EphemeralScratch,
        });
    }
    Ok(recipes)
}

fn load_recipes(default_shell: &str, mut builtin_recipes: Vec<Recipe>) -> Vec<Recipe> {
    let mut recipes = vec![Recipe {
        id: "shell".into(),
        title: "Shell".into(),
        description: "Plain interactive shell with encrypted transcript history".into(),
        command: default_shell.into(),
        cwd: "/".into(),
        workspace_policy: WorkspacePolicy::EphemeralScratch,
    }];
    recipes.append(&mut builtin_recipes);

    if let Ok(command) = std::env::var("DD_SESSIOND_CODEX_COMMAND")
        .or_else(|_| std::env::var("DD_SHELL_CODEX_COMMAND"))
    {
        let command = command.trim();
        if !command.is_empty() {
            upsert_recipe(
                &mut recipes,
                Recipe {
                    id: "codex-podman".into(),
                    title: "Codex".into(),
                    description: "Podman-backed Codex development session".into(),
                    command: command.into(),
                    cwd: "/".into(),
                    workspace_policy: WorkspacePolicy::EphemeralScratch,
                },
            );
        }
    }

    recipes
}

fn upsert_recipe(recipes: &mut Vec<Recipe>, recipe: Recipe) {
    if let Some(existing) = recipes.iter_mut().find(|r| r.id == recipe.id) {
        *existing = recipe;
    } else {
        recipes.push(recipe);
    }
}

fn builtin_recipe_seeds() -> Vec<RecipeSeed> {
    vec![
        RecipeSeed {
            id: "codex-podman",
            title: "Codex",
            description: "Podman-backed Codex development session",
            script_name: "codex-podman",
            script: CODEX_PODMAN_RECIPE,
        },
        RecipeSeed {
            id: "podman-ubuntu",
            title: "Ubuntu",
            description: "Podman Ubuntu 24.04 shell",
            script_name: "podman-ubuntu",
            script: PODMAN_UBUNTU_RECIPE,
        },
        RecipeSeed {
            id: "podman-alpine",
            title: "Alpine",
            description: "Podman Alpine shell",
            script_name: "podman-alpine",
            script: PODMAN_ALPINE_RECIPE,
        },
    ]
}

async fn prepare_scratch_dir(
    app: &App,
    id: &str,
    policy: &WorkspacePolicy,
) -> Result<Option<PathBuf>> {
    match policy {
        WorkspacePolicy::EphemeralScratch => {
            let root = app.scratch_root.join(id);
            tokio::fs::create_dir_all(&root).await?;
            set_private_dir_permissions(&root).await?;
            for name in ["workspace", "home", "containers", "cache", "tmp"] {
                let path = root.join(name);
                tokio::fs::create_dir_all(&path).await?;
                set_private_dir_permissions(&path).await?;
            }
            Ok(Some(root))
        }
    }
}

async fn set_private_dir_permissions(path: &Path) -> Result<()> {
    let permissions = std::fs::Permissions::from_mode(0o700);
    tokio::fs::set_permissions(path, permissions).await?;
    Ok(())
}

async fn set_private_file_permissions(path: &Path) -> Result<()> {
    let permissions = std::fs::Permissions::from_mode(0o700);
    tokio::fs::set_permissions(path, permissions).await?;
    Ok(())
}

fn session_env(id: &str, scratch_dir: Option<&Path>) -> Vec<(String, String)> {
    let mut env = vec![("DD_SESSION_ID".into(), id.into())];
    if let Some(root) = scratch_dir {
        env.push(("DD_SESSION_DIR".into(), root.display().to_string()));
        env.push((
            "DD_WORKSPACE".into(),
            root.join("workspace").display().to_string(),
        ));
        env.push(("DD_HOME".into(), root.join("home").display().to_string()));
        env.push((
            "DD_CONTAINER_ROOT".into(),
            root.join("containers").display().to_string(),
        ));
        env.push(("DD_CACHE".into(), root.join("cache").display().to_string()));
        env.push(("TMPDIR".into(), root.join("tmp").display().to_string()));
    }
    env
}

fn session_name(recipe: &Recipe, id: &str) -> String {
    format!("{}-{}", recipe.id, &id[..8])
}

fn spawn_pty(
    command: &str,
    cwd: &str,
    env_vars: &[(String, String)],
) -> Result<(Child, TokioFile, TokioFile, i32)> {
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
    for (key, value) in env_vars {
        cmd.env(key, value);
    }
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
                    eprintln!("dd-sessiond: signal {signal} for {id}: {err}");
                }
                break;
            }
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
        }
    });
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
                        eprintln!("dd-sessiond: transcript append failed: {e}");
                    }
                    session.meta.write().await.updated_at = unix_ts();
                }
                Err(e) => {
                    eprintln!("dd-sessiond: {kind} read failed: {e}");
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
        cleanup_session_scratch(&session).await;
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
        eprintln!("dd-sessiond: exit meta append failed: {e}");
    }
}

async fn cleanup_session_scratch(session: &Session) {
    if !session.cleanup_scratch_on_exit {
        return;
    }
    let Some(path) = &session.scratch_dir else {
        return;
    };
    match tokio::fs::remove_dir_all(path).await {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => eprintln!(
            "dd-sessiond: scratch cleanup failed for {}: {e}",
            path.display()
        ),
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
    if let Ok(raw) =
        std::env::var("DD_SESSIOND_HISTORY_KEY").or_else(|_| std::env::var("DD_SHELL_HISTORY_KEY"))
    {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(raw.trim())
            .or_else(|_| hex::decode(raw.trim()))
            .map_err(|_| {
                Error::BadRequest("DD_SESSIOND_HISTORY_KEY must be base64 or hex".into())
            })?;
        if bytes.len() != 32 {
            return Err(Error::BadRequest(
                "DD_SESSIOND_HISTORY_KEY must decode to 32 bytes".into(),
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
    hasher.update(b"dd-sessiond-history-v1");
    Ok(hasher.finalize().into())
}

fn unix_ts() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs() as i64
}
