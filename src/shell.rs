//! Multi-session shell sidecar.
//!
//! One process per VM, multiple reconnectable PTY sessions, read-only workload
//! terminals, and encrypted append-only transcripts on disk.
#![allow(dead_code, unused_imports)]

use std::cmp::Reverse;
use std::collections::{HashMap, VecDeque};
use std::fs::File as StdFile;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path as AxPath, Query, State};
use axum::http::{HeaderMap, StatusCode, Uri};
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
use tokio::net::TcpStream;
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
    ee: Arc<Ee>,
    http: reqwest::Client,
    agent_api: String,
    sessiond_http_url: String,
    sessiond_attach_addr: String,
    owner: crate::gh_oidc::Principal,
    auth: crate::auth::AuthConfig,
    hostname: String,
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

#[derive(Clone, Serialize)]
struct SessionMeta {
    id: String,
    name: String,
    recipe_id: String,
    recipe_title: String,
    workspace_policy: WorkspacePolicy,
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

#[derive(Clone, Serialize)]
struct Recipe {
    id: String,
    title: String,
    description: String,
    command: String,
    cwd: String,
    workspace_policy: WorkspacePolicy,
}

struct RecipeSeed {
    id: &'static str,
    title: &'static str,
    description: &'static str,
    script_name: &'static str,
    script: &'static str,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "snake_case")]
enum WorkspacePolicy {
    EphemeralScratch,
}

#[derive(Deserialize, Serialize)]
struct CreateSession {
    name: Option<String>,
    recipe_id: Option<String>,
    command: Option<String>,
    cwd: Option<String>,
}

#[derive(Serialize)]
struct CreateSessionResponse {
    id: String,
}

#[derive(Deserialize, Serialize)]
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
    let dir = std::env::var("DD_SHELL_DIR").unwrap_or_else(|_| DEFAULT_DIR.into());
    let requested_shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".into());
    let scratch_root = std::env::var("DD_SHELL_SCRATCH_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(&dir).join("sessions"));
    let ee_socket = std::env::var("DD_SHELL_EE_SOCKET")
        .unwrap_or_else(|_| "/var/lib/easyenclave/agent.sock".into());
    let agent_api = std::env::var("DD_SHELL_AGENT_API_URL")
        .unwrap_or_else(|_| format!("http://127.0.0.1:{}", crate::cf::AGENT_API_PORT));
    let sessiond_http_url =
        std::env::var("DD_SESSIOND_HTTP_URL").unwrap_or_else(|_| "http://127.0.0.1:7683".into());
    let sessiond_attach_addr =
        std::env::var("DD_SESSIOND_ATTACH_ADDR").unwrap_or_else(|_| "127.0.0.1:7684".into());
    let shell_dir = PathBuf::from(&dir);
    let store = TranscriptStore::new(shell_dir.clone()).await?;
    tokio::fs::create_dir_all(&scratch_root).await?;
    set_private_dir_permissions(&scratch_root).await?;
    let recipe_dir = shell_dir.join("recipes");
    let default_shell = install_default_shell_command(&recipe_dir, &requested_shell).await?;
    let recipe_scripts = install_builtin_recipe_scripts(&recipe_dir).await?;
    let recipes = Arc::new(load_recipes(&default_shell, recipe_scripts));

    let app_state = App {
        sessions: Arc::new(RwLock::new(HashMap::new())),
        store,
        ee: Arc::new(Ee::new(ee_socket)),
        http: reqwest::Client::builder()
            .timeout(Duration::from_secs(3))
            .no_hickory_dns()
            .build()
            .unwrap_or_else(|_| crate::system_http_client()),
        agent_api,
        sessiond_http_url,
        sessiond_attach_addr,
        owner: common.owner,
        auth,
        hostname,
        recipes,
        scratch_root,
    };

    let app = Router::new()
        .route("/", get(index))
        .route("/favicon.ico", get(favicon))
        .route("/manifest.webmanifest", get(manifest))
        .route("/sw.js", get(service_worker))
        .route("/icon.svg", get(icon_svg))
        .route("/assets/xterm/xterm.css", get(xterm_css))
        .route("/assets/xterm/xterm.js", get(xterm_js))
        .route("/assets/xterm/addon-fit.js", get(xterm_fit_js))
        .route("/api/recipes", get(list_recipes))
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

async fn manifest() -> impl IntoResponse {
    (
        [
            ("content-type", "application/manifest+json; charset=utf-8"),
            ("cache-control", "no-cache"),
        ],
        r##"{
  "name": "DD Shell",
  "short_name": "DD Shell",
  "description": "DevOps Defender confidential shell",
  "start_url": "/",
  "scope": "/",
  "display": "standalone",
  "background_color": "#05070a",
  "theme_color": "#111520",
  "icons": [
    {"src": "/icon.svg", "sizes": "any", "type": "image/svg+xml", "purpose": "any maskable"}
  ]
}"##,
    )
}

async fn service_worker() -> impl IntoResponse {
    (
        [
            ("content-type", "application/javascript; charset=utf-8"),
            ("cache-control", "no-cache"),
        ],
        r#"self.addEventListener("install", event => {
  event.waitUntil(self.skipWaiting());
});
self.addEventListener("activate", event => {
  event.waitUntil(self.clients.claim());
});
self.addEventListener("notificationclick", event => {
  event.notification.close();
  event.waitUntil((async () => {
    const allClients = await self.clients.matchAll({type: "window", includeUncontrolled: true});
    if (allClients.length) {
      await allClients[0].focus();
      return;
    }
    await self.clients.openWindow("/");
  })());
});
self.addEventListener("message", event => {
  const data = event.data || {};
  if (data.type !== "notify") return;
  const title = data.title || "DD Shell";
  const body = data.body || "";
  event.waitUntil(self.registration.showNotification(title, {
    body,
    tag: data.tag || "dd-shell",
    renotify: true,
    icon: "/icon.svg",
    badge: "/icon.svg"
  }));
});
"#,
    )
}

async fn icon_svg() -> impl IntoResponse {
    (
        [
            ("content-type", "image/svg+xml; charset=utf-8"),
            ("cache-control", "public, max-age=31536000, immutable"),
        ],
        r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128">
  <rect width="128" height="128" rx="24" fill="#05070a"/>
  <path fill="#7aa2f7" d="M25 28h37c25 0 42 14 42 36S87 100 62 100H25V28Zm20 18v36h17c14 0 22-7 22-18s-8-18-22-18H45Z"/>
  <path fill="#9ece6a" d="M38 55h23v18H38z"/>
</svg>"##,
    )
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

    if let Ok(command) = std::env::var("DD_SHELL_CODEX_COMMAND") {
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

async fn list_workloads(
    State(app): State<App>,
    headers: HeaderMap,
    uri: Uri,
) -> Result<Json<Vec<ManagedUnit>>> {
    ensure_shell_auth(&app, &headers, &uri)?;
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

async fn list_oracles(
    State(app): State<App>,
    headers: HeaderMap,
    uri: Uri,
) -> Result<Json<Vec<OracleStatus>>> {
    ensure_shell_auth(&app, &headers, &uri)?;
    Ok(Json(load_oracles(&app).await))
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

async fn system_status(
    State(app): State<App>,
    headers: HeaderMap,
    uri: Uri,
) -> Result<Json<SystemStatus>> {
    ensure_shell_auth(&app, &headers, &uri)?;
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
    Ok(Json(SystemStatus { ee, agent }))
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

async fn replay_workload(
    State(app): State<App>,
    headers: HeaderMap,
    uri: Uri,
    AxPath(name): AxPath<String>,
) -> Result<Json<ReplayResponse>> {
    ensure_shell_auth(&app, &headers, &uri)?;
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

async fn close_session(
    State(app): State<App>,
    headers: HeaderMap,
    uri: Uri,
    AxPath(id): AxPath<String>,
) -> Result<StatusCode> {
    ensure_shell_auth(&app, &headers, &uri)?;
    sessiond_post_empty(&app, &format!("/api/sessions/{id}/close")).await
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
        eprintln!("dd-shell: exit meta append failed: {e}");
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
            "dd-shell: scratch cleanup failed for {}: {e}",
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

const XTERM_CSS: &str = include_str!("../assets/xterm/xterm.css");
const XTERM_JS: &str = include_str!("../assets/xterm/xterm.js");
const XTERM_FIT_JS: &str = include_str!("../assets/xterm/addon-fit.js");

const SHELL_HTML: &str = r##"
<link rel="stylesheet" href="/assets/xterm/xterm.css">
<style>
body { background:#0b0d12; color:#d7deea; overflow:hidden; }
main { max-width:none; padding:0; height:100dvh; display:grid; grid-template-columns:320px 1fr; }
.sidebar { border-right:1px solid #252a36; background:#111520; overflow:auto; min-height:0; }
.sidebar-top { position:sticky; top:0; z-index:5; background:#111520; padding:16px 16px 12px; border-bottom:1px solid #252a36; }
.sidebar-scroll { padding:0 16px 16px; }
.terminal-wrap { height:100dvh; display:flex; flex-direction:column; min-width:0; }
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
.recipe-launcher { display:grid; grid-template-columns:1fr auto; gap:8px; }
.recipe-select { min-width:0; background:#0b0d12; color:#d7deea; border:1px solid #2b3242; border-radius:6px; padding:9px 10px; font:inherit; font-size:13px; }
.recipe-summary { margin-top:8px; color:#8791a5; font-size:11px; line-height:1.4; }
.badges { display:flex; flex-wrap:wrap; gap:5px; margin-top:7px; }
.badge { border:1px solid #2b3242; border-radius:999px; padding:1px 6px; color:#8791a5; font-size:10px; }
.badge.ok { color:#9ece6a; border-color:#334b35; }
.badge.bad { color:#f7768e; border-color:#57323d; }
.system { display:flex; flex-direction:column; gap:8px; }
.metrics { display:grid; grid-template-columns:1fr 1fr; gap:8px; }
.metric { background:#171c29; border:1px solid #2b3242; border-radius:6px; padding:10px; min-width:0; }
.metric .label { color:#8791a5; font-size:10px; text-transform:uppercase; }
.metric .value { margin-top:3px; font-size:16px; font-weight:700; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
.metric .subvalue { margin-top:2px; color:#8791a5; font-size:11px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
.probe { color:#d7deea; background:#171c29; border:1px solid #2b3242; border-radius:6px; padding:10px; }
.probe .row { display:flex; align-items:center; justify-content:space-between; gap:8px; }
.probe .name { font-weight:700; font-size:13px; }
.probe .meta { margin-top:3px; color:#8791a5; font-size:11px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
.pill { border:1px solid #2b3242; border-radius:999px; padding:2px 7px; color:#8791a5; font-size:11px; }
.pill.ok { color:#9ece6a; border-color:#334b35; }
.pill.bad { color:#f7768e; border-color:#57323d; }
.notify-feed { display:flex; flex-direction:column; gap:8px; margin-top:8px; }
.notify-item { background:#171c29; border:1px solid #2b3242; border-radius:6px; padding:9px 10px; min-width:0; }
.notify-item .notify-title { display:flex; align-items:center; justify-content:space-between; gap:8px; font-size:12px; font-weight:700; }
.notify-item .notify-time { color:#8791a5; font-size:10px; font-weight:400; white-space:nowrap; }
.notify-item .notify-body { margin-top:3px; color:#8791a5; font-size:11px; line-height:1.4; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
.notify-badge { display:none; min-width:18px; height:18px; border-radius:999px; background:#7aa2f7; color:#05070a; font-size:11px; font-weight:800; align-items:center; justify-content:center; padding:0 5px; }
.notify-badge.active { display:inline-flex; }
.toast-stack { position:fixed; top:60px; right:14px; z-index:50; display:flex; flex-direction:column; gap:8px; width:min(340px, calc(100vw - 28px)); pointer-events:none; }
.toast { background:#171c29; border:1px solid #3a4256; box-shadow:0 12px 30px #0008; border-radius:7px; padding:10px 12px; opacity:0; transform:translateY(-8px); transition:opacity .14s ease, transform .14s ease; }
.toast.show { opacity:1; transform:translateY(0); }
.toast .notify-title { font-size:12px; font-weight:800; }
.toast .notify-body { margin-top:3px; color:#d7deea; font-size:12px; line-height:1.35; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
.filter { width:100%; margin-top:10px; box-sizing:border-box; background:#0b0d12; color:#d7deea; border:1px solid #2b3242; border-radius:6px; padding:9px 10px; font:inherit; font-size:13px; }
.filter:focus { outline:1px solid #7aa2f7; border-color:#7aa2f7; }
.empty-mini { color:#8791a5; font-size:12px; padding:8px 2px; }
.status { color:#8791a5; font-size:12px; margin-left:auto; }
button.secondary { background:#252a36; color:#d7deea; }
.mobile-tabs { display:none; }
.panel { display:block; }
.panel-close { display:none; }
@media (max-width:860px) {
  main { display:block; height:100dvh; }
  .terminal-wrap { height:calc(100dvh - 52px); padding-bottom:env(safe-area-inset-bottom); }
  .toolbar { height:44px; padding:0 8px; gap:6px; }
  .toolbar button { padding:8px 10px; font-size:12px; }
  .status { font-size:11px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  .term { padding:4px; }
  .sidebar { position:fixed; left:0; right:0; bottom:52px; z-index:20; height:min(64dvh,520px); border-right:0; border-top:1px solid #252a36; border-radius:10px 10px 0 0; transform:translateY(105%); transition:transform .16s ease; box-shadow:0 -16px 40px #0008; }
  .sidebar.open { transform:translateY(0); }
  .sidebar-top { padding:12px 14px; }
  .sidebar-scroll { padding:0 14px 14px; }
  .groups { gap:0; }
  .panel { display:none; }
  .panel.active { display:block; }
  .group-title { position:static; margin:0 -14px 10px; padding:10px 14px; }
  .panel-close { display:inline-flex; position:absolute; top:10px; right:12px; padding:7px 10px; }
  .mobile-tabs { position:fixed; left:0; right:0; bottom:0; z-index:30; display:grid; grid-template-columns:repeat(4,1fr); height:52px; padding-bottom:env(safe-area-inset-bottom); background:#111520; border-top:1px solid #252a36; }
  .mobile-tabs button { border:0; border-right:1px solid #252a36; border-radius:0; background:#111520; color:#8791a5; font-size:12px; padding:8px 4px; }
  .mobile-tabs button.active { color:#d7deea; background:#171c29; }
  .toast-stack { top:52px; right:8px; width:calc(100vw - 16px); }
}
</style>
<div class="sidebar">
  <div class="sidebar-top">
    <h1>Shell</h1>
    <div class="sub">Observed logs and controlled PTYs</div>
    <button class="secondary panel-close" id="panel-close">Done</button>
    <input class="filter" id="workload-filter" type="search" placeholder="Filter workloads">
  </div>
  <div class="sidebar-scroll">
    <div class="groups">
      <div class="panel active" data-panel="system">
        <div class="group-title">System</div>
        <div class="system" id="system"></div>
        <div class="group-title">Notifications</div>
        <div class="notify-feed" id="notify-feed"></div>
      </div>
      <div class="panel" data-panel="recipes">
        <div class="group-title">New session</div>
        <div class="recipe-launcher">
          <select class="recipe-select" id="recipe-select"></select>
          <button class="secondary" id="launch-recipe">Start</button>
        </div>
        <div class="recipe-summary" id="recipe-summary"></div>
      </div>
      <div class="panel" data-panel="sessions">
        <div class="group-title">Read-write sessions</div>
        <div class="sessions" id="sessions"></div>
      </div>
      <div class="panel" data-panel="workloads">
        <div class="group-title">Read-only workloads</div>
        <div class="sessions" id="workloads"></div>
      </div>
    </div>
  </div>
</div>
<div class="terminal-wrap">
  <div class="toolbar">
    <button class="secondary" id="panels">Panels</button>
    <button class="secondary" id="close">Close session</button>
    <button class="secondary" id="notify" title="Enable notifications">Notify</button>
    <button class="secondary" id="notify-test" title="Send a test notification">Test</button>
    <span class="notify-badge" id="notify-badge">0</span>
    <span class="status" id="status">No session</span>
  </div>
  <div class="term" id="terminal"></div>
</div>
<div class="toast-stack" id="toast-stack"></div>
<div class="mobile-tabs" id="mobile-tabs">
  <button data-panel="system" class="active">System</button>
  <button data-panel="recipes">New</button>
  <button data-panel="sessions">Sessions</button>
  <button data-panel="workloads">Logs</button>
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
let cachedRecipes = [];
let cachedWorkloads = [];
let activePanel = "system";
let notifications = loadNotificationHistory();
let unreadNotifications = 0;
const decoder = new TextDecoder();
let serviceWorkerReady = null;
installPwaMetadata();
registerServiceWorker();

async function api(path, opts) {
  const res = await fetch(path, opts);
  if (!res.ok) throw new Error(await res.text());
  if (res.status === 204) return null;
  return res.json();
}

async function refresh() {
  const [system, recipes, sessions, workloads] = await Promise.all([
    api("/api/system").catch(() => null),
    api("/api/recipes").catch(() => []),
    api("/api/sessions").catch(() => []),
    api("/api/workloads").catch(() => [])
  ]);
  renderSystem(system);
  renderNotificationFeed();
  cachedRecipes = recipes;
  renderRecipes();
  cachedWorkloads = workloads;
  const root = document.getElementById("sessions");
  root.innerHTML = "";
  sessions.forEach(s => {
    const el = document.createElement("button");
    el.className = "session" + (currentKind === "session" && s.id === current ? " active" : "");
    const recipe = s.recipe_title || s.recipe_id || "Shell";
    el.innerHTML = `<div class="name">${escapeHtml(s.name)}</div><div class="meta">${escapeHtml(recipe)} - read-write - controlled - ${s.status} - ${new Date(s.updated_at*1000).toLocaleString()}</div>`;
    el.onclick = () => attach(s.id);
    root.appendChild(el);
  });
  renderWorkloads();
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
    metricsHtml(system.agent && system.agent.data),
    notificationHtml(),
    probeHtml("EasyEnclave", system.ee),
    probeHtml("Agent API", system.agent)
  ].join("");
}

function metricsHtml(data) {
  if (!data) return "";
  const cpu = data.cpu_percent ?? data.cpu_pct;
  const memUsed = data.memory_used_mb ?? data.mem_used_mb;
  const memTotal = data.memory_total_mb ?? data.mem_total_mb;
  const uptime = data.system_uptime_secs ?? data.uptime_secs;
  const load = data.load_1m;
  const disks = Array.isArray(data.disks) ? data.disks : [];
  const nets = Array.isArray(data.nets) ? data.nets : [];
  const disk = disks.find(d => d.mount === "/var/lib/easyenclave/data") || disks.find(d => d.mount === "/") || disks[0];
  const netRx = nets.reduce((sum, n) => sum + Number(n.rx_bytes || 0), 0);
  const netTx = nets.reduce((sum, n) => sum + Number(n.tx_bytes || 0), 0);
  const netNames = nets.map(n => n.iface).filter(Boolean).join(", ");
  return `<div class="metrics">
    ${metricHtml("CPU", cpu === undefined ? "unknown" : `${cpu}%`, load === undefined ? "load unknown" : `load ${Number(load).toFixed(2)}`)}
    ${metricHtml("Memory", memUsed === undefined || memTotal === undefined ? "unknown" : `${memUsed}/${memTotal} MB`, memTotal ? `${Math.round((memUsed / memTotal) * 100)}% used` : "")}
    ${metricHtml("Disk", disk ? `${formatBytes(disk.used_bytes)} / ${formatBytes(disk.total_bytes)}` : "unknown", disk ? disk.mount : "no disk data")}
    ${metricHtml("Network", nets.length ? `${formatBytes(netRx)} / ${formatBytes(netTx)}` : "unknown", nets.length ? `rx / tx ${netNames}` : "no net data")}
    ${metricHtml("Uptime", uptime === undefined ? "unknown" : formatDuration(uptime), data.vm_name || "agent")}
  </div>`;
}

function metricHtml(label, value, subvalue) {
  return `<div class="metric"><div class="label">${escapeHtml(label)}</div><div class="value">${escapeHtml(value)}</div><div class="subvalue">${escapeHtml(subvalue || "")}</div></div>`;
}

function notificationHtml() {
  const supported = "Notification" in window;
  const permission = supported ? Notification.permission : "unavailable";
  const enabled = supported && permission === "granted" && notifyMode !== "off";
  const sw = "serviceWorker" in navigator ? "service worker ready" : "service worker unavailable";
  const detail = supported ? `native ${permission}; ${sw}; in-app history on` : `in-app history on; native unavailable; ${sw}`;
  return `<div class="probe"><div class="row"><span class="name">Notifications</span><span class="pill ${enabled ? "ok" : "bad"}">${enabled ? "native" : "in-app"}</span></div><div class="meta">${escapeHtml(detail)}</div></div>`;
}

function renderNotificationFeed() {
  const root = document.getElementById("notify-feed");
  const badge = document.getElementById("notify-badge");
  if (!root || !badge) return;
  badge.textContent = unreadNotifications > 99 ? "99+" : String(unreadNotifications);
  badge.classList.toggle("active", unreadNotifications > 0);
  if (!notifications.length) {
    root.innerHTML = `<div class="empty-mini">No notifications yet</div>`;
    return;
  }
  root.innerHTML = notifications.slice(0, 12).map(n => `
    <div class="notify-item">
      <div class="notify-title"><span>${escapeHtml(n.title || "Shell")}</span><span class="notify-time">${escapeHtml(formatClock(n.ts))}</span></div>
      <div class="notify-body">${escapeHtml(n.body || "")}</div>
    </div>
  `).join("");
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

async function createSession(recipeId) {
  const body = recipeId ? {recipe_id: recipeId} : {};
  const r = await api("/api/sessions", {method:"POST", headers:{"content-type":"application/json"}, body:JSON.stringify(body)});
  await refresh();
  closePanels();
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
  closePanels();
  setTimeout(() => term.focus(), 0);
}

async function attachWorkload(name) {
  if (ws) ws.close();
  ws = null;
  stopWorkloadRefresh();
  current = name;
  currentKind = "workload";
  await loadWorkload(name);
  closePanels();
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

document.getElementById("workload-filter").oninput = renderWorkloads;
document.getElementById("recipe-select").onchange = renderRecipeSummary;
document.getElementById("launch-recipe").onclick = () => {
  const id = document.getElementById("recipe-select").value;
  if (id) createSession(id);
};
document.getElementById("panels").onclick = () => openPanels(activePanel);
document.getElementById("panel-close").onclick = closePanels;
document.querySelectorAll("#mobile-tabs button").forEach(btn => {
  btn.onclick = () => {
    setPanel(btn.dataset.panel);
    openPanels(btn.dataset.panel);
  };
});
document.getElementById("close").onclick = async () => {
  if (!current || currentKind !== "session") return;
  await api(`/api/sessions/${current}/close`, {method:"POST"});
  if (ws) ws.close();
  await refresh();
};
document.getElementById("notify").onclick = async () => {
  await registerServiceWorker();
  if (!("Notification" in window)) {
    document.getElementById("status").textContent = "Notifications unavailable";
    return;
  }
  const permission = Notification.permission === "default" ? await Notification.requestPermission() : Notification.permission;
  if (permission === "granted") {
    notifyMode = "always";
    localStorage.setItem("dd-shell-notify", notifyMode);
    document.getElementById("status").textContent = "Notifications enabled";
    renderSystem(await api("/api/system").catch(() => null));
  } else {
    notifyMode = "off";
    localStorage.setItem("dd-shell-notify", notifyMode);
    document.getElementById("status").textContent = "Notifications blocked";
    renderSystem(await api("/api/system").catch(() => null));
  }
};
document.getElementById("notify-test").onclick = async () => {
  if ("Notification" in window && Notification.permission !== "granted") {
    await document.getElementById("notify").onclick();
  }
  notify("DD Shell", "notification test");
};

function setPanel(panel) {
  activePanel = panel || "system";
  document.querySelectorAll(".panel").forEach(el => el.classList.toggle("active", el.dataset.panel === activePanel));
  document.querySelectorAll("#mobile-tabs button").forEach(el => el.classList.toggle("active", el.dataset.panel === activePanel));
  if (activePanel === "system") {
    unreadNotifications = 0;
    renderNotificationFeed();
  }
}

function openPanels(panel) {
  setPanel(panel || activePanel);
  document.querySelector(".sidebar").classList.add("open");
}

function closePanels() {
  document.querySelector(".sidebar").classList.remove("open");
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
  const item = {
    title: title || "Shell",
    body: body || "",
    ts: Date.now()
  };
  notifications.unshift(item);
  notifications = notifications.slice(0, 50);
  saveNotificationHistory();
  if (activePanel !== "system") unreadNotifications++;
  renderNotificationFeed();
  showToast(item);
  deliverNativeNotification(item);
}
function registerServiceWorker() {
  if (!("serviceWorker" in navigator) || !window.isSecureContext) return Promise.resolve(null);
  if (!serviceWorkerReady) {
    serviceWorkerReady = navigator.serviceWorker.register("/sw.js")
      .then(() => navigator.serviceWorker.ready)
      .catch(() => null);
  }
  return serviceWorkerReady;
}
async function deliverNativeNotification(item) {
  if (!("Notification" in window) || Notification.permission !== "granted") return;
  if (notifyMode !== "always" && document.hasFocus()) return;
  const title = item.title || "DD Shell";
  const body = item.body || "";
  const tag = current ? `dd-shell-${current}` : "dd-shell";
  const registration = await registerServiceWorker();
  if (registration && "showNotification" in registration) {
    await registration.showNotification(title, {body, tag, renotify: true, icon: "/icon.svg", badge: "/icon.svg"});
    return;
  }
  const n = new Notification(title, {body, tag});
  n.onclick = () => { window.focus(); term.focus(); n.close(); };
}
function installPwaMetadata() {
  const manifest = document.createElement("link");
  manifest.rel = "manifest";
  manifest.href = "/manifest.webmanifest";
  document.head.appendChild(manifest);
  const theme = document.createElement("meta");
  theme.name = "theme-color";
  theme.content = "#111520";
  document.head.appendChild(theme);
}
function loadNotificationHistory() {
  try {
    const parsed = JSON.parse(localStorage.getItem("dd-shell-notifications") || "[]");
    return Array.isArray(parsed) ? parsed.slice(0, 50) : [];
  } catch (_) {
    return [];
  }
}
function saveNotificationHistory() {
  localStorage.setItem("dd-shell-notifications", JSON.stringify(notifications.slice(0, 50)));
}
function showToast(item) {
  const stack = document.getElementById("toast-stack");
  if (!stack) return;
  const el = document.createElement("div");
  el.className = "toast";
  el.innerHTML = `<div class="notify-title">${escapeHtml(item.title || "Shell")}</div><div class="notify-body">${escapeHtml(item.body || "")}</div>`;
  stack.prepend(el);
  requestAnimationFrame(() => el.classList.add("show"));
  setTimeout(() => {
    el.classList.remove("show");
    setTimeout(() => el.remove(), 180);
  }, 4200);
}
function formatClock(ts) {
  try {
    return new Date(ts).toLocaleTimeString([], {hour:"2-digit", minute:"2-digit"});
  } catch (_) {
    return "";
  }
}
function formatBytes(value) {
  const n = Number(value || 0);
  if (n < 1024) return `${n} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v >= 10 ? v.toFixed(0) : v.toFixed(1)} ${units[i]}`;
}
function formatDuration(value) {
  let s = Number(value || 0);
  const d = Math.floor(s / 86400); s %= 86400;
  const h = Math.floor(s / 3600); s %= 3600;
  const m = Math.floor(s / 60);
  if (d) return `${d}d ${h}h`;
  if (h) return `${h}h ${m}m`;
  return `${m}m`;
}
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
window.addEventListener("resize", fitAndResize);
new ResizeObserver(fitAndResize).observe(terminalEl);
refresh();
setPanel("system");
fitAndResize();
term.focus();
</script>
"##;
