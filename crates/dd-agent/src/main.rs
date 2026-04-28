use std::collections::HashMap;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::RwLock;

const GITHUB_ISSUER: &str = "https://token.actions.githubusercontent.com";
const GITHUB_JWKS_URL: &str = "https://token.actions.githubusercontent.com/.well-known/jwks";
const DEFAULT_AUDIENCE: &str = "dd-agent";
const MAX_LOG_LINES: usize = 2_000;

type Result<T> = std::result::Result<T, ApiError>;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cfg = Config::from_env()?;
    let state = AppState::new(cfg);
    let addr = format!("0.0.0.0:{}", state.cfg.port);

    let app = Router::new()
        .route("/health", get(health))
        .route("/owner", post(set_owner))
        .route("/deploy", post(deploy))
        .route("/logs/{app}", get(logs))
        .route("/exec", post(exec))
        .with_state(state);

    eprintln!("dd-agent: listening on {addr}");
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

#[derive(Clone)]
struct AppState {
    cfg: Arc<Config>,
    verifier: Arc<GithubOidc>,
    started_at: DateTime<Utc>,
    owner: Arc<RwLock<Option<Assignment>>>,
    workloads: Arc<RwLock<HashMap<String, WorkloadRecord>>>,
}

impl AppState {
    fn new(cfg: Config) -> Self {
        let verifier = Arc::new(GithubOidc::new(cfg.oidc_audience.clone()));
        Self {
            cfg: Arc::new(cfg),
            verifier,
            started_at: Utc::now(),
            owner: Arc::new(RwLock::new(None)),
            workloads: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[derive(Clone)]
struct Config {
    agent_id: String,
    hostname: String,
    port: u16,
    assignment_authority: Principal,
    capabilities: Capabilities,
    attestation: AttestationProof,
    oidc_audience: String,
}

impl Config {
    fn from_env() -> anyhow::Result<Self> {
        let agent_id = std::env::var("DD_AGENT_ID")
            .unwrap_or_else(|_| format!("dd-agent-{}", uuid::Uuid::new_v4()));
        let hostname = std::env::var("DD_HOSTNAME").unwrap_or_else(|_| "localhost".into());
        let port = std::env::var("DD_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(8080);
        let assignment_authority = Principal::from_env("DD_ASSIGNMENT_AUTHORITY")?;
        let capabilities = Capabilities {
            runtime_deploy: env_truthy("DD_CAP_RUNTIME_DEPLOY", true),
            exec: env_truthy("DD_CAP_EXEC", false),
            interactive_shell: env_truthy("DD_CAP_INTERACTIVE_SHELL", false),
            logs: env_truthy("DD_CAP_LOGS", true),
        };
        let attestation = AttestationProof {
            kind: std::env::var("DD_ATTESTATION_TYPE").unwrap_or_else(|_| "dev".into()),
            quote_b64: std::env::var("DD_TDX_QUOTE_B64").ok(),
            mrtd: std::env::var("DD_TDX_MRTD").ok(),
            tcb_status: std::env::var("DD_TCB_STATUS").ok(),
        };
        let oidc_audience =
            std::env::var("DD_OIDC_AUDIENCE").unwrap_or_else(|_| DEFAULT_AUDIENCE.into());
        Ok(Self {
            agent_id,
            hostname,
            port,
            assignment_authority,
            capabilities,
            attestation,
            oidc_audience,
        })
    }
}

fn env_truthy(key: &str, default: bool) -> bool {
    match std::env::var(key) {
        Ok(value) => matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => default,
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
enum PrincipalKind {
    User,
    Org,
    Repo,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct Principal {
    kind: PrincipalKind,
    name: String,
    id: u64,
}

impl Principal {
    fn from_env(prefix: &str) -> anyhow::Result<Self> {
        let kind = match required_env(&format!("{prefix}_KIND"))?.as_str() {
            "user" => PrincipalKind::User,
            "org" => PrincipalKind::Org,
            "repo" => PrincipalKind::Repo,
            other => anyhow::bail!("{prefix}_KIND must be user|org|repo, got {other:?}"),
        };
        let name = required_env(&format!("{prefix}_NAME"))?;
        let id = required_env(&format!("{prefix}_ID"))?.parse::<u64>()?;
        Self::validate(kind, name, id)
    }

    fn validate(kind: PrincipalKind, name: String, id: u64) -> anyhow::Result<Self> {
        if id == 0 {
            anyhow::bail!("principal id must be non-zero");
        }
        if name.trim().is_empty() {
            anyhow::bail!("principal name must be non-empty");
        }
        let has_slash = name.contains('/');
        let shape_ok = matches!(
            (&kind, has_slash),
            (PrincipalKind::Repo, true)
                | (PrincipalKind::User, false)
                | (PrincipalKind::Org, false)
        );
        if !shape_ok {
            anyhow::bail!("principal shape mismatch for {kind:?}: {name}");
        }
        Ok(Self { kind, name, id })
    }

    fn matches(&self, claims: &GithubClaims) -> bool {
        match self.kind {
            PrincipalKind::User | PrincipalKind::Org => {
                claims.repository_owner == self.name
                    && claims.repository_owner_id != 0
                    && claims.repository_owner_id == self.id
            }
            PrincipalKind::Repo => {
                claims.repository == self.name
                    && claims.repository_id != 0
                    && claims.repository_id == self.id
            }
        }
    }
}

fn required_env(key: &str) -> anyhow::Result<String> {
    std::env::var(key)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("{key} is required"))
}

#[derive(Clone, Debug, Serialize)]
struct Capabilities {
    runtime_deploy: bool,
    exec: bool,
    interactive_shell: bool,
    logs: bool,
}

#[derive(Clone, Debug, Serialize)]
struct AttestationProof {
    #[serde(rename = "type")]
    kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    quote_b64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mrtd: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tcb_status: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
struct Assignment {
    owner: Principal,
    claim_id: String,
    assigned_at: DateTime<Utc>,
    assigned_by: OidcActor,
}

#[derive(Clone, Debug, Serialize)]
struct OidcActor {
    sub: String,
    repository: String,
    repository_id: u64,
    repository_owner: String,
    repository_owner_id: u64,
    workflow: String,
    ref_: String,
    sha: String,
}

impl From<&GithubClaims> for OidcActor {
    fn from(claims: &GithubClaims) -> Self {
        Self {
            sub: claims.sub.clone(),
            repository: claims.repository.clone(),
            repository_id: claims.repository_id,
            repository_owner: claims.repository_owner.clone(),
            repository_owner_id: claims.repository_owner_id,
            workflow: claims.workflow.clone(),
            ref_: claims.ref_.clone(),
            sha: claims.sha.clone(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct SourceIdentity {
    repo: String,
    #[serde(default)]
    ref_: String,
    #[serde(default)]
    commit: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct WorkloadSpec {
    app_name: String,
    cmd: Vec<String>,
    #[serde(default)]
    source: Option<SourceIdentity>,
    #[serde(default)]
    artifact_digest: Option<String>,
    #[serde(default)]
    spec_digest: Option<String>,
    #[serde(default)]
    env: HashMap<String, String>,
}

#[derive(Clone, Debug, Serialize)]
struct WorkloadRecord {
    app_name: String,
    source: Option<SourceIdentity>,
    artifact_digest: Option<String>,
    spec_digest: Option<String>,
    status: WorkloadStatus,
    started_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    exited_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    exit_code: Option<i32>,
    deployed_by: OidcActor,
    #[serde(skip_serializing)]
    logs: Vec<String>,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum WorkloadStatus {
    Running,
    Exited,
    Failed,
}

#[derive(Debug, Deserialize)]
struct OwnerReq {
    owner: Principal,
    #[serde(default)]
    claim_id: String,
}

async fn health(State(state): State<AppState>) -> Json<serde_json::Value> {
    let workloads: Vec<WorkloadRecord> = state.workloads.read().await.values().cloned().collect();
    let assignment = state.owner.read().await.clone();
    Json(serde_json::json!({
        "service": "dd-agent",
        "ok": true,
        "agent_id": state.cfg.agent_id,
        "hostname": state.cfg.hostname,
        "started_at": state.started_at,
        "uptime_secs": (Utc::now() - state.started_at).num_seconds().max(0),
        "assignment_authority": state.cfg.assignment_authority,
        "owner": assignment.as_ref().map(|assignment| assignment.owner.clone()),
        "assignment": assignment,
        "attestation": state.cfg.attestation,
        "capabilities": state.cfg.capabilities,
        "workloads": workloads,
    }))
}

async fn set_owner(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<OwnerReq>,
) -> Result<Json<serde_json::Value>> {
    let claims = state
        .verifier
        .verify_principal(bearer(&headers)?, &state.cfg.assignment_authority)
        .await?;
    let claim_id = req.claim_id.trim().to_string();
    let mut guard = state.owner.write().await;
    let previous = guard.clone();
    let changed = previous
        .as_ref()
        .map(|assignment| assignment.owner != req.owner || assignment.claim_id != claim_id)
        .unwrap_or(true);

    if changed {
        *guard = Some(Assignment {
            owner: req.owner,
            claim_id,
            assigned_at: Utc::now(),
            assigned_by: OidcActor::from(&claims),
        });
    }

    Ok(Json(serde_json::json!({
        "agent_id": state.cfg.agent_id,
        "changed": changed,
        "previous": previous,
        "assignment": guard.clone(),
    })))
}

async fn deploy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(spec): Json<WorkloadSpec>,
) -> Result<Json<serde_json::Value>> {
    if !state.cfg.capabilities.runtime_deploy {
        return Err(ApiError::Forbidden("runtime deployment is disabled".into()));
    }
    validate_workload(&spec)?;
    let claims = require_current_owner(&state, &headers).await?;
    let app_name = spec.app_name.clone();
    let record = WorkloadRecord {
        app_name: app_name.clone(),
        source: spec.source.clone(),
        artifact_digest: spec.artifact_digest.clone(),
        spec_digest: spec.spec_digest.clone(),
        status: WorkloadStatus::Running,
        started_at: Utc::now(),
        exited_at: None,
        exit_code: None,
        deployed_by: OidcActor::from(&claims),
        logs: Vec::new(),
    };
    state
        .workloads
        .write()
        .await
        .insert(app_name.clone(), record);
    spawn_workload(state.workloads.clone(), app_name.clone(), spec).await?;
    Ok(Json(serde_json::json!({
        "agent_id": state.cfg.agent_id,
        "app_name": app_name,
        "status": "running",
    })))
}

fn validate_workload(spec: &WorkloadSpec) -> Result<()> {
    if spec.app_name.trim().is_empty() {
        return Err(ApiError::BadRequest("app_name is required".into()));
    }
    if spec.cmd.is_empty() || spec.cmd[0].trim().is_empty() {
        return Err(ApiError::BadRequest("cmd must be a non-empty array".into()));
    }
    Ok(())
}

async fn spawn_workload(
    workloads: Arc<RwLock<HashMap<String, WorkloadRecord>>>,
    app_name: String,
    spec: WorkloadSpec,
) -> Result<()> {
    let mut cmd = tokio::process::Command::new(&spec.cmd[0]);
    cmd.args(spec.cmd.iter().skip(1))
        .envs(spec.env)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd
        .spawn()
        .map_err(|error| ApiError::BadRequest(format!("spawn {}: {error}", spec.cmd[0])))?;

    if let Some(stdout) = child.stdout.take() {
        let workloads = workloads.clone();
        let app_name = app_name.clone();
        tokio::spawn(async move {
            stream_logs(workloads, app_name, "stdout", stdout).await;
        });
    }
    if let Some(stderr) = child.stderr.take() {
        let workloads = workloads.clone();
        let app_name = app_name.clone();
        tokio::spawn(async move {
            stream_logs(workloads, app_name, "stderr", stderr).await;
        });
    }

    tokio::spawn(async move {
        let status = child.wait().await;
        let mut guard = workloads.write().await;
        if let Some(record) = guard.get_mut(&app_name) {
            record.exited_at = Some(Utc::now());
            match status {
                Ok(status) => {
                    record.exit_code = status.code();
                    record.status = if status.success() {
                        WorkloadStatus::Exited
                    } else {
                        WorkloadStatus::Failed
                    };
                    push_log(
                        &mut record.logs,
                        format!("process exited with status {status}"),
                    );
                }
                Err(error) => {
                    record.status = WorkloadStatus::Failed;
                    push_log(&mut record.logs, format!("wait failed: {error}"));
                }
            }
        }
    });
    Ok(())
}

async fn stream_logs<T>(
    workloads: Arc<RwLock<HashMap<String, WorkloadRecord>>>,
    app_name: String,
    stream_name: &'static str,
    stream: T,
) where
    T: tokio::io::AsyncRead + Unpin,
{
    let mut lines = BufReader::new(stream).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let mut guard = workloads.write().await;
        if let Some(record) = guard.get_mut(&app_name) {
            push_log(&mut record.logs, format!("[{stream_name}] {line}"));
        }
    }
}

fn push_log(logs: &mut Vec<String>, line: String) {
    logs.push(line);
    if logs.len() > MAX_LOG_LINES {
        let excess = logs.len() - MAX_LOG_LINES;
        logs.drain(0..excess);
    }
}

async fn logs(
    State(state): State<AppState>,
    Path(app): Path<String>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>> {
    if !state.cfg.capabilities.logs {
        return Err(ApiError::Forbidden("logs are disabled".into()));
    }
    let _ = require_current_owner(&state, &headers).await?;
    let guard = state.workloads.read().await;
    let record = guard.get(&app).ok_or(ApiError::NotFound)?;
    Ok(Json(serde_json::json!({
        "app_name": app,
        "status": record.status,
        "lines": record.logs,
    })))
}

#[derive(Debug, Deserialize)]
struct ExecReq {
    cmd: Vec<String>,
    #[serde(default = "default_exec_timeout_secs")]
    timeout_secs: u64,
}

fn default_exec_timeout_secs() -> u64 {
    30
}

async fn exec(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ExecReq>,
) -> Result<Json<serde_json::Value>> {
    if !state.cfg.capabilities.exec {
        return Err(ApiError::Forbidden("exec is disabled".into()));
    }
    if req.cmd.is_empty() || req.cmd[0].trim().is_empty() {
        return Err(ApiError::BadRequest("cmd must be a non-empty array".into()));
    }
    let _ = require_current_owner(&state, &headers).await?;
    let output = tokio::time::timeout(
        Duration::from_secs(req.timeout_secs),
        tokio::process::Command::new(&req.cmd[0])
            .args(req.cmd.iter().skip(1))
            .output(),
    )
    .await
    .map_err(|_| ApiError::BadRequest("exec timed out".into()))?
    .map_err(|error| ApiError::BadRequest(format!("exec failed: {error}")))?;

    Ok(Json(serde_json::json!({
        "status": output.status.code(),
        "success": output.status.success(),
        "stdout": String::from_utf8_lossy(&output.stdout),
        "stderr": String::from_utf8_lossy(&output.stderr),
    })))
}

async fn require_current_owner(state: &AppState, headers: &HeaderMap) -> Result<GithubClaims> {
    let owner = state
        .owner
        .read()
        .await
        .as_ref()
        .map(|assignment| assignment.owner.clone())
        .ok_or_else(|| ApiError::Conflict("agent has no current owner".into()))?;
    state
        .verifier
        .verify_principal(bearer(headers)?, &owner)
        .await
}

fn bearer(headers: &HeaderMap) -> Result<&str> {
    let auth = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or(ApiError::Unauthorized)?;
    auth.strip_prefix("Bearer ")
        .or_else(|| auth.strip_prefix("bearer "))
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .ok_or(ApiError::Unauthorized)
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct GithubClaims {
    exp: i64,
    iat: i64,
    iss: String,
    #[serde(default)]
    sub: String,
    #[serde(default)]
    repository: String,
    #[serde(default)]
    repository_id: u64,
    #[serde(default)]
    repository_owner: String,
    #[serde(default)]
    repository_owner_id: u64,
    #[serde(default, rename = "ref")]
    ref_: String,
    #[serde(default)]
    workflow: String,
    #[serde(default)]
    sha: String,
}

struct GithubOidc {
    audience: String,
    http: Client,
    keys: RwLock<HashMap<String, DecodingKey>>,
}

impl GithubOidc {
    fn new(audience: String) -> Self {
        Self {
            audience,
            http: Client::new(),
            keys: RwLock::new(HashMap::new()),
        }
    }

    async fn verify_principal(&self, token: &str, principal: &Principal) -> Result<GithubClaims> {
        let claims = self.decode_and_validate(token).await?;
        if principal.matches(&claims) {
            Ok(claims)
        } else {
            Err(ApiError::Unauthorized)
        }
    }

    async fn decode_and_validate(&self, token: &str) -> Result<GithubClaims> {
        let header = jsonwebtoken::decode_header(token)
            .map_err(|error| ApiError::BadRequest(format!("gh oidc header: {error}")))?;
        if !allowed_alg(header.alg) {
            return Err(ApiError::BadRequest(format!(
                "gh oidc alg {:?} not allowed",
                header.alg
            )));
        }
        let kid = header
            .kid
            .ok_or_else(|| ApiError::BadRequest("gh oidc token missing kid".into()))?;
        let key =
            match self.keys.read().await.get(&kid).cloned() {
                Some(key) => key,
                None => {
                    self.refresh().await?;
                    self.keys.read().await.get(&kid).cloned().ok_or_else(|| {
                        ApiError::BadRequest(format!("gh oidc kid {kid} not found"))
                    })?
                }
            };
        let mut validation = Validation::new(header.alg);
        validation.set_issuer(&[GITHUB_ISSUER]);
        validation.set_audience(&[self.audience.as_str()]);
        validation.leeway = 60;
        validation.set_required_spec_claims(&["exp", "iat", "iss", "aud"]);
        let data = jsonwebtoken::decode::<GithubClaims>(token, &key, &validation)
            .map_err(|error| ApiError::BadRequest(format!("gh oidc verify: {error}")))?;
        Ok(data.claims)
    }

    async fn refresh(&self) -> Result<()> {
        let resp = self
            .http
            .get(GITHUB_JWKS_URL)
            .send()
            .await
            .map_err(|error| ApiError::Upstream(format!("GH JWKS fetch: {error}")))?;
        if !resp.status().is_success() {
            return Err(ApiError::Upstream(format!(
                "GH JWKS fetch returned HTTP {}",
                resp.status()
            )));
        }
        let jwks: jsonwebtoken::jwk::JwkSet = resp
            .json()
            .await
            .map_err(|error| ApiError::Upstream(format!("GH JWKS parse: {error}")))?;
        let mut keys = HashMap::new();
        for jwk in &jwks.keys {
            let Some(kid) = &jwk.common.key_id else {
                continue;
            };
            if let Ok(key) = DecodingKey::from_jwk(jwk) {
                keys.insert(kid.clone(), key);
            }
        }
        *self.keys.write().await = keys;
        Ok(())
    }
}

fn allowed_alg(alg: Algorithm) -> bool {
    matches!(
        alg,
        Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::PS256
            | Algorithm::PS384
            | Algorithm::PS512
    )
}

#[derive(Debug, thiserror::Error)]
enum ApiError {
    #[error("{0}")]
    BadRequest(String),
    #[error("unauthorized")]
    Unauthorized,
    #[error("{0}")]
    Forbidden(String),
    #[error("{0}")]
    Conflict(String),
    #[error("not found")]
    NotFound,
    #[error("{0}")]
    Upstream(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match self {
            ApiError::BadRequest(_) => StatusCode::BAD_REQUEST,
            ApiError::Unauthorized => StatusCode::UNAUTHORIZED,
            ApiError::Forbidden(_) => StatusCode::FORBIDDEN,
            ApiError::Conflict(_) => StatusCode::CONFLICT,
            ApiError::NotFound => StatusCode::NOT_FOUND,
            ApiError::Upstream(_) => StatusCode::BAD_GATEWAY,
        };
        let body = Json(serde_json::json!({
            "error": self.to_string(),
        }));
        (status, body).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims_for_repo() -> GithubClaims {
        GithubClaims {
            repository: "example/oracle".into(),
            repository_id: 42,
            repository_owner: "example".into(),
            repository_owner_id: 7,
            ..GithubClaims::default()
        }
    }

    #[test]
    fn principal_shape_validation() {
        assert!(Principal::validate(PrincipalKind::Repo, "example/oracle".into(), 42).is_ok());
        assert!(Principal::validate(PrincipalKind::Repo, "example".into(), 42).is_err());
        assert!(Principal::validate(PrincipalKind::Org, "example/oracle".into(), 7).is_err());
        assert!(Principal::validate(PrincipalKind::User, "alice".into(), 1).is_ok());
        assert!(Principal::validate(PrincipalKind::User, "alice".into(), 0).is_err());
    }

    #[test]
    fn repo_principal_matches_repo_claims() {
        let principal =
            Principal::validate(PrincipalKind::Repo, "example/oracle".into(), 42).unwrap();
        assert!(principal.matches(&claims_for_repo()));
    }

    #[test]
    fn org_principal_matches_owner_claims() {
        let principal = Principal::validate(PrincipalKind::Org, "example".into(), 7).unwrap();
        assert!(principal.matches(&claims_for_repo()));
    }

    #[test]
    fn principal_matching_requires_numeric_id() {
        let principal =
            Principal::validate(PrincipalKind::Repo, "example/oracle".into(), 999).unwrap();
        assert!(!principal.matches(&claims_for_repo()));
    }

    #[test]
    fn workload_requires_app_and_command() {
        let ok = WorkloadSpec {
            app_name: "oracle".into(),
            cmd: vec!["/bin/echo".into(), "ok".into()],
            source: None,
            artifact_digest: None,
            spec_digest: None,
            env: HashMap::new(),
        };
        assert!(validate_workload(&ok).is_ok());

        let missing_cmd = WorkloadSpec {
            cmd: Vec::new(),
            ..ok.clone()
        };
        assert!(validate_workload(&missing_cmd).is_err());

        let missing_app = WorkloadSpec {
            app_name: String::new(),
            ..ok
        };
        assert!(validate_workload(&missing_app).is_err());
    }
}
