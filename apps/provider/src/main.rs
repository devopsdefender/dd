use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::info;

mod aggregator;
mod attestation;
mod config;
mod inspection;
mod reporting;
mod signing;

use aggregator::AggregatorState;

#[derive(Clone)]
struct AppState {
    signing_key: Arc<SigningKey>,
    public_key_b64: String,
    provider_id: Option<String>,
    config: Arc<config::Config>,
    http: reqwest::Client,
    aggregator: Arc<RwLock<AggregatorState>>,
}

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct MeasureAppRequest {
    app_id: String,
    version_id: String,
    image: String,
}

#[derive(Debug, Serialize)]
struct MeasureAppResponse {
    image: String,
    measurement_hash: String,
    signature: String,
    submitted: bool,
}

#[derive(Debug, Deserialize)]
struct MeasureNodeRequest {
    agent_id: String,
    node_mrtd: String,
}

#[derive(Debug, Serialize)]
struct MeasureNodeResponse {
    agent_id: String,
    measurement_hash: String,
    signature: String,
    submitted: bool,
}

#[derive(Debug, Deserialize)]
struct HeartbeatRequest {
    agent_id: String,
    #[serde(default)]
    status: Option<String>,
}

#[derive(Debug, Deserialize)]
struct MetricsRequest {
    agent_id: String,
    metrics: Vec<MetricItem>,
}

#[derive(Debug, Deserialize)]
struct MetricItem {
    name: String,
    value: f64,
}

#[derive(Debug, Deserialize)]
struct LogsRequest {
    agent_id: String,
    entries: Vec<LogItem>,
}

#[derive(Debug, Deserialize)]
struct LogItem {
    level: String,
    message: String,
}

#[derive(Debug, Serialize)]
struct StatusResponse {
    name: String,
    provider_id: Option<String>,
    public_key: String,
    connected_agents: usize,
    metrics_buffered: usize,
    logs_buffered: usize,
    last_flush: Option<String>,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn healthz() -> StatusCode {
    StatusCode::OK
}

async fn status(State(state): State<AppState>) -> Json<StatusResponse> {
    let agg = state.aggregator.read().await;
    Json(StatusResponse {
        name: state.config.provider_name.clone(),
        provider_id: state.provider_id.clone(),
        public_key: state.public_key_b64.clone(),
        connected_agents: agg.heartbeats.len(),
        metrics_buffered: agg.metrics_buffer.len(),
        logs_buffered: agg.logs_buffer.len(),
        last_flush: agg.last_flush.map(|t| t.to_rfc3339()),
    })
}

/// Measure an app image — pull, inspect, sign, submit to CP.
async fn measure_app(
    State(state): State<AppState>,
    Json(req): Json<MeasureAppRequest>,
) -> Result<(StatusCode, Json<MeasureAppResponse>), (StatusCode, String)> {
    let report = inspection::inspect_image(&req.image)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("inspect failed: {e}")))?;

    let signature =
        signing::sign_measurement(&state.signing_key, report.measurement_hash.as_bytes());

    let submitted = if let Some(ref pid) = state.provider_id {
        reporting::submit_app_measurement(
            &state.http,
            &state.config.cp_url,
            &req.app_id,
            &req.version_id,
            pid,
            &report,
            &signature,
        )
        .await
        .is_ok()
    } else {
        false
    };

    Ok((
        StatusCode::OK,
        Json(MeasureAppResponse {
            image: req.image,
            measurement_hash: report.measurement_hash,
            signature,
            submitted,
        }),
    ))
}

/// Measure an undeployed agent node — sign its MRTD before it registers with CP.
async fn measure_node(
    State(state): State<AppState>,
    Json(req): Json<MeasureNodeRequest>,
) -> Result<(StatusCode, Json<MeasureNodeResponse>), (StatusCode, String)> {
    let measurement_hash = format!("node:{}", req.node_mrtd);
    let signature = signing::sign_measurement(&state.signing_key, measurement_hash.as_bytes());

    let submitted = if let Some(ref pid) = state.provider_id {
        reporting::submit_node_measurement(
            &state.http,
            &state.config.cp_url,
            &req.agent_id,
            pid,
            &req.node_mrtd,
            &measurement_hash,
            &signature,
            &format!("{{\"node_mrtd\":\"{}\"}}", req.node_mrtd),
        )
        .await
        .is_ok()
    } else {
        false
    };

    Ok((
        StatusCode::OK,
        Json(MeasureNodeResponse {
            agent_id: req.agent_id,
            measurement_hash,
            signature,
            submitted,
        }),
    ))
}

/// Accept agent heartbeat (agents heartbeat here instead of CP directly).
async fn ingest_heartbeat(
    State(state): State<AppState>,
    Json(req): Json<HeartbeatRequest>,
) -> StatusCode {
    let mut agg = state.aggregator.write().await;
    agg.heartbeats.insert(
        req.agent_id.clone(),
        aggregator::AgentHeartbeat {
            agent_id: req.agent_id,
            timestamp: chrono::Utc::now(),
            status: req.status.unwrap_or_else(|| "ok".into()),
        },
    );
    StatusCode::ACCEPTED
}

/// Accept agent metrics.
async fn ingest_metrics(
    State(state): State<AppState>,
    Json(req): Json<MetricsRequest>,
) -> StatusCode {
    let mut agg = state.aggregator.write().await;
    for m in req.metrics {
        agg.metrics_buffer.push(aggregator::MetricEntry {
            agent_id: req.agent_id.clone(),
            timestamp: chrono::Utc::now(),
            name: m.name,
            value: m.value,
        });
    }
    StatusCode::ACCEPTED
}

/// Accept agent logs.
async fn ingest_logs(State(state): State<AppState>, Json(req): Json<LogsRequest>) -> StatusCode {
    let mut agg = state.aggregator.write().await;
    for entry in req.entries {
        agg.logs_buffer.push(aggregator::LogEntry {
            agent_id: req.agent_id.clone(),
            timestamp: chrono::Utc::now(),
            level: entry.level,
            message: entry.message,
        });
    }
    StatusCode::ACCEPTED
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "dd_provider=info".into()),
        )
        .json()
        .init();

    let cfg = config::Config::from_env();
    info!(name = %cfg.provider_name, cp_url = %cfg.cp_url, "starting dd-provider");

    // Generate keypair — private key lives only in memory
    let (signing_key, verifying_key) = signing::generate_keypair();
    let public_key_b64 = signing::public_key_base64(&verifying_key);
    info!("generated Ed25519 keypair");

    // Generate TDX quote binding public key to hardware
    let pk_hash = signing::public_key_hash(&verifying_key);
    let _quote = attestation::generate_quote(&pk_hash, cfg.skip_attestation);

    // Register with CP
    let http = reqwest::Client::new();
    let provider_id =
        match reporting::register_with_cp(&http, &cfg.cp_url, &cfg.provider_name, &public_key_b64)
            .await
        {
            Ok(id) => {
                info!(id = %id, "registered with control plane");
                Some(id)
            }
            Err(e) => {
                tracing::warn!("CP registration failed: {e} (running standalone)");
                None
            }
        };

    let aggregator = Arc::new(RwLock::new(AggregatorState::new()));
    let flush_interval = Duration::from_millis(cfg.flush_interval_ms);

    // Spawn background flush loop
    tokio::spawn(aggregator::flush_loop(
        aggregator.clone(),
        http.clone(),
        cfg.cp_url.clone(),
        provider_id.clone(),
        flush_interval,
    ));

    let state = AppState {
        signing_key: Arc::new(signing_key),
        public_key_b64,
        provider_id,
        config: Arc::new(cfg),
        http,
        aggregator,
    };

    let bind = state.config.bind_addr.clone();
    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/api/v1/status", get(status))
        // Measurement (one-time, at agent boot or app publish)
        .route("/api/v1/measure/app", post(measure_app))
        .route("/api/v1/measure/node", post(measure_node))
        // Aggregation (ongoing, agents push here instead of CP)
        .route("/api/v1/heartbeat", post(ingest_heartbeat))
        .route("/api/v1/metrics", post(ingest_metrics))
        .route("/api/v1/logs", post(ingest_logs))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&bind).await.unwrap();
    info!(addr = %bind, "listening");
    axum::serve(listener, app).await.unwrap();
}
