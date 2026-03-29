use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentHeartbeat {
    pub agent_id: String,
    pub timestamp: DateTime<Utc>,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricEntry {
    pub agent_id: String,
    pub timestamp: DateTime<Utc>,
    pub name: String,
    pub value: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub agent_id: String,
    pub timestamp: DateTime<Utc>,
    pub level: String,
    pub message: String,
}

pub struct AggregatorState {
    pub heartbeats: HashMap<String, AgentHeartbeat>,
    pub metrics_buffer: Vec<MetricEntry>,
    pub logs_buffer: Vec<LogEntry>,
    pub last_flush: Option<DateTime<Utc>>,
}

impl AggregatorState {
    pub fn new() -> Self {
        Self {
            heartbeats: HashMap::new(),
            metrics_buffer: Vec::new(),
            logs_buffer: Vec::new(),
            last_flush: None,
        }
    }
}

/// Flush buffered data to the control plane periodically.
pub async fn flush_loop(
    state: Arc<RwLock<AggregatorState>>,
    http: reqwest::Client,
    cp_url: String,
    provider_id: Option<String>,
    interval: Duration,
) {
    loop {
        tokio::time::sleep(interval).await;

        let provider_id = match &provider_id {
            Some(id) => id.clone(),
            None => {
                warn!("no provider_id, skipping flush");
                continue;
            }
        };

        let (heartbeats, metrics, logs) = {
            let mut inner = state.write().await;
            let heartbeats: Vec<_> = inner.heartbeats.values().cloned().collect();
            let metrics = std::mem::take(&mut inner.metrics_buffer);
            let logs = std::mem::take(&mut inner.logs_buffer);
            (heartbeats, metrics, logs)
        };

        if heartbeats.is_empty() && metrics.is_empty() && logs.is_empty() {
            continue;
        }

        // Flush heartbeats — fan out to individual agent heartbeat endpoints
        for hb in &heartbeats {
            let url = format!("{cp_url}/api/v1/agents/{}/heartbeat", hb.agent_id);
            if let Err(e) = http.post(&url).send().await {
                error!(agent_id = %hb.agent_id, "heartbeat flush failed: {e}");
            }
        }

        // Flush metrics batch
        if !metrics.is_empty() {
            let url = format!("{cp_url}/api/v1/providers/{provider_id}/metrics");
            match http.post(&url).json(&metrics).send().await {
                Ok(resp) if resp.status().is_success() => {
                    info!(count = metrics.len(), "flushed metrics to CP");
                }
                Ok(resp) => {
                    let status = resp.status();
                    error!(%status, "metrics flush rejected by CP");
                    // Put metrics back
                    let mut inner = state.write().await;
                    inner.metrics_buffer.extend(metrics);
                }
                Err(e) => {
                    error!("metrics flush failed: {e}");
                    let mut inner = state.write().await;
                    inner.metrics_buffer.extend(metrics);
                }
            }
        }

        // Flush logs batch
        if !logs.is_empty() {
            let url = format!("{cp_url}/api/v1/providers/{provider_id}/logs");
            match http.post(&url).json(&logs).send().await {
                Ok(resp) if resp.status().is_success() => {
                    info!(count = logs.len(), "flushed logs to CP");
                }
                Ok(resp) => {
                    let status = resp.status();
                    error!(%status, "logs flush rejected by CP");
                    let mut inner = state.write().await;
                    inner.logs_buffer.extend(logs);
                }
                Err(e) => {
                    error!("logs flush failed: {e}");
                    let mut inner = state.write().await;
                    inner.logs_buffer.extend(logs);
                }
            }
        }

        {
            let mut inner = state.write().await;
            inner.last_flush = Some(Utc::now());
        }

        info!(heartbeats = heartbeats.len(), "flush complete");
    }
}
