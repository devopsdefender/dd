//! Read-only oracle workload scraping.
//!
//! Oracle workloads are ordinary easyenclave workloads with DD metadata in
//! their boot spec. dd-agent treats that metadata as an observation contract:
//! scrape a local HTTP endpoint, expose the result in health/dashboard APIs,
//! and never provide stdin/control through the oracle path.

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::config::OracleSpec;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OracleStatus {
    pub app_name: String,
    pub title: String,
    pub hostname_label: String,
    pub vanity_url: Option<String>,
    pub local_url: String,
    pub path: String,
    pub read_only: bool,
    pub status: String,
    pub last_ok: Option<String>,
    pub last_error: Option<String>,
    pub sample: Option<serde_json::Value>,
}

pub type OracleStore = Arc<RwLock<Vec<OracleStatus>>>;

pub fn initial_store(specs: &[OracleSpec], agent_hostname: &str) -> OracleStore {
    Arc::new(RwLock::new(
        specs
            .iter()
            .map(|spec| status_from_spec(spec, agent_hostname))
            .collect(),
    ))
}

pub fn spawn_scrapers(specs: Vec<OracleSpec>, store: OracleStore) {
    if specs.is_empty() {
        return;
    }
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());
    for spec in specs {
        let http = http.clone();
        let store = store.clone();
        tokio::spawn(async move {
            let interval = Duration::from_secs(spec.interval_secs.max(1));
            loop {
                scrape_once(&http, &store, &spec).await;
                tokio::time::sleep(interval).await;
            }
        });
    }
}

fn status_from_spec(spec: &OracleSpec, agent_hostname: &str) -> OracleStatus {
    let path = normalize_path(&spec.path);
    let vanity_url = (!spec.hostname_label.is_empty()).then(|| {
        format!(
            "https://{}{}",
            crate::cf::label_hostname(agent_hostname, &spec.hostname_label),
            path
        )
    });
    OracleStatus {
        app_name: spec.app_name.clone(),
        title: spec.title.clone(),
        hostname_label: spec.hostname_label.clone(),
        vanity_url,
        local_url: local_url(spec.port, &path),
        path,
        read_only: true,
        status: "unknown".into(),
        last_ok: None,
        last_error: None,
        sample: None,
    }
}

async fn scrape_once(http: &reqwest::Client, store: &OracleStore, spec: &OracleSpec) {
    let path = normalize_path(&spec.path);
    let url = local_url(spec.port, &path);
    let result = async {
        let resp = http.get(&url).send().await?;
        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            return Ok::<_, reqwest::Error>((false, format!("HTTP {status}: {text}"), None));
        }
        let sample = serde_json::from_str::<serde_json::Value>(&text)
            .unwrap_or_else(|_| serde_json::json!({ "text": text }));
        Ok((true, String::new(), Some(sample)))
    }
    .await;

    let mut statuses = store.write().await;
    let Some(st) = statuses.iter_mut().find(|st| st.app_name == spec.app_name) else {
        return;
    };
    match result {
        Ok((true, _, sample)) => {
            st.status = "healthy".into();
            st.last_ok = Some(Utc::now().to_rfc3339());
            st.last_error = None;
            st.sample = sample;
        }
        Ok((false, err, _)) => {
            st.status = "error".into();
            st.last_error = Some(err);
        }
        Err(e) => {
            st.status = "error".into();
            st.last_error = Some(e.to_string());
        }
    }
}

fn normalize_path(path: &str) -> String {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        "/oracle.json".into()
    } else if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{trimmed}")
    }
}

fn local_url(port: u16, path: &str) -> String {
    format!("http://127.0.0.1:{port}{path}")
}
