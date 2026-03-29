use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::{error, info};

use crate::inspection::ImageReport;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RegisterProviderRequest {
    name: String,
    public_key: String,
    measurement_types: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProviderResponse {
    id: String,
    name: String,
    status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SubmitMeasurementRequest {
    measurer_id: String,
    image_digest: Option<String>,
    measurement_hash: String,
    signature: String,
    report: String,
}

/// Register this provider with the control plane.
pub async fn register_with_cp(
    client: &Client,
    cp_url: &str,
    name: &str,
    public_key: &str,
) -> Result<String, String> {
    let url = format!("{cp_url}/api/v1/providers");
    let body = RegisterProviderRequest {
        name: name.to_string(),
        public_key: public_key.to_string(),
        measurement_types: "app,node".to_string(),
    };

    let resp = client
        .post(&url)
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("register with CP: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        return Err(format!("register failed ({status}): {text}"));
    }

    let provider: ProviderResponse = resp
        .json()
        .await
        .map_err(|e| format!("parse register response: {e}"))?;

    info!(id = %provider.id, "registered with control plane");
    Ok(provider.id)
}

/// Submit a signed app measurement to the control plane.
pub async fn submit_app_measurement(
    client: &Client,
    cp_url: &str,
    app_id: &str,
    version_id: &str,
    provider_id: &str,
    report: &ImageReport,
    signature: &str,
) -> Result<(), String> {
    let url = format!("{cp_url}/api/v1/apps/{app_id}/versions/{version_id}/measure");

    let report_json =
        serde_json::to_string(report).map_err(|e| format!("serialize report: {e}"))?;

    let body = SubmitMeasurementRequest {
        measurer_id: provider_id.to_string(),
        image_digest: report.digest.clone(),
        measurement_hash: report.measurement_hash.clone(),
        signature: signature.to_string(),
        report: report_json,
    };

    let resp = client
        .post(&url)
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("submit measurement: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        error!(%status, "measurement submission failed: {text}");
        return Err(format!("submit failed ({status}): {text}"));
    }

    info!(app_id, version_id, "measurement submitted");
    Ok(())
}

/// Submit a signed node measurement to the control plane (for undeployed agents).
pub async fn submit_node_measurement(
    client: &Client,
    cp_url: &str,
    agent_id: &str,
    provider_id: &str,
    node_mrtd: &str,
    measurement_hash: &str,
    signature: &str,
    report: &str,
) -> Result<(), String> {
    let url = format!("{cp_url}/api/v1/agents/{agent_id}/measure");

    let body = SubmitMeasurementRequest {
        measurer_id: provider_id.to_string(),
        image_digest: None,
        measurement_hash: measurement_hash.to_string(),
        signature: signature.to_string(),
        report: report.to_string(),
    };

    let resp = client
        .post(&url)
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("submit node measurement: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        error!(%status, "node measurement failed: {text}");
        return Err(format!("submit failed ({status}): {text}"));
    }

    info!(agent_id, node_mrtd, "node measurement submitted");
    Ok(())
}
