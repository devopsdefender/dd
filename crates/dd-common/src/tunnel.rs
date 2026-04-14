//! Cloudflare tunnel management -- create, delete, and configure tunnels.
//!
//! Used by the registration service to provision tunnels for agents,
//! and by the `dd rm` CLI command to clean them up.
//! Structured as pure functions over reqwest so it can be compiled to WASM
//! for Cloudflare Workers in the future.

use serde::{Deserialize, Serialize};

/// Cloudflare API credentials.
#[derive(Debug, Clone)]
pub struct CfConfig {
    pub api_token: String,
    pub account_id: String,
    pub zone_id: String,
    pub domain: String,
}

impl CfConfig {
    pub fn from_env() -> Result<Self, String> {
        Ok(Self {
            api_token: std::env::var("DD_CF_API_TOKEN")
                .map_err(|_| "DD_CF_API_TOKEN not set".to_string())?,
            account_id: std::env::var("DD_CF_ACCOUNT_ID")
                .map_err(|_| "DD_CF_ACCOUNT_ID not set".to_string())?,
            zone_id: std::env::var("DD_CF_ZONE_ID")
                .map_err(|_| "DD_CF_ZONE_ID not set".to_string())?,
            domain: std::env::var("DD_CF_DOMAIN")
                .map_err(|_| "DD_CF_DOMAIN not set".to_string())?,
        })
    }
}

/// Result of creating a tunnel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelInfo {
    pub tunnel_id: String,
    pub tunnel_token: String,
    pub hostname: String,
}

const CF_API: &str = "https://api.cloudflare.com/client/v4";

/// Create a CF tunnel for an agent, configure ingress, create DNS CNAME.
/// Tunnel name uses agent_id (UUID) to guarantee uniqueness.
/// `hostname_override` sets the public DNS name -- pass `None` for UUID-based.
/// Callers must pass the override explicitly; this function never reads DD_HOSTNAME
/// from the environment (to avoid the register's hostname leaking to remote agents).
pub async fn create_agent_tunnel(
    client: &reqwest::Client,
    cf: &CfConfig,
    agent_id: &str,
    _vm_name: &str,
    hostname_override: Option<&str>,
) -> Result<TunnelInfo, String> {
    // DD_ENV is required. Callers (dd-register, dd-web) fail fast at
    // startup if it's not set, so by the time we're here it's always
    // defined. Previously defaulted to "dev" silently, which in a prod
    // VM would mint tunnels named `dd-dev-*` and never match the
    // `dd-{prod_env}-*` filter in dd-web's collector.
    let env_label = std::env::var("DD_ENV").expect("DD_ENV must be set before tunnel ops");
    let tunnel_name = format!("dd-{env_label}-{agent_id}");
    let tunnel_secret = uuid::Uuid::new_v4().to_string().replace('-', "");
    let hostname = hostname_override
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("{tunnel_name}.{}", cf.domain));

    // Delete existing tunnel with this name (idempotent redeploy)
    let _ = delete_tunnel_by_name(client, cf, &tunnel_name).await;

    // Create tunnel
    let resp = client
        .post(format!("{CF_API}/accounts/{}/cfd_tunnel", cf.account_id))
        .header("Authorization", format!("Bearer {}", cf.api_token))
        .json(&serde_json::json!({
            "name": tunnel_name,
            "tunnel_secret": base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                tunnel_secret.as_bytes()
            ),
        }))
        .send()
        .await
        .map_err(|e| format!("tunnel create: {e}"))?;

    if !resp.status().is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("tunnel create failed: {body}"));
    }

    let body: serde_json::Value = resp.json().await.map_err(|e| format!("parse: {e}"))?;
    let tunnel_id = body["result"]["id"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let tunnel_token = body["result"]["token"]
        .as_str()
        .unwrap_or(&tunnel_secret)
        .to_string();

    // Configure ingress
    configure_ingress(client, cf, &tunnel_id, &hostname, "http://localhost:8080").await?;

    // Create DNS CNAME
    create_dns_cname(client, cf, &tunnel_id, &hostname).await?;

    Ok(TunnelInfo {
        tunnel_id,
        tunnel_token,
        hostname,
    })
}

/// Delete a tunnel by name (lookup -> clean connections -> delete).
pub async fn delete_tunnel_by_name(
    client: &reqwest::Client,
    cf: &CfConfig,
    name: &str,
) -> Result<(), String> {
    let resp = client
        .get(format!(
            "{CF_API}/accounts/{}/cfd_tunnel?name={name}",
            cf.account_id
        ))
        .header("Authorization", format!("Bearer {}", cf.api_token))
        .send()
        .await
        .map_err(|e| format!("tunnel lookup: {e}"))?;

    let body: serde_json::Value = resp.json().await.unwrap_or_default();

    if let Some(tunnels) = body["result"].as_array() {
        for tunnel in tunnels {
            if let Some(id) = tunnel["id"].as_str() {
                // Clean connections
                let _ = client
                    .delete(format!(
                        "{CF_API}/accounts/{}/cfd_tunnel/{id}/connections",
                        cf.account_id
                    ))
                    .header("Authorization", format!("Bearer {}", cf.api_token))
                    .send()
                    .await;

                // Delete tunnel
                let _ = client
                    .delete(format!(
                        "{CF_API}/accounts/{}/cfd_tunnel/{id}",
                        cf.account_id
                    ))
                    .header("Authorization", format!("Bearer {}", cf.api_token))
                    .send()
                    .await;
            }
        }
    }

    Ok(())
}

/// Delete a DNS CNAME record by hostname.
pub async fn delete_dns_record(
    client: &reqwest::Client,
    cf: &CfConfig,
    hostname: &str,
) -> Result<(), String> {
    if let Some(record_id) = find_dns_record_id(client, cf, hostname).await? {
        let resp = client
            .delete(format!(
                "{CF_API}/zones/{}/dns_records/{record_id}",
                cf.zone_id
            ))
            .header("Authorization", format!("Bearer {}", cf.api_token))
            .send()
            .await
            .map_err(|e| format!("DNS delete: {e}"))?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("DNS delete failed: {body}"));
        }
    }
    Ok(())
}

/// Remove an agent's tunnel and DNS record.
pub async fn remove_agent(
    client: &reqwest::Client,
    cf: &CfConfig,
    agent_id: &str,
    hostname: &str,
) -> Result<(), String> {
    // DD_ENV: see provision_tunnel above.
    let env_label = std::env::var("DD_ENV").expect("DD_ENV must be set before tunnel ops");
    let tunnel_name = format!("dd-{env_label}-{agent_id}");
    delete_tunnel_by_name(client, cf, &tunnel_name).await?;
    delete_dns_record(client, cf, hostname).await?;
    Ok(())
}

/// List all tunnels for the account.
pub async fn list_tunnels(
    client: &reqwest::Client,
    cf: &CfConfig,
) -> Result<Vec<serde_json::Value>, String> {
    let resp = client
        .get(format!("{CF_API}/accounts/{}/cfd_tunnel", cf.account_id))
        .header("Authorization", format!("Bearer {}", cf.api_token))
        .send()
        .await
        .map_err(|e| format!("list tunnels: {e}"))?;

    let body: serde_json::Value = resp.json().await.map_err(|e| format!("parse: {e}"))?;
    Ok(body["result"].as_array().cloned().unwrap_or_default())
}

/// Fetch the list of hostnames a tunnel's ingress config routes to.
///
/// Used by STONITH to identify stale tunnels by the hostname they serve
/// rather than by reconstructing `{name}.{domain}` — which breaks when
/// the tunnel's hostname was overridden at creation (e.g. CP tunnels
/// all serve `app-{env}.{domain}` regardless of tunnel name).
pub async fn tunnel_ingress_hostnames(
    client: &reqwest::Client,
    cf: &CfConfig,
    tunnel_id: &str,
) -> Result<Vec<String>, String> {
    let resp = client
        .get(format!(
            "{CF_API}/accounts/{}/cfd_tunnel/{tunnel_id}/configurations",
            cf.account_id
        ))
        .header("Authorization", format!("Bearer {}", cf.api_token))
        .send()
        .await
        .map_err(|e| format!("tunnel config fetch: {e}"))?;

    if !resp.status().is_success() {
        return Ok(Vec::new());
    }

    let body: serde_json::Value = resp.json().await.map_err(|e| format!("parse: {e}"))?;
    Ok(body["result"]["config"]["ingress"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|r| r["hostname"].as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default())
}

// -- Internal helpers ---------------------------------------------------------

pub async fn configure_ingress(
    client: &reqwest::Client,
    cf: &CfConfig,
    tunnel_id: &str,
    hostname: &str,
    service: &str,
) -> Result<(), String> {
    let resp = client
        .put(format!(
            "{CF_API}/accounts/{}/cfd_tunnel/{tunnel_id}/configurations",
            cf.account_id
        ))
        .header("Authorization", format!("Bearer {}", cf.api_token))
        .json(&serde_json::json!({
            "config": {
                "ingress": [
                    { "hostname": hostname, "service": service },
                    { "service": "http_status:404" }
                ]
            }
        }))
        .send()
        .await
        .map_err(|e| format!("tunnel config: {e}"))?;

    if !resp.status().is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("tunnel config failed: {body}"));
    }
    Ok(())
}

pub async fn create_dns_cname(
    client: &reqwest::Client,
    cf: &CfConfig,
    tunnel_id: &str,
    hostname: &str,
) -> Result<(), String> {
    let content = format!("{tunnel_id}.cfargotunnel.com");

    // Check for existing record
    let existing = find_dns_record_id(client, cf, hostname).await?;

    let (method, url) = if let Some(ref record_id) = existing {
        (
            reqwest::Method::PUT,
            format!("{CF_API}/zones/{}/dns_records/{record_id}", cf.zone_id),
        )
    } else {
        (
            reqwest::Method::POST,
            format!("{CF_API}/zones/{}/dns_records", cf.zone_id),
        )
    };

    let resp = client
        .request(method, &url)
        .header("Authorization", format!("Bearer {}", cf.api_token))
        .json(&serde_json::json!({
            "type": "CNAME",
            "name": hostname,
            "content": content,
            "proxied": true,
        }))
        .send()
        .await
        .map_err(|e| format!("DNS upsert: {e}"))?;

    if !resp.status().is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("DNS upsert failed: {body}"));
    }
    Ok(())
}

pub async fn find_dns_record_id(
    client: &reqwest::Client,
    cf: &CfConfig,
    hostname: &str,
) -> Result<Option<String>, String> {
    let resp = client
        .get(format!(
            "{CF_API}/zones/{}/dns_records?type=CNAME&name={hostname}",
            cf.zone_id
        ))
        .header("Authorization", format!("Bearer {}", cf.api_token))
        .send()
        .await
        .map_err(|e| format!("DNS lookup: {e}"))?;

    if !resp.status().is_success() {
        return Ok(None);
    }

    let body: serde_json::Value = resp.json().await.map_err(|e| format!("parse: {e}"))?;
    Ok(body["result"]
        .as_array()
        .and_then(|arr| arr.first())
        .and_then(|rec| rec["id"].as_str())
        .map(|s| s.to_string()))
}
