use crate::common::error::{AppError, AppResult};
use uuid::Uuid;

/// Cloudflare tunnel management for agent ingress.
#[derive(Clone)]
pub struct TunnelService {
    api_token: Option<String>,
    account_id: Option<String>,
    zone_id: Option<String>,
    domain: String,
}

/// Result of creating a tunnel.
#[derive(Debug, Clone)]
pub struct TunnelInfo {
    pub tunnel_id: String,
    pub tunnel_token: String,
    pub hostname: String,
}

impl TunnelService {
    /// Create a real tunnel service from env vars.
    pub fn from_env() -> Self {
        Self {
            api_token: std::env::var("DD_CP_CF_API_TOKEN").ok(),
            account_id: std::env::var("DD_CP_CF_ACCOUNT_ID").ok(),
            zone_id: std::env::var("DD_CP_CF_ZONE_ID").ok(),
            domain: std::env::var("DD_CP_CF_DOMAIN")
                .unwrap_or_else(|_| "devopsdefender.com".to_string()),
        }
    }

    /// Create a Cloudflare tunnel for an agent.
    pub async fn create_tunnel_for_agent(
        &self,
        agent_id: Uuid,
        vm_name: &str,
    ) -> AppResult<TunnelInfo> {
        let api_token = self
            .api_token
            .as_ref()
            .ok_or_else(|| AppError::Config("DD_CP_CF_API_TOKEN not set".into()))?;
        let account_id = self
            .account_id
            .as_ref()
            .ok_or_else(|| AppError::Config("DD_CP_CF_ACCOUNT_ID not set".into()))?;

        let tunnel_name = format!("dd-agent-{agent_id}");
        let tunnel_secret = uuid::Uuid::new_v4().to_string().replace('-', "");

        let client = reqwest::Client::new();

        // Create the tunnel
        let create_resp = client
            .post(format!(
                "https://api.cloudflare.com/client/v4/accounts/{account_id}/cfd_tunnel"
            ))
            .header("Authorization", format!("Bearer {api_token}"))
            .json(&serde_json::json!({
                "name": tunnel_name,
                "tunnel_secret": base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    tunnel_secret.as_bytes()
                ),
            }))
            .send()
            .await
            .map_err(|e| AppError::External(format!("CF tunnel create failed: {e}")))?;

        if !create_resp.status().is_success() {
            let body = create_resp.text().await.unwrap_or_default();
            return Err(AppError::External(format!(
                "CF tunnel create failed: {body}"
            )));
        }

        let resp_body: serde_json::Value = create_resp
            .json()
            .await
            .map_err(|e| AppError::External(format!("CF tunnel response parse: {e}")))?;

        let tunnel_id = resp_body["result"]["id"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        let tunnel_token = resp_body["result"]["token"]
            .as_str()
            .unwrap_or(&tunnel_secret)
            .to_string();

        let hostname = format!("{vm_name}.{}", self.domain);

        // Create DNS record
        self.create_dns_record(&tunnel_id, &hostname).await?;

        Ok(TunnelInfo {
            tunnel_id,
            tunnel_token,
            hostname,
        })
    }

    /// Retrieve a tunnel token for an existing agent (for re-registration).
    /// When tunnels are disabled, returns a synthetic token.
    pub async fn get_tunnel_token_for_agent(
        &self,
        agent_id: Uuid,
        vm_name: &str,
    ) -> AppResult<String> {
        let api_token = self
            .api_token
            .as_ref()
            .ok_or_else(|| AppError::Config("DD_CP_CF_API_TOKEN not set".into()))?;
        let account_id = self
            .account_id
            .as_ref()
            .ok_or_else(|| AppError::Config("DD_CP_CF_ACCOUNT_ID not set".into()))?;

        let tunnel_name = format!("dd-agent-{agent_id}");
        let client = reqwest::Client::new();

        // List tunnels to find existing one
        let list_resp = client
            .get(format!(
                "https://api.cloudflare.com/client/v4/accounts/{account_id}/tunnels?name={tunnel_name}&is_deleted=false"
            ))
            .header("Authorization", format!("Bearer {api_token}"))
            .send()
            .await
            .map_err(|e| AppError::External(format!("CF tunnel list failed: {e}")))?;

        let body: serde_json::Value = list_resp
            .json()
            .await
            .map_err(|e| AppError::External(format!("CF tunnel list parse failed: {e}")))?;

        if let Some(tunnels) = body["result"].as_array() {
            if let Some(tunnel) = tunnels.first() {
                if let Some(token) = tunnel["token"].as_str() {
                    return Ok(token.to_string());
                }
            }
        }

        // Fallback: can't retrieve token, return a placeholder
        // The agent will need a fresh registration with a new tunnel
        Err(AppError::External(format!(
            "No existing tunnel found for agent {agent_id} ({vm_name})"
        )))
    }

    /// Delete a Cloudflare tunnel.
    pub async fn delete_tunnel(&self, tunnel_id: &str) -> AppResult<()> {
        let api_token = self
            .api_token
            .as_ref()
            .ok_or_else(|| AppError::Config("DD_CP_CF_API_TOKEN not set".into()))?;
        let account_id = self
            .account_id
            .as_ref()
            .ok_or_else(|| AppError::Config("DD_CP_CF_ACCOUNT_ID not set".into()))?;

        let client = reqwest::Client::new();
        let resp = client
            .delete(format!(
                "https://api.cloudflare.com/client/v4/accounts/{account_id}/cfd_tunnel/{tunnel_id}"
            ))
            .header("Authorization", format!("Bearer {api_token}"))
            .send()
            .await
            .map_err(|e| AppError::External(format!("CF tunnel delete failed: {e}")))?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(AppError::External(format!(
                "CF tunnel delete failed: {body}"
            )));
        }

        Ok(())
    }

    /// Create a Cloudflare tunnel for the control plane itself, configure
    /// ingress to route to a local port, create the DNS CNAME, and spawn
    /// `cloudflared` to connect the tunnel.
    pub async fn create_and_run_cp_tunnel(
        &self,
        hostname: &str,
        local_port: u16,
    ) -> AppResult<TunnelInfo> {
        let api_token = self
            .api_token
            .as_ref()
            .ok_or_else(|| AppError::Config("DD_CP_CF_API_TOKEN not set".into()))?;
        let account_id = self
            .account_id
            .as_ref()
            .ok_or_else(|| AppError::Config("DD_CP_CF_ACCOUNT_ID not set".into()))?;

        let tunnel_name = format!("dd-cp-{}", hostname.replace('.', "-"));
        let tunnel_secret = Uuid::new_v4().to_string().replace('-', "");

        let client = reqwest::Client::new();

        // 1. Create the tunnel.
        let create_resp = client
            .post(format!(
                "https://api.cloudflare.com/client/v4/accounts/{account_id}/cfd_tunnel"
            ))
            .header("Authorization", format!("Bearer {api_token}"))
            .json(&serde_json::json!({
                "name": tunnel_name,
                "tunnel_secret": base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    tunnel_secret.as_bytes()
                ),
            }))
            .send()
            .await
            .map_err(|e| AppError::External(format!("CF tunnel create failed: {e}")))?;

        if !create_resp.status().is_success() {
            let body = create_resp.text().await.unwrap_or_default();
            return Err(AppError::External(format!(
                "CF tunnel create failed: {body}"
            )));
        }

        let resp_body: serde_json::Value = create_resp
            .json()
            .await
            .map_err(|e| AppError::External(format!("CF tunnel response parse: {e}")))?;

        let tunnel_id = resp_body["result"]["id"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        let tunnel_token = resp_body["result"]["token"]
            .as_str()
            .unwrap_or(&tunnel_secret)
            .to_string();

        // 2. Configure tunnel ingress to route to localhost.
        self.configure_tunnel_ingress(
            &tunnel_id,
            hostname,
            &format!("http://localhost:{local_port}"),
        )
        .await?;

        // 3. Create DNS CNAME record.
        self.create_dns_record(&tunnel_id, hostname).await?;

        // 4. Spawn cloudflared.
        Self::spawn_cloudflared(&tunnel_token)?;

        Ok(TunnelInfo {
            tunnel_id,
            tunnel_token,
            hostname: hostname.to_string(),
        })
    }

    /// Create or update a CNAME DNS record pointing to a tunnel.
    ///
    /// If a CNAME record for `hostname` already exists, it is updated in place.
    pub async fn create_dns_record(&self, tunnel_id: &str, hostname: &str) -> AppResult<()> {
        let api_token = self
            .api_token
            .as_ref()
            .ok_or_else(|| AppError::Config("DD_CP_CF_API_TOKEN not set".into()))?;
        let zone_id = self
            .zone_id
            .as_ref()
            .ok_or_else(|| AppError::Config("DD_CP_CF_ZONE_ID not set".into()))?;

        let tunnel_content = format!("{tunnel_id}.cfargotunnel.com");
        let client = reqwest::Client::new();

        // Check if a CNAME record already exists for this hostname.
        let existing_id = self
            .find_dns_record_id(&client, api_token, zone_id, hostname)
            .await?;

        if let Some(record_id) = existing_id {
            // Update the existing record to point to the new tunnel.
            let resp = client
                .put(format!(
                    "https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}"
                ))
                .header("Authorization", format!("Bearer {api_token}"))
                .json(&serde_json::json!({
                    "type": "CNAME",
                    "name": hostname,
                    "content": tunnel_content,
                    "proxied": true,
                }))
                .send()
                .await
                .map_err(|e| AppError::External(format!("CF DNS update failed: {e}")))?;

            if !resp.status().is_success() {
                let body = resp.text().await.unwrap_or_default();
                return Err(AppError::External(format!("CF DNS update failed: {body}")));
            }
        } else {
            // Create a new record.
            let resp = client
                .post(format!(
                    "https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"
                ))
                .header("Authorization", format!("Bearer {api_token}"))
                .json(&serde_json::json!({
                    "type": "CNAME",
                    "name": hostname,
                    "content": tunnel_content,
                    "proxied": true,
                }))
                .send()
                .await
                .map_err(|e| AppError::External(format!("CF DNS create failed: {e}")))?;

            if !resp.status().is_success() {
                let body = resp.text().await.unwrap_or_default();
                return Err(AppError::External(format!("CF DNS create failed: {body}")));
            }
        }

        Ok(())
    }

    /// Look up an existing CNAME DNS record by hostname, returning its record ID if found.
    async fn find_dns_record_id(
        &self,
        client: &reqwest::Client,
        api_token: &str,
        zone_id: &str,
        hostname: &str,
    ) -> AppResult<Option<String>> {
        let resp = client
            .get(format!(
                "https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?type=CNAME&name={hostname}"
            ))
            .header("Authorization", format!("Bearer {api_token}"))
            .send()
            .await
            .map_err(|e| AppError::External(format!("CF DNS lookup failed: {e}")))?;

        if !resp.status().is_success() {
            // Non-fatal: if lookup fails, fall through to create.
            return Ok(None);
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| AppError::External(format!("CF DNS lookup parse: {e}")))?;

        Ok(body["result"]
            .as_array()
            .and_then(|arr| arr.first())
            .and_then(|rec| rec["id"].as_str())
            .map(|s| s.to_string()))
    }

    /// Configure tunnel ingress rules via the Cloudflare API.
    async fn configure_tunnel_ingress(
        &self,
        tunnel_id: &str,
        hostname: &str,
        service: &str,
    ) -> AppResult<()> {
        let api_token = self
            .api_token
            .as_ref()
            .ok_or_else(|| AppError::Config("DD_CP_CF_API_TOKEN not set".into()))?;
        let account_id = self
            .account_id
            .as_ref()
            .ok_or_else(|| AppError::Config("DD_CP_CF_ACCOUNT_ID not set".into()))?;

        let client = reqwest::Client::new();
        let resp = client
            .put(format!(
                "https://api.cloudflare.com/client/v4/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations"
            ))
            .header("Authorization", format!("Bearer {api_token}"))
            .json(&serde_json::json!({
                "config": {
                    "ingress": [
                        {
                            "hostname": hostname,
                            "service": service,
                        },
                        {
                            "service": "http_status:404"
                        }
                    ]
                }
            }))
            .send()
            .await
            .map_err(|e| AppError::External(format!("CF tunnel config failed: {e}")))?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(AppError::External(format!(
                "CF tunnel config failed: {body}"
            )));
        }

        Ok(())
    }

    /// Spawn cloudflared as a detached background process.
    fn spawn_cloudflared(token: &str) -> AppResult<()> {
        use std::process::{Command, Stdio};

        let child = Command::new("cloudflared")
            .args(["tunnel", "--no-autoupdate", "run", "--token", token])
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| AppError::External(format!("spawn cloudflared: {e}")))?;

        // Detach -- we intentionally leak the child handle so cloudflared
        // keeps running for the lifetime of the process.
        std::mem::forget(child);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unconfigured_service_errors_on_create() {
        let svc = TunnelService {
            api_token: None,
            account_id: None,
            zone_id: None,
            domain: "devopsdefender.com".into(),
        };
        let agent_id = Uuid::new_v4();
        let result = svc.create_tunnel_for_agent(agent_id, "test-vm").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn unconfigured_service_errors_on_delete() {
        let svc = TunnelService {
            api_token: None,
            account_id: None,
            zone_id: None,
            domain: "devopsdefender.com".into(),
        };
        let result = svc.delete_tunnel("fake-tunnel-id").await;
        assert!(result.is_err());
    }
}
