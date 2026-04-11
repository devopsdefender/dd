//! WebSocket registration handler and fleet registry types.
//!
//! Implements `/register`: dd-client calls this over a WebSocket,
//! performs a Noise XX handshake (dd_common::noise) with an attestation
//! payload, and dd-register provisions a Cloudflare tunnel + DNS record
//! for the agent via dd_common::tunnel.

use axum::extract::ws::WebSocket;
use dd_common::noise;
use dd_common::tunnel;
use futures_util::StreamExt;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

// ── Agent registry ──────────────────────────────────────────────────────

/// Agent record in the fleet registry.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RegisteredAgent {
    pub agent_id: String,
    pub hostname: String,
    pub vm_name: String,
    pub attestation_type: String,
    pub registered_at: String,
    pub last_seen: chrono::DateTime<chrono::Utc>,
    pub status: String,
}

pub type AgentRegistry = Arc<Mutex<HashMap<String, RegisteredAgent>>>;

// ── Registration request from agent ─────────────────────────────────────

#[derive(serde::Deserialize)]
struct RegReq {
    owner: String,
    vm_name: String,
}

// ── WebSocket registration handler ──────────────────────────────────────

/// Handle a single agent registration over WebSocket + Noise XX.
///
/// Protocol:
///   1. Noise XX handshake (agent sends attestation in msg3)
///   2. Read encrypted registration request {owner, vm_name}
///   3. Stale cleanup: remove old entries with same vm_name + delete CF tunnels
///   4. Create new CF tunnel for the agent
///   5. Insert into registry
///   6. Send encrypted bootstrap config back
pub async fn handle_ws_register(
    socket: WebSocket,
    registry: AgentRegistry,
    cf: tunnel::CfConfig,
    auth_public_key_b64: Option<String>,
    auth_issuer: Option<String>,
) {
    let (mut ws_tx, mut ws_rx) = socket.split();

    let keypair = match noise::generate_keypair() {
        Ok(k) => k,
        Err(e) => {
            eprintln!("dd-register: keypair: {e}");
            return;
        }
    };

    // Noise XX handshake — we pass an empty responder payload; the agent
    // sends its attestation as the initiator payload in msg3.
    let (mut transport, peer_payload) = match noise::noise_xx_responder_ws(
        &mut ws_tx,
        &mut ws_rx,
        &keypair.private,
        &[], // register sends no payload in msg2
    )
    .await
    {
        Ok(result) => result,
        Err(e) => {
            eprintln!("dd-register: handshake failed: {e}");
            return;
        }
    };

    let attestation: noise::AttestationPayload = match serde_json::from_slice(&peer_payload) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("dd-register: bad attestation: {e}");
            return;
        }
    };

    eprintln!(
        "dd-register: agent {} ({})",
        attestation.vm_name, attestation.attestation_type
    );

    // Read encrypted registration request
    let req_bytes = match noise::noise_recv_ws(&mut ws_rx, &mut transport).await {
        Ok(b) => b,
        Err(e) => {
            eprintln!("dd-register: recv reg request: {e}");
            return;
        }
    };
    let reg: RegReq = match serde_json::from_slice(&req_bytes) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("dd-register: bad reg request: {e}");
            return;
        }
    };

    let client = reqwest::Client::new();

    // Stale cleanup: remove old entries with same vm_name + delete their CF tunnels.
    // Without this the fleet accumulates stale entries on every VM redeploy.
    let stale: Vec<(String, String)> = {
        let registry = registry.lock().await;
        registry
            .values()
            .filter(|a| a.vm_name == reg.vm_name)
            .map(|a| (a.agent_id.clone(), a.hostname.clone()))
            .collect()
    };
    if !stale.is_empty() {
        for (old_agent_id, old_hostname) in &stale {
            if let Err(e) = tunnel::remove_agent(&client, &cf, old_agent_id, old_hostname).await {
                eprintln!("dd-register: stale tunnel cleanup failed for {old_hostname}: {e}");
            } else {
                eprintln!(
                    "dd-register: removed stale tunnel for vm {} (agent_id={old_agent_id}, hostname={old_hostname})",
                    reg.vm_name
                );
            }
        }
        let mut registry = registry.lock().await;
        for (old_agent_id, _) in &stale {
            registry.remove(old_agent_id);
        }
    }

    // Create CF tunnel for the agent
    let agent_id = uuid::Uuid::new_v4().to_string();
    let tunnel_info =
        match tunnel::create_agent_tunnel(&client, &cf, &agent_id, &reg.vm_name, None).await {
            Ok(info) => info,
            Err(e) => {
                eprintln!("dd-register: tunnel creation failed: {e}");
                return;
            }
        };

    eprintln!(
        "dd-register: {} registered at {}",
        reg.vm_name, tunnel_info.hostname
    );

    // Record in registry
    let now = chrono::Utc::now();
    registry.lock().await.insert(
        agent_id.clone(),
        RegisteredAgent {
            agent_id,
            hostname: tunnel_info.hostname.clone(),
            vm_name: reg.vm_name,
            attestation_type: attestation.attestation_type,
            registered_at: now.to_rfc3339(),
            last_seen: now,
            status: "healthy".into(),
        },
    );

    // Send bootstrap config back via Noise
    let config = noise::BootstrapConfig {
        owner: reg.owner,
        tunnel_token: tunnel_info.tunnel_token,
        hostname: tunnel_info.hostname,
        auth_public_key: auth_public_key_b64,
        auth_issuer,
    };
    let config_json = serde_json::to_vec(&config).unwrap();
    if let Err(e) = noise::noise_send_ws(&mut ws_tx, &mut transport, &config_json).await {
        eprintln!("dd-register: send bootstrap config: {e}");
    }
}

// ── Deregistration ──────────────────────────────────────────────────────

/// Remove an agent from the registry and delete its CF tunnel + DNS record.
pub async fn handle_deregister(
    registry: AgentRegistry,
    cf: &tunnel::CfConfig,
    agent_id: &str,
) -> Result<(), dd_common::error::AppError> {
    let agent = registry.lock().await.remove(agent_id);
    match agent {
        Some(agent) => {
            let client = reqwest::Client::new();
            if let Err(e) =
                tunnel::remove_agent(&client, cf, &agent.agent_id, &agent.hostname).await
            {
                eprintln!("dd-register: deregister tunnel cleanup failed: {e}");
            } else {
                eprintln!(
                    "dd-register: deregistered {} ({})",
                    agent.agent_id, agent.hostname
                );
            }
            Ok(())
        }
        None => Err(dd_common::error::AppError::NotFound),
    }
}
