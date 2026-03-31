//! Registration service — accepts Noise-over-WebSocket connections from agents,
//! verifies attestation, provisions CF tunnels, delivers tokens.
//!
//! Single HTTP server with one WebSocket endpoint. No database, no state.

use axum::extract::ws::{Message, WebSocket};
use axum::extract::WebSocketUpgrade;
use axum::routing::get;
use axum::Router;
use futures_util::{SinkExt, StreamExt};

use dd_agent::noise::{self, AttestationPayload, BootstrapConfig};
use dd_agent::tunnel::{self, CfConfig};

#[derive(Debug, serde::Deserialize)]
struct RegisterRequest {
    owner: String,
    vm_name: String,
}

#[tokio::main]
async fn main() {
    let port: u16 = std::env::var("DD_REGISTER_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(9090);

    let cf = match CfConfig::from_env() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("dd-register: {e}");
            eprintln!("dd-register: set DD_CF_API_TOKEN, DD_CF_ACCOUNT_ID, DD_CF_ZONE_ID");
            std::process::exit(1);
        }
    };

    let app = Router::new()
        .route("/health", get(|| async { "ok" }))
        .route(
            "/register",
            get(move |ws: WebSocketUpgrade| {
                let cf = cf.clone();
                async move { ws.on_upgrade(move |socket| handle_registration(socket, cf)) }
            }),
        );

    let addr = format!("0.0.0.0:{port}");
    eprintln!("dd-register: listening on {addr}");
    eprintln!("dd-register: agents connect to ws://host:{port}/register");

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("failed to bind");
    axum::serve(listener, app).await.expect("server error");
}

async fn handle_registration(socket: WebSocket, cf: CfConfig) {
    let (mut ws_tx, mut ws_rx) = socket.split();

    let keypair = match noise::generate_keypair() {
        Ok(k) => k,
        Err(e) => {
            eprintln!("dd-register: keypair: {e}");
            return;
        }
    };

    let mut noise = match snow::Builder::new(noise::NOISE_PATTERN.parse().unwrap())
        .local_private_key(&keypair.private)
        .and_then(|b| b.build_responder())
    {
        Ok(n) => n,
        Err(e) => {
            eprintln!("dd-register: noise setup: {e}");
            return;
        }
    };

    let mut buf = vec![0u8; 65535];

    // XX handshake over WebSocket binary frames

    // msg1 from agent
    let msg1 = match ws_rx.next().await {
        Some(Ok(Message::Binary(data))) => data.to_vec(),
        _ => return,
    };
    if noise.read_message(&msg1, &mut buf).is_err() {
        eprintln!("dd-register: handshake msg1 failed");
        return;
    }

    // msg2 (no payload from register side)
    let mut msg2_buf = vec![0u8; 65535];
    let msg2_len = match noise.write_message(&[], &mut msg2_buf) {
        Ok(n) => n,
        Err(_) => return,
    };
    if ws_tx
        .send(Message::Binary(msg2_buf[..msg2_len].to_vec().into()))
        .await
        .is_err()
    {
        return;
    }

    // msg3 from agent (with attestation payload)
    let msg3 = match ws_rx.next().await {
        Some(Ok(Message::Binary(data))) => data.to_vec(),
        _ => return,
    };
    let payload_len = match noise.read_message(&msg3, &mut buf) {
        Ok(n) => n,
        Err(_) => {
            eprintln!("dd-register: handshake msg3 failed");
            return;
        }
    };

    let attestation: AttestationPayload = match serde_json::from_slice(&buf[..payload_len]) {
        Ok(a) => a,
        Err(_) => {
            eprintln!("dd-register: parse attestation failed");
            return;
        }
    };

    eprintln!(
        "dd-register: agent {} attestation: {}",
        attestation.vm_name, attestation.attestation_type
    );

    let mut transport = match noise.into_transport_mode() {
        Ok(t) => t,
        Err(_) => return,
    };

    // Read encrypted registration request
    let enc_req = match ws_rx.next().await {
        Some(Ok(Message::Binary(data))) => data.to_vec(),
        _ => return,
    };
    let req_len = match transport.read_message(&enc_req, &mut buf) {
        Ok(n) => n,
        Err(_) => return,
    };

    let reg: RegisterRequest = match serde_json::from_slice(&buf[..req_len]) {
        Ok(r) => r,
        Err(_) => {
            eprintln!("dd-register: parse request failed");
            return;
        }
    };

    eprintln!(
        "dd-register: creating tunnel for owner={} vm={}",
        reg.owner, reg.vm_name
    );

    // Create CF tunnel
    let client = reqwest::Client::new();
    let tunnel_info =
        match tunnel::create_agent_tunnel(&client, &cf, &reg.owner, &reg.vm_name).await {
            Ok(info) => info,
            Err(e) => {
                eprintln!("dd-register: tunnel creation failed: {e}");
                return;
            }
        };

    eprintln!(
        "dd-register: tunnel created — hostname={}",
        tunnel_info.hostname
    );

    // Send encrypted bootstrap config
    let config = BootstrapConfig {
        owner: reg.owner,
        tunnel_token: tunnel_info.tunnel_token,
        hostname: tunnel_info.hostname.clone(),
    };
    let config_json = serde_json::to_vec(&config).unwrap();
    let mut enc_resp = vec![0u8; 65535];
    if let Ok(len) = transport.write_message(&config_json, &mut enc_resp) {
        let _ = ws_tx
            .send(Message::Binary(enc_resp[..len].to_vec().into()))
            .await;
    }

    eprintln!(
        "dd-register: agent {} registered at {}",
        attestation.vm_name, tunnel_info.hostname
    );
}
