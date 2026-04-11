//! Noise XX handshake helpers for WebSocket channels.
//!
//! Two reusable async functions: one for the responder (dd-register)
//! and one for the initiator (dd-client). Both use the same
//! Noise_XX_25519_ChaChaPoly_SHA256 pattern with an attestation payload
//! exchanged in msg3.

use axum::extract::ws::{Message, WebSocket};
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use snow::Builder;

pub const NOISE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_SHA256";
const MAX_MSG_LEN: usize = 65535;

/// Attestation payload sent during the Noise handshake (msg3 from initiator,
/// or msg2 from responder).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AttestationPayload {
    pub attestation_type: String,
    pub vm_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tdx_quote_b64: Option<String>,
}

/// Bootstrap config returned by the register after a successful handshake.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BootstrapConfig {
    pub owner: String,
    pub tunnel_token: String,
    pub hostname: String,
    /// Ed25519 public key (base64) for verifying register-issued JWTs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_public_key: Option<String>,
    /// Register hostname for auth redirects.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_issuer: Option<String>,
}

/// A Noise keypair (raw bytes).
pub struct NoiseKeypair {
    pub private: Vec<u8>,
    pub public: Vec<u8>,
}

/// Generate a fresh Noise keypair.
pub fn generate_keypair() -> Result<NoiseKeypair, String> {
    let builder = Builder::new(NOISE_PATTERN.parse().unwrap());
    let kp = builder
        .generate_keypair()
        .map_err(|e| format!("keypair generation failed: {e}"))?;
    Ok(NoiseKeypair {
        private: kp.private.to_vec(),
        public: kp.public.to_vec(),
    })
}

/// Noise XX responder (register / agent-server side).
///
/// Performs the three-message XX handshake:
///   1. Read msg1 from peer (initiator's ephemeral key).
///   2. Write msg2 carrying `responder_payload` (e.g. attestation or server info).
///   3. Read msg3 from peer carrying their payload (e.g. attestation).
///
/// Returns `(transport, peer_payload_bytes)`.
pub async fn noise_xx_responder_ws(
    ws_tx: &mut SplitSink<WebSocket, Message>,
    ws_rx: &mut SplitStream<WebSocket>,
    private_key: &[u8],
    responder_payload: &[u8],
) -> Result<(snow::TransportState, Vec<u8>), String> {
    let mut noise = Builder::new(NOISE_PATTERN.parse().unwrap())
        .local_private_key(private_key)
        .build_responder()
        .map_err(|e| format!("noise responder setup: {e}"))?;

    let mut buf = vec![0u8; MAX_MSG_LEN];

    // msg1: read initiator's first message
    let msg1 = match ws_rx.next().await {
        Some(Ok(Message::Binary(data))) => data.to_vec(),
        other => return Err(format!("expected binary msg1, got: {other:?}")),
    };
    noise
        .read_message(&msg1, &mut buf)
        .map_err(|e| format!("msg1 read: {e}"))?;

    // msg2: write responder payload
    let mut msg2_buf = vec![0u8; MAX_MSG_LEN];
    let msg2_len = noise
        .write_message(responder_payload, &mut msg2_buf)
        .map_err(|e| format!("msg2 write: {e}"))?;
    ws_tx
        .send(Message::Binary(msg2_buf[..msg2_len].to_vec().into()))
        .await
        .map_err(|e| format!("send msg2: {e}"))?;

    // msg3: read initiator's payload
    let msg3 = match ws_rx.next().await {
        Some(Ok(Message::Binary(data))) => data.to_vec(),
        other => return Err(format!("expected binary msg3, got: {other:?}")),
    };
    let payload_len = noise
        .read_message(&msg3, &mut buf)
        .map_err(|e| format!("msg3 read: {e}"))?;

    let peer_payload = buf[..payload_len].to_vec();

    let transport = noise
        .into_transport_mode()
        .map_err(|e| format!("transport mode: {e}"))?;

    Ok((transport, peer_payload))
}

/// Noise XX initiator (dd-client side).
///
/// Performs the three-message XX handshake:
///   1. Write msg1 (ephemeral key, empty payload).
///   2. Read msg2 carrying responder's payload.
///   3. Write msg3 carrying `initiator_payload` (e.g. attestation).
///
/// Returns `(transport, peer_payload_bytes)`.
pub async fn noise_xx_initiator_ws(
    ws_tx: &mut SplitSink<WebSocket, Message>,
    ws_rx: &mut SplitStream<WebSocket>,
    private_key: &[u8],
    initiator_payload: &[u8],
) -> Result<(snow::TransportState, Vec<u8>), String> {
    let mut noise = Builder::new(NOISE_PATTERN.parse().unwrap())
        .local_private_key(private_key)
        .build_initiator()
        .map_err(|e| format!("noise initiator setup: {e}"))?;

    let mut buf = vec![0u8; MAX_MSG_LEN];

    // msg1: write empty payload (ephemeral key)
    let mut msg1_buf = vec![0u8; MAX_MSG_LEN];
    let msg1_len = noise
        .write_message(&[], &mut msg1_buf)
        .map_err(|e| format!("msg1 write: {e}"))?;
    ws_tx
        .send(Message::Binary(msg1_buf[..msg1_len].to_vec().into()))
        .await
        .map_err(|e| format!("send msg1: {e}"))?;

    // msg2: read responder's payload
    let msg2 = match ws_rx.next().await {
        Some(Ok(Message::Binary(data))) => data.to_vec(),
        other => return Err(format!("expected binary msg2, got: {other:?}")),
    };
    let payload_len = noise
        .read_message(&msg2, &mut buf)
        .map_err(|e| format!("msg2 read: {e}"))?;

    let peer_payload = buf[..payload_len].to_vec();

    // msg3: write initiator payload (e.g. attestation)
    let mut msg3_buf = vec![0u8; MAX_MSG_LEN];
    let msg3_len = noise
        .write_message(initiator_payload, &mut msg3_buf)
        .map_err(|e| format!("msg3 write: {e}"))?;
    ws_tx
        .send(Message::Binary(msg3_buf[..msg3_len].to_vec().into()))
        .await
        .map_err(|e| format!("send msg3: {e}"))?;

    let transport = noise
        .into_transport_mode()
        .map_err(|e| format!("transport mode: {e}"))?;

    Ok((transport, peer_payload))
}

/// Send an encrypted message over a WebSocket.
pub async fn noise_send_ws(
    ws_tx: &mut SplitSink<WebSocket, Message>,
    transport: &mut snow::TransportState,
    plaintext: &[u8],
) -> Result<(), String> {
    let mut enc = vec![0u8; MAX_MSG_LEN];
    let len = transport
        .write_message(plaintext, &mut enc)
        .map_err(|e| format!("encrypt: {e}"))?;
    ws_tx
        .send(Message::Binary(enc[..len].to_vec().into()))
        .await
        .map_err(|e| format!("send: {e}"))?;
    Ok(())
}

/// Receive and decrypt a message from a WebSocket.
pub async fn noise_recv_ws(
    ws_rx: &mut SplitStream<WebSocket>,
    transport: &mut snow::TransportState,
) -> Result<Vec<u8>, String> {
    let data = match ws_rx.next().await {
        Some(Ok(Message::Binary(data))) => data.to_vec(),
        Some(Ok(Message::Close(_))) | None => return Err("connection closed".into()),
        other => return Err(format!("expected binary frame, got: {other:?}")),
    };
    let mut dec = vec![0u8; MAX_MSG_LEN];
    let len = transport
        .read_message(&data, &mut dec)
        .map_err(|e| format!("decrypt: {e}"))?;
    Ok(dec[..len].to_vec())
}
