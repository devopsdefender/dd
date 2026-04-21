//! CP↔agent m2m RPC over a Noise_IK-tunneled WebSocket.
//!
//! Replaces the ITA-bearer-over-HTTP pattern for calls where both
//! sides have pinned static keys (set up at registration in
//! `crate::noise_m2m::AgentRegistry`). Each call is a fresh
//! WebSocket with a 1-RTT handshake + one request/response pair;
//! no connection pooling. The rare-ops set (`ingress_replace`,
//! `api_agents`, later `heartbeat`) absorbs the ~150 ms handshake
//! cost without blinking.
//!
//! Auth is by pinned pubkey. The responder learns the initiator's
//! static during the IK handshake and matches it against the
//! registry; a mismatch or unknown pubkey → `unauthorized` response.
//! No ITA bearer, no timestamp dance, no token rotation.
//!
//! Wire shape inside the encrypted tunnel is JSON:
//!
//! ```json
//! // Request
//! {"op": "ingress_replace", "agent_id": "...", "extras": [...]}
//! // Response
//! {"ok": true, "data": {...}}  |  {"ok": false, "error": "..."}
//! ```
//!
//! The module exposes one server entry point (`serve`) and one
//! client entry point (`call`); individual ops live in `cp.rs` /
//! `agent.rs` where the state they need is already in scope.

use dd_common::noise_static::NoiseStatic;
use dd_common::noise_tunnel::{Initiator, Responder};
use serde_json::Value;
use std::sync::Arc;

/// Drive one full responder session on an already-upgraded axum
/// WebSocket. Consumes `msg1`, emits `msg2`, then reads a single
/// encrypted request and sends a single encrypted response. Caller
/// supplies the request dispatcher which receives the initiator's
/// pubkey + the decoded request value.
pub async fn serve<F, Fut>(
    mut socket: axum::extract::ws::WebSocket,
    noise_key: &NoiseStatic,
    handler: F,
) where
    F: FnOnce([u8; 32], Value) -> Fut,
    Fut: std::future::Future<Output = Value>,
{
    use axum::extract::ws::Message;

    let mut responder = match Responder::new(noise_key.secret_bytes()) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("noise-rpc: responder init: {e}");
            return;
        }
    };

    let msg1 = match socket.recv().await {
        Some(Ok(Message::Binary(b))) => b,
        other => {
            eprintln!("noise-rpc: expected binary msg1, got {other:?}");
            return;
        }
    };
    if let Err(e) = responder.read_msg1(&msg1) {
        eprintln!("noise-rpc: msg1 read: {e}");
        return;
    }
    let peer = match responder.peer_pubkey() {
        Some(p) => p,
        None => {
            eprintln!("noise-rpc: missing peer pubkey after msg1");
            return;
        }
    };
    let msg2 = match responder.write_msg2(&[]) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("noise-rpc: msg2 write: {e}");
            return;
        }
    };
    if socket.send(Message::Binary(msg2.into())).await.is_err() {
        return;
    }
    let mut transport = match responder.into_transport() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("noise-rpc: transport xition: {e}");
            return;
        }
    };

    // Single request / single response.
    let cipher = match socket.recv().await {
        Some(Ok(Message::Binary(b))) => b,
        _ => return,
    };
    let plain = match transport.recv(&cipher) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("noise-rpc: decrypt: {e}");
            return;
        }
    };
    let req: Value = match serde_json::from_slice(&plain) {
        Ok(v) => v,
        Err(e) => {
            let _ = send_err(&mut socket, &mut transport, &format!("bad request: {e}")).await;
            return;
        }
    };
    let resp = handler(peer, req).await;
    let Ok(out) = serde_json::to_vec(&resp) else {
        return;
    };
    let Ok(ct) = transport.send(&out) else {
        return;
    };
    let _ = socket.send(Message::Binary(ct.into())).await;
}

async fn send_err(
    socket: &mut axum::extract::ws::WebSocket,
    transport: &mut dd_common::noise_tunnel::Transport,
    msg: &str,
) -> std::io::Result<()> {
    use axum::extract::ws::Message;
    let body = serde_json::json!({"ok": false, "error": msg});
    let Ok(bytes) = serde_json::to_vec(&body) else {
        return Ok(());
    };
    let Ok(ct) = transport.send(&bytes) else {
        return Ok(());
    };
    socket
        .send(Message::Binary(ct.into()))
        .await
        .map_err(|e| std::io::Error::other(format!("{e}")))
}

/// Open `wss_url`, run the Noise_IK handshake as initiator, send one
/// encrypted JSON request, read one encrypted response, close.
///
/// `client_static` is the agent's long-term keypair;
/// `server_pubkey` is the CP's pinned pubkey (cached after
/// `/cp/noise/attest`). Returns the decoded response `Value` or an
/// error if any step fails.
pub async fn call(
    wss_url: &str,
    client_static: &Arc<NoiseStatic>,
    server_pubkey: &[u8; 32],
    request: Value,
) -> Result<Value, CallError> {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::protocol::Message;

    let (mut ws, _resp) = tokio_tungstenite::connect_async(wss_url)
        .await
        .map_err(|e| CallError::Connect(format!("{e}")))?;

    let mut initiator = Initiator::new(client_static.secret_bytes(), server_pubkey)
        .map_err(|e| CallError::Handshake(format!("init: {e}")))?;
    let msg1 = initiator
        .write_msg1(&[])
        .map_err(|e| CallError::Handshake(format!("msg1: {e}")))?;
    ws.send(Message::Binary(msg1.into()))
        .await
        .map_err(|e| CallError::Connect(format!("send msg1: {e}")))?;

    let msg2 = match ws.next().await {
        Some(Ok(Message::Binary(b))) => b,
        Some(Ok(other)) => return Err(CallError::Handshake(format!("msg2 wrong kind: {other:?}"))),
        Some(Err(e)) => return Err(CallError::Connect(format!("{e}"))),
        None => return Err(CallError::Connect("closed before msg2".into())),
    };
    initiator
        .read_msg2(&msg2)
        .map_err(|e| CallError::Handshake(format!("msg2: {e}")))?;
    let mut transport = initiator
        .into_transport()
        .map_err(|e| CallError::Handshake(format!("transport: {e}")))?;

    let plain = serde_json::to_vec(&request).map_err(|e| CallError::Encode(format!("{e}")))?;
    let ct = transport
        .send(&plain)
        .map_err(|e| CallError::Encode(format!("encrypt: {e}")))?;
    ws.send(Message::Binary(ct.into()))
        .await
        .map_err(|e| CallError::Connect(format!("send req: {e}")))?;

    let resp = match ws.next().await {
        Some(Ok(Message::Binary(b))) => b,
        Some(Ok(other)) => return Err(CallError::Decode(format!("resp wrong kind: {other:?}"))),
        Some(Err(e)) => return Err(CallError::Connect(format!("{e}"))),
        None => return Err(CallError::Connect("closed before response".into())),
    };
    let plain_resp = transport
        .recv(&resp)
        .map_err(|e| CallError::Decode(format!("decrypt: {e}")))?;
    let _ = ws.close(None).await;
    serde_json::from_slice(&plain_resp).map_err(|e| CallError::Decode(format!("{e}")))
}

#[derive(Debug)]
pub enum CallError {
    Connect(String),
    Handshake(String),
    Encode(String),
    Decode(String),
}

impl std::fmt::Display for CallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CallError::Connect(s) => write!(f, "connect: {s}"),
            CallError::Handshake(s) => write!(f, "handshake: {s}"),
            CallError::Encode(s) => write!(f, "encode: {s}"),
            CallError::Decode(s) => write!(f, "decode: {s}"),
        }
    }
}

impl std::error::Error for CallError {}
