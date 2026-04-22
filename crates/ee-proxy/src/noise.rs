//! Noise_IK responder over WebSocket.
//!
//! Wire:
//!   1. Client opens `GET /noise/ws` and upgrades to WebSocket.
//!   2. Client sends the first Noise_IK message (binary WS frame).
//!      After reading it, we can inspect the initiator's static key
//!      via `get_remote_static()`. If it isn't in the trust store we
//!      close the connection.
//!   3. We respond with the second handshake message.
//!   4. Once both messages exchanged, both sides move into transport
//!      mode; each subsequent WS binary frame is one Noise transport
//!      message carrying a JSON request envelope. The proxy forwards
//!      the envelope to EE's agent socket, encrypts the response, and
//!      sends it back.
//!
//! Post-handshake flow:
//!   - decrypt → [`crate::allowlist::classify`] → EE upstream call →
//!     encrypt response → WS binary frame back.
//!   - any error at any step closes the connection with a short JSON
//!     error frame (encrypted) before the close.

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::response::Response;
use axum::routing::get;
use axum::Router;
use futures_util::StreamExt;
use snow::{Builder, HandshakeState, TransportState};

use crate::{allowlist, State as AppState};

const NOISE_PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
const MAX_NOISE_MSG: usize = 65535;

pub(crate) fn routes() -> Router<AppState> {
    Router::new().route("/noise/ws", get(upgrade))
}

async fn upgrade(ws: WebSocketUpgrade, State(state): State<AppState>) -> Response {
    ws.on_upgrade(move |socket| async move {
        if let Err(e) = handle(socket, state).await {
            eprintln!("ee-proxy: noise session ended: {e:#}");
        }
    })
}

async fn handle(mut socket: WebSocket, state: AppState) -> anyhow::Result<()> {
    // Build the responder with our static private key. `snow`'s
    // X25519 representation is the same 32-byte little-endian scalar
    // that `x25519-dalek::StaticSecret::to_bytes()` emits.
    let static_private = state.attest.secret().to_bytes();

    let mut hs: HandshakeState = Builder::new(NOISE_PATTERN.parse()?)
        .local_private_key(&static_private)
        .build_responder()?;

    // ── First handshake message (initiator → us) ────────────────────
    let Some(first) = next_binary(&mut socket).await? else {
        anyhow::bail!("closed before first handshake message");
    };
    let mut payload_buf = [0u8; MAX_NOISE_MSG];
    hs.read_message(&first, &mut payload_buf)?;

    let remote_static = hs
        .get_remote_static()
        .ok_or_else(|| anyhow::anyhow!("Noise_IK requires a remote static key"))?;
    if remote_static.len() != 32 {
        anyhow::bail!("unexpected remote static length: {}", remote_static.len());
    }
    let mut remote = [0u8; 32];
    remote.copy_from_slice(remote_static);

    if !state.trust.contains(&remote).await {
        // Send nothing — drop the connection. Prevents an oracle on
        // trust-list membership beyond the `Close` frame itself.
        let _ = socket
            .send(Message::Close(Some(axum::extract::ws::CloseFrame {
                code: axum::extract::ws::close_code::POLICY,
                reason: "unknown peer".into(),
            })))
            .await;
        anyhow::bail!("initiator pubkey not in trust list");
    }

    // ── Second handshake message (us → initiator) ───────────────────
    let mut second_buf = [0u8; MAX_NOISE_MSG];
    let n = hs.write_message(&[], &mut second_buf)?;
    socket
        .send(Message::Binary(second_buf[..n].to_vec().into()))
        .await?;

    let mut transport: TransportState = hs.into_transport_mode()?;

    // ── Transport loop ──────────────────────────────────────────────
    while let Some(frame) = next_binary(&mut socket).await? {
        let mut plain = vec![0u8; frame.len()];
        let n = transport.read_message(&frame, &mut plain)?;
        plain.truncate(n);

        let request: serde_json::Value = serde_json::from_slice(&plain)
            .map_err(|e| anyhow::anyhow!("decrypted frame is not JSON: {e}"))?;

        let response = match allowlist::classify(&request) {
            Ok(_method) => state.upstream.call(request).await.unwrap_or_else(|e| {
                serde_json::json!({
                    "error": "upstream_failed",
                    "detail": e.to_string(),
                })
            }),
            Err(e) => serde_json::json!({
                "error": "method_rejected",
                "detail": e.to_string(),
            }),
        };

        let plain = serde_json::to_vec(&response)?;
        let mut cipher = vec![0u8; plain.len() + 16];
        let n = transport.write_message(&plain, &mut cipher)?;
        cipher.truncate(n);
        socket.send(Message::Binary(cipher.into())).await?;
    }

    Ok(())
}

/// Pull the next WS binary frame. Returns `Ok(None)` on normal close
/// (including `Close` and stream exhaustion); text frames and pings
/// are ignored (pong handled by axum automatically).
async fn next_binary(socket: &mut WebSocket) -> anyhow::Result<Option<Vec<u8>>> {
    while let Some(msg) = socket.next().await {
        match msg? {
            Message::Binary(b) => return Ok(Some(b.to_vec())),
            Message::Close(_) => return Ok(None),
            Message::Text(_) | Message::Ping(_) | Message::Pong(_) => continue,
        }
    }
    Ok(None)
}
