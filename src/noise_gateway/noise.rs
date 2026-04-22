//! Noise_IK responder over WebSocket.
//!
//! Wire:
//!   1. Client opens `GET /noise/ws` and upgrades to WebSocket.
//!   2. Client sends the first Noise_IK message (binary WS frame).
//!      After reading it we inspect the initiator's static key via
//!      `get_remote_static()`. If it isn't in the shared trust set
//!      we close the connection.
//!   3. We respond with the second handshake message.
//!   4. Both sides move into transport mode; each subsequent WS
//!      binary frame is one Noise transport message carrying a JSON
//!      request envelope, gated by [`super::allowlist::classify`]
//!      and forwarded to the EE agent socket.

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::response::Response;
use axum::routing::get;
use axum::Router;
use futures_util::StreamExt;
use snow::{Builder, HandshakeState, TransportState};

use super::{allowlist, State as AppState};

const NOISE_PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
const MAX_NOISE_MSG: usize = 65535;

pub(crate) fn routes() -> Router<AppState> {
    Router::new().route("/noise/ws", get(upgrade))
}

async fn upgrade(ws: WebSocketUpgrade, State(state): State<AppState>) -> Response {
    ws.on_upgrade(move |socket| async move {
        if let Err(e) = handle(socket, state).await {
            eprintln!("noise-gw: session ended: {e:#}");
        }
    })
}

async fn handle(mut socket: WebSocket, state: AppState) -> anyhow::Result<()> {
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

    let trusted = state.trust.read().await.contains(&remote);
    if !trusted {
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
