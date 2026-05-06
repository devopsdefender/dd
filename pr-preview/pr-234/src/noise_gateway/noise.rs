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
//!
//! `attach` is special: after the one JSON ack frame, the session
//! shifts into a raw bidirectional byte bridge. Client→server
//! frames carry stdin bytes; server→client frames carry stdout/
//! stderr bytes. Either side closing the WS ends the session. This
//! keeps one Noise session == one PTY, which is fine — a second
//! shell opens a second WS.

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::response::Response;
use axum::routing::get;
use axum::Router;
use futures_util::StreamExt;
use snow::{Builder, HandshakeState, TransportState};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{allowlist, State as AppState};

const NOISE_PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
const MAX_NOISE_MSG: usize = 65535;
/// Chunk size for raw PTY bytes flowing EE→client in attach mode.
/// Under `MAX_NOISE_MSG - 16` (auth tag) with plenty of headroom.
const ATTACH_CHUNK: usize = 4096;

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

        match allowlist::classify(&request) {
            Ok(allowlist::Method::Attach) => {
                // Streaming path. attach_stream either hands us the EE
                // socket + ack (happy) or returns an error we surface
                // as a normal JSON response and keep the session in
                // one-shot mode for the next request.
                match state.upstream.attach_stream(request).await {
                    Ok((ack, ee_stream)) => {
                        send_encrypted_json(&mut transport, &mut socket, &ack).await?;
                        bridge_attach(&mut transport, &mut socket, ee_stream).await?;
                        return Ok(());
                    }
                    Err(e) => {
                        let resp = serde_json::json!({
                            "error": "attach_failed",
                            "detail": e.to_string(),
                        });
                        send_encrypted_json(&mut transport, &mut socket, &resp).await?;
                        continue;
                    }
                }
            }
            Ok(_method) => {
                let response = state.upstream.call(request).await.unwrap_or_else(|e| {
                    serde_json::json!({
                        "error": "upstream_failed",
                        "detail": e.to_string(),
                    })
                });
                send_encrypted_json(&mut transport, &mut socket, &response).await?;
            }
            Err(e) => {
                let response = serde_json::json!({
                    "error": "method_rejected",
                    "detail": e.to_string(),
                });
                send_encrypted_json(&mut transport, &mut socket, &response).await?;
            }
        }
    }

    Ok(())
}

async fn send_encrypted_json(
    transport: &mut TransportState,
    socket: &mut WebSocket,
    value: &serde_json::Value,
) -> anyhow::Result<()> {
    let plain = serde_json::to_vec(value)?;
    send_encrypted_bytes(transport, socket, &plain).await
}

async fn send_encrypted_bytes(
    transport: &mut TransportState,
    socket: &mut WebSocket,
    plain: &[u8],
) -> anyhow::Result<()> {
    let mut cipher = vec![0u8; plain.len() + 16];
    let n = transport.write_message(plain, &mut cipher)?;
    cipher.truncate(n);
    socket.send(Message::Binary(cipher.into())).await?;
    Ok(())
}

/// Bridge WS ↔ EE socket as raw bytes for the life of one PTY.
/// Runs in the same future that owns the Noise `TransportState` so
/// we don't need a mutex around it — `select!` gives us concurrent
/// reads on both sides while serializing access to the transport.
async fn bridge_attach(
    transport: &mut TransportState,
    socket: &mut WebSocket,
    ee_stream: tokio::net::UnixStream,
) -> anyhow::Result<()> {
    let (mut ee_rd, mut ee_wr) = ee_stream.into_split();
    let mut ee_buf = [0u8; ATTACH_CHUNK];

    loop {
        tokio::select! {
            biased;
            // EE → client: raw PTY bytes, encrypted and forwarded.
            n = ee_rd.read(&mut ee_buf) => {
                match n? {
                    0 => break, // EE closed (shell exited)
                    n => send_encrypted_bytes(transport, socket, &ee_buf[..n]).await?,
                }
            }
            // Client → EE: decrypt and write stdin.
            frame = next_binary(socket) => {
                match frame? {
                    Some(cipher) => {
                        let mut plain = vec![0u8; cipher.len()];
                        let n = transport.read_message(&cipher, &mut plain)?;
                        ee_wr.write_all(&plain[..n]).await?;
                    }
                    None => break, // WS closed
                }
            }
        }
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
