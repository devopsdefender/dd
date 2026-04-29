//! Noise XX gateway.
//!
//! Terminates client-side Noise sessions at dd-agent: the workload
//! container stays plain HTTP on loopback. The wire is:
//!
//!   WSS frame (TLS to Cloudflare)
//!     → Noise XX (terminated here)
//!       → length-prefixed JSON RPC (`WsRpcRequest` / `WsRpcResponse`)
//!         → forwarded as a plain HTTP request to the workload
//!
//! v1 chooses serde_json over a hand-rolled length-prefix instead of
//! confer-proxy's protobuf wire format. The security properties are
//! identical; confer-proxy interop is a follow-up that swaps the
//! decoder, not the threat model. (We sidestep the build-time
//! `protoc` dependency this way.)
//!
//! The handshake uses **Noise_XX_25519_ChaChaPoly_SHA256**. The
//! server-static keypair is derived per-deployment so the same vanity
//! gets a stable pubkey across host migrations *for the same code
//! measurement* — if the workload is replaced, the static key
//! changes and clients pinning to the old fingerprint will fail the
//! handshake.

use std::sync::Arc;

use axum::{
    extract::ws::{Message, WebSocket},
    extract::{State, WebSocketUpgrade},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use snow::{params::NoiseParams, Builder};

const NOISE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_SHA256";
const MAX_FRAME_LEN: usize = 65535;

/// Per-deployment Noise gateway state. The static keypair binds the
/// deployment identity to the vanity hostname; clients are expected
/// to pin against the manifest pubkey.
#[derive(Clone)]
pub struct NoiseGateway {
    private_key: Arc<[u8; 32]>,
    public_key: Arc<[u8; 32]>,
    upstream_origin: String,
    http: reqwest::Client,
}

impl NoiseGateway {
    /// Build a gateway with a freshly-generated keypair. In the real
    /// deployment the keypair is derived from the TDX measurement via
    /// EE; for now we accept caller-supplied bytes.
    pub fn from_keypair(private_key: [u8; 32], upstream_origin: String) -> Self {
        let priv_arc: Arc<[u8; 32]> = Arc::new(private_key);
        let pub_arc: Arc<[u8; 32]> = Arc::new(
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(*priv_arc)).to_bytes(),
        );
        Self {
            private_key: priv_arc,
            public_key: pub_arc,
            upstream_origin,
            http: reqwest::Client::new(),
        }
    }

    /// 32-byte raw X25519 public key. Surfaced at `/manifest` so
    /// clients can pin.
    pub fn public_key(&self) -> [u8; 32] {
        *self.public_key
    }
}

/// `GET /noise` — WebSocket upgrade. Performs Noise XX with the
/// client and bridges decoded RPCs to the workload's loopback HTTP.
pub async fn handler(State(gw): State<NoiseGateway>, ws: WebSocketUpgrade) -> Response {
    ws.on_upgrade(move |socket| async move {
        if let Err(e) = serve(socket, gw).await {
            eprintln!("noise: session ended: {e}");
        }
    })
}

async fn serve(mut ws: WebSocket, gw: NoiseGateway) -> Result<(), String> {
    let params: NoiseParams = NOISE_PATTERN
        .parse()
        .map_err(|e: snow::Error| e.to_string())?;
    let mut hs = Builder::new(params)
        .local_private_key(gw.private_key.as_ref())
        .build_responder()
        .map_err(|e| e.to_string())?;

    // Three-message XX:
    // ← e
    // → e, ee, s, es
    // ← s, se
    let mut buf = vec![0u8; 1024];

    let msg1 = recv_binary(&mut ws).await.ok_or("noise: msg1 closed")?;
    hs.read_message(&msg1, &mut buf)
        .map_err(|e| e.to_string())?;

    let len = hs.write_message(&[], &mut buf).map_err(|e| e.to_string())?;
    ws.send(Message::Binary(buf[..len].to_vec().into()))
        .await
        .map_err(|e| e.to_string())?;

    let msg3 = recv_binary(&mut ws).await.ok_or("noise: msg3 closed")?;
    hs.read_message(&msg3, &mut buf)
        .map_err(|e| e.to_string())?;

    let mut transport = hs.into_transport_mode().map_err(|e| e.to_string())?;

    // Steady-state RPC loop.
    let mut frame = vec![0u8; MAX_FRAME_LEN];
    loop {
        let ct = match recv_binary(&mut ws).await {
            Some(b) => b,
            None => break,
        };
        let plain_len = transport
            .read_message(&ct, &mut frame)
            .map_err(|e| e.to_string())?;
        let req: WsRpcRequest =
            serde_json::from_slice(&frame[..plain_len]).map_err(|e| e.to_string())?;

        let resp = forward(&gw, req).await;
        let plain = serde_json::to_vec(&resp).map_err(|e| e.to_string())?;
        let mut ct_buf = vec![0u8; plain.len() + 16];
        let n = transport
            .write_message(&plain, &mut ct_buf)
            .map_err(|e| e.to_string())?;
        ws.send(Message::Binary(ct_buf[..n].to_vec().into()))
            .await
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

async fn forward(gw: &NoiseGateway, req: WsRpcRequest) -> WsRpcResponse {
    let url = format!("{}{}", gw.upstream_origin.trim_end_matches('/'), req.path);
    let method = match req.verb.as_str() {
        "GET" => reqwest::Method::GET,
        "POST" => reqwest::Method::POST,
        "PUT" => reqwest::Method::PUT,
        "DELETE" => reqwest::Method::DELETE,
        "PATCH" => reqwest::Method::PATCH,
        _ => {
            return WsRpcResponse {
                id: req.id,
                status: 405,
                body: Default::default(),
            }
        }
    };
    match gw
        .http
        .request(method, url)
        .body(req.body.into_bytes())
        .send()
        .await
    {
        Ok(resp) => {
            let status = resp.status().as_u16() as u32;
            let body = resp.bytes().await.unwrap_or_default().to_vec();
            WsRpcResponse {
                id: req.id,
                status,
                body,
            }
        }
        Err(e) => WsRpcResponse {
            id: req.id,
            status: 502,
            body: e.to_string().into_bytes(),
        },
    }
}

async fn recv_binary(ws: &mut WebSocket) -> Option<Vec<u8>> {
    while let Some(msg) = ws.recv().await {
        match msg.ok()? {
            Message::Binary(b) => return Some(b.to_vec()),
            Message::Text(_) | Message::Ping(_) | Message::Pong(_) => continue,
            Message::Close(_) => return None,
        }
    }
    None
}

/// Application-layer RPC inside the Noise tunnel. Mirrors confer-proxy's
/// `WebsocketRequest` semantically, encoded as JSON instead of protobuf.
#[derive(Debug, Serialize, Deserialize)]
pub struct WsRpcRequest {
    pub id: i64,
    pub verb: String,
    pub path: String,
    #[serde(default)]
    pub body: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WsRpcResponse {
    pub id: i64,
    pub status: u32,
    #[serde(with = "serde_bytes_b64")]
    pub body: Vec<u8>,
}

mod serde_bytes_b64 {
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&base64::engine::general_purpose::STANDARD.encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        base64::engine::general_purpose::STANDARD
            .decode(s.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}

/// `GET /manifest` payload. Surfaces the deployment's static Noise
/// pubkey so clients can pin against it before sending the first
/// message.
#[derive(Serialize)]
pub struct Manifest {
    pub kind: &'static str,
    pub noise_pubkey_b64: String,
}

pub fn build_manifest(kind: &'static str, gw: &NoiseGateway) -> Manifest {
    use base64::Engine;
    Manifest {
        kind,
        noise_pubkey_b64: base64::engine::general_purpose::STANDARD.encode(gw.public_key()),
    }
}

/// `GET /manifest` — handler suitable for axum routes.
pub async fn manifest_handler(State(gw): State<NoiseGateway>) -> impl IntoResponse {
    let m = build_manifest("workload", &gw);
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        serde_json::to_string(&m).unwrap_or_default(),
    )
}

/// Construct a static Noise keypair from a 32-byte seed. In the real
/// deployment this seed is derived from the TDX measurement via EE.
pub fn keypair_from_seed(seed: [u8; 32]) -> ([u8; 32], [u8; 32]) {
    let priv_key = seed; // X25519 secret keys are clamped on use; raw seed is fine
    let pub_key = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(priv_key));
    (priv_key, pub_key.to_bytes())
}

#[allow(dead_code)]
fn _unused(_h: HeaderMap) {}
