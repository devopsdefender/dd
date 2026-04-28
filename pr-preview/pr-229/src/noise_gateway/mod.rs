//! # Noise_IK attested gateway to EE's agent socket.
//!
//! Route exposed alongside DD's normal HTTP surface (same port):
//!   - `GET /noise/ws` — WebSocket upgrade; server runs Noise_IK
//!     responder. Initiator's static pubkey must be in the local
//!     trust set. After the handshake every decrypted binary frame
//!     is one JSON request envelope gated by [`allowlist::classify`],
//!     forwarded to EE's unix agent socket with the `EE_TOKEN`
//!     (when available) injected server-side.
//!
//! The pre-handshake TDX quote + Noise pubkey bundle is served by the
//! containing service's `/health` endpoint, not by this module — see
//! `agent::health` / `cp::health` for `{ noise: { quote_b64,
//! pubkey_hex } }`. Clients do one `/health` fetch, verify the quote
//! against ITA, pin the pubkey from `report_data`, and open this
//! WebSocket.
//!
//! This module used to live in `crates/ee-proxy/`; folded in here
//! so the trust list can be a shared in-memory set (not a file
//! contract) and so the gateway inherits whatever `EE_TOKEN` the
//! main `devopsdefender` process already has.

pub mod allowlist;
pub mod attest;
pub mod noise;
pub mod upstream;

use std::collections::HashSet;
use std::sync::Arc;

use axum::Router;
use tokio::sync::RwLock;

/// Live set of device pubkeys the local Noise responder will accept.
/// Mutated by `devices::Store` (on the CP) or by the agent's
/// `sync_trusted_devices` poll loop.
pub type TrustHandle = Arc<RwLock<HashSet<[u8; 32]>>>;

pub fn new_trust_handle() -> TrustHandle {
    Arc::new(RwLock::new(HashSet::new()))
}

#[derive(Clone)]
pub struct State {
    pub attest: Arc<attest::Attestor>,
    pub trust: TrustHandle,
    pub upstream: Arc<upstream::EeAgent>,
}

pub fn router(state: State) -> Router {
    Router::new().merge(noise::routes()).with_state(state)
}
