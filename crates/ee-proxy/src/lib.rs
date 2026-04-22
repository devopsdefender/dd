//! # ee-proxy
//!
//! A thin Noise_IK + ITA-attested proxy in front of easyenclave's agent
//! socket. Deployed as a workload inside the enclave, exposed externally
//! via a Cloudflare tunnel. Authenticated external clients (e.g. the
//! `bastion-app` CLI) get to call EE's `exec` / `attach` / `logs` /
//! `list` / `health` / `attest` methods without ever seeing the
//! `EE_TOKEN` — the proxy injects it server-side.
//!
//! ## Wire shape
//!
//! - `GET  /attest`   — returns `{ quote_b64, pubkey_hex }`. The TDX
//!   quote's `report_data` is the raw X25519 static pubkey used for
//!   Noise. Clients verify via ITA, then trust that pubkey for the
//!   handshake.
//! - `GET  /noise/ws` — WebSocket upgrade. Server runs the Noise_IK
//!   responder. The initiator's static pubkey must be on the trusted
//!   list (see [`trust`]). After the handshake, every decrypted frame
//!   is a JSON request envelope gated by the [`allowlist`].
//!
//! The upstream unix socket is [`upstream::EE_AGENT_SOCK`] by default.

pub mod allowlist;
pub mod attest;
pub mod noise;
pub mod trust;
pub mod upstream;

use std::sync::Arc;

use axum::Router;

/// Shared state wired into the axum app.
#[derive(Clone)]
pub struct State {
    pub attest: Arc<attest::Attestor>,
    pub trust: Arc<trust::TrustStore>,
    pub upstream: Arc<upstream::EeAgent>,
}

/// Mount the public router.
pub fn router(state: State) -> Router {
    Router::new()
        .merge(attest::routes())
        .merge(noise::routes())
        .with_state(state)
}
