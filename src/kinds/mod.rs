//! Kind-specific glue.
//!
//! The four typed kinds (oracle / llm / shell / bot) all share most of
//! their lifecycle: deploy via EE, expose via cloudflared tunnel,
//! attest via ITA. The kind-specific differences are small and live
//! in this directory:
//!
//!   - `oracle::manifest` — attestation manifest fields surfaced at
//!     `/manifest` for on-chain verifiers.
//!   - `llm::Proxy`        — in-process reverse proxy for proxy-mode.
//!   - `shell::bridge_pty` — WebSocket ↔ EE PTY socket bridge.
//!   - `bot::wake_loop`    — periodic poke of a bot's `/tick` endpoint.
//!
//! Everything else is uniform — see `agent.rs` for the shared deploy /
//! /health / etc. handlers.

pub mod bot;
pub mod llm;
pub mod oracle;
pub mod shell;
