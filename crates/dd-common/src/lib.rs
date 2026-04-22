//! Types shared between the `devopsdefender` binary (CP + agent modes)
//! and the `bastion` binary (block-aware terminal + workload-capture).
//!
//! - [`BlockRecord`] — the wire shape for a single segmented event.
//! - [`noise_tunnel`] — Noise_IK handshake primitive used by both
//!   browser↔bastion tunnels and CP↔agent m2m.
//! - [`noise_static`] — persistent X25519 keypair shared as the
//!   Noise "static" key for every long-lived identity.

pub mod noise_static;
pub mod noise_tunnel;

use serde::{Deserialize, Serialize};

/// One parsed event from bastion's capture pipeline.
///
/// - `kind == "shell"` → OSC 133-segmented command from an interactive
///   PTY session. `owner_id` is the shell session id; `command` is the
///   line the user submitted; `output_bytes` is the ANSI-preserved
///   slice from the prompt-exit (OSC 133 C) to the command-done marker
///   (OSC 133 D).
/// - `kind == "workload"` → process-lifetime event from easyenclave's
///   capture socket. `owner_id` is the workload's `app_name`; `command`
///   is `argv` joined with spaces; `output_bytes` is the accumulated
///   stdout/stderr bytes from spawn to exit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockRecord {
    pub node_id: String,
    pub kind: BlockKind,
    pub owner_id: String,
    pub seq: u64,
    pub started_at_ms: u64,
    pub ended_at_ms: u64,
    pub command: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub argv: Vec<String>,
    /// base64 of the raw ANSI output slice.
    pub output_b64: String,
    pub exit_code: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BlockKind {
    Shell,
    Workload,
}
