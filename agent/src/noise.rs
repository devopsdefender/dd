//! Noise protocol — the agent's shell interface.
//!
//! Persistent sessions over Noise_XX_25519_ChaChaPoly_SHA256.
//! One session = one shell. Jobs run in background or foreground.
//! Wire format: `[u32 big-endian length][payload]`.

use serde::{Deserialize, Serialize};
use snow::Builder;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub const NOISE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_SHA256";
const MAX_MSG_LEN: usize = 65535;

// ── Message Protocol ─────────────────────────────────────────────────────

/// Messages sent over the Noise channel. The shell protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum NoiseMessage {
    // ── Job management (client → agent) ──
    /// Start a workload in background.
    #[serde(rename = "deploy")]
    Deploy {
        #[serde(default)]
        cmd: Vec<String>,
        #[serde(default)]
        image: Option<String>,
        #[serde(default)]
        app_name: Option<String>,
        #[serde(default)]
        env: Option<Vec<String>>,
        #[serde(default)]
        tty: bool,
    },
    /// Stop a running job.
    #[serde(rename = "stop")]
    Stop { id: String },
    /// List all jobs.
    #[serde(rename = "jobs")]
    Jobs,
    /// Foreground a job — attach session I/O to it.
    #[serde(rename = "fg")]
    Fg { id: String },
    /// Background the current foreground job.
    #[serde(rename = "bg")]
    Bg,
    /// Stream logs from a job.
    #[serde(rename = "logs")]
    Logs { id: String },
    /// Close the session.
    #[serde(rename = "exit")]
    Exit,

    // ── I/O (bidirectional when fg'd) ──
    /// Stdin data from client to foreground job.
    #[serde(rename = "stdin")]
    Stdin { data: Vec<u8> },
    /// Stdout data from foreground job to client.
    #[serde(rename = "stdout")]
    Stdout { data: Vec<u8> },
    /// Stderr data from foreground job to client.
    #[serde(rename = "stderr")]
    Stderr { data: Vec<u8> },

    // ── Responses (agent → client) ──
    #[serde(rename = "ok")]
    Ok {
        #[serde(skip_serializing_if = "Option::is_none")]
        id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        status: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        message: Option<String>,
    },
    #[serde(rename = "error")]
    Error { message: String },
    #[serde(rename = "job_list")]
    JobList { jobs: Vec<JobInfo> },

    // ── Bootstrap (agent → register service) ──
    #[serde(rename = "bootstrap")]
    Bootstrap(BootstrapConfig),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobInfo {
    pub id: String,
    pub app_name: String,
    pub image: String,
    pub status: String,
    pub tty: bool,
}

/// Attestation payload sent during Noise handshake.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationPayload {
    pub attestation_type: String,
    pub vm_name: String,
    pub noise_static_pubkey_hash_hex: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tdx_quote_b64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
}

/// Bootstrap config for registration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapConfig {
    pub agent_id: String,
    pub owner: String,
    pub tunnel_token: String,
    pub hostname: String,
    pub lease_ttl_secs: u64,
    pub register_epoch: u64,
    /// Ed25519 public key (base64) for verifying register-issued JWTs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_public_key: Option<String>,
    /// Register hostname for auth redirects (e.g. "https://app-staging.devopsdefender.com").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_issuer: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub owner: String,
    pub vm_name: String,
    pub agent_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaseRenewRequest {
    pub agent_id: String,
    pub register_epoch: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaseRenewResponse {
    pub ok: bool,
    pub lease_ttl_secs: u64,
    pub register_epoch: u64,
    #[serde(default)]
    pub revoked: bool,
}

// ── Wire helpers ─────────────────────────────────────────────────────────

pub async fn send_msg(stream: &mut TcpStream, data: &[u8]) -> Result<(), String> {
    let len = data.len() as u32;
    stream
        .write_all(&len.to_be_bytes())
        .await
        .map_err(|e| format!("send length: {e}"))?;
    stream
        .write_all(data)
        .await
        .map_err(|e| format!("send payload: {e}"))?;
    Ok(())
}

pub async fn recv_msg(stream: &mut TcpStream) -> Result<Vec<u8>, String> {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| format!("recv length: {e}"))?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_MSG_LEN {
        return Err(format!("message too large: {len}"));
    }
    let mut buf = vec![0u8; len];
    stream
        .read_exact(&mut buf)
        .await
        .map_err(|e| format!("recv payload: {e}"))?;
    Ok(buf)
}

pub fn generate_keypair() -> Result<snow::Keypair, String> {
    let builder = Builder::new(NOISE_PATTERN.parse().unwrap());
    builder
        .generate_keypair()
        .map_err(|e| format!("keypair generation failed: {e}"))
}

pub fn build_attestation_payload(
    vm_name: &str,
    owner: Option<&str>,
    backend: &dyn crate::attestation::AttestationBackend,
    noise_static_public_key: &[u8],
) -> AttestationPayload {
    let report_data = crate::attestation::report_data_for_noise_static(noise_static_public_key);
    AttestationPayload {
        attestation_type: backend.attestation_type().to_string(),
        vm_name: vm_name.to_string(),
        noise_static_pubkey_hash_hex: crate::attestation::noise_static_pubkey_hash_hex(
            noise_static_public_key,
        ),
        tdx_quote_b64: backend.generate_quote_b64_with_report_data(&report_data),
        owner: owner.map(|value| value.to_string()),
    }
}

pub fn verify_remote_attestation(
    payload: &AttestationPayload,
    remote_static_public_key: &[u8],
) -> Result<(), String> {
    let expected_hash = crate::attestation::noise_static_pubkey_hash_hex(remote_static_public_key);
    if payload.noise_static_pubkey_hash_hex != expected_hash {
        return Err("attestation payload hash does not match Noise static key".into());
    }

    match payload.attestation_type.as_str() {
        "tdx" => {
            let quote = payload
                .tdx_quote_b64
                .as_deref()
                .ok_or_else(|| "missing TDX quote in attestation payload".to_string())?;
            crate::attestation::verify_quote_binds_noise_static(quote, remote_static_public_key)
        }
        other => Err(format!(
            "unsupported Noise attestation type '{other}' for required attestation"
        )),
    }
}

// ── Transport: encrypt/decrypt over an established Noise session ─────────

/// Send a NoiseMessage over an established transport.
async fn send_encrypted(
    stream: &mut TcpStream,
    transport: &mut snow::TransportState,
    msg: &NoiseMessage,
) -> Result<(), String> {
    let json = serde_json::to_vec(msg).unwrap();
    let mut buf = vec![0u8; MAX_MSG_LEN];
    let len = transport
        .write_message(&json, &mut buf)
        .map_err(|e| format!("encrypt: {e}"))?;
    send_msg(stream, &buf[..len]).await
}

/// Receive and decrypt a NoiseMessage from an established transport.
async fn recv_encrypted(
    stream: &mut TcpStream,
    transport: &mut snow::TransportState,
) -> Result<NoiseMessage, String> {
    let enc = recv_msg(stream).await?;
    let mut buf = vec![0u8; MAX_MSG_LEN];
    let len = transport
        .read_message(&enc, &mut buf)
        .map_err(|e| format!("decrypt: {e}"))?;
    serde_json::from_slice(&buf[..len]).map_err(|e| format!("parse message: {e}"))
}

// ── CLI-side: send a single command (backward compat) ────────────────────

/// Open a session, send one command, get response, close.
pub async fn send_command(
    agent_addr: &str,
    private_key: &[u8],
    command: &NoiseMessage,
) -> Result<(AttestationPayload, NoiseMessage), String> {
    let mut stream = TcpStream::connect(agent_addr)
        .await
        .map_err(|e| format!("connect to {agent_addr}: {e}"))?;

    let mut noise = Builder::new(NOISE_PATTERN.parse().unwrap())
        .local_private_key(private_key)
        .map_err(|e| format!("set key: {e}"))?
        .build_initiator()
        .map_err(|e| format!("build initiator: {e}"))?;

    let mut buf = vec![0u8; MAX_MSG_LEN];

    // XX handshake
    let mut msg1_buf = vec![0u8; MAX_MSG_LEN];
    let msg1_len = noise
        .write_message(&[], &mut msg1_buf)
        .map_err(|e| format!("msg1: {e}"))?;
    send_msg(&mut stream, &msg1_buf[..msg1_len]).await?;

    let msg2 = recv_msg(&mut stream).await?;
    let payload_len = noise
        .read_message(&msg2, &mut buf)
        .map_err(|e| format!("msg2: {e}"))?;
    let attestation: AttestationPayload =
        serde_json::from_slice(&buf[..payload_len]).map_err(|e| format!("attestation: {e}"))?;
    let remote_static = noise
        .get_remote_static()
        .ok_or_else(|| "noise responder static key missing after msg2".to_string())?;
    verify_remote_attestation(&attestation, remote_static)?;

    let mut msg3_buf = vec![0u8; MAX_MSG_LEN];
    let msg3_len = noise
        .write_message(&[], &mut msg3_buf)
        .map_err(|e| format!("msg3: {e}"))?;
    send_msg(&mut stream, &msg3_buf[..msg3_len]).await?;

    let mut transport = noise
        .into_transport_mode()
        .map_err(|e| format!("transport: {e}"))?;

    // Send command, get response
    send_encrypted(&mut stream, &mut transport, command).await?;
    let response = recv_encrypted(&mut stream, &mut transport).await?;

    // Send exit
    let _ = send_encrypted(&mut stream, &mut transport, &NoiseMessage::Exit).await;

    Ok((attestation, response))
}
