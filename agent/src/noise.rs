//! Noise protocol — the agent's shell interface.
//!
//! Persistent sessions over Noise_XX_25519_ChaChaPoly_SHA256.
//! One session = one shell. Jobs run in background or foreground.
//! Wire format: `[u32 big-endian length][payload]`.

use serde::{Deserialize, Serialize};
use snow::Builder;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

use crate::server::Deployments;

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
        cmd: Vec<String>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tdx_quote_b64: Option<String>,
}

/// Bootstrap config for registration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapConfig {
    pub owner: String,
    pub tunnel_token: String,
    pub hostname: String,
    /// Ed25519 public key (base64) for verifying register-issued JWTs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_public_key: Option<String>,
    /// Register hostname for auth redirects (e.g. "https://app-staging.devopsdefender.com").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_issuer: Option<String>,
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

// ── Agent-side: persistent session server ────────────────────────────────

/// Handle one persistent shell session from a client.
async fn handle_session(
    mut stream: TcpStream,
    private_key: &[u8],
    attestation: &AttestationPayload,
    deployments: &Deployments,
) -> Option<BootstrapConfig> {
    let mut noise = match Builder::new(NOISE_PATTERN.parse().unwrap())
        .local_private_key(private_key)
        .and_then(|b| b.build_responder())
    {
        Ok(n) => n,
        Err(e) => {
            eprintln!("dd-agent: noise setup: {e}");
            return None;
        }
    };

    let mut buf = vec![0u8; MAX_MSG_LEN];

    // XX handshake: read msg1 → write msg2 (attestation) → read msg3
    let msg1 = recv_msg(&mut stream).await.ok()?;
    noise.read_message(&msg1, &mut buf).ok()?;

    let attestation_json = serde_json::to_vec(attestation).unwrap();
    let mut msg2_buf = vec![0u8; MAX_MSG_LEN];
    let msg2_len = noise.write_message(&attestation_json, &mut msg2_buf).ok()?;
    send_msg(&mut stream, &msg2_buf[..msg2_len]).await.ok()?;

    let msg3 = recv_msg(&mut stream).await.ok()?;
    noise.read_message(&msg3, &mut buf).ok()?;

    let mut transport = noise.into_transport_mode().ok()?;

    eprintln!("dd-agent: Noise session established");

    // Channel for container stdout → client (used when fg'd)
    let (container_tx, mut container_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);

    let mut bootstrap_result = None;
    let mut fg_task: Option<tokio::task::JoinHandle<()>> = None;
    let mut fg_input: Option<std::pin::Pin<Box<dyn tokio::io::AsyncWrite + Send>>> = None;

    loop {
        tokio::select! {
            // Container output → send to client as Stdout
            Some(data) = container_rx.recv() => {
                let msg = NoiseMessage::Stdout { data };
                if send_encrypted(&mut stream, &mut transport, &msg).await.is_err() {
                    break;
                }
            }
            // Client message
            result = recv_encrypted(&mut stream, &mut transport) => {
                let msg = match result {
                    Ok(m) => m,
                    Err(e) => {
                        eprintln!("dd-agent: session recv: {e}");
                        break;
                    }
                };

                let response = match msg {
                    NoiseMessage::Stdin { data } => {
                        // Forward to foreground container's stdin
                        if let Some(ref mut input) = fg_input {
                            let _ = input.write_all(&data).await;
                            let _ = input.flush().await;
                        }
                        continue; // no response needed for stdin
                    }
                    NoiseMessage::Fg { id } => {
                        // Detach current fg if any
                        if let Some(task) = fg_task.take() {
                            task.abort();
                        }
                        fg_input = None;

                        // Find process PID and tail its log
                        let pid = {
                            let deps = deployments.lock().await;
                            deps.get(&id).and_then(|d| d.pid)
                        };

                        match pid {
                            Some(pid) => {
                                let log_path = format!("/var/lib/dd/workloads/logs/{pid}.log");
                                match tokio::fs::File::open(&log_path).await {
                                    Ok(file) => {
                                        let tx = container_tx.clone();
                                        fg_task = Some(tokio::spawn(async move {
                                            let mut reader = BufReader::new(file).lines();
                                            loop {
                                                match reader.next_line().await {
                                                    Ok(Some(line)) => {
                                                        if tx.send(format!("{line}\n").into_bytes()).await.is_err() {
                                                            break;
                                                        }
                                                    }
                                                    Ok(None) => {
                                                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                                                    }
                                                    Err(_) => break,
                                                }
                                            }
                                        }));
                                        NoiseMessage::Ok {
                                            id: Some(id),
                                            status: Some("attached".into()),
                                            message: None,
                                        }
                                    }
                                    Err(e) => NoiseMessage::Error {
                                        message: format!("open log: {e}"),
                                    },
                                }
                            }
                            None => NoiseMessage::Error {
                                message: "job not found or not running".into(),
                            },
                        }
                    }
                    NoiseMessage::Bg => {
                        if let Some(task) = fg_task.take() {
                            task.abort();
                        }
                        fg_input = None;
                        NoiseMessage::Ok {
                            id: None,
                            status: Some("detached".into()),
                            message: None,
                        }
                    }
                    NoiseMessage::Deploy { cmd, app_name, env, tty } => {
                        let req = crate::server::DeployRequest {
                            cmd, env,
                            app_name: app_name.clone(),
                            app_version: None, tty,
                        };
                        let (id, status) = crate::server::execute_deploy(deployments, req).await;
                        NoiseMessage::Ok {
                            id: Some(id),
                            status: Some(status),
                            message: app_name,
                        }
                    }
                    NoiseMessage::Stop { id } => {
                        match crate::server::execute_stop(deployments, &id).await {
                            Ok(()) => NoiseMessage::Ok {
                                id: Some(id), status: Some("stopped".into()), message: None,
                            },
                            Err(e) => NoiseMessage::Error { message: e },
                        }
                    }
                    NoiseMessage::Jobs => {
                        let deps = deployments.lock().await;
                        let jobs: Vec<JobInfo> = deps.values().map(|d| JobInfo {
                            id: d.id.clone(),
                            app_name: d.app_name.clone(),
                            image: d.image.clone(),
                            status: d.status.clone(),
                            tty: false,
                        }).collect();
                        NoiseMessage::JobList { jobs }
                    }
                    NoiseMessage::Logs { id } => {
                        let pid = {
                            let deps = deployments.lock().await;
                            deps.get(&id).and_then(|d| d.pid)
                        };
                        match pid {
                            Some(pid) => {
                                let log_path = format!("/var/lib/dd/workloads/logs/{pid}.log");
                                let content = tokio::fs::read_to_string(&log_path).await.unwrap_or_default();
                                let tail: String = content.lines().rev().take(50).collect::<Vec<_>>().into_iter().rev().collect::<Vec<_>>().join("\n");
                                NoiseMessage::Stdout { data: tail.into_bytes() }
                            }
                            None => NoiseMessage::Error { message: "job not found".into() },
                        }
                    }
                    NoiseMessage::Bootstrap(config) => {
                        bootstrap_result = Some(config);
                        NoiseMessage::Ok { id: None, status: Some("bootstrapped".into()), message: None }
                    }
                    NoiseMessage::Exit => {
                        let _ = send_encrypted(&mut stream, &mut transport, &NoiseMessage::Ok {
                            id: None, status: Some("goodbye".into()), message: None,
                        }).await;
                        break;
                    }
                    _ => NoiseMessage::Error { message: "unexpected message type".into() },
                };

                if send_encrypted(&mut stream, &mut transport, &response).await.is_err() {
                    break;
                }
            }
        }
    }

    // Cleanup: abort fg task on session end
    if let Some(task) = fg_task {
        task.abort();
    }

    bootstrap_result
}

/// Run the Noise session server. Accepts persistent shell sessions.
pub async fn run_session_server(
    port: u16,
    private_key: &[u8],
    attestation: &AttestationPayload,
    deployments: Deployments,
    bootstrap_tx: tokio::sync::oneshot::Sender<BootstrapConfig>,
) {
    let listener = match tokio::net::TcpListener::bind(format!("0.0.0.0:{port}")).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("dd-agent: noise server bind: {e}");
            return;
        }
    };

    eprintln!("dd-agent: Noise shell server listening on port {port}");

    let mut bootstrap_tx = Some(bootstrap_tx);

    loop {
        let (stream, addr) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("dd-agent: noise accept: {e}");
                continue;
            }
        };

        eprintln!("dd-agent: session from {addr}");

        let result = handle_session(stream, private_key, attestation, &deployments).await;

        if let Some(config) = result {
            if let Some(tx) = bootstrap_tx.take() {
                let _ = tx.send(config);
            }
        }

        eprintln!("dd-agent: session from {addr} ended");
    }
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
