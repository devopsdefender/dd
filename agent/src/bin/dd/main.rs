use clap::{Parser, Subcommand};
use futures_util::{SinkExt, StreamExt};
use std::io::{BufRead, Write};
use tokio_tungstenite::tungstenite;

use dd_agent::noise::{self, NoiseMessage};

#[derive(Parser)]
#[command(name = "dd", version, about = "DevOps Defender CLI")]
struct Cli {
    #[command(subcommand)]
    command: CliCommand,
}

#[derive(Subcommand)]
enum CliCommand {
    /// Open an interactive shell session (persistent Noise over WebSocket).
    Connect {
        #[arg(long)]
        to: String,
    },
    /// Deploy a container (single Noise command over WebSocket).
    Deploy {
        #[arg(long)]
        to: String,
        #[arg(long)]
        image: String,
        #[arg(long)]
        app_name: Option<String>,
        #[arg(long = "env", short = 'e')]
        env_vars: Vec<String>,
        #[arg(long)]
        cmd: Vec<String>,
        #[arg(long)]
        tty: bool,
    },
    /// Stop a job.
    Stop {
        #[arg(long)]
        to: String,
        #[arg(long)]
        id: String,
    },
    /// List all jobs.
    Jobs {
        #[arg(long)]
        to: String,
    },
    /// Check agent health (HTTP).
    Health {
        #[arg(long)]
        to: String,
    },
    /// List deployments (HTTP).
    Ls {
        #[arg(long)]
        to: String,
    },
    /// Get deployment logs (HTTP).
    Logs {
        #[arg(long)]
        to: String,
        #[arg(long)]
        id: String,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let result = match cli.command {
        CliCommand::Connect { to } => cmd_connect(&to).await,
        CliCommand::Deploy {
            to,
            image,
            app_name,
            env_vars,
            cmd,
            tty,
        } => {
            cmd_noise(
                &to,
                &NoiseMessage::Deploy {
                    image,
                    app_name,
                    env: if env_vars.is_empty() {
                        None
                    } else {
                        Some(env_vars)
                    },
                    cmd: if cmd.is_empty() { None } else { Some(cmd) },
                    tty,
                },
            )
            .await
        }
        CliCommand::Stop { to, id } => cmd_noise(&to, &NoiseMessage::Stop { id }).await,
        CliCommand::Jobs { to } => cmd_noise(&to, &NoiseMessage::Jobs).await,
        CliCommand::Health { to } => cmd_health(&to).await,
        CliCommand::Ls { to } => cmd_ls(&to).await,
        CliCommand::Logs { to, id } => cmd_logs(&to, &id).await,
    };
    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

// ── WebSocket + Noise helpers ────────────────────────────────────────────

fn noise_ws_url(host: &str) -> String {
    let base = host.trim_end_matches('/');
    if base.starts_with("ws://") || base.starts_with("wss://") {
        format!("{base}/noise/cmd")
    } else if base.contains("localhost") || base.contains("127.0.0.1") {
        format!("ws://{base}/noise/cmd")
    } else {
        format!("wss://{base}/noise/cmd")
    }
}

struct NoiseWsSession {
    ws_tx: futures_util::stream::SplitSink<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        tungstenite::Message,
    >,
    ws_rx: futures_util::stream::SplitStream<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    >,
    transport: snow::TransportState,
}

impl NoiseWsSession {
    async fn connect(host: &str) -> Result<(Self, serde_json::Value), String> {
        let url = noise_ws_url(host);
        let (ws, _) = tokio_tungstenite::connect_async(&url)
            .await
            .map_err(|e| format!("connect {url}: {e}"))?;

        let (mut ws_tx, mut ws_rx) = ws.split();

        let keypair = noise::generate_keypair()?;
        let mut noise = snow::Builder::new(noise::NOISE_PATTERN.parse().unwrap())
            .local_private_key(&keypair.private)
            .map_err(|e| format!("key: {e}"))?
            .build_initiator()
            .map_err(|e| format!("initiator: {e}"))?;

        let mut buf = vec![0u8; 65535];

        // msg1
        let mut msg1 = vec![0u8; 65535];
        let len = noise
            .write_message(&[], &mut msg1)
            .map_err(|e| format!("msg1: {e}"))?;
        ws_tx
            .send(tungstenite::Message::Binary(msg1[..len].to_vec()))
            .await
            .map_err(|e| format!("send: {e}"))?;

        // msg2 (attestation)
        let msg2 = match ws_rx.next().await {
            Some(Ok(tungstenite::Message::Binary(d))) => d.to_vec(),
            other => return Err(format!("expected msg2: {other:?}")),
        };
        let att_len = noise
            .read_message(&msg2, &mut buf)
            .map_err(|e| format!("msg2: {e}"))?;
        let attestation: serde_json::Value =
            serde_json::from_slice(&buf[..att_len]).unwrap_or_default();

        // msg3
        let mut msg3 = vec![0u8; 65535];
        let len = noise
            .write_message(&[], &mut msg3)
            .map_err(|e| format!("msg3: {e}"))?;
        ws_tx
            .send(tungstenite::Message::Binary(msg3[..len].to_vec()))
            .await
            .map_err(|e| format!("send: {e}"))?;

        let transport = noise
            .into_transport_mode()
            .map_err(|e| format!("transport: {e}"))?;

        Ok((
            Self {
                ws_tx,
                ws_rx,
                transport,
            },
            attestation,
        ))
    }

    async fn send(&mut self, msg: &NoiseMessage) -> Result<(), String> {
        let json = serde_json::to_vec(msg).unwrap();
        let mut enc = vec![0u8; 65535];
        let len = self
            .transport
            .write_message(&json, &mut enc)
            .map_err(|e| format!("encrypt: {e}"))?;
        self.ws_tx
            .send(tungstenite::Message::Binary(enc[..len].to_vec()))
            .await
            .map_err(|e| format!("send: {e}"))
    }

    async fn recv(&mut self) -> Result<NoiseMessage, String> {
        let data = match self.ws_rx.next().await {
            Some(Ok(tungstenite::Message::Binary(d))) => d.to_vec(),
            Some(Ok(tungstenite::Message::Close(_))) | None => {
                return Err("connection closed".into())
            }
            other => return Err(format!("unexpected: {other:?}")),
        };
        let mut dec = vec![0u8; 65535];
        let len = self
            .transport
            .read_message(&data, &mut dec)
            .map_err(|e| format!("decrypt: {e}"))?;
        serde_json::from_slice(&dec[..len]).map_err(|e| format!("parse: {e}"))
    }
}

// ── Single-command via WebSocket ─────────────────────────────────────────

async fn cmd_noise(to: &str, command: &NoiseMessage) -> Result<(), String> {
    let (mut session, attestation) = NoiseWsSession::connect(to).await?;
    eprintln!(
        "agent: {} (attestation: {})",
        attestation["vm_name"].as_str().unwrap_or("?"),
        attestation["attestation_type"].as_str().unwrap_or("?")
    );
    session.send(command).await?;
    let response = session.recv().await?;
    let _ = session.send(&NoiseMessage::Exit).await;
    print_response(&response);
    if matches!(&response, NoiseMessage::Error { .. }) {
        std::process::exit(1);
    }
    Ok(())
}

// ── Interactive shell via WebSocket ──────────────────────────────────────

async fn cmd_connect(to: &str) -> Result<(), String> {
    let (mut session, attestation) = NoiseWsSession::connect(to).await?;
    eprintln!(
        "agent: {} (attestation: {})",
        attestation["vm_name"].as_str().unwrap_or("?"),
        attestation["attestation_type"].as_str().unwrap_or("?")
    );
    eprintln!("connected. type 'help' for commands, 'exit' to quit.");

    let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(16);

    // Stdin reader
    std::thread::spawn(move || {
        let stdin = std::io::stdin();
        let mut line = String::new();
        loop {
            line.clear();
            print!("dd> ");
            std::io::stdout().flush().ok();
            match stdin.lock().read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    if tx.blocking_send(line.trim().to_string()).is_err() {
                        break;
                    }
                }
            }
        }
    });

    let mut fg_mode = false;

    loop {
        tokio::select! {
            Some(line) = rx.recv() => {
                if fg_mode {
                    if line == "~." || line == "bg" {
                        session.send(&NoiseMessage::Bg).await?;
                        let resp = session.recv().await?;
                        print_response(&resp);
                        fg_mode = false;
                        continue;
                    }
                    session.send(&NoiseMessage::Stdin { data: format!("{line}\n").into_bytes() }).await?;
                    continue;
                }

                if line.is_empty() { continue; }
                let parts: Vec<&str> = line.splitn(2, ' ').collect();
                let cmd = parts[0];
                let arg = parts.get(1).unwrap_or(&"").to_string();

                match cmd {
                    "help" => {
                        eprintln!("commands: deploy <image> [--tty], stop <id>, jobs, fg <id>, bg, logs <id>, exit");
                        continue;
                    }
                    "exit" | "quit" => {
                        let _ = session.send(&NoiseMessage::Exit).await;
                        break;
                    }
                    "fg" => {
                        session.send(&NoiseMessage::Fg { id: arg.clone() }).await?;
                        let resp = session.recv().await?;
                        if matches!(&resp, NoiseMessage::Ok { status, .. } if status.as_deref() == Some("attached")) {
                            eprintln!("attached to {arg}. type 'bg' or '~.' to detach.");
                            fg_mode = true;
                        } else {
                            print_response(&resp);
                        }
                        continue;
                    }
                    _ => {}
                }

                let msg = match cmd {
                    "jobs" => NoiseMessage::Jobs,
                    "stop" => NoiseMessage::Stop { id: arg },
                    "logs" => NoiseMessage::Logs { id: arg },
                    "deploy" => {
                        let (image, tty) = if arg.contains("--tty") {
                            (arg.replace("--tty", "").trim().to_string(), true)
                        } else {
                            (arg, false)
                        };
                        let app_name = image.split(':').next().and_then(|s| s.rsplit('/').next()).map(|s| s.to_string());
                        NoiseMessage::Deploy { image, app_name, env: None, cmd: None, tty }
                    }
                    _ => {
                        eprintln!("unknown command: {cmd}. type 'help'.");
                        continue;
                    }
                };

                session.send(&msg).await?;
                let resp = session.recv().await?;
                print_response(&resp);
            }
            result = session.recv() => {
                match result {
                    Ok(NoiseMessage::Stdout { data }) => {
                        print!("{}", String::from_utf8_lossy(&data));
                        std::io::stdout().flush().ok();
                    }
                    Ok(NoiseMessage::Stderr { data }) => {
                        eprint!("{}", String::from_utf8_lossy(&data));
                    }
                    Ok(msg) => print_response(&msg),
                    Err(_) => {
                        eprintln!("\nconnection closed");
                        break;
                    }
                }
            }
        }
    }
    Ok(())
}

fn print_response(msg: &NoiseMessage) {
    match msg {
        NoiseMessage::Ok {
            id,
            status,
            message,
            ..
        } => {
            let parts: Vec<String> = [
                id.as_ref().map(|v| format!("id={v}")),
                status.as_ref().map(|v| format!("status={v}")),
                message.clone(),
            ]
            .into_iter()
            .flatten()
            .collect();
            println!("{}", parts.join(" "));
        }
        NoiseMessage::Error { message } => eprintln!("error: {message}"),
        NoiseMessage::JobList { jobs } => {
            if jobs.is_empty() {
                println!("no jobs");
            } else {
                for (i, job) in jobs.iter().enumerate() {
                    println!(
                        "  [{}] {:<20} {:<12} {}{}",
                        i + 1,
                        job.app_name,
                        job.status,
                        job.image,
                        if job.tty { " (tty)" } else { "" }
                    );
                }
            }
        }
        NoiseMessage::Stdout { data } => {
            print!("{}", String::from_utf8_lossy(data));
            std::io::stdout().flush().ok();
        }
        other => println!("{}", serde_json::to_string_pretty(other).unwrap()),
    }
}

// ── HTTP commands ────────────────────────────────────────────────────────

fn github_token() -> Option<String> {
    std::env::var("DD_GITHUB_TOKEN")
        .ok()
        .or_else(|| std::env::var("GITHUB_TOKEN").ok())
}

fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(false)
        .build()
        .expect("http client")
}

fn ensure_https(host: &str) -> String {
    if host.starts_with("http://") || host.starts_with("https://") {
        host.to_string()
    } else {
        format!("https://{host}")
    }
}

async fn cmd_health(to: &str) -> Result<(), String> {
    let resp = http_client()
        .get(format!("{}/health", ensure_https(to)))
        .send()
        .await
        .map_err(|e| format!("{e}"))?;
    if !resp.status().is_success() {
        return Err(format!("status {}", resp.status()));
    }
    let body: serde_json::Value = resp.json().await.map_err(|e| format!("{e}"))?;
    println!("{}", serde_json::to_string_pretty(&body).unwrap());
    Ok(())
}

async fn cmd_ls(to: &str) -> Result<(), String> {
    let token = github_token().ok_or("DD_GITHUB_TOKEN or GITHUB_TOKEN not set")?;
    let resp = http_client()
        .get(format!("{}/deployments", ensure_https(to)))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .map_err(|e| format!("{e}"))?;
    if !resp.status().is_success() {
        return Err(format!("status {}", resp.status()));
    }
    let body: serde_json::Value = resp.json().await.map_err(|e| format!("{e}"))?;
    if let Some(deps) = body.as_array() {
        if deps.is_empty() {
            println!("no deployments");
            return Ok(());
        }
        for dep in deps {
            println!(
                "{}\t{}\t{}\t{}",
                dep["id"].as_str().unwrap_or("-"),
                dep["app_name"].as_str().unwrap_or("-"),
                dep["image"].as_str().unwrap_or("-"),
                dep["status"].as_str().unwrap_or("-")
            );
        }
    }
    Ok(())
}

async fn cmd_logs(to: &str, id: &str) -> Result<(), String> {
    let token = github_token().ok_or("DD_GITHUB_TOKEN or GITHUB_TOKEN not set")?;
    let resp = http_client()
        .get(format!("{}/deployments/{id}/logs", ensure_https(to)))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .map_err(|e| format!("{e}"))?;
    if !resp.status().is_success() {
        return Err(format!("status {}", resp.status()));
    }
    let body: serde_json::Value = resp.json().await.map_err(|e| format!("{e}"))?;
    if let Some(logs) = body["logs"].as_array() {
        for line in logs {
            println!("{}", line.as_str().unwrap_or(""));
        }
    }
    Ok(())
}
