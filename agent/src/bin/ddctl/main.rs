use std::env;
use std::time::{Duration, Instant};

use dd_agent::local_control::{
    socket_path_from_env, LocalControlRequest, LocalControlResponse, LocalDeployRequest,
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        usage(1);
    }

    let (socket_path, args) = parse_socket_flag(args);
    if args.is_empty() {
        usage(1);
    }

    let command = &args[0];
    let result = match command.as_str() {
        "status" => cmd_status(&socket_path, &args[1..]).await,
        "wait-ready" => cmd_wait_ready(&socket_path, &args[1..]).await,
        "list" => cmd_list(&socket_path, &args[1..]).await,
        "spawn" => cmd_spawn(&socket_path, &args[1..]).await,
        "stop" => cmd_stop(&socket_path, &args[1..]).await,
        _ => {
            eprintln!("ddctl: unknown command: {command}");
            usage(1);
        }
    };

    if let Err(error) = result {
        eprintln!("ddctl: {error}");
        std::process::exit(1);
    }
}

fn parse_socket_flag(args: Vec<String>) -> (String, Vec<String>) {
    let mut socket_path = socket_path_from_env();
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--socket" {
            if i + 1 >= args.len() {
                eprintln!("ddctl: --socket requires a path");
                usage(1);
            }
            socket_path = args[i + 1].clone();
            i += 2;
        } else {
            out.push(args[i].clone());
            i += 1;
        }
    }
    (socket_path, out)
}

async fn cmd_status(socket_path: &str, args: &[String]) -> Result<(), String> {
    let json = args.iter().any(|arg| arg == "--json");
    match round_trip(socket_path, &LocalControlRequest::Status).await? {
        LocalControlResponse::Status { status } => {
            if json {
                println!("{}", serde_json::to_string_pretty(&status).unwrap());
            } else {
                println!("mode: {}", status.mode);
                println!("vm: {}", status.vm_name);
                println!("agent_id: {}", status.agent_id);
                println!("ready: {}", status.ready);
                println!("register_mode: {}", status.register_mode);
                println!("socket: {}", status.socket_path);
                println!("deployments: {}", status.deployment_count);
            }
            Ok(())
        }
        LocalControlResponse::Error { message } => Err(message),
        other => Err(format!("unexpected response: {other:?}")),
    }
}

async fn cmd_wait_ready(socket_path: &str, args: &[String]) -> Result<(), String> {
    let mut timeout_secs = 60u64;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--timeout" => {
                if i + 1 >= args.len() {
                    return Err("--timeout requires seconds".into());
                }
                timeout_secs = args[i + 1]
                    .parse::<u64>()
                    .map_err(|_| "invalid --timeout".to_string())?;
                i += 2;
            }
            other => return Err(format!("unknown wait-ready arg: {other}")),
        }
    }

    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        match round_trip(socket_path, &LocalControlRequest::Status).await {
            Ok(LocalControlResponse::Status { status }) if status.ready => {
                println!("ready");
                return Ok(());
            }
            Ok(LocalControlResponse::Error { message }) => {
                if Instant::now() >= deadline {
                    return Err(message);
                }
            }
            Ok(_) | Err(_) if Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Ok(other) => return Err(format!("unexpected response: {other:?}")),
            Err(error) => return Err(error),
        }
    }
}

async fn cmd_list(socket_path: &str, args: &[String]) -> Result<(), String> {
    let json = args.iter().any(|arg| arg == "--json");
    match round_trip(socket_path, &LocalControlRequest::List).await? {
        LocalControlResponse::Deployments { deployments } => {
            if json {
                println!("{}", serde_json::to_string_pretty(&deployments).unwrap());
            } else if deployments.is_empty() {
                println!("no deployments");
            } else {
                for deployment in deployments {
                    println!(
                        "{}\t{}\t{}\t{}",
                        deployment.id, deployment.app_name, deployment.status, deployment.image
                    );
                }
            }
            Ok(())
        }
        LocalControlResponse::Error { message } => Err(message),
        other => Err(format!("unexpected response: {other:?}")),
    }
}

async fn cmd_spawn(socket_path: &str, args: &[String]) -> Result<(), String> {
    let request = parse_spawn_request(args)?;
    match round_trip(socket_path, &LocalControlRequest::Spawn { request }).await? {
        LocalControlResponse::Spawned { id, status } => {
            println!("{id}\t{status}");
            Ok(())
        }
        LocalControlResponse::Error { message } => Err(message),
        other => Err(format!("unexpected response: {other:?}")),
    }
}

fn parse_spawn_request(args: &[String]) -> Result<LocalDeployRequest, String> {
    let mut request = LocalDeployRequest::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--app-name" => {
                if i + 1 >= args.len() {
                    return Err("--app-name requires a value".into());
                }
                request.app_name = Some(args[i + 1].clone());
                i += 2;
            }
            "--image" => {
                if i + 1 >= args.len() {
                    return Err("--image requires a value".into());
                }
                request.image = Some(args[i + 1].clone());
                i += 2;
            }
            "--env" => {
                if i + 1 >= args.len() {
                    return Err("--env requires KEY=VALUE".into());
                }
                request.env.push(args[i + 1].clone());
                i += 2;
            }
            "--volume" => {
                if i + 1 >= args.len() {
                    return Err("--volume requires a value".into());
                }
                request.volumes.push(args[i + 1].clone());
                i += 2;
            }
            "--tty" => {
                request.tty = true;
                i += 1;
            }
            "--cmd" => {
                if i + 1 >= args.len() {
                    return Err("--cmd requires at least one token".into());
                }
                request.cmd = args[i + 1..].to_vec();
                break;
            }
            other => return Err(format!("unknown spawn arg: {other}")),
        }
    }

    let has_image = request.image.is_some();
    let has_cmd = !request.cmd.is_empty();
    if has_image == has_cmd {
        return Err("spawn requires exactly one of --image or --cmd".into());
    }

    Ok(request)
}

async fn cmd_stop(socket_path: &str, args: &[String]) -> Result<(), String> {
    let mut id = None;
    let mut app_name = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--id" => {
                if i + 1 >= args.len() {
                    return Err("--id requires a value".into());
                }
                id = Some(args[i + 1].clone());
                i += 2;
            }
            "--app-name" => {
                if i + 1 >= args.len() {
                    return Err("--app-name requires a value".into());
                }
                app_name = Some(args[i + 1].clone());
                i += 2;
            }
            other => return Err(format!("unknown stop arg: {other}")),
        }
    }

    match round_trip(socket_path, &LocalControlRequest::Stop { id, app_name }).await? {
        LocalControlResponse::Stopped { ids } => {
            for id in ids {
                println!("{id}");
            }
            Ok(())
        }
        LocalControlResponse::Error { message } => Err(message),
        other => Err(format!("unexpected response: {other:?}")),
    }
}

async fn round_trip(
    socket_path: &str,
    request: &LocalControlRequest,
) -> Result<LocalControlResponse, String> {
    let mut stream = UnixStream::connect(socket_path)
        .await
        .map_err(|e| format!("connect {socket_path}: {e}"))?;

    let payload = serde_json::to_vec(request).map_err(|e| format!("encode request: {e}"))?;
    stream
        .write_all(&payload)
        .await
        .map_err(|e| format!("write request: {e}"))?;
    stream
        .write_all(b"\n")
        .await
        .map_err(|e| format!("write request newline: {e}"))?;
    stream
        .flush()
        .await
        .map_err(|e| format!("flush request: {e}"))?;

    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    let read = reader
        .read_line(&mut line)
        .await
        .map_err(|e| format!("read response: {e}"))?;
    if read == 0 {
        return Err("empty response".into());
    }

    serde_json::from_str(line.trim()).map_err(|e| format!("parse response: {e}"))
}

fn usage(code: i32) -> ! {
    eprintln!(
        "usage:
  ddctl [--socket PATH] status [--json]
  ddctl [--socket PATH] wait-ready [--timeout SECONDS]
  ddctl [--socket PATH] list [--json]
  ddctl [--socket PATH] spawn --app-name NAME (--image IMAGE | --cmd CMD [ARGS...]) [--env KEY=VALUE]... [--volume SPEC]... [--tty]
  ddctl [--socket PATH] stop (--id ID | --app-name NAME)"
    );
    std::process::exit(code);
}
