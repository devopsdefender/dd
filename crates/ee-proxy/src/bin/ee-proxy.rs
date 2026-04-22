//! ee-proxy CLI entry.
//!
//! Example:
//!
//! ```sh
//! ee-proxy \
//!   --port 7682 \
//!   --ee-socket /var/lib/easyenclave/agent.sock \
//!   --trust-file /run/ee-proxy/trusted-devices.json \
//!   --key-file /run/ee-proxy/noise.key
//! ```
//!
//! `EE_TOKEN` is read once from the environment (supplied by EE when
//! the workload was spawned with `inherit_token: true`).

use std::env;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};

use ee_proxy::{attest, trust, upstream, State};

struct Args {
    port: u16,
    ee_socket: PathBuf,
    trust_file: PathBuf,
    key_file: PathBuf,
}

fn parse_args() -> Result<Args> {
    let mut port: u16 = 7682;
    let mut ee_socket = PathBuf::from("/var/lib/easyenclave/agent.sock");
    let mut trust_file = PathBuf::from("/run/ee-proxy/trusted-devices.json");
    let mut key_file = PathBuf::from("/run/ee-proxy/noise.key");

    let mut it = env::args().skip(1);
    while let Some(flag) = it.next() {
        let take = |it: &mut dyn Iterator<Item = String>| {
            it.next()
                .with_context(|| format!("missing value for {flag}"))
        };
        match flag.as_str() {
            "--port" => port = take(&mut it)?.parse().context("--port")?,
            "--ee-socket" => ee_socket = take(&mut it)?.into(),
            "--trust-file" => trust_file = take(&mut it)?.into(),
            "--key-file" => key_file = take(&mut it)?.into(),
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            other => anyhow::bail!("unknown flag: {other}"),
        }
    }

    Ok(Args {
        port,
        ee_socket,
        trust_file,
        key_file,
    })
}

fn print_help() {
    eprintln!(
        "ee-proxy — Noise_IK + ITA-attested proxy for easyenclave's agent socket.\n\
         \n\
         Flags:\n\
           --port <u16>           listen port (default 7682)\n\
           --ee-socket <path>     upstream EE agent socket\n\
           --trust-file <path>    JSON file listing trusted device pubkeys\n\
           --key-file <path>      where to persist the Noise static key (per-boot)\n\
         \n\
         Env:\n\
           EE_TOKEN               injected by EE via inherit_token; forwarded server-side"
    );
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = parse_args()?;

    let ee_token = env::var("EE_TOKEN").ok();
    if ee_token.is_none() {
        eprintln!("ee-proxy: warning — EE_TOKEN not set; upstream requests will omit the token");
    }

    let attestor = Arc::new(attest::Attestor::load_or_mint(&args.key_file).await?);
    let trust = trust::TrustStore::load_and_watch(&args.trust_file).await?;
    let upstream = Arc::new(upstream::EeAgent::new(args.ee_socket.clone(), ee_token));

    let state = State {
        attest: attestor.clone(),
        trust,
        upstream,
    };

    let app = ee_proxy::router(state);

    let addr = format!("0.0.0.0:{}", args.port);
    eprintln!(
        "ee-proxy: listening on {addr} (noise_pubkey={})",
        hex::encode(attestor.public_key())
    );

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
