//! Native Noise client for operator shell sessions.
//!
//! This is intentionally small and dependency-light: it speaks the same
//! Noise_IK-over-WebSocket framing as `noise_gateway`, then sends the
//! shell/session RPCs that the gateway forwards to local `dd-sessiond`.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context};
use base64::Engine as _;
use futures_util::{SinkExt, StreamExt};
use rand::rngs::OsRng;
use serde_json::Value;
use snow::{Builder, TransportState};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};
use x25519_dalek::{PublicKey, StaticSecret};

const NOISE_PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
const MAX_NOISE_MSG: usize = 65535;
const ATTACH_CHUNK: usize = 4096;

type WsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;
type WsSink = futures_util::stream::SplitSink<WsStream, WsMessage>;
type WsRead = futures_util::stream::SplitStream<WsStream>;

pub async fn run_cli() -> anyhow::Result<()> {
    let mut args: Vec<String> = std::env::args().skip(2).collect();
    if args.is_empty() || args[0] == "-h" || args[0] == "--help" {
        print_usage();
        return Ok(());
    }

    let command = args.remove(0);
    match command.as_str() {
        "keygen" => {
            let opts = parse_opts(args)?;
            let key_path = opts.key_path();
            let secret = load_or_create_key(&key_path).await?;
            let pubkey = public_hex(&secret);
            println!("{pubkey}");
            if let Some(cp_url) = opts.cp_url.as_deref() {
                let label = opts.label.unwrap_or_else(default_label);
                println!("{}", enrollment_url(cp_url, &pubkey, &label));
            }
        }
        "pubkey" => {
            let opts = parse_opts(args)?;
            let secret = load_or_create_key(&opts.key_path()).await?;
            println!("{}", public_hex(&secret));
        }
        "recipes" => {
            let opts = parse_opts(args)?;
            let mut conn = connect(&opts).await?;
            print_json(
                conn.call(serde_json::json!({"method": "shell.list_recipes"}))
                    .await?,
            )?;
        }
        "sessions" => {
            let opts = parse_opts(args)?;
            let mut conn = connect(&opts).await?;
            print_json(
                conn.call(serde_json::json!({"method": "shell.list_sessions"}))
                    .await?,
            )?;
        }
        "create" => {
            let opts = parse_opts(args)?;
            let mut conn = connect(&opts).await?;
            let session = create_session(&mut conn, &opts).await?;
            print_json(session)?;
        }
        "replay" => {
            let opts = parse_opts(args)?;
            let id = opts
                .id
                .as_deref()
                .ok_or_else(|| anyhow!("replay requires --id"))?;
            let mut conn = connect(&opts).await?;
            print_json(
                conn.call(serde_json::json!({
                    "method": "shell.replay_session",
                    "id": id,
                }))
                .await?,
            )?;
        }
        "resize" => {
            let opts = parse_opts(args)?;
            let id = opts
                .id
                .as_deref()
                .ok_or_else(|| anyhow!("resize requires --id"))?;
            let cols = opts.cols.ok_or_else(|| anyhow!("resize requires --cols"))?;
            let rows = opts.rows.ok_or_else(|| anyhow!("resize requires --rows"))?;
            let mut conn = connect(&opts).await?;
            print_json(
                conn.call(serde_json::json!({
                    "method": "shell.resize_session",
                    "id": id,
                    "cols": cols,
                    "rows": rows,
                }))
                .await?,
            )?;
        }
        "close" => {
            let opts = parse_opts(args)?;
            let id = opts
                .id
                .as_deref()
                .ok_or_else(|| anyhow!("close requires --id"))?;
            let mut conn = connect(&opts).await?;
            print_json(
                conn.call(serde_json::json!({
                    "method": "shell.close_session",
                    "id": id,
                }))
                .await?,
            )?;
        }
        "attach" => {
            let opts = parse_opts(args)?;
            let id = opts
                .id
                .as_deref()
                .ok_or_else(|| anyhow!("attach requires --id"))?;
            let conn = connect(&opts).await?;
            attach_session(conn, id).await?;
        }
        "shell" => {
            let opts = parse_opts(args)?;
            let mut conn = connect(&opts).await?;
            let session = create_session(&mut conn, &opts).await?;
            let id = session_id(&session)?;
            attach_session(conn, &id).await?;
        }
        "exec" => {
            let (opts, cmd) = parse_exec_opts(args)?;
            let mut conn = connect(&opts).await?;
            print_json(
                conn.call(serde_json::json!({
                    "method": "exec",
                    "cmd": cmd,
                    "timeout_secs": opts.timeout_secs.unwrap_or(60),
                }))
                .await?,
            )?;
        }
        other => {
            anyhow::bail!("unknown noise command `{other}`");
        }
    }
    Ok(())
}

fn print_usage() {
    eprintln!(
        "usage:
  devopsdefender noise keygen [--key PATH] [--cp-url URL] [--label LABEL]
  devopsdefender noise pubkey [--key PATH]
  devopsdefender noise recipes --url AGENT_URL [--key PATH]
  devopsdefender noise sessions --url AGENT_URL [--key PATH]
  devopsdefender noise create --url AGENT_URL [--key PATH] [--recipe ID] [--name NAME] [--command PATH]
  devopsdefender noise replay --url AGENT_URL [--key PATH] --id SESSION_ID
  devopsdefender noise resize --url AGENT_URL [--key PATH] --id SESSION_ID --cols N --rows N
  devopsdefender noise close --url AGENT_URL [--key PATH] --id SESSION_ID
  devopsdefender noise attach --url AGENT_URL [--key PATH] --id SESSION_ID
  devopsdefender noise shell --url AGENT_URL [--key PATH] [--recipe ID] [--name NAME] [--command PATH]
  devopsdefender noise exec --url AGENT_URL [--key PATH] [--timeout SECS] -- CMD [ARG...]

Quote verification is enabled by default and uses DD_ITA_API_KEY plus optional
DD_ITA_BASE_URL, DD_ITA_JWKS_URL, and DD_ITA_ISSUER. Local dev can pass
--insecure-skip-quote-verify explicitly."
    );
}

#[derive(Default)]
struct Opts {
    url: Option<String>,
    key: Option<PathBuf>,
    cp_url: Option<String>,
    label: Option<String>,
    recipe: Option<String>,
    name: Option<String>,
    command: Option<String>,
    id: Option<String>,
    cols: Option<u64>,
    rows: Option<u64>,
    timeout_secs: Option<u64>,
    insecure_skip_quote_verify: bool,
    ita_api_key: Option<String>,
    ita_base_url: Option<String>,
    ita_jwks_url: Option<String>,
    ita_issuer: Option<String>,
}

impl Opts {
    fn key_path(&self) -> PathBuf {
        self.key
            .clone()
            .or_else(|| std::env::var_os("DD_NOISE_CLIENT_KEY").map(PathBuf::from))
            .unwrap_or_else(default_key_path)
    }

    fn agent_url(&self) -> anyhow::Result<&str> {
        self.url
            .as_deref()
            .ok_or_else(|| anyhow!("missing --url AGENT_URL"))
    }
}

fn parse_opts(args: Vec<String>) -> anyhow::Result<Opts> {
    let mut opts = Opts::default();
    let mut i = 0;
    while i < args.len() {
        let key = args[i].as_str();
        i += 1;
        let mut take = |name: &str| -> anyhow::Result<String> {
            let value = args
                .get(i)
                .cloned()
                .ok_or_else(|| anyhow!("{name} requires a value"))?;
            i += 1;
            Ok(value)
        };
        match key {
            "--url" => opts.url = Some(take("--url")?),
            "--key" => opts.key = Some(PathBuf::from(take("--key")?)),
            "--cp-url" => opts.cp_url = Some(take("--cp-url")?),
            "--label" => opts.label = Some(take("--label")?),
            "--recipe" => opts.recipe = Some(take("--recipe")?),
            "--name" => opts.name = Some(take("--name")?),
            "--command" => opts.command = Some(take("--command")?),
            "--id" => opts.id = Some(take("--id")?),
            "--cols" => opts.cols = Some(parse_u64("--cols", &take("--cols")?)?),
            "--rows" => opts.rows = Some(parse_u64("--rows", &take("--rows")?)?),
            "--timeout" => opts.timeout_secs = Some(parse_u64("--timeout", &take("--timeout")?)?),
            "--ita-api-key" => opts.ita_api_key = Some(take("--ita-api-key")?),
            "--ita-base-url" => opts.ita_base_url = Some(take("--ita-base-url")?),
            "--ita-jwks-url" => opts.ita_jwks_url = Some(take("--ita-jwks-url")?),
            "--ita-issuer" => opts.ita_issuer = Some(take("--ita-issuer")?),
            "--insecure-skip-quote-verify" => opts.insecure_skip_quote_verify = true,
            "-h" | "--help" => {
                print_usage();
                std::process::exit(0);
            }
            other => anyhow::bail!("unknown option `{other}`"),
        }
    }
    Ok(opts)
}

fn parse_exec_opts(args: Vec<String>) -> anyhow::Result<(Opts, Vec<String>)> {
    let split = args
        .iter()
        .position(|arg| arg == "--")
        .ok_or_else(|| anyhow!("exec requires `-- CMD [ARG...]`"))?;
    let opts = parse_opts(args[..split].to_vec())?;
    let cmd = args[split + 1..].to_vec();
    if cmd.is_empty() {
        anyhow::bail!("exec requires a command after `--`");
    }
    Ok((opts, cmd))
}

fn parse_u64(name: &str, value: &str) -> anyhow::Result<u64> {
    value
        .parse()
        .with_context(|| format!("{name} must be an unsigned integer"))
}

struct NoiseConnection {
    transport: TransportState,
    sink: WsSink,
    stream: WsRead,
}

impl NoiseConnection {
    async fn call(&mut self, request: Value) -> anyhow::Result<Value> {
        let plain = serde_json::to_vec(&request)?;
        send_encrypted(&mut self.transport, &mut self.sink, &plain).await?;
        let cipher = next_binary(&mut self.stream)
            .await?
            .ok_or_else(|| anyhow!("Noise websocket closed before response"))?;
        let mut out = vec![0u8; cipher.len()];
        let n = self.transport.read_message(&cipher, &mut out)?;
        out.truncate(n);
        Ok(serde_json::from_slice(&out)?)
    }
}

async fn connect(opts: &Opts) -> anyhow::Result<NoiseConnection> {
    let base_url = opts.agent_url()?;
    let secret = load_or_create_key(&opts.key_path()).await?;
    let server_pubkey = fetch_and_verify_server_pubkey(base_url, opts).await?;
    let ws_url = noise_ws_url(base_url);

    let (ws, _response) = connect_async(&ws_url)
        .await
        .with_context(|| format!("connect {ws_url}"))?;
    let (mut sink, mut stream) = ws.split();

    let mut hs = Builder::new(NOISE_PATTERN.parse()?)
        .local_private_key(secret.as_bytes())
        .remote_public_key(&server_pubkey)
        .build_initiator()?;

    let mut first = [0u8; MAX_NOISE_MSG];
    let n = hs.write_message(&[], &mut first)?;
    sink.send(WsMessage::Binary(first[..n].to_vec().into()))
        .await?;

    let second = next_binary(&mut stream)
        .await?
        .ok_or_else(|| anyhow!("Noise websocket closed during handshake"))?;
    let mut payload = [0u8; MAX_NOISE_MSG];
    hs.read_message(&second, &mut payload)?;

    Ok(NoiseConnection {
        transport: hs.into_transport_mode()?,
        sink,
        stream,
    })
}

async fn fetch_and_verify_server_pubkey(base_url: &str, opts: &Opts) -> anyhow::Result<[u8; 32]> {
    let url = health_url(base_url);
    let body: Value = reqwest::get(&url)
        .await
        .with_context(|| format!("GET {url}"))?
        .error_for_status()
        .with_context(|| format!("GET {url}"))?
        .json()
        .await
        .with_context(|| format!("parse {url}"))?;
    let pubkey_hex = body
        .pointer("/noise/pubkey_hex")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("{url} did not include noise.pubkey_hex"))?;
    let quote_b64 = body
        .pointer("/noise/quote_b64")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("{url} did not include noise.quote_b64"))?;
    let bytes = hex::decode(pubkey_hex).context("decode noise.pubkey_hex")?;
    if bytes.len() != 32 {
        anyhow::bail!(
            "noise.pubkey_hex decoded to {} bytes, expected 32",
            bytes.len()
        );
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    verify_quote_binding(quote_b64, &out, opts).await?;
    Ok(out)
}

async fn verify_quote_binding(
    quote_b64: &str,
    pubkey: &[u8; 32],
    opts: &Opts,
) -> anyhow::Result<()> {
    if opts.insecure_skip_quote_verify {
        eprintln!("warning: skipping agent TDX quote verification by explicit request");
        return Ok(());
    }

    let api_key = opt_or_env(opts.ita_api_key.as_deref(), "DD_ITA_API_KEY")
        .ok_or_else(|| anyhow!("DD_ITA_API_KEY required for quote verification"))?;
    let base_url = opt_or_env(opts.ita_base_url.as_deref(), "DD_ITA_BASE_URL")
        .unwrap_or_else(|| "https://api.trustauthority.intel.com".into());
    let jwks_url = opt_or_env(opts.ita_jwks_url.as_deref(), "DD_ITA_JWKS_URL")
        .unwrap_or_else(|| "https://portal.trustauthority.intel.com/certs".into());
    let issuer = opt_or_env(opts.ita_issuer.as_deref(), "DD_ITA_ISSUER")
        .unwrap_or_else(|| "https://portal.trustauthority.intel.com".into());

    let token = crate::ita::mint(&base_url, &api_key, quote_b64)
        .await
        .map_err(|e| anyhow!("ITA quote appraisal failed: {e}"))?;
    let verifier = crate::ita::Verifier::new(jwks_url, issuer);
    let claims = verifier
        .verify(&token)
        .await
        .map_err(|e| anyhow!("ITA token verification failed: {e}"))?;
    let report_data = claims
        .report_data
        .as_deref()
        .ok_or_else(|| anyhow!("ITA token missing attester_held_data/report_data"))?;
    verify_report_data(report_data, pubkey)
}

fn opt_or_env(opt: Option<&str>, env: &str) -> Option<String> {
    opt.map(str::to_owned).or_else(|| {
        std::env::var(env)
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    })
}

fn verify_report_data(report_data: &str, pubkey: &[u8; 32]) -> anyhow::Result<()> {
    let bytes = decode_report_data(report_data)?;
    match bytes.len() {
        32 if bytes.as_slice() == pubkey => Ok(()),
        64 if bytes[..32] == pubkey[..] && bytes[32..].iter().all(|b| *b == 0) => Ok(()),
        32 | 64 => anyhow::bail!("TDX report_data does not bind expected Noise public key"),
        n => anyhow::bail!("TDX report_data decoded to {n} bytes, expected 32 or 64"),
    }
}

fn decode_report_data(report_data: &str) -> anyhow::Result<Vec<u8>> {
    let s = report_data.trim();
    let hexish = s.strip_prefix("0x").unwrap_or(s);
    if hexish.len().is_multiple_of(2) && hexish.bytes().all(|b| b.is_ascii_hexdigit()) {
        return hex::decode(hexish).context("decode ITA report_data hex");
    }
    for engine in [
        &base64::engine::general_purpose::STANDARD,
        &base64::engine::general_purpose::STANDARD_NO_PAD,
        &base64::engine::general_purpose::URL_SAFE,
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
    ] {
        if let Ok(bytes) = engine.decode(s) {
            return Ok(bytes);
        }
    }
    anyhow::bail!("ITA report_data is neither hex nor base64")
}

async fn create_session(conn: &mut NoiseConnection, opts: &Opts) -> anyhow::Result<Value> {
    let mut request = serde_json::Map::from_iter([(
        "method".to_string(),
        Value::String("shell.create_session".into()),
    )]);
    if let Some(recipe) = opts.recipe.as_deref() {
        request.insert("recipe_id".into(), Value::String(recipe.into()));
    }
    if let Some(name) = opts.name.as_deref() {
        request.insert("name".into(), Value::String(name.into()));
    }
    if let Some(command) = opts.command.as_deref() {
        request.insert("command".into(), Value::String(command.into()));
    }
    conn.call(Value::Object(request)).await
}

async fn attach_session(mut conn: NoiseConnection, id: &str) -> anyhow::Result<()> {
    let ack = conn
        .call(serde_json::json!({
            "method": "shell.attach_session",
            "id": id,
            "tail": true,
        }))
        .await?;
    if ack.get("error").is_some() {
        anyhow::bail!("attach failed: {}", serde_json::to_string(&ack)?);
    }

    let _raw = RawMode::enter()?;
    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut in_buf = [0u8; ATTACH_CHUNK];

    loop {
        tokio::select! {
            n = stdin.read(&mut in_buf) => {
                let n = n?;
                if n == 0 {
                    break;
                }
                send_encrypted(&mut conn.transport, &mut conn.sink, &in_buf[..n]).await?;
            }
            frame = next_binary(&mut conn.stream) => {
                let Some(cipher) = frame? else {
                    break;
                };
                let mut plain = vec![0u8; cipher.len()];
                let n = conn.transport.read_message(&cipher, &mut plain)?;
                stdout.write_all(&plain[..n]).await?;
                stdout.flush().await?;
            }
        }
    }
    Ok(())
}

async fn send_encrypted(
    transport: &mut TransportState,
    sink: &mut WsSink,
    plain: &[u8],
) -> anyhow::Result<()> {
    let mut cipher = vec![0u8; plain.len() + 16];
    let n = transport.write_message(plain, &mut cipher)?;
    cipher.truncate(n);
    sink.send(WsMessage::Binary(cipher.into())).await?;
    Ok(())
}

async fn next_binary(stream: &mut WsRead) -> anyhow::Result<Option<Vec<u8>>> {
    while let Some(msg) = stream.next().await {
        match msg? {
            WsMessage::Binary(b) => return Ok(Some(b.to_vec())),
            WsMessage::Close(_) => return Ok(None),
            WsMessage::Text(_) | WsMessage::Ping(_) | WsMessage::Pong(_) | WsMessage::Frame(_) => {
                continue
            }
        }
    }
    Ok(None)
}

fn session_id(value: &Value) -> anyhow::Result<String> {
    if let Some(error) = value.get("error") {
        anyhow::bail!("create failed: {error}");
    }
    value
        .get("id")
        .or_else(|| value.pointer("/session/id"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| anyhow!("create response did not include a session id: {value}"))
}

async fn load_or_create_key(path: &Path) -> anyhow::Result<StaticSecret> {
    match tokio::fs::read(path).await {
        Ok(bytes) if bytes.len() == 32 => {
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes);
            Ok(StaticSecret::from(key))
        }
        Ok(bytes) => anyhow::bail!("{} is {} bytes, expected 32", path.display(), bytes.len()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let secret = StaticSecret::random_from_rng(OsRng);
            persist_key(path, secret.as_bytes()).await?;
            Ok(secret)
        }
        Err(e) => Err(e).with_context(|| format!("read {}", path.display())),
    }
}

async fn persist_key(path: &Path, bytes: &[u8; 32]) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let tmp = path.with_extension("key.tmp");
    tokio::fs::write(&tmp, bytes).await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600)).await?;
    }
    tokio::fs::rename(&tmp, path).await?;
    Ok(())
}

fn public_hex(secret: &StaticSecret) -> String {
    hex::encode(PublicKey::from(secret).as_bytes())
}

fn default_key_path() -> PathBuf {
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home)
            .join(".config")
            .join("devopsdefender")
            .join("noise.key");
    }
    PathBuf::from(".devopsdefender-noise.key")
}

fn default_label() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "native-cli".into())
}

fn enrollment_url(cp_url: &str, pubkey_hex: &str, label: &str) -> String {
    format!(
        "{}/admin/enroll?pubkey={}&label={}",
        normalize_http_base(cp_url),
        pubkey_hex,
        urlencoding::encode(label)
    )
}

fn health_url(base_url: &str) -> String {
    format!("{}/health", normalize_http_base(base_url))
}

fn noise_ws_url(base_url: &str) -> String {
    let base = normalize_http_base(base_url);
    let ws_base = if let Some(rest) = base.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = base.strip_prefix("http://") {
        format!("ws://{rest}")
    } else {
        base
    };
    format!("{}/noise/ws", ws_base.trim_end_matches('/'))
}

fn normalize_http_base(base_url: &str) -> String {
    let trimmed = base_url.trim().trim_end_matches('/');
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        trimmed.to_string()
    } else {
        format!("https://{trimmed}")
    }
}

fn print_json(value: Value) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

struct RawMode {
    #[cfg(unix)]
    original: Option<libc::termios>,
}

impl RawMode {
    fn enter() -> anyhow::Result<Self> {
        #[cfg(unix)]
        {
            if unsafe { libc::isatty(libc::STDIN_FILENO) } != 1 {
                return Ok(Self { original: None });
            }
            let mut original = std::mem::MaybeUninit::<libc::termios>::uninit();
            if unsafe { libc::tcgetattr(libc::STDIN_FILENO, original.as_mut_ptr()) } != 0 {
                return Err(std::io::Error::last_os_error()).context("tcgetattr");
            }
            let original = unsafe { original.assume_init() };
            let mut raw = original;
            unsafe { libc::cfmakeraw(&mut raw) };
            if unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &raw) } != 0 {
                return Err(std::io::Error::last_os_error()).context("tcsetattr raw");
            }
            Ok(Self {
                original: Some(original),
            })
        }
        #[cfg(not(unix))]
        {
            Ok(Self {})
        }
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        #[cfg(unix)]
        if let Some(original) = &self.original {
            let _ = unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, original) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_urls_from_bare_host() {
        assert_eq!(
            health_url("agent.example.com/"),
            "https://agent.example.com/health"
        );
        assert_eq!(
            noise_ws_url("agent.example.com/"),
            "wss://agent.example.com/noise/ws"
        );
    }

    #[test]
    fn keeps_local_http_scheme() {
        assert_eq!(
            health_url("http://127.0.0.1:8080"),
            "http://127.0.0.1:8080/health"
        );
        assert_eq!(
            noise_ws_url("http://127.0.0.1:8080"),
            "ws://127.0.0.1:8080/noise/ws"
        );
    }

    #[test]
    fn enrollment_url_encodes_label() {
        assert_eq!(
            enrollment_url("https://cp.example.com/", "abcd", "me laptop"),
            "https://cp.example.com/admin/enroll?pubkey=abcd&label=me%20laptop"
        );
    }

    #[test]
    fn report_data_accepts_64_byte_hex_binding() {
        let mut report = [0u8; 64];
        report[..32].fill(7);
        let pubkey = [7u8; 32];
        verify_report_data(&hex::encode(report), &pubkey).unwrap();
    }

    #[test]
    fn report_data_rejects_wrong_key() {
        let mut report = [0u8; 64];
        report[..32].fill(7);
        let pubkey = [8u8; 32];
        assert!(verify_report_data(&hex::encode(report), &pubkey).is_err());
    }

    #[test]
    fn report_data_accepts_base64_binding() {
        let mut report = [0u8; 64];
        report[..32].fill(9);
        let pubkey = [9u8; 32];
        let encoded = base64::engine::general_purpose::STANDARD.encode(report);
        verify_report_data(&encoded, &pubkey).unwrap();
    }
}
