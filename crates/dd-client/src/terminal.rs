//! WebSocket terminal — xterm.js page and WS proxy through easyenclave.

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Response};
use dd_common::error::AppError;
use futures_util::{SinkExt, StreamExt};

use crate::auth::{require_browser_token, verify_owner, DashQuery};
use crate::AppState;

// ── Terminal page (xterm.js) ────────────────────────────────────────────

pub async fn session_page(
    State(state): State<AppState>,
    Path(app_name): Path<String>,
    axum::extract::Query(query): axum::extract::Query<DashQuery>,
    headers: HeaderMap,
    axum::extract::OriginalUri(uri): axum::extract::OriginalUri,
) -> Result<Response, AppError> {
    if !state.config.owner.is_empty() {
        match require_browser_token(&state, &headers, query.token.as_deref(), &uri).await {
            Ok(_) => {}
            Err(response) => return Ok(response),
        }
    }

    Ok(Html(terminal_html(&app_name)).into_response())
}

fn terminal_html(app_name: &str) -> String {
    let title = format!("DD — {app_name}");
    format!(
        r#"<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/xterm@5.3.0/css/xterm.min.css">
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}

  body {{
    background: #1e1e2e;
    color: #cdd6f4;
    font-family: 'JetBrains Mono', ui-monospace, monospace;
  }}

  main {{
    min-height: 100dvh;
    max-width: 960px;
    margin: 0 auto;
    padding: 12px;
    display: grid;
    grid-template-rows: auto 1fr auto;
    gap: 12px;
  }}

  header {{
    display: flex;
    align-items: center;
    gap: 12px;
    flex-wrap: wrap;
  }}

  a {{ color: #89b4fa; text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}

  .app-name {{ font-size: 16px; font-weight: 700; }}

  #status {{
    font-size: 13px;
    padding: 2px 8px;
    border-radius: 4px;
  }}
  #status.ok {{ background: #a6e3a122; color: #a6e3a1; }}
  #status.warn {{ background: #fab38722; color: #fab387; }}
  #status.err {{ background: #f38ba822; color: #f38ba8; }}

  #detail {{ color: #585b70; font-size: 12px; }}
  #attestation {{ color: #585b70; font-size: 12px; }}

  .spacer {{ flex: 1; }}

  .terminal-frame {{
    min-height: min(72dvh, 720px);
    padding: 8px;
    background: #11111b;
    border: 1px solid #313244;
    border-radius: 8px;
    overflow: hidden;
  }}

  #terminal {{ height: min(72dvh, 700px); }}

  .controls {{
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
  }}

  .controls button {{
    min-width: 64px;
    height: 36px;
    padding: 0 12px;
    border: 1px solid #313244;
    border-radius: 6px;
    background: #181825;
    color: #cdd6f4;
    font-family: inherit;
    font-size: 13px;
    cursor: pointer;
  }}
  .controls button:hover {{ border-color: #89b4fa; }}
  .controls button.primary {{ background: #89b4fa; color: #1e1e2e; border-color: #89b4fa; font-weight: 600; }}
  .controls button.primary:hover {{ background: #74c7ec; border-color: #74c7ec; }}

  @media (min-width: 720px) {{
    main {{ padding: 20px; }}
    .terminal-frame {{ min-height: 76dvh; }}
    #terminal {{ height: 76dvh; }}
  }}
</style>
</head>
<body>
<main>
  <header>
    <a href="/">&larr; dashboard</a>
    <span class="app-name" id="appName">{app_name}</span>
    <span id="status" class="warn">Connecting</span>
    <span id="detail"></span>
    <span id="attestation"></span>
    <span class="spacer"></span>
    <a href="/auth/logout">log out</a>
  </header>

  <section class="terminal-frame" id="terminalFrame">
    <div id="terminal"></div>
  </section>

  <nav class="controls">
    <button type="button" class="primary" id="keyboardButton">Keyboard</button>
    <button type="button" data-send="\u0003">Ctrl+C</button>
    <button type="button" data-send="\t">Tab</button>
    <button type="button" data-send="\u001b">Esc</button>
    <button type="button" id="clearButton">Clear</button>
  </nav>
</main>

<script src="https://cdn.jsdelivr.net/npm/xterm@5.3.0/lib/xterm.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/xterm-addon-fit@0.8.0/lib/xterm-addon-fit.min.js"></script>
<script>
const path = window.location.pathname;
const appName = decodeURIComponent(path.split('/session/')[1] || '');

const statusEl = document.getElementById('status');
const detailEl = document.getElementById('detail');
const attestationEl = document.getElementById('attestation');
const keyboardButton = document.getElementById('keyboardButton');
const clearButton = document.getElementById('clearButton');
const terminalFrame = document.getElementById('terminalFrame');

const term = new Terminal({{
  cursorBlink: true,
  fontFamily: "'JetBrains Mono', ui-monospace, monospace",
  fontSize: 15,
  scrollback: 3000,
  theme: {{
    background: '#11111b',
    foreground: '#cdd6f4',
    cursor: '#f5e0dc',
    selectionBackground: '#585b7066',
    black: '#45475a',
    red: '#f38ba8',
    green: '#a6e3a1',
    yellow: '#f9e2af',
    blue: '#89b4fa',
    magenta: '#cba6f7',
    cyan: '#94e2d5',
    white: '#bac2de',
  }},
}});

const fitAddon = new FitAddon.FitAddon();
term.loadAddon(fitAddon);
term.open(document.getElementById('terminal'));

function fitTerminal() {{
  requestAnimationFrame(() => {{
    try {{ fitAddon.fit(); }} catch (_) {{}}
  }});
}}

fitTerminal();
window.addEventListener('resize', fitTerminal);
if (window.visualViewport) {{
  window.visualViewport.addEventListener('resize', fitTerminal);
}}

function setStatus(tone, text, detail) {{
  statusEl.textContent = text;
  statusEl.className = tone;
  detailEl.textContent = detail || '';
}}

function focusTerminal() {{
  term.focus();
  fitTerminal();
}}

let ws = null;

function sendInput(data) {{
  if (ws && ws.readyState === WebSocket.OPEN) {{
    ws.send(JSON.stringify({{
      type: 'stdin',
      data: Array.from(new TextEncoder().encode(data)),
    }}));
  }}
}}

function connect() {{
  if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) {{
    ws.close();
  }}

  setStatus('warn', 'Connecting', `Opening ${{appName || 'shell'}} session...`);

  const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl = `${{proto}}//${{window.location.host}}/ws/session/${{encodeURIComponent(appName)}}`;
  ws = new WebSocket(wsUrl);

  ws.onopen = () => {{
    setStatus('warn', 'Handshake', 'Waiting for the shell to become ready...');
  }};

  ws.onmessage = (event) => {{
    try {{
      const text = typeof event.data === 'string' ? event.data : new TextDecoder().decode(event.data);
      const msg = JSON.parse(text);

      switch (msg.type) {{
        case 'stdout':
        case 'stderr': {{
          const output = typeof msg.data === 'string'
            ? msg.data
            : String.fromCharCode(...msg.data);
          term.write(output);
          break;
        }}
        case 'ok':
          setStatus('ok', msg.status || 'Connected', 'Session ready.');
          if (msg.attestation_type) {{
            let label = `attestation: ${{msg.attestation_type}}`;
            if (msg.attestation_type === 'tdx') label += ' (hardware-verified enclave)';
            attestationEl.textContent = label;
          }}
          focusTerminal();
          break;
        case 'error':
          setStatus('err', 'Error', msg.message || 'Session error.');
          break;
        case 'attestation': {{
          let label = `attestation: ${{msg.attestation_type || 'unknown'}}`;
          if (msg.vm_name) label += ` (${{msg.vm_name}})`;
          attestationEl.textContent = label;
          break;
        }}
      }}
    }} catch (_) {{
      const text = typeof event.data === 'string' ? event.data : new TextDecoder().decode(event.data);
      term.write(text);
    }}
  }};

  ws.onclose = () => {{
    setStatus('err', 'Disconnected', 'Session ended.');
    term.write('\r\n[session ended]\r\n');
  }};

  ws.onerror = () => {{
    setStatus('err', 'Connection error', 'Could not connect. Check if the workload is running.');
  }};
}}

term.onData((data) => {{ sendInput(data); }});
terminalFrame.addEventListener('click', focusTerminal);
keyboardButton.addEventListener('click', focusTerminal);

for (const button of document.querySelectorAll('[data-send]')) {{
  button.addEventListener('click', () => {{
    focusTerminal();
    sendInput(button.dataset.send);
  }});
}}

clearButton.addEventListener('click', () => {{
  term.clear();
  focusTerminal();
}});

connect();
</script>
</body>
</html>"#,
        title = title,
        app_name = app_name,
    )
}

// ── WebSocket session handler ───────────────────────────────────────────

pub async fn ws_session(
    State(state): State<AppState>,
    Path(app_name): Path<String>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Result<impl IntoResponse, AppError> {
    verify_owner(&state, &headers).await?;
    Ok(ws.on_upgrade(move |socket| handle_ws_session(socket, state, app_name)))
}

/// Proxy WebSocket I/O to easyenclave exec.
///
/// dd-client never touches the workload process directly; interactive
/// sessions go through the easyenclave exec API on /var/lib/easyenclave/agent.sock.
async fn handle_ws_session(socket: WebSocket, state: AppState, app_name: String) {
    let (mut ws_tx, mut ws_rx) = socket.split();

    // Get attestation info from easyenclave health
    let ee_health = state.ee_client.health().await.unwrap_or_default();
    let attestation_type = ee_health["attestation_type"].as_str().unwrap_or("unknown");

    let attestation_msg = serde_json::json!({
        "type": "attestation",
        "attestation_type": attestation_type,
        "vm_name": state.config.vm_name,
        "owner": state.config.owner,
    });
    let _ = ws_tx
        .send(Message::Text(attestation_msg.to_string().into()))
        .await;

    // Check if the workload exists by listing deployments
    let list_resp = state.ee_client.list().await.unwrap_or_default();
    let deployments: Vec<&serde_json::Value> = list_resp["deployments"]
        .as_array()
        .map(|a| a.iter().collect())
        .unwrap_or_default();
    let exists = deployments.iter().any(|d| {
        d["app_name"].as_str() == Some(app_name.as_str()) && d["status"].as_str() == Some("running")
    });

    if !exists {
        let err = serde_json::json!({
            "type": "error",
            "message": format!("no running workload named '{app_name}'")
        });
        let _ = ws_tx.send(Message::Text(err.to_string().into())).await;
        return;
    }

    // Send ok status
    let ok = serde_json::json!({
        "type": "ok",
        "status": format!("attached to {app_name}"),
        "attestation_type": attestation_type,
    });
    let _ = ws_tx.send(Message::Text(ok.to_string().into())).await;

    // Proxy loop: stdin from WebSocket -> easyenclave exec,
    // easyenclave stdout -> WebSocket.
    //
    // For interactive sessions, we open a persistent connection to
    // easyenclave and relay data bidirectionally. Since the easyenclave
    // unix socket uses request-response (not streaming), we use polling
    // to get new log output while forwarding stdin as exec commands.
    //
    // The exec-based approach: each keystroke batch is sent as a write
    // to the process stdin file descriptor. Log output is polled.

    let ee_client = state.ee_client.clone();
    let app_name_clone = app_name.clone();

    // Start a log-polling task that sends stdout to the WebSocket
    let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel::<()>();
    let (stdout_tx, mut stdout_rx) = tokio::sync::mpsc::channel::<String>(256);

    // Poll logs periodically
    let poll_ee = ee_client.clone();
    let poll_id = {
        let deps = deployments
            .iter()
            .find(|d| d["app_name"].as_str() == Some(app_name_clone.as_str()));
        deps.and_then(|d| d["id"].as_str())
            .unwrap_or("")
            .to_string()
    };

    let poll_handle = tokio::spawn(async move {
        let mut last_line_count = 0usize;
        let mut interval = tokio::time::interval(std::time::Duration::from_millis(500));
        loop {
            tokio::select! {
                _ = &mut stop_rx => break,
                _ = interval.tick() => {
                    let resp = poll_ee.logs(&poll_id).await.unwrap_or_default();
                    if let Some(lines) = resp["lines"].as_array() {
                        if lines.len() > last_line_count {
                            for line in &lines[last_line_count..] {
                                if let Some(text) = line.as_str() {
                                    let _ = stdout_tx.send(format!("{text}\r\n")).await;
                                }
                            }
                            last_line_count = lines.len();
                        }
                    }
                }
            }
        }
    });

    // Bidirectional relay
    loop {
        tokio::select! {
            Some(text) = stdout_rx.recv() => {
                let msg = serde_json::json!({ "type": "stdout", "data": text });
                if ws_tx.send(Message::Text(msg.to_string().into())).await.is_err() {
                    break;
                }
            }
            msg = ws_rx.next() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&text) {
                            if parsed["type"] == "stdin" {
                                if let Some(data) = parsed["data"].as_array() {
                                    let bytes: Vec<u8> = data
                                        .iter()
                                        .filter_map(|v| v.as_u64().map(|b| b as u8))
                                        .collect();
                                    let input = String::from_utf8_lossy(&bytes).to_string();
                                    // Execute the input as a command through easyenclave
                                    // For a shell session, this writes to the process stdin
                                    let _ = ee_client
                                        .exec(&[input], 5)
                                        .await;
                                }
                            }
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    _ => {}
                }
            }
        }
    }

    let _ = stop_tx.send(());
    poll_handle.abort();
}
