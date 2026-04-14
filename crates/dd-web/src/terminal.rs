//! Interactive shell into the management VM (CP).
//!
//! - GET /cp/shell → xterm.js HTML page
//! - GET /cp/ws/shell → WebSocket bridge to easyenclave's `attach` socket method
//!
//! Same WS envelope as `dd-client/src/terminal.rs` so the on-the-wire
//! protocol is symmetric across the fleet.

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Response};
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::auth::require_browser_auth;
use crate::state::WebState;

pub async fn shell_page(
    State(state): State<WebState>,
    headers: HeaderMap,
    axum::extract::OriginalUri(uri): axum::extract::OriginalUri,
) -> Result<Response, Response> {
    if !state.config.owner.is_empty() {
        require_browser_auth(&state, &headers, &uri).await?;
    }
    Ok(Html(SHELL_HTML).into_response())
}

pub async fn ws_shell(
    State(state): State<WebState>,
    headers: HeaderMap,
    axum::extract::OriginalUri(uri): axum::extract::OriginalUri,
    ws: WebSocketUpgrade,
) -> Result<Response, Response> {
    if !state.config.owner.is_empty() {
        require_browser_auth(&state, &headers, &uri).await?;
    }
    Ok(ws.on_upgrade(move |socket| handle_ws(socket, state)))
}

async fn handle_ws(socket: WebSocket, state: WebState) {
    let (mut ws_tx, mut ws_rx) = socket.split();

    let attach = match state.ee_client.attach(&[]).await {
        Ok(s) => s,
        Err(e) => {
            let err = serde_json::json!({"type": "error", "message": format!("attach: {e}")});
            let _ = ws_tx.send(Message::Text(err.to_string().into())).await;
            return;
        }
    };
    let ok = serde_json::json!({"type": "ok", "status": "attached to control-plane"});
    let _ = ws_tx.send(Message::Text(ok.to_string().into())).await;

    let (mut sock_rd, mut sock_wr) = attach.into_split();

    // sock → ws
    let read_task = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            match sock_rd.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let chunk = String::from_utf8_lossy(&buf[..n]).to_string();
                    let msg = serde_json::json!({"type": "stdout", "data": chunk});
                    if ws_tx
                        .send(Message::Text(msg.to_string().into()))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            }
        }
        let _ = ws_tx.close().await;
    });

    // ws → sock
    while let Some(Ok(msg)) = ws_rx.next().await {
        match msg {
            Message::Text(text) => {
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&text) {
                    if parsed["type"] == "stdin" {
                        if let Some(data) = parsed["data"].as_array() {
                            let bytes: Vec<u8> = data
                                .iter()
                                .filter_map(|v| v.as_u64().map(|b| b as u8))
                                .collect();
                            if sock_wr.write_all(&bytes).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            }
            Message::Close(_) => break,
            _ => {}
        }
    }

    drop(sock_wr);
    let _ = read_task.await;
}

const SHELL_HTML: &str = r#"<!DOCTYPE html>
<html><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DD — control-plane shell</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/xterm@5.3.0/css/xterm.min.css">
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:#1e1e2e;color:#cdd6f4;font-family:ui-monospace,monospace;display:flex;flex-direction:column;height:100vh}
  header{padding:.5em 1em;border-bottom:1px solid #313244;display:flex;justify-content:space-between;align-items:center;font-size:.85em}
  header a{color:#89b4fa;text-decoration:none}
  #status{padding:.2em .5em;border-radius:4px;background:#313244}
  #status.ok{background:#2d4a37;color:#a6e3a1}
  #status.err{background:#4a2d34;color:#f38ba8}
  #terminal{flex:1;padding:.5em;background:#11111b}
</style>
</head><body>
<header>
  <a href="/agent/control-plane">&larr; control-plane</a>
  <div><span id="status">connecting</span></div>
</header>
<div id="terminal"></div>
<script src="https://cdn.jsdelivr.net/npm/xterm@5.3.0/lib/xterm.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/xterm-addon-fit@0.8.0/lib/xterm-addon-fit.min.js"></script>
<script>
const term = new Terminal({fontFamily:'ui-monospace,monospace',fontSize:13,cursorBlink:true,
  theme:{background:'#11111b',foreground:'#cdd6f4',cursor:'#f5e0dc'}});
const fit = new FitAddon.FitAddon();
term.loadAddon(fit);
term.open(document.getElementById('terminal'));
const fitNow = () => requestAnimationFrame(() => { try { fit.fit(); } catch (_) {} });
fitNow();
window.addEventListener('resize', fitNow);
const status = document.getElementById('status');
const setStatus = (t, c) => { status.textContent = t; status.className = c || ''; };

const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
const ws = new WebSocket(`${proto}//${location.host}/cp/ws/shell`);
ws.onopen = () => setStatus('handshake', 'warn');
ws.onmessage = (e) => {
  try {
    const m = JSON.parse(typeof e.data === 'string' ? e.data : new TextDecoder().decode(e.data));
    if (m.type === 'stdout' || m.type === 'stderr') term.write(typeof m.data === 'string' ? m.data : String.fromCharCode(...m.data));
    else if (m.type === 'ok') { setStatus(m.status || 'connected', 'ok'); term.focus(); }
    else if (m.type === 'error') setStatus(m.message || 'error', 'err');
  } catch (_) { term.write(typeof e.data === 'string' ? e.data : new TextDecoder().decode(e.data)); }
};
ws.onclose = () => { setStatus('disconnected', 'err'); term.write('\r\n[session ended]\r\n'); };
ws.onerror = () => setStatus('connection error', 'err');
term.onData((d) => {
  if (ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({type:'stdin', data: Array.from(new TextEncoder().encode(d))}));
  }
});
</script></body></html>
"#;
