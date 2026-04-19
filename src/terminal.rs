//! xterm.js shell page + WebSocket ↔ easyenclave PTY bridge.
//!
//! Wire format: one text frame on connect with the banner JSON, then
//! raw binary frames in both directions carrying PTY bytes. xterm.js
//! handles binary frames natively so no JSON envelope overhead.

use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket};
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::ee::Ee;

/// `title` is shown in the header; `ws_path` is the WebSocket endpoint
/// relative to the current origin.
pub fn page(title: &str, ws_path: &str) -> String {
    format!(
        r#"<!DOCTYPE html><html><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{t}</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/xterm@5.3.0/css/xterm.min.css">
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:#1e1e2e;color:#cdd6f4;font-family:'JetBrains Mono',ui-monospace,monospace}}
  main{{min-height:100dvh;max-width:1080px;margin:0 auto;padding:12px;display:grid;grid-template-rows:auto 1fr auto;gap:12px}}
  header{{display:flex;align-items:center;gap:12px;flex-wrap:wrap}}
  a{{color:#89b4fa;text-decoration:none}} a:hover{{text-decoration:underline}}
  #status{{font-size:13px;padding:2px 8px;border-radius:4px}}
  #status.ok{{background:#a6e3a122;color:#a6e3a1}}
  #status.warn{{background:#fab38722;color:#fab387}}
  #status.err{{background:#f38ba822;color:#f38ba8}}
  #banner{{color:#585b70;font-size:12px}}
  .spacer{{flex:1}}
  .frame{{min-height:min(72dvh,720px);padding:8px;background:#11111b;border:1px solid #313244;border-radius:8px;overflow:hidden}}
  #term{{height:min(72dvh,700px)}}
  .keys{{display:flex;flex-wrap:wrap;gap:8px}}
  .keys button{{min-width:64px;height:36px;padding:0 12px;border:1px solid #313244;border-radius:6px;background:#181825;color:#cdd6f4;font:inherit;font-size:13px;cursor:pointer}}
  .keys button:hover{{border-color:#89b4fa}}
  .keys .primary{{background:#89b4fa;color:#1e1e2e;border-color:#89b4fa;font-weight:600}}
  @media(min-width:720px){{main{{padding:20px}} .frame{{min-height:76dvh}} #term{{height:76dvh}}}}
</style></head><body>
<main>
  <header>
    <a href="/">← dashboard</a>
    <span style="font-size:16px;font-weight:700">{t}</span>
    <span id="status" class="warn">Connecting</span>
    <span id="banner"></span>
    <span class="spacer"></span>
  </header>
  <section class="frame"><div id="term"></div></section>
  <nav class="keys">
    <button class="primary" id="focus">Focus</button>
    <button data-send="\u0003">Ctrl+C</button>
    <button data-send="\t">Tab</button>
    <button data-send="\u001b">Esc</button>
    <button id="clear">Clear</button>
  </nav>
</main>
<script src="https://cdn.jsdelivr.net/npm/xterm@5.3.0/lib/xterm.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/xterm-addon-fit@0.8.0/lib/xterm-addon-fit.min.js"></script>
<script>
const statusEl = document.getElementById('status');
const bannerEl = document.getElementById('banner');
const term = new Terminal({{cursorBlink:true,fontFamily:"'JetBrains Mono',monospace",fontSize:15,scrollback:3000,theme:{{background:'#11111b',foreground:'#cdd6f4',cursor:'#f5e0dc',black:'#45475a',red:'#f38ba8',green:'#a6e3a1',yellow:'#f9e2af',blue:'#89b4fa',magenta:'#cba6f7',cyan:'#94e2d5',white:'#bac2de'}}}});
const fit = new FitAddon.FitAddon(); term.loadAddon(fit); term.open(document.getElementById('term'));
const refit = () => requestAnimationFrame(() => {{ try{{fit.fit()}}catch(_){{}} }});
refit(); addEventListener('resize', refit);
const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
const ws = new WebSocket(proto + '//' + location.host + "{ws}");
ws.binaryType = 'arraybuffer';
const enc = new TextEncoder();
ws.onopen = () => {{ statusEl.textContent='Handshake'; statusEl.className='warn'; }};
ws.onmessage = e => {{
  if (typeof e.data === 'string') {{
    try {{
      const m = JSON.parse(e.data);
      if (m.type === 'banner') {{ statusEl.textContent='Connected'; statusEl.className='ok'; bannerEl.textContent = (m.attestation||'') + ' · ' + (m.vm_name||''); term.focus(); refit(); }}
      else if (m.type === 'error') {{ statusEl.textContent='Error'; statusEl.className='err'; bannerEl.textContent = m.message||''; }}
    }} catch {{}}
  }} else {{
    term.write(new Uint8Array(e.data));
  }}
}};
ws.onclose = () => {{ statusEl.textContent='Disconnected'; statusEl.className='err'; term.write('\r\n[session ended]\r\n'); }};
const send = d => {{ if (ws.readyState === 1) ws.send(enc.encode(d)); }};
term.onData(send);
document.getElementById('focus').onclick = () => term.focus();
document.getElementById('clear').onclick = () => {{ term.clear(); term.focus(); }};
document.querySelectorAll('[data-send]').forEach(b => b.onclick = () => {{ term.focus(); send(b.dataset.send); }});
</script></body></html>"#,
        t = title,
        ws = ws_path
    )
}

/// Bridge browser WS ↔ EE PTY socket.
///
/// Sends a banner text frame with attestation info, then raw binary
/// frames both directions until one side closes.
pub async fn bridge(ws: WebSocket, ee: Arc<Ee>, vm_name: &str) {
    let (mut tx, mut rx) = ws.split();

    let attestation = ee
        .health()
        .await
        .ok()
        .and_then(|v| v["attestation_type"].as_str().map(String::from))
        .unwrap_or_else(|| "unknown".into());
    let banner =
        serde_json::json!({"type": "banner", "vm_name": vm_name, "attestation": attestation});
    let _ = tx.send(Message::Text(banner.to_string().into())).await;

    let sock = match ee.attach(&[]).await {
        Ok(s) => s,
        Err(e) => {
            let err = serde_json::json!({"type": "error", "message": e.to_string()});
            let _ = tx.send(Message::Text(err.to_string().into())).await;
            return;
        }
    };
    let (mut rd, mut wr) = sock.into_split();

    // PTY → WS (raw binary)
    let reader = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            match rd.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if tx
                        .send(Message::Binary(buf[..n].to_vec().into()))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            }
        }
        let _ = tx.close().await;
    });

    // WS → PTY (raw binary; ignore non-binary)
    while let Some(Ok(msg)) = rx.next().await {
        let bytes = match msg {
            Message::Binary(b) => b,
            Message::Close(_) => break,
            _ => continue,
        };
        if wr.write_all(&bytes).await.is_err() {
            break;
        }
    }
    drop(wr);
    let _ = reader.await;
}
