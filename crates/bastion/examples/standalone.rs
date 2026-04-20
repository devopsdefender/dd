//! Minimal embedding: mount bastion under `/term` on a tiny host app.
//!
//! Run: `cargo run --example standalone` then open
//! <http://127.0.0.1:7681/term/>.

use axum::{response::Html, routing::get, Router};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let mgr = bastion::Manager::new().with_shell(|title, body| {
        format!(
            r#"<!DOCTYPE html><html><head><meta charset="utf-8">
<title>{title} — demo</title>
<style>html,body{{height:100%;margin:0;background:#1e1e2e;color:#cdd6f4;
font-family:ui-monospace,monospace;display:flex;flex-direction:column}}
header{{padding:10px 16px;border-bottom:1px solid #313244;
background:#181825;color:#89b4fa;font-weight:600;font-size:13px}}
.fullpage{{flex:1;min-height:0;display:flex}}</style></head>
<body><header>{title} — embedded demo</header>
<div class="fullpage">{body}</div></body></html>"#,
        )
    });

    let app: Router = Router::new()
        .route("/", get(|| async { Html("<a href=\"/term/\">/term/</a>") }))
        .nest("/term", bastion::router(mgr));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:7681").await?;
    eprintln!("standalone demo: http://127.0.0.1:7681/term/");
    axum::serve(listener, app)
        .await
        .map_err(|e| std::io::Error::other(format!("{e}")))
}
