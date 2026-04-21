//! Minimal embedding: mount bastion under `/term` on a tiny host app.
//!
//! Run: `cargo run --example standalone` then open
//! <http://127.0.0.1:7681/term/>.

use axum::{response::Html, routing::get, Router};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let mgr = bastion::Manager::new();

    let app: Router = Router::new()
        .route("/", get(|| async { Html("<a href=\"/term/\">/term/</a>") }))
        .nest("/term", bastion::router(mgr));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:7681").await?;
    eprintln!("standalone demo: http://127.0.0.1:7681/term/");
    axum::serve(listener, app)
        .await
        .map_err(|e| std::io::Error::other(format!("{e}")))
}
