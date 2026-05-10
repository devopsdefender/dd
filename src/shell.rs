//! Multi-session shell sidecar.
//!
//! Authenticated shell endpoint marker.
//!
//! Native clients in `devopsdefender/dd-client` are the primary shell/session
//! workflow. This sidecar does not expose an interactive browser shell or
//! session control surface.

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use axum::Router;

use crate::error::{Error, Result};
use crate::html;

const DEFAULT_PORT: u16 = 7681;

#[derive(Clone)]
struct App {
    owner: crate::gh_oidc::Principal,
    auth: crate::auth::AuthConfig,
    hostname: String,
}

pub async fn run() -> Result<()> {
    let common = crate::config::Common::from_env()?;
    let domain = std::env::var("DD_CF_DOMAIN")
        .map_err(|_| Error::Internal("DD_CF_DOMAIN required in shell mode".into()))?;
    let hostname = std::env::var("DD_HOSTNAME")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| common.vm_name.clone());
    let auth = crate::auth::AuthConfig::from_env(&hostname, &domain)?;
    let port = std::env::var("DD_SHELL_PORT")
        .ok()
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(DEFAULT_PORT);

    let app_state = App {
        owner: common.owner,
        auth,
        hostname,
    };

    let app = Router::new()
        .route("/", get(index))
        .route("/favicon.ico", get(favicon))
        .with_state(app_state);

    let addr = format!("0.0.0.0:{port}");
    eprintln!("dd-shell: listening on {addr}");
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app.into_make_service())
        .await
        .map_err(|e| Error::Internal(e.to_string()))
}

fn shell_path_and_query(uri: &Uri) -> &str {
    uri.path_and_query().map(|p| p.as_str()).unwrap_or("/")
}

fn require_shell_auth(app: &App, headers: &HeaderMap, uri: &Uri) -> Option<Response> {
    if app.auth.verify_session(&app.owner, headers).is_some() {
        None
    } else {
        let return_to =
            crate::auth::absolute_url(headers, &app.hostname, shell_path_and_query(uri));
        Some(crate::auth::unauthorized_or_redirect(
            &app.auth, headers, &return_to,
        ))
    }
}

async fn index(State(app): State<App>, headers: HeaderMap, uri: Uri) -> Response {
    if let Some(resp) = require_shell_auth(&app, &headers, &uri) {
        return resp;
    }
    Html(html::shell("DD Shell", "", SHELL_HTML)).into_response()
}

async fn favicon() -> StatusCode {
    StatusCode::NO_CONTENT
}

const SHELL_HTML: &str = r##"
<style>
body { background:#0f1218; color:#d7deea; }
main { max-width:760px; }
.notice { margin-top:64px; border:1px solid #252a36; border-radius:8px; padding:24px; background:#141923; }
.notice h1 { margin:0 0 10px; font-size:24px; }
.notice p { margin:0; color:#9aa5b8; line-height:1.5; }
code { color:#d7deea; background:#202635; border-radius:4px; padding:2px 5px; }
@media (max-width:720px) {
  .notice { margin-top:32px; padding:18px; }
}
</style>
<div class="notice">
  <h1>Shell moved to dd-client</h1>
  <p>Use <code>dd-client</code> for interactive sessions. This endpoint no longer exposes a browser terminal or session control API.</p>
</div>
"##;
