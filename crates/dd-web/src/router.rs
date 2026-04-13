use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use axum::Router;

use crate::auth::require_browser_auth;
use crate::html::{nav_bar, page_shell};
use crate::state::WebState;
use crate::{auth, federate, fleet};

async fn health() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "ok": true,
        "service": "dd-web",
    }))
}

pub fn build_router(state: WebState) -> Router {
    Router::new()
        .route("/", get(fleet::fleet_dashboard))
        .route("/health", get(health))
        .route("/agent/{id}", get(fleet::agent_detail))
        .route("/cp/deployments", get(cp_deployments))
        .route("/cp/deployments/{id}/logs", get(cp_deployment_logs))
        .route("/federate", get(federate::federate))
        .route("/auth/github/start", get(auth::github_start))
        .route("/auth/github/callback", get(auth::github_callback))
        .route("/auth/logout", get(auth::logout))
        .route("/logged-out", get(auth::logged_out_page))
        .with_state(state)
}

// ── Control-plane workload routes ──────────────────────────────────────
// These query the local easyenclave socket to show workload info and logs
// for the management VM itself (the control-plane agent).

/// GET /cp/deployments -- list workloads running on the CP via easyenclave socket.
async fn cp_deployments(
    State(state): State<WebState>,
    headers: HeaderMap,
    axum::extract::OriginalUri(uri): axum::extract::OriginalUri,
) -> Result<Response, Response> {
    if !state.config.owner.is_empty() {
        require_browser_auth(&state, &headers, &uri).await?;
    }

    let deployments = state.ee_client.list().await.unwrap_or_default();
    let nav = nav_bar(&[("Fleet", "/", false)]);

    let mut rows = String::new();
    if let Some(deps) = deployments["deployments"].as_array() {
        for info in deps {
            let id = info["id"].as_str().unwrap_or("unknown");
            let app_name = info["app_name"].as_str().unwrap_or("unknown");
            let status = info["status"].as_str().unwrap_or("unknown");
            let image = info["image"].as_str().unwrap_or("-");
            rows.push_str(&format!(
                r#"<tr>
                    <td>{app_name}</td>
                    <td><span class="pill {status}">{status}</span></td>
                    <td style="font-size:0.85em">{image}</td>
                    <td><a href="/cp/deployments/{id}/logs">logs</a></td>
                </tr>"#,
            ));
        }
    }

    let table = if rows.is_empty() {
        r#"<div class="empty">No deployments found (easyenclave socket not reachable?)</div>"#
            .to_string()
    } else {
        format!(
            r#"<table><tr><th>workload</th><th>status</th><th>image</th><th></th></tr>{rows}</table>"#
        )
    };

    let content = format!(
        r#"<div class="back"><a href="/agent/control-plane">&larr; control-plane</a></div>
<h1>Control Plane Workloads</h1>
<div class="sub">local easyenclave deployments</div>
{table}"#
    );

    Ok(Html(page_shell("CP Workloads -- DD Fleet", &nav, &content)).into_response())
}

/// GET /cp/deployments/{id}/logs -- show logs for a CP workload.
async fn cp_deployment_logs(
    Path(id): Path<String>,
    State(state): State<WebState>,
    headers: HeaderMap,
    axum::extract::OriginalUri(uri): axum::extract::OriginalUri,
) -> Result<Response, Response> {
    if !state.config.owner.is_empty() {
        require_browser_auth(&state, &headers, &uri).await?;
    }

    let logs = state.ee_client.logs(&id).await.unwrap_or_default();
    let nav = nav_bar(&[("Fleet", "/", false)]);

    let log_text = if let Some(stdout) = logs["stdout"].as_str() {
        html_escape(stdout)
    } else if let Some(output) = logs["output"].as_str() {
        html_escape(output)
    } else {
        html_escape(&logs.to_string())
    };

    let content = format!(
        r#"<div class="back"><a href="/cp/deployments">&larr; workloads</a></div>
<h1>Logs: {id}</h1>
<pre style="background:#1e1e2e;padding:1em;border-radius:8px;overflow-x:auto;max-height:80vh;font-size:0.85em">{log_text}</pre>"#,
    );

    Ok(Html(page_shell(
        &format!("Logs {id} -- DD Fleet"),
        &nav,
        &content,
    ))
    .into_response())
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}
