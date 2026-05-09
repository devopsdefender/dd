//! Cloudflare tunnel + DNS client.
//!
//! Naming convention (enforced here): CP tunnels are `dd-{env}-cp-{uuid}`,
//! agent tunnels are `dd-{env}-agent-{uuid}`. The suffix is how the
//! collector knows which tunnels to scrape and STONITH knows which to
//! target, without ever fetching the ingress config.

use base64::Engine;
use reqwest::{Client, Method};
use serde::{Deserialize, Serialize};

use crate::config::CfCreds;
use crate::error::{Error, Result};

const API: &str = "https://api.cloudflare.com/client/v4";
pub const AGENT_API_LABEL: &str = "agent-api";
pub const AGENT_API_PORT: u16 = 8081;

pub fn cp_tunnel_name(env: &str) -> String {
    format!("dd-{env}-cp-{}", uuid::Uuid::new_v4())
}
pub fn agent_tunnel_name(env: &str) -> String {
    format!("dd-{env}-agent-{}", uuid::Uuid::new_v4())
}
pub fn cp_prefix(env: &str) -> String {
    format!("dd-{env}-cp-")
}
pub fn agent_prefix(env: &str) -> String {
    format!("dd-{env}-agent-")
}
pub fn agent_api_hostname(agent_hostname: &str) -> String {
    match agent_hostname.split_once('.') {
        Some((base, rest)) => {
            if let Some((prefix, suffix)) = base.split_once("-agent-") {
                format!("{prefix}-api-{suffix}.{rest}")
            } else {
                format!("{base}-{AGENT_API_LABEL}.{rest}")
            }
        }
        None => format!("{agent_hostname}-{AGENT_API_LABEL}"),
    }
}

pub fn extra_hostname(agent_hostname: &str, label: &str) -> String {
    if label == AGENT_API_LABEL {
        agent_api_hostname(agent_hostname)
    } else {
        label_hostname(agent_hostname, label)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tunnel {
    pub id: String,
    pub token: String,
    pub hostname: String,
    #[serde(default)]
    pub extra_hostnames: Vec<String>,
}

/// One-liner HTTP wrapper: all CF calls go through this. Returns the
/// parsed JSON body on any 2xx, turns anything else into `Error::Upstream`
/// carrying the response text.
async fn call(
    http: &Client,
    cf: &CfCreds,
    method: Method,
    path: &str,
    body: Option<serde_json::Value>,
) -> Result<serde_json::Value> {
    let mut req = http
        .request(method.clone(), format!("{API}{path}"))
        .bearer_auth(&cf.api_token);
    if let Some(b) = body {
        req = req.json(&b);
    }
    let resp = req.send().await?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(Error::Upstream(format!(
            "CF {method} {path} → {status}: {body}"
        )));
    }
    let parsed: serde_json::Value = resp.json().await?;
    // CF v4 API returns 200 with {success: false, errors: [...]} on
    // validation failures. We used to silently drop those — which led
    // to Cloudflare apps that appeared created but never matched any
    // requests (manifested as /health etc. 503'ing behind the root
    // human app). Promote to Err so the CP's `?` unwinding catches it.
    if parsed.get("success") == Some(&serde_json::Value::Bool(false)) {
        let errors = parsed
            .get("errors")
            .map(|e| e.to_string())
            .unwrap_or_default();
        return Err(Error::Upstream(format!(
            "CF {method} {path}: success=false errors={errors}"
        )));
    }
    Ok(parsed)
}

/// Create (or recreate) a CF tunnel with ingress pointing at the local
/// service on port 8080, a proxied CNAME for `hostname`, and one
/// additional `{label}.{hostname}` → `localhost:{port}` ingress +
/// CNAME per entry in `extras`. Extras are prepended to the ingress
/// rules so they match before the primary wildcard catch-all.
pub async fn create(
    http: &Client,
    cf: &CfCreds,
    name: &str,
    hostname: &str,
    extras: &[(String, u16)],
) -> Result<Tunnel> {
    delete_by_name(http, cf, name).await;

    let secret = base64::engine::general_purpose::STANDARD.encode(uuid::Uuid::new_v4().as_bytes());
    // `config_src: "cloudflare"` marks the tunnel as dashboard/API-managed
    // so cloudflared won't try to push its (empty) local config at connect
    // time. Without this, cloudflared 2026.3.0 logs
    // `ERR unable to send local configuration … Invalid ConfigurationSource
    // change` and the tunnel never registers a connection — the CP's
    // /health endpoint stays unreachable and `Wait for agent health`
    // times out.
    let resp = call(
        http,
        cf,
        Method::POST,
        &format!("/accounts/{}/cfd_tunnel", cf.account_id),
        Some(serde_json::json!({
            "name": name,
            "tunnel_secret": secret,
            "config_src": "cloudflare",
        })),
    )
    .await?;

    let id = resp["result"]["id"]
        .as_str()
        .ok_or_else(|| Error::Upstream("tunnel create: missing id".into()))?
        .to_string();
    let token = resp["result"]["token"]
        .as_str()
        .ok_or_else(|| Error::Upstream("tunnel create: missing token".into()))?
        .to_string();

    let extra_hostnames = apply_ingress(http, cf, &id, hostname, extras).await?;

    Ok(Tunnel {
        id,
        token,
        hostname: hostname.to_string(),
        extra_hostnames,
    })
}

/// Replace an existing tunnel's ingress rules + CNAME records. Used
/// for runtime updates — e.g. a workload POSTed to `/deploy` declares
/// `expose`, the agent forwards the full current extras list to the
/// CP, and the CP calls this to re-PUT the tunnel config without
/// recreating the tunnel or touching the tunnel token. Returns the
/// resolved extra hostnames so the caller can log / store them.
pub async fn update_ingress(
    http: &Client,
    cf: &CfCreds,
    tunnel_id: &str,
    hostname: &str,
    extras: &[(String, u16)],
) -> Result<Vec<String>> {
    apply_ingress(http, cf, tunnel_id, hostname, extras).await
}

/// Turn `(hostname="pr-144.devopsdefender.com", label="shell")` into
/// `"pr-144-shell.devopsdefender.com"`. Cloudflare's Universal SSL
/// only covers one level of wildcard (`*.devopsdefender.com`), so
/// we can't nest sub-workload subdomains under the agent's hostname
/// — the TLS handshake fails for `foo.bar.devopsdefender.com`.
/// Flattening the prefix keeps every workload URL one-level deep
/// under the zone apex.
pub fn label_hostname(hostname: &str, label: &str) -> String {
    match hostname.split_once('.') {
        Some((base, rest)) => format!("{base}-{label}.{rest}"),
        None => format!("{hostname}-{label}"),
    }
}

/// Build the ingress array (extras first, then the primary
/// `hostname → localhost:8080` rule, then the 404 catch-all), PUT
/// it to the tunnel, and upsert a CNAME for each hostname pointing
/// at `{tunnel_id}.cfargotunnel.com`.
async fn apply_ingress(
    http: &Client,
    cf: &CfCreds,
    tunnel_id: &str,
    hostname: &str,
    extras: &[(String, u16)],
) -> Result<Vec<String>> {
    let mut ingress: Vec<serde_json::Value> = extras
        .iter()
        .map(|(label, port)| {
            serde_json::json!({
                "hostname": extra_hostname(hostname, label),
                "service": format!("http://localhost:{port}"),
            })
        })
        .collect();
    ingress.push(serde_json::json!({
        "hostname": hostname,
        "service": "http://localhost:8080",
    }));
    ingress.push(serde_json::json!({"service": "http_status:404"}));

    call(
        http,
        cf,
        Method::PUT,
        &format!(
            "/accounts/{}/cfd_tunnel/{tunnel_id}/configurations",
            cf.account_id
        ),
        Some(serde_json::json!({"config": {"ingress": ingress}})),
    )
    .await?;

    upsert_cname(http, cf, tunnel_id, hostname).await?;
    let mut extra_hostnames = Vec::with_capacity(extras.len());
    for (label, _) in extras {
        let extra = extra_hostname(hostname, label);
        upsert_cname(http, cf, tunnel_id, &extra).await?;
        extra_hostnames.push(extra);
    }
    Ok(extra_hostnames)
}

async fn upsert_cname(http: &Client, cf: &CfCreds, tunnel_id: &str, hostname: &str) -> Result<()> {
    let content = format!("{tunnel_id}.cfargotunnel.com");
    let body = serde_json::json!({
        "type": "CNAME", "name": hostname, "content": content, "proxied": true,
    });
    match find_record_id(http, cf, hostname).await? {
        Some(rec) => {
            call(
                http,
                cf,
                Method::PUT,
                &format!("/zones/{}/dns_records/{rec}", cf.zone_id),
                Some(body),
            )
            .await?;
        }
        None => {
            call(
                http,
                cf,
                Method::POST,
                &format!("/zones/{}/dns_records", cf.zone_id),
                Some(body),
            )
            .await?;
        }
    }
    Ok(())
}

pub async fn find_record_id(http: &Client, cf: &CfCreds, hostname: &str) -> Result<Option<String>> {
    // Best-effort lookup: CF returns 200 with an empty array on miss.
    let resp = call(
        http,
        cf,
        Method::GET,
        &format!(
            "/zones/{}/dns_records?type=CNAME&name={hostname}",
            cf.zone_id
        ),
        None,
    )
    .await
    .unwrap_or(serde_json::Value::Null);
    Ok(resp["result"]
        .as_array()
        .and_then(|a| a.first())
        .and_then(|r| r["id"].as_str())
        .map(String::from))
}

pub async fn delete_cname(http: &Client, cf: &CfCreds, hostname: &str) -> Result<()> {
    if let Some(id) = find_record_id(http, cf, hostname).await? {
        let _ = call(
            http,
            cf,
            Method::DELETE,
            &format!("/zones/{}/dns_records/{id}", cf.zone_id),
            None,
        )
        .await;
    }
    Ok(())
}

/// Best-effort delete by name. Used for STONITH + idempotent re-create;
/// callers can't act usefully on failure.
pub async fn delete_by_name(http: &Client, cf: &CfCreds, name: &str) {
    let Ok(resp) = call(
        http,
        cf,
        Method::GET,
        &format!("/accounts/{}/cfd_tunnel?name={name}", cf.account_id),
        None,
    )
    .await
    else {
        return;
    };
    let Some(items) = resp["result"].as_array() else {
        return;
    };
    for t in items {
        let Some(id) = t["id"].as_str() else { continue };
        let _ = call(
            http,
            cf,
            Method::DELETE,
            &format!("/accounts/{}/cfd_tunnel/{id}/connections", cf.account_id),
            None,
        )
        .await;
        let _ = call(
            http,
            cf,
            Method::DELETE,
            &format!("/accounts/{}/cfd_tunnel/{id}", cf.account_id),
            None,
        )
        .await;
    }
}

pub async fn list(http: &Client, cf: &CfCreds) -> Result<Vec<serde_json::Value>> {
    let mut out = Vec::new();
    let per_page = 200u64;
    let mut page = 1u64;
    loop {
        let resp = call(
            http,
            cf,
            Method::GET,
            &format!(
                "/accounts/{}/cfd_tunnel?is_deleted=false&per_page={per_page}&page={page}",
                cf.account_id
            ),
            None,
        )
        .await?;
        let items = resp["result"].as_array().cloned().unwrap_or_default();
        let count = items.len();
        out.extend(items);

        let total_pages = resp["result_info"]["total_pages"].as_u64().unwrap_or(page);
        if page >= total_pages || count < per_page as usize {
            break;
        }
        page += 1;
    }
    Ok(out)
}

/// `Some(true)` if present, `Some(false)` if confirmed deleted, `None`
/// on ambiguous transport error — the watchdog uses `None` to mean
/// "don't count as gone" and avoid flaky kernel_poweroffs.
pub async fn exists(http: &Client, cf: &CfCreds, tunnel_id: &str) -> Option<bool> {
    let resp = http
        .get(format!(
            "{API}/accounts/{}/cfd_tunnel/{tunnel_id}",
            cf.account_id
        ))
        .bearer_auth(&cf.api_token)
        .send()
        .await
        .ok()?;
    match resp.status().as_u16() {
        404 => Some(false),
        s if (200..300).contains(&s) => {
            let body: serde_json::Value = resp.json().await.ok()?;
            Some(body["result"]["deleted_at"].is_null())
        }
        _ => None,
    }
}

// ── Cloudflare self-hosted app provisioning ─────────────────────────────
//
// The CP provisions Cloudflare self-hosted apps as routing bypasses
// only. Browser auth is enforced in DD via GitHub App OAuth; machine
// paths use in-code auth (ITA for /register + /ingress/replace,
// GitHub Actions OIDC for agent /deploy + /exec).

/// List all Cloudflare self-hosted apps, return the full app JSON for
/// one whose primary or included `domain` exactly matches `domain`, or
/// `None`.
async fn find_app_by_domain(
    http: &Client,
    cf: &CfCreds,
    domain: &str,
) -> Result<Option<serde_json::Value>> {
    let resp = call(
        http,
        cf,
        Method::GET,
        &format!("/accounts/{}/access/apps?per_page=1000", cf.account_id),
        None,
    )
    .await?;
    Ok(resp["result"].as_array().and_then(|items| {
        items
            .iter()
            .find(|a| routing_app_matches_domain(a, domain))
            .cloned()
    }))
}

fn routing_app_matches_domain(app: &serde_json::Value, domain: &str) -> bool {
    if app["domain"].as_str() == Some(domain) {
        return true;
    }
    if app["destinations"].as_array().is_some_and(|items| {
        items
            .iter()
            .any(|d| d["type"].as_str() == Some("public") && d["uri"].as_str() == Some(domain))
    }) {
        return true;
    }
    app["self_hosted_domains"].as_array().is_some_and(|items| {
        items.iter().any(|d| {
            d.as_str() == Some(domain)
                || d["domain"].as_str() == Some(domain)
                || d["uri"].as_str() == Some(domain)
        })
    })
}

fn bypass_policy() -> serde_json::Value {
    serde_json::json!({
        "name": "dd-bypass",
        "decision": "bypass",
        "include": [ { "everyone": {} } ],
    })
}

/// Idempotently upsert a Cloudflare self-hosted app at `domain` with the
/// provided policy list. Matches on exact `domain`; updates in place
/// if present, creates otherwise.
async fn ensure_routing_app(
    http: &Client,
    cf: &CfCreds,
    name: &str,
    domain: &str,
    policies: Vec<serde_json::Value>,
) -> Result<String> {
    let body = serde_json::json!({
        "name": name,
        "domain": domain,
        "destinations": [
            {
                "type": "public",
                "uri": domain,
            }
        ],
        "type": "self_hosted",
        "session_duration": "24h",
        "app_launcher_visible": false,
        "policies": policies,
    });
    if let Some(existing) = find_app_by_domain(http, cf, domain).await? {
        let id = existing["id"].as_str().unwrap_or_default().to_string();
        call(
            http,
            cf,
            Method::PUT,
            &format!("/accounts/{}/access/apps/{id}", cf.account_id),
            Some(body),
        )
        .await?;
        return Ok(id);
    }
    let resp = call(
        http,
        cf,
        Method::POST,
        &format!("/accounts/{}/access/apps", cf.account_id),
        Some(body),
    )
    .await?;
    resp["result"]["id"]
        .as_str()
        .map(String::from)
        .ok_or_else(|| Error::Upstream(format!("Cloudflare app create missing id for {domain}")))
}

/// Idempotently upsert a path-scoped public routing app. Anyone can
/// reach `domain/path` without authentication; used for /health,
/// /register (which is authenticated by ITA in-app), and every
/// workload-exposed URL.
async fn ensure_public_route_app(
    http: &Client,
    cf: &CfCreds,
    name: &str,
    domain: &str,
) -> Result<()> {
    ensure_routing_app(http, cf, name, domain, vec![bypass_policy()]).await?;
    Ok(())
}

/// Hostname labels that run DD-authenticated admin workloads.
const ADMIN_LABELS: &[&str] = &["shell"];

fn is_admin_label(label: &str) -> bool {
    ADMIN_LABELS.contains(&label)
}

/// Provision the CP's Cloudflare routing apps at startup.
///
/// Routes created:
///   - `{hostname}` — dashboard, app-layer GitHub auth
///   - `{hostname}-shell` — dd-shell, app-layer GitHub auth
///   - `{hostname}/health` — public (read-only fleet health;
///     also carries the Noise pre-handshake `{quote_b64, pubkey_hex}`)
///   - `{hostname}/api/agents` — read-only agent list
///   - `{hostname}/noise/ws` — Noise_IK-gated in code
///   - `{hostname}/register` — ITA-gated in code
///   - `{hostname}/ingress/replace` — ITA-gated in code
pub async fn provision_cp_routing(
    http: &Client,
    cf: &CfCreds,
    env: &str,
    hostname: &str,
    workload_labels: &[String],
) -> Result<()> {
    ensure_routing_app(
        http,
        cf,
        &format!("dd-{env}-cp"),
        hostname,
        vec![bypass_policy()],
    )
    .await?;

    // One Cloudflare routing app per CP-exposed workload label.
    // Admin labels still use bypass policies: DD checks browser sessions
    // in-code, and non-admin workload URLs remain public by default.
    let desired: std::collections::HashSet<String> = workload_labels
        .iter()
        .map(|l| label_hostname(hostname, l))
        .collect();
    for label in workload_labels {
        let domain = label_hostname(hostname, label);
        if is_admin_label(label) {
            ensure_routing_app(
                http,
                cf,
                &format!("dd-{env}-cp-{label}"),
                &domain,
                vec![bypass_policy()],
            )
            .await?;
        } else {
            ensure_public_route_app(http, cf, &format!("dd-{env}-cp-{label}"), &domain).await?;
        }
    }

    // Reap any stale workload apps under the CP's flat subdomain space
    // that are no longer in the desired label set. Shape is
    // `{base}-{label}.{tld}` — prefix+suffix match so we don't touch
    // the CP's own root human app or any bypass-path apps.
    let (base, tld) = hostname.split_once('.').unwrap_or((hostname, ""));
    let prefix = format!("{base}-");
    let suffix_tld = format!(".{tld}");
    if let Ok(resp) = call(
        http,
        cf,
        Method::GET,
        &format!("/accounts/{}/access/apps?per_page=1000", cf.account_id),
        None,
    )
    .await
    {
        if let Some(items) = resp["result"].as_array() {
            for app in items {
                let Some(domain) = app["domain"].as_str() else {
                    continue;
                };
                if !(domain.starts_with(&prefix) && domain.ends_with(&suffix_tld)) {
                    continue;
                }
                if desired.contains(domain) {
                    continue;
                }
                if let Some(id) = app["id"].as_str() {
                    let _ = call(
                        http,
                        cf,
                        Method::DELETE,
                        &format!("/accounts/{}/access/apps/{id}", cf.account_id),
                        None,
                    )
                    .await;
                }
            }
        }
    }
    // One-shot reap: any prior deploy left behind a
    // `dd-{env}-cp-noise-attest` route fronting `{hostname}/attest`.
    // The attest route is gone, so the route has no job. The workload
    // sweep above is subdomain-scoped and won't catch path-scoped routes,
    // so delete it explicitly here. Lookup-by-domain is idempotent;
    // no-op once the app is gone.
    if let Ok(Some(stale)) = find_app_by_domain(http, cf, &format!("{hostname}/attest")).await {
        if let Some(id) = stale["id"].as_str() {
            let _ = call(
                http,
                cf,
                Method::DELETE,
                &format!("/accounts/{}/access/apps/{id}", cf.account_id),
                None,
            )
            .await;
        }
    }

    for (path_suffix, label) in [
        ("/health", "health"),
        ("/api/agents", "api-agents"),
        ("/api/v1/devices/trusted", "api-devices-trusted"),
        ("/api/v1/admin/export", "api-admin-export"),
        // The Noise pre-handshake bundle (`quote_b64` + `pubkey_hex`)
        // now rides on `/health` — `/attest` was deleted. Only the
        // handshake itself still needs its own bypass.
        ("/noise/ws", "noise-ws"),
        ("/register", "register"),
        ("/ingress/replace", "ingress"),
    ] {
        ensure_public_route_app(
            http,
            cf,
            &format!("dd-{env}-cp-{label}"),
            &format!("{hostname}{path_suffix}"),
        )
        .await?;
    }
    Ok(())
}

/// Provision routing apps for one agent. Called at /register and again
/// at /ingress/replace so newly-exposed workload labels get their
/// public routes and labels that disappeared get cleaned up.
///
///   - `{agent}.{domain}` — browser dashboard, app-layer auth
///   - `<admin-label>.{agent}.{domain}` for labels in
///     `ADMIN_LABELS` — app-layer auth
///   - `dd-{env}-api-{uuid}.{domain}` — machine API only
///   - `{agent}.{domain}/health` — public; carries the Noise
///     pre-handshake `{quote_b64, pubkey_hex}` in its response
///   - `{agent}.{domain}/deploy` — GH-OIDC-gated in code
///   - `{agent}.{domain}/exec` — GH-OIDC-gated in code
///   - `{agent}.{domain}/owner` — fleet-GH-OIDC-gated in code
///   - `{agent}.{domain}/logs/*` — GH-OIDC-gated in code
///   - `{agent}.{domain}/noise/ws` — Noise_IK-gated in code
///     against the CP-trusted paired device pubkey set
///   - `{label}.{agent}.{domain}` for other labels — workload
///     URLs are public by default.
///   - Any existing `*.{agent}.{domain}` app whose label is no longer
///     in `workload_labels` is deleted.
pub async fn provision_agent_routing(
    http: &Client,
    cf: &CfCreds,
    env: &str,
    agent_hostname: &str,
    workload_labels: &[String],
) -> Result<()> {
    ensure_routing_app(
        http,
        cf,
        &format!("dd-{env}-agent-{agent_hostname}"),
        agent_hostname,
        vec![bypass_policy()],
    )
    .await?;
    for (suffix, label) in [
        ("/health", "health"),
        ("/deploy", "deploy"),
        ("/exec", "exec"),
        ("/owner", "owner"),
        ("/logs", "logs"),
        // The in-process Noise gateway (merged into the agent's
        // router in agent.rs) lives on the same port + hostname as
        // /deploy + /exec, so a direct bastion-app attach needs the
        // same bypass treatment the CP hostname already gets. The
        // pre-handshake quote bundle is served by /health above
        // (collapsed from the old /attest), so only the handshake
        // WebSocket needs its own entry here. Noise_IK against the
        // paired device pubkey set is the gate.
        ("/noise/ws", "noise-ws"),
    ] {
        ensure_public_route_app(
            http,
            cf,
            &format!("dd-{env}-agent-{agent_hostname}-{label}"),
            &format!("{agent_hostname}{suffix}"),
        )
        .await?;
    }

    let desired: std::collections::HashSet<String> = workload_labels
        .iter()
        .map(|l| extra_hostname(agent_hostname, l))
        .collect();
    for label in workload_labels {
        let domain = extra_hostname(agent_hostname, label);
        if is_admin_label(label) {
            ensure_routing_app(
                http,
                cf,
                &format!("dd-{env}-workload-{domain}"),
                &domain,
                vec![bypass_policy()],
            )
            .await?;
        } else {
            ensure_public_route_app(http, cf, &format!("dd-{env}-workload-{domain}"), &domain)
                .await?;
        }
    }

    // Reap any stale workload apps under this agent that are no
    // longer in the desired set. Flat-subdomain workload URLs look
    // like `{base}-{label}.{tld}` (one level deep — see
    // `label_hostname` for why). Prefix + suffix match so we don't
    // accidentally delete the agent's own human app at
    // `{base}.{tld}`.
    let (base, tld) = agent_hostname
        .split_once('.')
        .unwrap_or((agent_hostname, ""));
    let prefix = format!("{base}-");
    let suffix_tld = format!(".{tld}");
    let agent_api_domain = agent_api_hostname(agent_hostname);
    let resp = call(
        http,
        cf,
        Method::GET,
        &format!("/accounts/{}/access/apps?per_page=1000", cf.account_id),
        None,
    )
    .await?;
    if let Some(items) = resp["result"].as_array() {
        for app in items {
            let Some(domain) = app["domain"].as_str() else {
                continue;
            };
            if domain != agent_api_domain
                && !(domain.starts_with(&prefix) && domain.ends_with(&suffix_tld))
            {
                continue;
            }
            if desired.contains(domain) {
                continue;
            }
            if let Some(id) = app["id"].as_str() {
                let _ = call(
                    http,
                    cf,
                    Method::DELETE,
                    &format!("/accounts/{}/access/apps/{id}", cf.account_id),
                    None,
                )
                .await;
            }
        }
    }
    Ok(())
}

/// Cleanup hook invoked by the collector's orphan-GC path and by any
/// explicit reap: delete the agent's dashboard route, its /health
/// route, and every `*.{agent_hostname}` workload route in one sweep.
pub async fn delete_routing_apps_for(http: &Client, cf: &CfCreds, agent_hostname: &str) {
    let Ok(resp) = call(
        http,
        cf,
        Method::GET,
        &format!("/accounts/{}/access/apps?per_page=1000", cf.account_id),
        None,
    )
    .await
    else {
        return;
    };
    let Some(items) = resp["result"].as_array() else {
        return;
    };
    let (base, tld) = agent_hostname
        .split_once('.')
        .unwrap_or((agent_hostname, ""));
    let prefix = format!("{base}-");
    let suffix_tld = format!(".{tld}");
    let agent_api_domain = agent_api_hostname(agent_hostname);
    for app in items {
        let Some(domain) = app["domain"].as_str() else {
            continue;
        };
        // Match: the agent hostname itself, any path-scoped app
        // under it, and flat-subdomain workload URLs of the shape
        // `{base}-*.{tld}`.
        let matches_agent = domain == agent_hostname
            || domain.starts_with(&format!("{agent_hostname}/"))
            || domain == agent_api_domain
            || (domain.starts_with(&prefix) && domain.ends_with(&suffix_tld));
        if !matches_agent {
            continue;
        }
        if let Some(id) = app["id"].as_str() {
            let _ = call(
                http,
                cf,
                Method::DELETE,
                &format!("/accounts/{}/access/apps/{id}", cf.account_id),
                None,
            )
            .await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_hostname_flattens_to_one_level() {
        assert_eq!(
            label_hostname("pr-144.devopsdefender.com", "shell"),
            "pr-144-shell.devopsdefender.com"
        );
        assert_eq!(
            label_hostname("dd-pr-144-agent-abc.devopsdefender.com", "api"),
            "dd-pr-144-agent-abc-api.devopsdefender.com"
        );
        assert_eq!(
            label_hostname("app.devopsdefender.com", "shell"),
            "app-shell.devopsdefender.com"
        );
    }

    #[test]
    fn agent_api_hostname_uses_reserved_flat_subdomain() {
        assert_eq!(
            agent_api_hostname("dd-pr-144-agent-abc.devopsdefender.com"),
            "dd-pr-144-api-abc.devopsdefender.com"
        );
        assert_eq!(
            agent_api_hostname(
                "dd-production-agent-73744f46-0a97-4628-ad8b-dd37a07b1e10.devopsdefender.com"
            ),
            "dd-production-api-73744f46-0a97-4628-ad8b-dd37a07b1e10.devopsdefender.com"
        );
    }

    #[test]
    fn label_hostname_handles_dotless_hostname() {
        assert_eq!(label_hostname("localhost", "shell"), "localhost-shell");
    }

    #[test]
    fn routing_app_matches_primary_domain() {
        let app = serde_json::json!({
            "domain": "agent.example.com/health",
            "type": "self_hosted",
        });
        assert!(routing_app_matches_domain(&app, "agent.example.com/health"));
        assert!(!routing_app_matches_domain(
            &app,
            "agent.example.com/deploy"
        ));
    }

    #[test]
    fn routing_app_matches_public_destination() {
        let app = serde_json::json!({
            "domain": "agent.example.com",
            "destinations": [
                { "type": "public", "uri": "agent.example.com/health" },
                { "type": "private", "hostname": "agent.internal" }
            ],
        });
        assert!(routing_app_matches_domain(&app, "agent.example.com/health"));
        assert!(!routing_app_matches_domain(
            &app,
            "agent.example.com/deploy"
        ));
    }
}
