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
    // to Access apps that appeared created but never matched any
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

/// Turn `(hostname="pr-144.devopsdefender.com", label="term")` into
/// `"pr-144-term.devopsdefender.com"`. Cloudflare's Universal SSL
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
                "hostname": label_hostname(hostname, label),
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
        let extra = label_hostname(hostname, label);
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
    // `per_page=200` — CF's default is 20, and every caller here scans
    // for a name-prefix match. A predecessor CP tunnel sorting off page 1
    // silently breaks both `stonith::kill_old_tunnels` (leaks the old
    // tunnel instead of STONITHing it) and `cp::run`'s hydrate gate
    // (skips hydrate, losing devices + agents on a deploy). 200 is the
    // same cap `.github/workflows/cleanup.yml` uses.
    let resp = call(
        http,
        cf,
        Method::GET,
        &format!(
            "/accounts/{}/cfd_tunnel?is_deleted=false&per_page=200",
            cf.account_id
        ),
        None,
    )
    .await?;
    Ok(resp["result"].as_array().cloned().unwrap_or_default())
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

// ── CF Access (Zero Trust) provisioning ────────────────────────────────
//
// The CP provisions a handful of Access apps at startup and one human
// app per agent at /register. Everything machine-to-machine uses
// bypass apps + in-code auth (ITA for /register + /ingress/replace,
// GitHub Actions OIDC for agent /deploy + /exec). No service tokens,
// no External Evaluation — just CF Access for humans and bypass for
// everything else.

/// Return the UUID of the GitHub login method in this CF Access
/// account, if configured. Manual one-time setup in the Cloudflare
/// dashboard (Zero Trust → Settings → Authentication → Login methods
/// → add GitHub) is required before the CP can provision org-based
/// policies.
pub async fn github_idp_uuid(http: &Client, cf: &CfCreds) -> Result<String> {
    let resp = call(
        http,
        cf,
        Method::GET,
        &format!("/accounts/{}/access/identity_providers", cf.account_id),
        None,
    )
    .await?;
    resp["result"]
        .as_array()
        .and_then(|items| items.iter().find(|i| i["type"].as_str() == Some("github")))
        .and_then(|i| i["id"].as_str())
        .map(String::from)
        .ok_or_else(|| {
            Error::Upstream(
                "CF Access has no GitHub identity provider — add one in \
                 Zero Trust → Settings → Authentication → Login methods"
                    .into(),
            )
        })
}

/// List all Access apps, return the full app JSON for one whose primary
/// or included `domain` exactly matches `domain`, or `None`.
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
            .find(|a| a["domain"].as_str() == Some(domain))
            .cloned()
    }))
}

/// Build the two-include GitHub-org-OR-admin-email policy used for
/// every human-facing app (CP root + per-agent dashboard).
fn human_policy(owner: &str, admin_email: &str, gh_idp_uuid: &str) -> serde_json::Value {
    serde_json::json!({
        "name": "dd-human",
        "decision": "allow",
        "include": [
            { "github-organization": { "name": owner, "identity_provider_id": gh_idp_uuid } },
            { "email": { "email": admin_email } }
        ],
    })
}

fn bypass_policy() -> serde_json::Value {
    serde_json::json!({
        "name": "dd-bypass",
        "decision": "bypass",
        "include": [ { "everyone": {} } ],
    })
}

/// Idempotently upsert a self-hosted Access app at `domain` with the
/// provided policy list. Matches on exact `domain`; updates in place
/// if present, creates otherwise.
async fn ensure_app(
    http: &Client,
    cf: &CfCreds,
    name: &str,
    domain: &str,
    policies: Vec<serde_json::Value>,
) -> Result<String> {
    let body = serde_json::json!({
        "name": name,
        "domain": domain,
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
        .ok_or_else(|| Error::Upstream(format!("Access app create missing id for {domain}")))
}

/// Idempotently upsert a path-scoped bypass Access app. Anyone can
/// reach `domain/path` without authentication; used for /health,
/// /register (which is authenticated by ITA in-app), and every
/// workload-exposed URL.
async fn ensure_bypass_app(http: &Client, cf: &CfCreds, name: &str, domain: &str) -> Result<()> {
    ensure_app(http, cf, name, domain, vec![bypass_policy()]).await?;
    Ok(())
}

/// Hostname labels that run admin workloads (shell access, future
/// log viewer, future metrics panel). These get a human CF Access
/// app, not a public bypass — otherwise exposing ttyd on a public
/// subdomain would be a free shell for the internet.
///
/// - `term` — legacy ttyd subdomain (kept admin-gated for older deploys).
/// - `block` — ttyd workload; exposing it without auth is the same
///   "free shell for the internet" risk.
const ADMIN_LABELS: &[&str] = &["term", "block"];

fn is_admin_label(label: &str) -> bool {
    ADMIN_LABELS.contains(&label)
}

/// Provision the CP's Access apps at startup.
///
/// Apps created:
///   - Human: `{hostname}` — GitHub org or admin email (dashboard, /agent/*, /cp/*)
///   - Human: `term.{hostname}` — ttyd shell, org members only
///   - Bypass: `{hostname}/health` — public (read-only fleet health;
///     also carries the Noise pre-handshake `{quote_b64, pubkey_hex}`)
///   - Bypass: `{hostname}/api/agents` — read-only agent list
///   - Bypass: `{hostname}/noise/ws` — Noise_IK-gated in code
///   - Bypass: `{hostname}/register` — ITA-gated in code
///   - Bypass: `{hostname}/ingress/replace` — ITA-gated in code
pub async fn provision_cp_access(
    http: &Client,
    cf: &CfCreds,
    env: &str,
    hostname: &str,
    owner: &str,
    admin_email: &str,
    workload_labels: &[String],
) -> Result<()> {
    let idp = github_idp_uuid(http, cf).await?;
    let human = human_policy(owner, admin_email, &idp);

    ensure_app(
        http,
        cf,
        &format!("dd-{env}-cp"),
        hostname,
        vec![human.clone()],
    )
    .await?;

    // One CF Access app per CP-exposed workload label. Admin labels
    // (from `ADMIN_LABELS` — e.g. the ttyd terminal at `block`) get
    // the human policy; anything else gets a public bypass.
    let desired: std::collections::HashSet<String> = workload_labels
        .iter()
        .map(|l| label_hostname(hostname, l))
        .collect();
    for label in workload_labels {
        let domain = label_hostname(hostname, label);
        if is_admin_label(label) {
            ensure_app(
                http,
                cf,
                &format!("dd-{env}-cp-{label}"),
                &domain,
                vec![human_policy(owner, admin_email, &idp)],
            )
            .await?;
        } else {
            ensure_bypass_app(http, cf, &format!("dd-{env}-cp-{label}"), &domain).await?;
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
    // `dd-{env}-cp-noise-attest` bypass app fronting `{hostname}/attest`.
    // The attest route is gone, so the bypass has no job. The workload
    // sweep above is subdomain-scoped and won't catch path-bypass apps,
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
        ensure_bypass_app(
            http,
            cf,
            &format!("dd-{env}-cp-{label}"),
            &format!("{hostname}{path_suffix}"),
        )
        .await?;
    }
    Ok(())
}

/// Provision Access apps for one agent. Called at /register and again
/// at /ingress/replace so newly-exposed workload labels get their
/// bypass apps and labels that disappeared get cleaned up.
///
///   - Human: `{agent}.{domain}` — browser dashboard only
///   - Human: `<admin-label>.{agent}.{domain}` for labels in
///     `ADMIN_LABELS` (ttyd et al) — org members only
///   - Bypass: `{agent}.{domain}/health` — public; carries the Noise
///     pre-handshake `{quote_b64, pubkey_hex}` in its response
///   - Bypass: `{agent}.{domain}/deploy` — GH-OIDC-gated in code
///   - Bypass: `{agent}.{domain}/exec` — GH-OIDC-gated in code
///   - Bypass: `{agent}.{domain}/owner` — fleet-GH-OIDC-gated in code
///   - Bypass: `{agent}.{domain}/logs/*` — GH-OIDC-gated in code
///   - Bypass: `{agent}.{domain}/noise/ws` — Noise_IK-gated in code
///     against the CP-trusted paired device pubkey set
///   - Bypass: `{label}.{agent}.{domain}` for other labels — workload
///     URLs are public by default (this is the nvidia-smi exemption).
///   - Any existing `*.{agent}.{domain}` app whose label is no longer
///     in `workload_labels` is deleted.
pub async fn provision_agent_access(
    http: &Client,
    cf: &CfCreds,
    env: &str,
    agent_hostname: &str,
    owner: &str,
    admin_email: &str,
    workload_labels: &[String],
) -> Result<()> {
    let idp = github_idp_uuid(http, cf).await?;
    let human = human_policy(owner, admin_email, &idp);

    ensure_app(
        http,
        cf,
        &format!("dd-{env}-agent-{agent_hostname}"),
        agent_hostname,
        vec![human],
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
        ensure_bypass_app(
            http,
            cf,
            &format!("dd-{env}-agent-{agent_hostname}-{label}"),
            &format!("{agent_hostname}{suffix}"),
        )
        .await?;
    }

    let desired: std::collections::HashSet<String> = workload_labels
        .iter()
        .map(|l| label_hostname(agent_hostname, l))
        .collect();
    for label in workload_labels {
        let domain = label_hostname(agent_hostname, label);
        if is_admin_label(label) {
            ensure_app(
                http,
                cf,
                &format!("dd-{env}-workload-{domain}"),
                &domain,
                vec![human_policy(owner, admin_email, &idp)],
            )
            .await?;
        } else {
            ensure_bypass_app(http, cf, &format!("dd-{env}-workload-{domain}"), &domain).await?;
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
    Ok(())
}

/// Cleanup hook invoked by the collector's orphan-GC path and by any
/// explicit reap: delete the agent's human app, its /health bypass,
/// and every `*.{agent_hostname}` workload bypass in one sweep.
pub async fn delete_access_apps_for(http: &Client, cf: &CfCreds, agent_hostname: &str) {
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
    for app in items {
        let Some(domain) = app["domain"].as_str() else {
            continue;
        };
        // Match: the agent hostname itself, any path-scoped app
        // under it, and flat-subdomain workload URLs of the shape
        // `{base}-*.{tld}`.
        let matches_agent = domain == agent_hostname
            || domain.starts_with(&format!("{agent_hostname}/"))
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
            label_hostname("pr-144.devopsdefender.com", "term"),
            "pr-144-term.devopsdefender.com"
        );
        assert_eq!(
            label_hostname("dd-pr-144-agent-abc.devopsdefender.com", "gpu"),
            "dd-pr-144-agent-abc-gpu.devopsdefender.com"
        );
        assert_eq!(
            label_hostname("app.devopsdefender.com", "term"),
            "app-term.devopsdefender.com"
        );
    }

    #[test]
    fn label_hostname_handles_dotless_hostname() {
        assert_eq!(label_hostname("localhost", "term"), "localhost-term");
    }
}
