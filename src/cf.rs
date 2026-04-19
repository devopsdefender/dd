//! Cloudflare tunnel + DNS client.
//!
//! Naming convention (enforced here): CP tunnels are `dd-{env}-cp-{uuid}`,
//! agent tunnels are `dd-{env}-agent-{uuid}`. The suffix is how the
//! collector knows which tunnels to scrape and STONITH knows which to
//! target, without ever fetching the ingress config.

use base64::Engine;
use reqwest::{Client, Method};
use serde::{Deserialize, Serialize};

use crate::config::{AccessAllow, CfAccess, CfCreds};
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
    Ok(resp.json().await?)
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
    let resp = call(
        http,
        cf,
        Method::POST,
        &format!("/accounts/{}/cfd_tunnel", cf.account_id),
        Some(serde_json::json!({"name": name, "tunnel_secret": secret})),
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
                "hostname": format!("{label}.{hostname}"),
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
        let extra = format!("{label}.{hostname}");
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
    let resp = call(
        http,
        cf,
        Method::GET,
        &format!("/accounts/{}/cfd_tunnel?is_deleted=false", cf.account_id),
        None,
    )
    .await?;
    Ok(resp["result"].as_array().cloned().unwrap_or_default())
}

/// Discover Cloudflare Access origin-JWT verifier metadata for a hostname
/// from the account's configured Access applications. Exact hostname apps
/// win over wildcard apps. Returns `Ok(None)` when Access is not configured
/// for the hostname.
pub async fn discover_access(
    http: &Client,
    cf: &CfCreds,
    hostname: &str,
) -> Result<Option<CfAccess>> {
    let org = call(
        http,
        cf,
        Method::GET,
        &format!("/accounts/{}/access/organizations", cf.account_id),
        None,
    )
    .await?;
    let auth_domain = org["result"]["auth_domain"]
        .as_str()
        .ok_or_else(|| Error::Upstream("CF Access organization: missing auth_domain".into()))?;
    let issuer = normalize_access_issuer(auth_domain);

    let apps = call(
        http,
        cf,
        Method::GET,
        &format!("/accounts/{}/access/apps?per_page=200", cf.account_id),
        None,
    )
    .await?;
    let Some(items) = apps["result"].as_array() else {
        return Ok(None);
    };

    let mut best: Option<(u8, String)> = None;
    for app in items {
        if app["type"].as_str() != Some("self_hosted") {
            continue;
        }
        let Some(aud) = app["aud"].as_str() else {
            continue;
        };
        let score = access_app_match_score(app, hostname);
        if score > best.as_ref().map(|(s, _)| *s).unwrap_or(0) {
            best = Some((score, aud.to_string()));
        }
    }

    Ok(best.map(|(_, aud)| CfAccess {
        jwks_url: format!("{issuer}/cdn-cgi/access/certs"),
        issuer,
        audiences: vec![aud],
    }))
}

fn normalize_access_issuer(raw: &str) -> String {
    let raw = raw.trim().trim_end_matches('/');
    if raw.starts_with("https://") || raw.starts_with("http://") {
        raw.to_string()
    } else {
        format!("https://{raw}")
    }
}

fn access_app_match_score(app: &serde_json::Value, hostname: &str) -> u8 {
    access_app_patterns(app)
        .into_iter()
        .filter_map(|pattern| hostname_pattern_score(&pattern, hostname))
        .max()
        .unwrap_or(0)
}

fn access_app_patterns(app: &serde_json::Value) -> Vec<String> {
    let mut patterns = Vec::new();
    if let Some(domain) = app["domain"].as_str() {
        patterns.push(domain.to_string());
    }
    if let Some(items) = app["self_hosted_domains"].as_array() {
        patterns.extend(items.iter().filter_map(|v| v.as_str().map(String::from)));
    }
    if let Some(items) = app["destinations"].as_array() {
        patterns.extend(
            items
                .iter()
                .filter_map(|v| v["uri"].as_str().map(String::from)),
        );
    }
    patterns
}

fn hostname_pattern_score(pattern: &str, hostname: &str) -> Option<u8> {
    let pattern = pattern_host(pattern)?;
    if pattern == hostname {
        return Some(2);
    }
    let suffix = pattern.strip_prefix("*.")?;
    if hostname != suffix && hostname.ends_with(&format!(".{suffix}")) {
        Some(1)
    } else {
        None
    }
}

fn pattern_host(pattern: &str) -> Option<String> {
    let without_scheme = pattern
        .trim()
        .strip_prefix("https://")
        .or_else(|| pattern.trim().strip_prefix("http://"))
        .unwrap_or_else(|| pattern.trim());
    let host = without_scheme
        .split('/')
        .next()
        .unwrap_or_default()
        .trim()
        .trim_end_matches('.');
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

/// Find the account's GitHub Access IdP. Required for the `Org` allow
/// path: CF Access's `github-organization` policy include references
/// a GitHub IdP UUID, and there's no code path that works without
/// one. A GitHub IdP has to be created manually in the Cloudflare
/// Access dashboard exactly once per account.
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
        .into_iter()
        .flatten()
        .find(|idp| idp["type"].as_str() == Some("github"))
        .and_then(|idp| idp["id"].as_str().map(String::from))
        .ok_or_else(|| {
            Error::Upstream(
                "no GitHub IdP found in CF Access; add one at dash.cloudflare.com → Zero Trust → Settings → Authentication → Login methods".into(),
            )
        })
}

/// Build the policy `include` block for an allow policy given the
/// resolved `AccessAllow` shape. Org case uses `github-organization`
/// (requires the GitHub IdP UUID); email case is one `email` include
/// per address so each is independently matchable.
fn access_allow_include(allow: &AccessAllow, github_idp: &str) -> serde_json::Value {
    match allow {
        AccessAllow::Org(name) => serde_json::json!([{
            "github-organization": { "name": name, "identity_provider_id": github_idp }
        }]),
        AccessAllow::Emails(emails) => serde_json::Value::Array(
            emails
                .iter()
                .map(|e| serde_json::json!({ "email": { "email": e } }))
                .collect(),
        ),
    }
}

/// Ensure a self-hosted Access app exists covering `app_domain`
/// (which may include a path like `"app.example.com/register"` for
/// path-scoped bypass apps) with the named single policy attached.
/// Idempotent — app is matched by `name` and updated in place if it
/// already exists. Returns the app's `aud`.
#[allow(clippy::too_many_arguments)]
async fn ensure_access_app(
    http: &Client,
    cf: &CfCreds,
    name: &str,
    app_domain: &str,
    session_duration: &str,
    policy_name: &str,
    policy_decision: &str,
    policy_include: serde_json::Value,
) -> Result<String> {
    // Find existing app by name.
    let apps = call(
        http,
        cf,
        Method::GET,
        &format!("/accounts/{}/access/apps?per_page=200", cf.account_id),
        None,
    )
    .await?;
    let existing = apps["result"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|a| a["name"].as_str() == Some(name))
        .cloned();

    let app_body = serde_json::json!({
        "name": name,
        "type": "self_hosted",
        "domain": app_domain,
        "session_duration": session_duration,
        "auto_redirect_to_identity": false,
    });

    let app = if let Some(e) = existing {
        let id = e["id"]
            .as_str()
            .ok_or_else(|| Error::Upstream(format!("access app {name}: missing id")))?;
        call(
            http,
            cf,
            Method::PUT,
            &format!("/accounts/{}/access/apps/{id}", cf.account_id),
            Some(app_body),
        )
        .await?
    } else {
        call(
            http,
            cf,
            Method::POST,
            &format!("/accounts/{}/access/apps", cf.account_id),
            Some(app_body),
        )
        .await?
    };

    let app_id = app["result"]["id"]
        .as_str()
        .ok_or_else(|| Error::Upstream(format!("access app {name}: missing id after upsert")))?
        .to_string();
    let aud = app["result"]["aud"]
        .as_str()
        .ok_or_else(|| Error::Upstream(format!("access app {name}: missing aud")))?
        .to_string();

    // Ensure the single policy attached to this app matches what we want.
    let policies = call(
        http,
        cf,
        Method::GET,
        &format!("/accounts/{}/access/apps/{app_id}/policies", cf.account_id),
        None,
    )
    .await?;
    let existing_policies: Vec<&serde_json::Value> = policies["result"]
        .as_array()
        .into_iter()
        .flatten()
        .collect();

    let policy_body = serde_json::json!({
        "name": policy_name,
        "decision": policy_decision,
        "include": policy_include,
        "precedence": 1,
    });

    if let Some(p) = existing_policies
        .iter()
        .find(|p| p["name"].as_str() == Some(policy_name))
    {
        let pid = p["id"]
            .as_str()
            .ok_or_else(|| Error::Upstream(format!("access policy {policy_name}: missing id")))?;
        call(
            http,
            cf,
            Method::PUT,
            &format!(
                "/accounts/{}/access/apps/{app_id}/policies/{pid}",
                cf.account_id
            ),
            Some(policy_body),
        )
        .await?;
    } else {
        call(
            http,
            cf,
            Method::POST,
            &format!("/accounts/{}/access/apps/{app_id}/policies", cf.account_id),
            Some(policy_body),
        )
        .await?;
    }

    // Strip any stale policies attached to this app — idempotence
    // across schema changes.
    for p in &existing_policies {
        if p["name"].as_str() == Some(policy_name) {
            continue;
        }
        let Some(pid) = p["id"].as_str() else {
            continue;
        };
        let _ = call(
            http,
            cf,
            Method::DELETE,
            &format!(
                "/accounts/{}/access/apps/{app_id}/policies/{pid}",
                cf.account_id
            ),
            None,
        )
        .await;
    }

    Ok(aud)
}

/// Provision the Access apps covering the CP hostname:
///
/// - **Main app** (`<hostname>`) — allow policy gating everything
///   behind the configured `AccessAllow`.
/// - **Bypass apps** (`<hostname>/register`, `<hostname>/ingress/replace`)
///   — `decision: bypass`, include everyone. These paths carry
///   agent → CP Bearer-PAT calls that can't present a CF Access JWT.
///
/// Returns the main app's `CfAccess` (issuer + audience + JWKS URL)
/// ready to seed the `AccessValidator`. Idempotent across restarts.
pub async fn provision_cp_access(
    http: &Client,
    cf: &CfCreds,
    env_label: &str,
    hostname: &str,
    allow: &AccessAllow,
) -> Result<CfAccess> {
    let idp = match allow {
        AccessAllow::Org(_) => github_idp_uuid(http, cf).await?,
        AccessAllow::Emails(_) => String::new(),
    };
    let main_aud = ensure_access_app(
        http,
        cf,
        &format!("dd-{env_label}-cp"),
        hostname,
        "24h",
        "allow owner",
        "allow",
        access_allow_include(allow, &idp),
    )
    .await?;

    for path in ["register", "ingress/replace"] {
        ensure_access_app(
            http,
            cf,
            &format!("dd-{env_label}-cp-bypass-{}", path.replace('/', "-")),
            &format!("{hostname}/{path}"),
            "24h",
            "bypass programmatic",
            "bypass",
            serde_json::json!([{ "everyone": {} }]),
        )
        .await?;
    }

    let issuer = access_issuer(http, cf).await?;
    Ok(CfAccess {
        jwks_url: format!("{issuer}/cdn-cgi/access/certs"),
        issuer,
        audiences: vec![main_aud],
    })
}

/// Provision a single allow-policy Access app covering an agent's
/// main hostname. Called from `/register` for each agent. Returns
/// the `CfAccess` validator metadata the CP sends back to the agent
/// in its bootstrap payload.
pub async fn provision_agent_access(
    http: &Client,
    cf: &CfCreds,
    env_label: &str,
    hostname: &str,
    allow: &AccessAllow,
) -> Result<CfAccess> {
    let idp = match allow {
        AccessAllow::Org(_) => github_idp_uuid(http, cf).await?,
        AccessAllow::Emails(_) => String::new(),
    };
    let aud = ensure_access_app(
        http,
        cf,
        &format!("dd-{env_label}-agent-{}", hostname),
        hostname,
        "24h",
        "allow owner",
        "allow",
        access_allow_include(allow, &idp),
    )
    .await?;
    let issuer = access_issuer(http, cf).await?;
    Ok(CfAccess {
        jwks_url: format!("{issuer}/cdn-cgi/access/certs"),
        issuer,
        audiences: vec![aud],
    })
}

/// Delete any Access apps we provisioned for an agent hostname.
/// Best-effort — failures don't propagate; a stray app gets cleaned
/// up the next time the user edits it or we re-reap.
pub async fn delete_access_apps_for(http: &Client, cf: &CfCreds, hostname: &str) {
    let Ok(resp) = call(
        http,
        cf,
        Method::GET,
        &format!("/accounts/{}/access/apps?per_page=200", cf.account_id),
        None,
    )
    .await
    else {
        return;
    };
    let Some(items) = resp["result"].as_array() else {
        return;
    };
    for app in items {
        let Some(id) = app["id"].as_str() else {
            continue;
        };
        let Some(d) = app["domain"].as_str() else {
            continue;
        };
        let host = d.split('/').next().unwrap_or(d);
        if host == hostname {
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

async fn access_issuer(http: &Client, cf: &CfCreds) -> Result<String> {
    let org = call(
        http,
        cf,
        Method::GET,
        &format!("/accounts/{}/access/organizations", cf.account_id),
        None,
    )
    .await?;
    let auth_domain = org["result"]["auth_domain"]
        .as_str()
        .ok_or_else(|| Error::Upstream("CF Access organization: missing auth_domain".into()))?;
    Ok(normalize_access_issuer(auth_domain))
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

#[cfg(test)]
mod tests {
    use super::{access_app_match_score, hostname_pattern_score, normalize_access_issuer};

    #[test]
    fn issuer_is_normalized_to_https_url() {
        assert_eq!(
            normalize_access_issuer("team.cloudflareaccess.com"),
            "https://team.cloudflareaccess.com"
        );
        assert_eq!(
            normalize_access_issuer("https://team.cloudflareaccess.com/"),
            "https://team.cloudflareaccess.com"
        );
    }

    #[test]
    fn hostname_patterns_match_exact_and_wildcard() {
        assert_eq!(
            hostname_pattern_score("app.example.com", "app.example.com"),
            Some(2)
        );
        assert_eq!(
            hostname_pattern_score("*.example.com", "agent.example.com"),
            Some(1)
        );
        assert_eq!(hostname_pattern_score("*.example.com", "example.com"), None);
        assert_eq!(
            hostname_pattern_score("*.example.com", "badexample.com"),
            None
        );
    }

    #[test]
    fn access_app_match_score_reads_all_supported_fields() {
        let app = serde_json::json!({
            "domain": "old.example.com",
            "self_hosted_domains": ["*.example.com"],
            "destinations": [{"type": "public", "uri": "https://exact.example.com/path"}]
        });

        assert_eq!(access_app_match_score(&app, "agent.example.com"), 1);
        assert_eq!(access_app_match_score(&app, "exact.example.com"), 2);
        assert_eq!(access_app_match_score(&app, "other.test"), 0);
    }
}
