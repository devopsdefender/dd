//! Cloudflare tunnel + DNS client.
//!
//! Naming convention (enforced here): CP tunnels are `dd-{env}-cp-{uuid}`,
//! agent tunnels are `dd-{env}-agent-{uuid}`. The suffix is how the
//! collector knows which tunnels to scrape and STONITH knows which to
//! target, without ever fetching the ingress config.

use base64::Engine;
use reqwest::{Client, Method};
use serde::{Deserialize, Serialize};

use crate::config::{CfAccess, CfCreds};

/// Paths under the wildcard Access domain that programmatic callers
/// (CI probes, agent → CP handshake, slopandmop browser → agent
/// deploy) hit with Bearer PAT. The CP upserts a bypass app for
/// each on startup so CF Access doesn't 302 them to the login page
/// before the Bearer reaches the origin. The app still enforces
/// Bearer PAT + `verify_pat` internally — "bypass" at CF only means
/// "don't challenge at the edge."
pub const BYPASS_PATHS: &[&str] = &[
    "health",
    "cp/attest",
    "register",
    "ingress/replace",
    "deploy",
    "exec",
];
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

/// Upsert the CF Access bypass apps for the programmatic paths
/// listed in `BYPASS_PATHS`. Each one is a self-hosted app on the
/// wildcard domain `*.{cf.domain}/{path}` with a single bypass
/// policy (`include: everyone`). CF Access matches longest-domain
/// first, so these override the global `*.{cf.domain}` allow app
/// for their specific paths. Idempotent — skip/update on the app's
/// `name`. Best-effort: log-and-continue on error so the CP still
/// starts if CF Access isn't fully set up yet.
pub async fn ensure_bypass_apps(http: &Client, cf: &CfCreds) -> Result<()> {
    let existing = call(
        http,
        cf,
        Method::GET,
        &format!("/accounts/{}/access/apps?per_page=200", cf.account_id),
        None,
    )
    .await
    .ok();
    let existing_map: std::collections::HashMap<String, String> = existing
        .as_ref()
        .and_then(|r| r["result"].as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|a| {
                    let name = a["name"].as_str()?.to_string();
                    let id = a["id"].as_str()?.to_string();
                    Some((name, id))
                })
                .collect()
        })
        .unwrap_or_default();

    for path in BYPASS_PATHS {
        let name = format!("dd-bypass-{}", path.replace('/', "-"));
        let domain = format!("*.{}/{path}", cf.domain);
        let body = serde_json::json!({
            "name": name,
            "type": "self_hosted",
            "domain": domain,
            "session_duration": "24h",
            "auto_redirect_to_identity": false,
        });
        let app_id = if let Some(id) = existing_map.get(&name) {
            let _ = call(
                http,
                cf,
                Method::PUT,
                &format!("/accounts/{}/access/apps/{id}", cf.account_id),
                Some(body),
            )
            .await;
            id.clone()
        } else {
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
                .ok_or_else(|| Error::Upstream(format!("access app {name}: missing id")))?
                .to_string()
        };
        let policies = call(
            http,
            cf,
            Method::GET,
            &format!("/accounts/{}/access/apps/{app_id}/policies", cf.account_id),
            None,
        )
        .await
        .ok();
        let have_bypass = policies
            .as_ref()
            .and_then(|p| p["result"].as_array())
            .map(|arr| arr.iter().any(|p| p["decision"].as_str() == Some("bypass")))
            .unwrap_or(false);
        if !have_bypass {
            let _ = call(
                http,
                cf,
                Method::POST,
                &format!("/accounts/{}/access/apps/{app_id}/policies", cf.account_id),
                Some(serde_json::json!({
                    "name": "bypass",
                    "decision": "bypass",
                    "include": [{"everyone": {}}],
                    "precedence": 1,
                })),
            )
            .await;
        }
        eprintln!("cp: CF Access bypass app ensured for {domain}");
    }
    Ok(())
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
