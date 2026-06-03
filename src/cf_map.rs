//! Unified, cross-environment Cloudflare map.
//!
//! Where [`crate::cf_snapshot`] scopes to the serving CP's own env, this
//! enumerates EVERY `dd-*` resource in the account and attributes each to
//! its installation (`production`, every `pr-N`, `bot`, `dogfood`, …) by
//! parsing the env out of the name ([`Env::from_resource_name`]). DNS is
//! attributed by the tunnel its CNAME targets. Resources whose env can't
//! be parsed, or whose CNAME points at a tunnel we no longer have, land in
//! an `(unattributed)` bucket — the leaked state a per-env view can't see.
//!
//! It is built from the Cloudflare API directly, so it reflects reality
//! regardless of which control planes are currently up — the basis for
//! treating CF as the source of truth during recovery. Read-only.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::SystemTime;

use reqwest::Client;
use serde::Serialize;

use crate::cf;
use crate::cf_snapshot::{infer_policy_kind, CfApp, CfDns, CfTunnel};
use crate::collector;
use crate::config::CfCreds;
use crate::env::Env;

const UNATTRIBUTED: &str = "(unattributed)";

#[derive(Debug, Clone, Serialize)]
pub struct CfMap {
    pub fetched_at: String,
    pub cf_account_id: String,
    pub cf_zone_id: String,
    /// True if any of the three CF list calls failed → partial view.
    pub degraded: bool,
    pub cf_fetch_errors: Vec<String>,
    /// The env this map was served from (its CP enriches its own agents).
    pub serving_env: String,
    /// Installations sorted by env label, with `(unattributed)` last.
    pub installations: Vec<Installation>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Installation {
    pub env: String,
    /// `production` | `staging` | `dev` | `preview` | `named` |
    /// `unattributed`.
    pub kind: String,
    /// A non-soft-deleted `dd-{env}-cp-*` tunnel exists → the control
    /// plane for this env is present. `false` = likely leaked (a
    /// torn-down env whose resources linger).
    pub has_live_cp: bool,
    /// The env this CP serves (its in-memory agent store is authoritative
    /// for the live-agent count below).
    pub is_serving_env: bool,
    /// Agents the serving CP currently knows for this env (0 for others —
    /// a CP only holds its own env's store).
    pub known_agents: usize,
    pub tunnels: Vec<CfTunnel>,
    pub dns: Vec<CfDns>,
    pub apps: Vec<CfApp>,
}

#[derive(Default)]
struct Bucket {
    tunnels: Vec<CfTunnel>,
    dns: Vec<CfDns>,
    apps: Vec<CfApp>,
}

/// Build the cross-env map from a fresh CF read. Each list call is
/// independently fallible (mirrors [`crate::cf_snapshot`]); a partial read
/// sets `degraded`, and a downstream reconcile must refuse to act on it.
pub async fn build_map(
    http: &Client,
    cf_creds: &CfCreds,
    serving_env: &str,
    store: &Arc<tokio::sync::Mutex<std::collections::HashMap<String, collector::Agent>>>,
) -> CfMap {
    let mut fetch_errors = Vec::new();
    let raw_tunnels = match cf::list(http, cf_creds).await {
        Ok(v) => v,
        Err(e) => {
            fetch_errors.push(format!("tunnels: {e}"));
            Vec::new()
        }
    };
    let raw_dns = match cf::list_dns_records(http, cf_creds).await {
        Ok(v) => v,
        Err(e) => {
            fetch_errors.push(format!("dns: {e}"));
            Vec::new()
        }
    };
    let raw_apps = match cf::list_access_apps(http, cf_creds).await {
        Ok(v) => v,
        Err(e) => {
            fetch_errors.push(format!("apps: {e}"));
            Vec::new()
        }
    };

    let mut buckets: BTreeMap<String, Bucket> = BTreeMap::new();
    // tunnel id → env label, so DNS (which references a tunnel by id in its
    // CNAME content) can be attributed to the same installation.
    let mut tunnel_env: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();

    // Tunnels — attribute by name; unparseable dd-* (and any stray) → unattributed.
    for t in &raw_tunnels {
        let (Some(id), Some(name)) = (
            t.get("id").and_then(|v| v.as_str()),
            t.get("name").and_then(|v| v.as_str()),
        ) else {
            continue;
        };
        // Only consider DD-owned tunnels; ignore unrelated tunnels in the account.
        if !name.starts_with("dd-") {
            continue;
        }
        let env = Env::from_resource_name(name)
            .map(|e| e.label().to_string())
            .unwrap_or_else(|| UNATTRIBUTED.to_string());
        let cft = CfTunnel {
            id: id.to_string(),
            name: name.to_string(),
            deleted_at: t
                .get("deleted_at")
                .and_then(|v| v.as_str())
                .map(String::from),
            status: t.get("status").and_then(|v| v.as_str()).map(String::from),
            created_at: t
                .get("created_at")
                .and_then(|v| v.as_str())
                .map(String::from),
        };
        tunnel_env.insert(cft.id.clone(), env.clone());
        buckets.entry(env).or_default().tunnels.push(cft);
    }

    // DNS — attribute by the tunnel its CNAME targets. A ref we no longer
    // have a tunnel for is a leaked record → unattributed. Non-tunnel
    // CNAMEs in the zone aren't ours; skip.
    for r in &raw_dns {
        let (Some(id), Some(name), Some(content)) = (
            r.get("id").and_then(|v| v.as_str()),
            r.get("name").and_then(|v| v.as_str()),
            r.get("content").and_then(|v| v.as_str()),
        ) else {
            continue;
        };
        let Some(tunnel_id_ref) = content.strip_suffix(".cfargotunnel.com").map(String::from)
        else {
            continue; // not a tunnel CNAME → not part of the DD map
        };
        let env = tunnel_env
            .get(&tunnel_id_ref)
            .cloned()
            .unwrap_or_else(|| UNATTRIBUTED.to_string());
        let dns = CfDns {
            id: id.to_string(),
            name: name.to_string(),
            content: content.to_string(),
            proxied: r.get("proxied").and_then(|v| v.as_bool()).unwrap_or(false),
            tunnel_id_ref: Some(tunnel_id_ref),
        };
        buckets.entry(env).or_default().dns.push(dns);
    }

    // Access apps — usually empty post-#274 (auth moved in-code). Attribute
    // DD-owned apps by name; skip unrelated zone apps.
    for a in &raw_apps {
        let (Some(id), Some(name), Some(domain)) = (
            a.get("id").and_then(|v| v.as_str()),
            a.get("name").and_then(|v| v.as_str()),
            a.get("domain").and_then(|v| v.as_str()),
        ) else {
            continue;
        };
        if !name.starts_with("dd-") {
            continue;
        }
        let env = Env::from_resource_name(name)
            .map(|e| e.label().to_string())
            .unwrap_or_else(|| UNATTRIBUTED.to_string());
        let app = CfApp {
            id: id.to_string(),
            name: name.to_string(),
            domain: domain.to_string(),
            policy_kind: infer_policy_kind(a),
        };
        buckets.entry(env).or_default().apps.push(app);
    }

    // Serving env's live agent count (exclude the CP's own pseudo-entry).
    let known_agents = {
        let s = store.lock().await;
        s.values().filter(|a| !a.tunnel_id.is_empty()).count()
    };

    let mut installations: Vec<Installation> = buckets
        .into_iter()
        .map(|(env, b)| {
            let unattributed = env == UNATTRIBUTED;
            let kind = if unattributed {
                "unattributed".to_string()
            } else {
                Env::parse(&env)
                    .map(|e| kind_str(&e))
                    .unwrap_or("unattributed")
                    .to_string()
            };
            let has_live_cp = b
                .tunnels
                .iter()
                .any(|t| t.name.contains("-cp-") && t.deleted_at.is_none());
            let is_serving_env = !unattributed && env == serving_env;
            Installation {
                kind,
                has_live_cp,
                is_serving_env,
                known_agents: if is_serving_env { known_agents } else { 0 },
                tunnels: b.tunnels,
                dns: b.dns,
                apps: b.apps,
                env,
            }
        })
        .collect();
    // `(unattributed)` sorts after real labels because '(' < 'a'; force it last.
    installations.sort_by(|a, b| {
        let rank = |i: &Installation| (i.env == UNATTRIBUTED, i.env.clone());
        rank(a).cmp(&rank(b))
    });

    CfMap {
        fetched_at: chrono::DateTime::<chrono::Utc>::from(SystemTime::now()).to_rfc3339(),
        cf_account_id: cf_creds.account_id.clone(),
        cf_zone_id: cf_creds.zone_id.clone(),
        degraded: !fetch_errors.is_empty(),
        cf_fetch_errors: fetch_errors,
        serving_env: serving_env.to_string(),
        installations,
    }
}

fn kind_str(e: &Env) -> &'static str {
    use crate::env::EnvKind::*;
    match e.kind() {
        Production => "production",
        Staging => "staging",
        Dev => "dev",
        Preview => "preview",
        Named => "named",
    }
}
