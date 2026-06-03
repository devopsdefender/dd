//! Side-by-side snapshot of (a) what the CP thinks it has provisioned in
//! Cloudflare and (b) what Cloudflare's API actually returns. The
//! iOS Manage view consumes this to surface drift (orphans, missing,
//! mismatches) for operator debugging. Read-only.
//!
//! Long-term direction: make the *CF state* the source of truth in
//! recovery (today the CP re-queries CF on demand but doesn't
//! systematically reconcile). This module is the first step — visibility
//! must precede automated repair.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::SystemTime;

use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::Serialize;

use crate::cf;
use crate::collector;
use crate::config::CfCreds;

#[derive(Debug, Clone, Serialize)]
pub struct Snapshot {
    pub fetched_at: String,
    pub cf_account_id: String,
    pub cf_zone_id: String,
    pub cf_api_reachable: bool,
    /// True when at least one of the three CF list calls (tunnels / dns /
    /// apps) failed, so `cf_state` is partial. Drift is NOT computed in
    /// this state, and any future reconcile must refuse to run — acting on
    /// a partial CF view would manufacture false orphans/missing.
    pub degraded: bool,
    /// Which CF sub-fetches failed, e.g. `["dns: <err>"]`. Empty when clean.
    pub cf_fetch_errors: Vec<String>,
    pub cp_state: CpState,
    pub cf_state: CfState,
    pub drift: Drift,
}

#[derive(Debug, Clone, Serialize)]
pub struct CpState {
    pub control_plane_hostname: String,
    pub env_label: String,
    pub agents: Vec<CpAgent>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CpAgent {
    pub agent_id: String,
    pub vm_name: String,
    pub hostname: String,
    pub status: String,
    pub last_seen: DateTime<Utc>,
    pub tunnel_id: String,
    pub extras: Vec<(String, u16)>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CfState {
    pub tunnels: Vec<CfTunnel>,
    pub dns: Vec<CfDns>,
    pub apps: Vec<CfApp>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CfTunnel {
    pub id: String,
    pub name: String,
    pub deleted_at: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CfDns {
    pub id: String,
    pub name: String,
    pub content: String,
    pub proxied: bool,
    /// `dd-{tunnel-id}` parsed from content like `<uuid>.cfargotunnel.com`,
    /// when applicable. Lets the iOS app group records by tunnel.
    pub tunnel_id_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CfApp {
    pub id: String,
    pub name: String,
    pub domain: String,
    /// Compact policy summary: `human` (GH-org-gated), `bypass` (everyone),
    /// or `unknown` if we couldn't recognize the shape. Full policy JSON
    /// would be nice but the iOS app just needs the kind for now.
    pub policy_kind: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Drift {
    pub orphan_tunnels: Vec<OrphanRef>,
    pub orphan_dns: Vec<OrphanRef>,
    pub orphan_apps: Vec<OrphanRef>,
    pub missing_tunnels: Vec<MissingRef>,
    pub missing_dns: Vec<MissingRef>,
    pub missing_apps: Vec<MissingRef>,
    pub access_mismatch: Vec<MismatchRef>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OrphanRef {
    pub id: String,
    pub name: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct MissingRef {
    pub expected: String,
    pub for_agent: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct MismatchRef {
    pub id: String,
    pub domain: String,
    pub expected_policy: String,
    pub actual_policy: String,
}

/// Build a snapshot from the CP's live store + a fresh CF API read. The
/// caller (an axum handler) gates auth before invoking this.
pub async fn snapshot(
    http: &Client,
    cf_creds: &CfCreds,
    env_label: &str,
    cp_hostname: &str,
    store: &Arc<tokio::sync::Mutex<HashMap<String, collector::Agent>>>,
) -> Snapshot {
    let cp_state = build_cp_state(env_label, cp_hostname, store).await;

    let (cf_state, fetch_errors) = build_cf_state(http, cf_creds, env_label, cp_hostname).await;
    // Reachable = at least one list call returned; degraded = any failed.
    // Drift (and any future reconcile) only runs on a complete view.
    let reachable = fetch_errors.len() < 3;
    let degraded = !fetch_errors.is_empty();

    let drift = if reachable && !degraded {
        compute_drift(&cp_state, &cf_state, env_label, cp_hostname)
    } else {
        Drift::default()
    };

    Snapshot {
        fetched_at: chrono::DateTime::<chrono::Utc>::from(SystemTime::now()).to_rfc3339(),
        cf_account_id: cf_creds.account_id.clone(),
        cf_zone_id: cf_creds.zone_id.clone(),
        cf_api_reachable: reachable,
        degraded,
        cf_fetch_errors: fetch_errors,
        cp_state,
        cf_state,
        drift,
    }
}

async fn build_cp_state(
    env_label: &str,
    cp_hostname: &str,
    store: &Arc<tokio::sync::Mutex<HashMap<String, collector::Agent>>>,
) -> CpState {
    let agents_map = store.lock().await.clone();
    let mut agents: Vec<CpAgent> = agents_map
        .into_values()
        .map(|a| CpAgent {
            agent_id: a.agent_id,
            vm_name: a.vm_name,
            hostname: a.hostname,
            status: a.status,
            last_seen: a.last_seen,
            tunnel_id: a.tunnel_id,
            extras: a.extras,
        })
        .collect();
    agents.sort_by(|a, b| a.agent_id.cmp(&b.agent_id));
    CpState {
        control_plane_hostname: cp_hostname.to_string(),
        env_label: env_label.to_string(),
        agents,
    }
}

/// Fetch CF state with each list call independently fallible: one flaky
/// endpoint degrades the snapshot (reported in the returned error list)
/// instead of blanking the whole thing. Returns the (possibly partial)
/// state plus the list of which sub-fetches failed.
async fn build_cf_state(
    http: &Client,
    cf_creds: &CfCreds,
    env_label: &str,
    cp_hostname: &str,
) -> (CfState, Vec<String>) {
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

    // Scope: staging + dev (and any other env in the same Cloudflare account)
    // share a zone, so listing tunnels/dns/apps returns everything. We filter
    // to just this env's namespace using the `dd-{env}-` name convention plus
    // the CP hostname's flat-subdomain space (`{base}.{tld}` and `{base}-*.{tld}`).
    let agent_prefix = crate::cf::agent_prefix(env_label);
    let cp_prefix = crate::cf::cp_prefix(env_label);
    let (cp_base, cp_tld) = cp_hostname.split_once('.').unwrap_or((cp_hostname, ""));

    let tunnels: Vec<CfTunnel> = raw_tunnels
        .iter()
        .filter_map(|t| {
            let name = t.get("name")?.as_str()?.to_string();
            // Keep only our env's tunnels (CP self-tunnels + agent tunnels).
            if !(name.starts_with(&agent_prefix) || name.starts_with(&cp_prefix)) {
                return None;
            }
            Some(CfTunnel {
                id: t.get("id")?.as_str()?.to_string(),
                name,
                deleted_at: t
                    .get("deleted_at")
                    .and_then(|v| v.as_str())
                    .map(String::from),
            })
        })
        .collect();
    let our_tunnel_ids: HashSet<String> = tunnels.iter().map(|t| t.id.clone()).collect();

    // DNS: keep only CNAMEs pointing into one of our env's tunnels.
    let dns: Vec<CfDns> = raw_dns
        .iter()
        .filter_map(|r| {
            let name = r.get("name")?.as_str()?.to_string();
            let content = r.get("content")?.as_str()?.to_string();
            let tunnel_id_ref = content.strip_suffix(".cfargotunnel.com").map(String::from);
            if let Some(tid) = &tunnel_id_ref {
                if !our_tunnel_ids.contains(tid) {
                    return None;
                }
            } else {
                return None;
            }
            Some(CfDns {
                id: r.get("id")?.as_str()?.to_string(),
                name,
                content,
                proxied: r.get("proxied").and_then(|v| v.as_bool()).unwrap_or(false),
                tunnel_id_ref,
            })
        })
        .collect();

    // Apps: keep only those whose domain is the CP hostname itself, a path
    // under it, or in the flat-subdomain space `{cp_base}-*.{cp_tld}`.
    let in_our_space = |domain: &str| -> bool {
        let (host, _) = domain.split_once('/').unwrap_or((domain, ""));
        if host == cp_hostname || host == cp_base {
            return true;
        }
        if let Some((base, tld)) = host.split_once('.') {
            tld == cp_tld && (base == cp_base || base.starts_with(&format!("{cp_base}-")))
        } else {
            false
        }
    };
    let apps: Vec<CfApp> = raw_apps
        .iter()
        .filter_map(|a| {
            let domain = a.get("domain")?.as_str()?.to_string();
            if !in_our_space(&domain) {
                return None;
            }
            let name = a.get("name")?.as_str()?.to_string();
            let id = a.get("id")?.as_str()?.to_string();
            let policy_kind = infer_policy_kind(a);
            Some(CfApp {
                id,
                name,
                domain,
                policy_kind,
            })
        })
        .collect();

    (CfState { tunnels, dns, apps }, fetch_errors)
}

/// Heuristic: bypass apps have a single policy with `decision="bypass"`
/// and `include` containing "everyone"; human apps have `decision="allow"`
/// with GitHub-org inclusion. Anything else is `unknown`.
pub(crate) fn infer_policy_kind(app: &serde_json::Value) -> String {
    let policies = app.get("policies").and_then(|p| p.as_array());
    let Some(policies) = policies else {
        return "unknown".into();
    };
    if policies.is_empty() {
        return "unknown".into();
    }
    let first = &policies[0];
    let decision = first.get("decision").and_then(|d| d.as_str()).unwrap_or("");
    if decision == "bypass" {
        return "bypass".into();
    }
    if decision == "allow" {
        let serialized = first.to_string().to_lowercase();
        if serialized.contains("github-organization") || serialized.contains("emails") {
            return "human".into();
        }
    }
    "unknown".into()
}

/// Compute orphans / missing / mismatches by comparing what the CP expects
/// (based on its current agents + the env prefix convention) to what CF
/// actually has. Pure function over the two states + a couple of env
/// constants; trivial to unit-test.
pub fn compute_drift(cp: &CpState, cf: &CfState, env_label: &str, cp_hostname: &str) -> Drift {
    let agent_prefix = crate::cf::agent_prefix(env_label);
    let cp_prefix = crate::cf::cp_prefix(env_label);

    // Expected tunnel IDs from CP: every agent's tunnel_id (when non-empty).
    let expected_tunnel_ids: HashSet<String> = cp
        .agents
        .iter()
        .filter(|a| !a.tunnel_id.is_empty())
        .map(|a| a.tunnel_id.clone())
        .collect();

    // CF tunnels matching our env prefix, not soft-deleted.
    let our_cf_tunnels: Vec<&CfTunnel> = cf
        .tunnels
        .iter()
        .filter(|t| {
            t.deleted_at.is_none()
                && (t.name.starts_with(&agent_prefix) || t.name.starts_with(&cp_prefix))
        })
        .collect();

    // Orphan tunnels: in CF but no CP agent claims them. We exclude the
    // active CP's own tunnel(s) by name-prefix.
    let cp_self_prefix = cp_prefix.clone();
    let orphan_tunnels: Vec<OrphanRef> = our_cf_tunnels
        .iter()
        .filter(|t| !expected_tunnel_ids.contains(&t.id) && !t.name.starts_with(&cp_self_prefix))
        .map(|t| OrphanRef {
            id: t.id.clone(),
            name: t.name.clone(),
            reason: "CF tunnel exists with no corresponding CP agent (likely a torn-down preview)"
                .into(),
        })
        .collect();

    // Missing tunnels: CP agent has a tunnel_id we can't find in CF.
    let cf_tunnel_ids: HashSet<String> = our_cf_tunnels.iter().map(|t| t.id.clone()).collect();
    let missing_tunnels: Vec<MissingRef> = cp
        .agents
        .iter()
        .filter(|a| !a.tunnel_id.is_empty() && !cf_tunnel_ids.contains(&a.tunnel_id))
        .map(|a| MissingRef {
            expected: a.tunnel_id.clone(),
            for_agent: a.agent_id.clone(),
            reason: "CP agent registered a tunnel_id that CF doesn't have (or it's soft-deleted)"
                .into(),
        })
        .collect();

    // Expected hostnames from CP: every agent's hostname + every workload
    // label flattened into a `{base}-{label}.{tld}` subdomain.
    let mut expected_hostnames: HashSet<String> = HashSet::new();
    expected_hostnames.insert(cp_hostname.to_string());
    for a in &cp.agents {
        expected_hostnames.insert(a.hostname.clone());
        for (label, _) in &a.extras {
            expected_hostnames.insert(crate::cf::label_hostname(&a.hostname, label));
        }
    }

    let our_cf_dns: Vec<&CfDns> = cf
        .dns
        .iter()
        .filter(|d| {
            // Only consider records pointing into our tunnels.
            d.tunnel_id_ref
                .as_ref()
                .map(|tid| our_cf_tunnels.iter().any(|t| &t.id == tid))
                .unwrap_or(false)
        })
        .collect();

    let cf_dns_names: HashSet<String> = our_cf_dns.iter().map(|d| d.name.clone()).collect();
    let orphan_dns: Vec<OrphanRef> = our_cf_dns
        .iter()
        .filter(|d| !expected_hostnames.contains(&d.name))
        .map(|d| OrphanRef {
            id: d.id.clone(),
            name: d.name.clone(),
            reason: format!(
                "CNAME points at {} but no CP agent claims this hostname",
                d.content
            ),
        })
        .collect();
    let missing_dns: Vec<MissingRef> = expected_hostnames
        .iter()
        .filter(|h| !cf_dns_names.contains(*h))
        // Don't flag the CP root if it's not under a tunnel (the CP's own
        // hostname is its own concern; only flag if it should be in our
        // tunnel set but isn't).
        .filter(|h| *h != cp_hostname)
        .map(|h| MissingRef {
            expected: h.clone(),
            for_agent: cp
                .agents
                .iter()
                .find(|a| {
                    a.hostname == *h
                        || h.starts_with(&format!(
                            "{}-",
                            a.hostname.split('.').next().unwrap_or(&a.hostname)
                        ))
                })
                .map(|a| a.agent_id.clone())
                .unwrap_or_default(),
            reason: "CP expects this hostname but no CF CNAME exists".into(),
        })
        .collect();

    // Expected access apps: post-PR-#274 the CP **deletes** DD-owned Access
    // apps at registration/startup (browser+machine auth moved in-code).
    // So the "expected" set is intentionally empty for the missing-apps
    // check — we only flag access mismatches (apps that exist but with the
    // wrong policy shape). If a future iteration brings back per-domain
    // apps, repopulate this set.
    let expected_app_domains: HashSet<String> = HashSet::new();

    // Apps in CF that are under our zone but unrelated to anything we
    // expect. We scope to apps whose domain matches the CP hostname or
    // an agent hostname's flat-subdomain space.
    let (cp_base, cp_tld) = cp_hostname.split_once('.').unwrap_or((cp_hostname, ""));
    let agent_bases: Vec<String> = cp
        .agents
        .iter()
        .map(|a| {
            a.hostname
                .split_once('.')
                .map(|(b, _)| b.to_string())
                .unwrap_or_default()
        })
        .filter(|s| !s.is_empty())
        .collect();
    let in_our_space = |domain: &str| -> bool {
        let (host, _) = domain.split_once('/').unwrap_or((domain, ""));
        if host == cp_hostname || host == cp_base {
            return true;
        }
        if let Some((base, tld)) = host.split_once('.') {
            if tld == cp_tld {
                return agent_bases
                    .iter()
                    .any(|ab| base == ab || base.starts_with(&format!("{ab}-")))
                    || base == cp_base
                    || base.starts_with(&format!("{cp_base}-"));
            }
        }
        false
    };

    let our_cf_apps: Vec<&CfApp> = cf.apps.iter().filter(|a| in_our_space(&a.domain)).collect();
    let cf_app_domains: HashSet<String> = our_cf_apps.iter().map(|a| a.domain.clone()).collect();
    let orphan_apps: Vec<OrphanRef> = our_cf_apps
        .iter()
        .filter(|a| !expected_app_domains.contains(&a.domain))
        .map(|a| OrphanRef {
            id: a.id.clone(),
            name: a.name.clone(),
            reason: format!("Access app on {} not in CP's expected set", a.domain),
        })
        .collect();
    let missing_apps: Vec<MissingRef> = expected_app_domains
        .iter()
        .filter(|d| !cf_app_domains.contains(*d))
        .map(|d| MissingRef {
            expected: d.clone(),
            for_agent: cp
                .agents
                .iter()
                .find(|a| d.starts_with(&a.hostname))
                .map(|a| a.agent_id.clone())
                .unwrap_or_default(),
            reason: "CP expects an Access app for this domain but CF has none".into(),
        })
        .collect();

    // Access mismatch: app domain matches an admin label (`-term` / `-block`)
    // but its policy isn't human-gated. Common drift after a recipe change.
    let admin_labels = ["term", "block"];
    let access_mismatch: Vec<MismatchRef> = our_cf_apps
        .iter()
        .filter_map(|app| {
            for al in admin_labels {
                if (app.domain.ends_with(&format!("-{al}.{cp_tld}"))
                    || app.domain.ends_with(&format!("-{al}")))
                    && app.policy_kind != "human"
                {
                    return Some(MismatchRef {
                        id: app.id.clone(),
                        domain: app.domain.clone(),
                        expected_policy: "human".into(),
                        actual_policy: app.policy_kind.clone(),
                    });
                }
            }
            None
        })
        .collect();

    Drift {
        orphan_tunnels,
        orphan_dns,
        orphan_apps,
        missing_tunnels,
        missing_dns,
        missing_apps,
        access_mismatch,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agent(id: &str, hostname: &str, tunnel_id: &str) -> CpAgent {
        CpAgent {
            agent_id: id.into(),
            vm_name: id.into(),
            hostname: hostname.into(),
            status: "healthy".into(),
            last_seen: Utc::now(),
            tunnel_id: tunnel_id.into(),
            extras: vec![],
        }
    }

    fn tunnel(id: &str, name: &str) -> CfTunnel {
        CfTunnel {
            id: id.into(),
            name: name.into(),
            deleted_at: None,
        }
    }

    #[test]
    fn orphan_tunnel_detected_when_cf_has_extra() {
        let cp = CpState {
            control_plane_hostname: "app.example.com".into(),
            env_label: "production".into(),
            agents: vec![agent("a1", "dd-production-agent-a1.example.com", "tid-1")],
        };
        let cf = CfState {
            tunnels: vec![
                tunnel("tid-1", "dd-production-agent-a1"),
                tunnel("tid-2", "dd-production-agent-old"),
            ],
            dns: vec![],
            apps: vec![],
        };
        let drift = compute_drift(&cp, &cf, "production", "app.example.com");
        assert_eq!(drift.orphan_tunnels.len(), 1);
        assert_eq!(drift.orphan_tunnels[0].id, "tid-2");
        assert!(drift.missing_tunnels.is_empty());
    }

    #[test]
    fn missing_tunnel_detected_when_cp_claims_unknown_tid() {
        let cp = CpState {
            control_plane_hostname: "app.example.com".into(),
            env_label: "production".into(),
            agents: vec![agent(
                "a1",
                "dd-production-agent-a1.example.com",
                "tid-ghost",
            )],
        };
        let cf = CfState {
            tunnels: vec![],
            dns: vec![],
            apps: vec![],
        };
        let drift = compute_drift(&cp, &cf, "production", "app.example.com");
        assert_eq!(drift.missing_tunnels.len(), 1);
        assert_eq!(drift.missing_tunnels[0].expected, "tid-ghost");
    }

    #[test]
    fn admin_label_with_bypass_policy_is_mismatch() {
        let cp = CpState {
            control_plane_hostname: "app.example.com".into(),
            env_label: "production".into(),
            agents: vec![],
        };
        let cf = CfState {
            tunnels: vec![],
            dns: vec![],
            apps: vec![CfApp {
                id: "app-1".into(),
                name: "dd-production-cp-term".into(),
                domain: "app-term.example.com".into(),
                policy_kind: "bypass".into(),
            }],
        };
        let drift = compute_drift(&cp, &cf, "production", "app.example.com");
        assert_eq!(drift.access_mismatch.len(), 1);
        assert_eq!(drift.access_mismatch[0].expected_policy, "human");
        assert_eq!(drift.access_mismatch[0].actual_policy, "bypass");
    }
}
