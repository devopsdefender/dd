//! Cross-environment Cloudflare reconcile plan (read-only / dry-run).
//!
//! Given the unified [`crate::cf_map::CfMap`] and the serving CP's view of
//! its own env, compute what a reconcile WOULD do — env-labelled — in
//! three buckets:
//!   - **adopt**: live CF agent tunnels in the serving env that the CP
//!     store is missing (fill-only recovery — rebuild the store from CF).
//!   - **prune**: leaked resources — a dead/unclaimed orphan in the serving
//!     env, OR everything belonging to an env with no live control plane
//!     (e.g. a closed PR), OR the `(unattributed)` bucket.
//!   - **refill**: hostnames the serving CP expects but CF has no CNAME for.
//!
//! This module only *plans*. Execution — with the in-flight-deploy + TTL +
//! zero-connection guards — is a separate, operator-gated step (next PR).

use std::collections::HashSet;
use std::time::SystemTime;

use serde::Serialize;

use crate::cf_map::CfMap;
use crate::cf_snapshot::CpState;

#[derive(Debug, Clone, Serialize)]
pub struct ReconcilePlan {
    pub computed_at: String,
    pub serving_env: String,
    /// The CF map was partial (a list call failed); the plan is empty and
    /// must not be applied.
    pub degraded: bool,
    pub adopt: Vec<PlanItem>,
    pub prune: Vec<PlanItem>,
    pub refill: Vec<PlanItem>,
    /// Human-readable notes (e.g. live foreign envs intentionally skipped).
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PlanItem {
    pub env: String,
    pub kind: String, // "tunnel" | "dns"
    pub id: String,
    pub name: String,
    pub reason: String,
}

fn item(env: &str, kind: &str, id: &str, name: &str, reason: &str) -> PlanItem {
    PlanItem {
        env: env.into(),
        kind: kind.into(),
        id: id.into(),
        name: name.into(),
        reason: reason.into(),
    }
}

/// Compute the dry-run plan. Pure over the map + the serving CP state.
pub fn plan(map: &CfMap, cp: &CpState) -> ReconcilePlan {
    let mut out = ReconcilePlan {
        computed_at: chrono::DateTime::<chrono::Utc>::from(SystemTime::now()).to_rfc3339(),
        serving_env: cp.env_label.clone(),
        degraded: map.degraded,
        adopt: vec![],
        prune: vec![],
        refill: vec![],
        notes: vec![],
    };
    if map.degraded {
        out.notes.push(
            "CF map is degraded (a list call failed); plan is empty and reconcile must not run"
                .into(),
        );
        return out;
    }

    // Serving CP's ground truth: the tunnel ids it knows + the hostnames it
    // expects to exist (agent hostnames + their per-workload labels).
    let known_tunnel_ids: HashSet<&str> = cp
        .agents
        .iter()
        .filter(|a| !a.tunnel_id.is_empty())
        .map(|a| a.tunnel_id.as_str())
        .collect();
    let mut expected_hostnames: HashSet<String> = HashSet::new();
    for a in &cp.agents {
        expected_hostnames.insert(a.hostname.clone());
        for (label, _) in &a.extras {
            expected_hostnames.insert(crate::cf::label_hostname(&a.hostname, label));
        }
    }

    for inst in &map.installations {
        let serving = inst.env == cp.env_label;
        let unattributed = inst.kind == "unattributed";

        if serving {
            // Agent tunnels the CP store doesn't know: adopt if live
            // (healthy), prune if dead. Never touch the CP's own `-cp-`
            // tunnel or already soft-deleted tunnels.
            for t in &inst.tunnels {
                if t.name.contains("-cp-") || t.deleted_at.is_some() {
                    continue;
                }
                if known_tunnel_ids.contains(t.id.as_str()) {
                    continue;
                }
                if t.status.as_deref() == Some("healthy") {
                    out.adopt.push(item(
                        &inst.env,
                        "tunnel",
                        &t.id,
                        &t.name,
                        "live CF agent tunnel not in the CP store — adopt (fill-only)",
                    ));
                } else {
                    out.prune.push(item(
                        &inst.env,
                        "tunnel",
                        &t.id,
                        &t.name,
                        &format!(
                            "agent tunnel unclaimed by any CP agent and not healthy (status={}) — prune",
                            t.status.as_deref().unwrap_or("unknown")
                        ),
                    ));
                }
            }
            // DNS: unexpected CNAME → prune; expected-but-absent → refill.
            let cf_dns_names: HashSet<&str> = inst.dns.iter().map(|d| d.name.as_str()).collect();
            for d in &inst.dns {
                if d.name != cp.control_plane_hostname && !expected_hostnames.contains(&d.name) {
                    out.prune.push(item(
                        &inst.env,
                        "dns",
                        &d.id,
                        &d.name,
                        "CNAME not claimed by any CP agent — prune",
                    ));
                }
            }
            for h in &expected_hostnames {
                if h != &cp.control_plane_hostname && !cf_dns_names.contains(h.as_str()) {
                    out.refill.push(item(
                        &inst.env,
                        "dns",
                        "",
                        h,
                        "CP expects this hostname but no CF CNAME exists — refill",
                    ));
                }
            }
        } else if unattributed || !inst.has_live_cp {
            // A whole env with no live control plane (e.g. a closed PR), or
            // the unattributed leak bucket → every live resource is prunable.
            let why = if unattributed {
                "resource has no parseable env / its target tunnel is gone — prune"
            } else {
                "env has no live control plane (torn-down install) — prune"
            };
            for t in &inst.tunnels {
                if t.deleted_at.is_some() {
                    continue;
                }
                out.prune
                    .push(item(&inst.env, "tunnel", &t.id, &t.name, why));
            }
            for d in &inst.dns {
                out.prune.push(item(&inst.env, "dns", &d.id, &d.name, why));
            }
        } else {
            // Another live env whose CP store this CP doesn't hold — only
            // its own CP can safely judge its agent set.
            out.notes.push(format!(
                "{}: live foreign env ({} tunnels, {} dns) left untouched — reconcile from its own CP",
                inst.env,
                inst.tunnels.len(),
                inst.dns.len()
            ));
        }
    }

    out
}
