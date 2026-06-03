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

    // The tunnel ids the serving CP knows it owns.
    let known_tunnel_ids: HashSet<&str> = cp
        .agents
        .iter()
        .filter(|a| !a.tunnel_id.is_empty())
        .map(|a| a.tunnel_id.as_str())
        .collect();

    // Pass 1 — tunnels. Decide adopt/prune/keep and record which tunnels
    // are being pruned, so DNS can follow its tunnel (pass 2).
    let mut prune_tunnel_ids: HashSet<String> = HashSet::new();
    for inst in &map.installations {
        let serving = inst.env == cp.env_label;
        let unattributed = inst.kind == "unattributed";
        let leaked_env = unattributed || !inst.has_live_cp;

        for t in &inst.tunnels {
            if t.deleted_at.is_some() {
                continue; // already soft-deleted
            }
            if serving {
                if t.name.contains("-cp-") || known_tunnel_ids.contains(t.id.as_str()) {
                    continue; // the CP's own tunnel, or a claimed agent → keep
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
                    prune_tunnel_ids.insert(t.id.clone());
                    out.prune.push(item(
                        &inst.env,
                        "tunnel",
                        &t.id,
                        &t.name,
                        &format!(
                            "serving-env agent tunnel unclaimed by any CP agent and not healthy (status={}) — prune",
                            t.status.as_deref().unwrap_or("unknown")
                        ),
                    ));
                }
            } else if leaked_env {
                prune_tunnel_ids.insert(t.id.clone());
                let why = if unattributed {
                    "tunnel name has no parseable env — prune"
                } else {
                    "tunnel for an env with no live control plane (torn-down install) — prune"
                };
                out.prune
                    .push(item(&inst.env, "tunnel", &t.id, &t.name, why));
            }
            // live foreign env → leave its tunnels alone (noted below)
        }
        if !serving && !leaked_env {
            out.notes.push(format!(
                "{}: live foreign env ({} tunnels, {} dns) left untouched — reconcile from its own CP",
                inst.env,
                inst.tunnels.len(),
                inst.dns.len()
            ));
        }
    }

    // Pass 2 — DNS, keyed purely on the tunnel it targets. We never guess
    // by hostname: the CP creates more CNAMEs (agent-api, oracle, shell)
    // than it records in its store, so a name-based "orphan" check would
    // falsely prune live records. A CNAME is prunable only if its target
    // tunnel is gone (unattributed bucket) or is itself being pruned.
    for inst in &map.installations {
        let unattributed = inst.kind == "unattributed";
        for d in &inst.dns {
            let targets_pruned_tunnel = d
                .tunnel_id_ref
                .as_deref()
                .map(|t| prune_tunnel_ids.contains(t))
                .unwrap_or(false);
            if unattributed {
                out.prune.push(item(
                    &inst.env,
                    "dns",
                    &d.id,
                    &d.name,
                    "CNAME targets a tunnel that no longer exists — prune",
                ));
            } else if targets_pruned_tunnel {
                out.prune.push(item(
                    &inst.env,
                    "dns",
                    &d.id,
                    &d.name,
                    "CNAME targets a tunnel being pruned — prune",
                ));
            }
        }
    }

    // Refill — only the reliably-known primary agent hostname. Extras
    // (agent-api / oracle / shell) aren't tracked in the store, so we never
    // synthesize them; a missing primary CNAME means the agent is
    // unreachable and is safe to flag.
    if let Some(serving_inst) = map.installations.iter().find(|i| i.env == cp.env_label) {
        let cf_dns_names: HashSet<&str> =
            serving_inst.dns.iter().map(|d| d.name.as_str()).collect();
        for a in &cp.agents {
            if !a.tunnel_id.is_empty()
                && a.hostname != cp.control_plane_hostname
                && !cf_dns_names.contains(a.hostname.as_str())
            {
                out.refill.push(item(
                    &cp.env_label,
                    "dns",
                    "",
                    &a.hostname,
                    "CP knows this agent but its primary CNAME is missing in CF — refill",
                ));
            }
        }
    }

    out
}
