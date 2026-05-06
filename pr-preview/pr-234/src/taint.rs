//! Integrity taint-reason tracking for a dd-agent node.
//!
//! An agent is either pristine (no reasons) or tainted (one or more
//! reasons). The spec (SATS_FOR_COMPUTE_SPEC.md) defines taint as a
//! SET of reasons — not a boolean — each tied to a specific mechanism
//! that let a non-fleet party influence the node. Third-party
//! verifiers who read `/health` reconstruct the node's trust profile
//! from the presence/absence of specific reasons:
//!
//! - `customer_workload_deployed + customer_owner_enabled + interactive_shell_enabled`
//!   → full customer-deploy mode (shared admin, shell access).
//! - `customer_workload_deployed` only
//!   → confidential mode (sealed oracle; no exec channels for anyone).
//! - empty set → pristine.
//!
//! v0 scope: taint is INFORMATIONAL. DD doesn't hard-block actions
//! based on it; the reasons just mirror what the node's boot config +
//! runtime events actually produced, for honest disclosure.

use std::collections::HashSet;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

/// One concrete mechanism through which a customer (or operator on
/// behalf of a customer) influenced the node post-boot.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq, Serialize, Deserialize, Ord, PartialOrd)]
#[serde(rename_all = "snake_case")]
pub enum TaintReason {
    /// `POST /owner` was invoked with a non-fleet tenant org; the
    /// agent accepts that org's GitHub OIDC on `/deploy`/`/exec`/
    /// `/logs`. Does not include ops (`DD_OWNER`) using `/deploy`.
    CustomerOwnerEnabled,
    /// A workload was deployed via `POST /deploy` at runtime. True
    /// whether the caller was ops or the tenant — any runtime deploy
    /// moves the node away from pristine.
    CustomerWorkloadDeployed,
    /// The agent booted with `/deploy` + `/exec` routes enabled.
    /// False in confidential mode (`DD_CONFIDENTIAL=true`), where
    /// the mutation endpoints aren't registered at all. Derived at
    /// boot from config; never toggled at runtime.
    ArbitraryExecEnabled,
    /// Interactive shell (ttyd or equivalent) is in the running
    /// workload set. Reserved — not populated by v0. Left in the
    /// enum so the `/health` schema is stable when it lands.
    #[allow(dead_code)]
    InteractiveShellEnabled,
}

/// Thread-safe handle over a `HashSet<TaintReason>`. Shared by the
/// axum state and the per-handler tainting code. Cheap to clone
/// (just an `Arc` bump).
#[derive(Clone, Default)]
pub struct TaintSet {
    inner: Arc<RwLock<HashSet<TaintReason>>>,
}

impl TaintSet {
    /// Seed the set with a boot-time reasons (e.g. `ArbitraryExecEnabled`
    /// when the agent boots in non-confidential mode).
    pub fn with_initial(reasons: impl IntoIterator<Item = TaintReason>) -> Self {
        let set: HashSet<_> = reasons.into_iter().collect();
        Self {
            inner: Arc::new(RwLock::new(set)),
        }
    }

    /// Insert a reason idempotently. Returns whether the reason was
    /// newly added (`true` first time, `false` on subsequent calls).
    pub async fn insert(&self, reason: TaintReason) -> bool {
        self.inner.write().await.insert(reason)
    }

    /// Snapshot the current set as a sorted `Vec` — stable ordering
    /// so `/health` JSON is diff-friendly and the TDX quote's
    /// embedded taint set has a canonical form.
    pub async fn snapshot(&self) -> Vec<TaintReason> {
        let mut v: Vec<_> = self.inner.read().await.iter().copied().collect();
        v.sort();
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn insert_is_idempotent() {
        let s = TaintSet::default();
        assert!(s.insert(TaintReason::CustomerOwnerEnabled).await);
        assert!(!s.insert(TaintReason::CustomerOwnerEnabled).await);
        assert_eq!(s.snapshot().await, vec![TaintReason::CustomerOwnerEnabled]);
    }

    #[tokio::test]
    async fn snapshot_is_sorted() {
        let s = TaintSet::with_initial([
            TaintReason::ArbitraryExecEnabled,
            TaintReason::CustomerOwnerEnabled,
        ]);
        s.insert(TaintReason::CustomerWorkloadDeployed).await;
        assert_eq!(
            s.snapshot().await,
            vec![
                TaintReason::CustomerOwnerEnabled,
                TaintReason::CustomerWorkloadDeployed,
                TaintReason::ArbitraryExecEnabled,
            ]
        );
    }

    #[test]
    fn reasons_serialize_as_snake_case() {
        let s = serde_json::to_string(&TaintReason::CustomerOwnerEnabled).unwrap();
        assert_eq!(s, "\"customer_owner_enabled\"");
    }
}
