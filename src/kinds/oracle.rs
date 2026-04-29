//! Oracle kind.
//!
//! v1: external signer. The operator supplies the chain key as an env
//! var (named in `kind_config.signer_env`); the agent records the
//! name in the attestation manifest so on-chain verifiers can confirm
//! "this enclave was configured with env var X holding the signer."
//! Future: bind the signer key to the TDX measurement (sealed key
//! derive) — separate EE+dd PR.

use serde::Serialize;

use crate::workload::{KindConfig, Workload};

/// Manifest exposed at `<vanity>/manifest` so on-chain verifiers can
/// fingerprint a deployed oracle. The manifest itself is *not*
/// signed — verifiers should pair it with the agent's ITA quote at
/// `/health` (which IS signed by Intel).
#[derive(Debug, Serialize)]
pub struct OracleManifest<'a> {
    pub kind: &'static str,
    pub name: &'a str,
    pub image: Option<&'a str>,
    pub schedule: Option<&'a str>,
    pub signer_env: Option<&'a str>,
    pub public_log: bool,
}

impl<'a> OracleManifest<'a> {
    pub fn from_workload(w: &'a Workload) -> Self {
        let (schedule, signer_env, public_log) = match &w.kind_config {
            KindConfig::Oracle {
                schedule,
                signer_env,
                public_log,
            } => (schedule.as_deref(), signer_env.as_deref(), *public_log),
            _ => (None, None, false),
        };
        Self {
            kind: "oracle",
            name: &w.name,
            image: w.image.as_deref(),
            schedule,
            signer_env,
            public_log,
        }
    }
}
