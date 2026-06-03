//! First-class environment identity for the control plane.
//!
//! Every DD installation — production, staging, dev, a per-PR preview, or
//! a named long-lived install like `bot` / `dogfood` — is one [`Env`].
//! It is the single axis that distinguishes installations: all Cloudflare
//! resource names derive from [`Env::label`] (see [`crate::cf`]), and
//! env-intrinsic behaviour (Intel ITA enforcement, ephemerality) lives
//! here as methods rather than scattered `== "production"` string checks.

use crate::error::{Error, Result};

/// Well-known classes of environment. Anything that validates as a label
/// but isn't one of these is [`EnvKind::Named`] — so a legitimately-named
/// install (`bot`, `dogfood`, a future env) is never rejected at boot,
/// only genuinely malformed `DD_ENV` values are.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EnvKind {
    Production,
    Staging,
    Dev,
    /// A per-PR ephemeral preview, `pr-<n>`.
    Preview,
    /// A valid but non-well-known label (e.g. `bot`, `dogfood`).
    Named,
}

/// A parsed, validated environment label.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Env {
    label: String,
    kind: EnvKind,
}

impl Env {
    /// Parse and validate the `DD_ENV` label.
    ///
    /// The label is embedded directly into Cloudflare resource names
    /// (`dd-{label}-cp-…`) and hostnames, so it must be a lowercase
    /// DNS-style token: `^[a-z0-9][a-z0-9-]*$`, at most 40 chars. This
    /// rejects empty/whitespace/uppercase values and junk like
    /// `invalid name {uuid}` that would silently break collector
    /// discovery, while still accepting any well-formed install name.
    pub fn parse(s: &str) -> Result<Self> {
        let label = s.trim();
        let valid = !label.is_empty()
            && label.len() <= 40
            && label
                .bytes()
                .next()
                .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if !valid {
            return Err(Error::Internal(format!(
                "DD_ENV {s:?} invalid: expected a lowercase DNS label \
                 (e.g. production, staging, dev, pr-42, bot)"
            )));
        }
        let kind = match label {
            "production" => EnvKind::Production,
            "staging" => EnvKind::Staging,
            "dev" => EnvKind::Dev,
            // Per-PR previews are `pr-<n>`. Any other label is a named
            // long-lived install.
            _ if label.starts_with("pr-") && label.len() > 3 => EnvKind::Preview,
            _ => EnvKind::Named,
        };
        Ok(Self {
            label: label.to_string(),
            kind,
        })
    }

    /// The canonical env label string (what every CF name derives from).
    pub fn label(&self) -> &str {
        &self.label
    }

    /// The classified kind.
    pub fn kind(&self) -> &EnvKind {
        &self.kind
    }

    /// Production and staging must use real Intel TDX attestation; other
    /// envs may run a signed local token on hosts without Intel PCCS
    /// collateral. Mirrors the prior `== "production" || == "staging"`
    /// check that gated `DD_ITA_MODE=local`.
    pub fn requires_intel_ita(&self) -> bool {
        matches!(self.kind, EnvKind::Production | EnvKind::Staging)
    }

    /// Per-PR previews are torn down with the PR; every other install is
    /// persistent. Drives lifecycle policy (libvirt autostart, CF GC TTL).
    pub fn is_ephemeral(&self) -> bool {
        matches!(self.kind, EnvKind::Preview)
    }

    /// Attribute a Cloudflare resource to its installation by parsing the
    /// env out of a `dd-{env}-{cp|agent|api}-…` name. The env segment is
    /// everything between the `dd-` prefix and the first role marker, so a
    /// hyphenated label like `pr-42` is recovered intact
    /// (`dd-pr-42-agent-<uuid>` → `pr-42`). Returns `None` for names that
    /// don't follow the convention (so the caller can bucket them as
    /// unattributed). Used by the cross-env CF map.
    pub fn from_resource_name(name: &str) -> Option<Self> {
        let rest = name.strip_prefix("dd-")?;
        let cut = ["-cp-", "-agent-", "-api-"]
            .iter()
            .filter_map(|m| rest.find(m))
            .min()?;
        Env::parse(&rest[..cut]).ok()
    }
}

impl std::fmt::Display for Env {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.label)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn well_known_kinds() {
        assert_eq!(
            *Env::parse("production").unwrap().kind(),
            EnvKind::Production
        );
        assert_eq!(*Env::parse("staging").unwrap().kind(), EnvKind::Staging);
        assert_eq!(*Env::parse("dev").unwrap().kind(), EnvKind::Dev);
        assert_eq!(*Env::parse("pr-42").unwrap().kind(), EnvKind::Preview);
        // Named long-lived installs are accepted, not rejected.
        assert_eq!(*Env::parse("bot").unwrap().kind(), EnvKind::Named);
        assert_eq!(*Env::parse("dogfood").unwrap().kind(), EnvKind::Named);
    }

    #[test]
    fn label_roundtrips_and_trims() {
        assert_eq!(Env::parse("  production  ").unwrap().label(), "production");
        assert_eq!(Env::parse("pr-7").unwrap().label(), "pr-7");
    }

    #[test]
    fn rejects_malformed() {
        assert!(Env::parse("").is_err());
        assert!(Env::parse("   ").is_err());
        assert!(Env::parse("Production").is_err()); // uppercase
        assert!(Env::parse("invalid name").is_err()); // whitespace
        assert!(Env::parse("-leading-hyphen").is_err());
        assert!(Env::parse("pr_42").is_err()); // underscore not allowed
        assert!(Env::parse(&"x".repeat(41)).is_err()); // too long
    }

    #[test]
    fn requires_intel_ita_matches_prior_behaviour() {
        assert!(Env::parse("production").unwrap().requires_intel_ita());
        assert!(Env::parse("staging").unwrap().requires_intel_ita());
        assert!(!Env::parse("dev").unwrap().requires_intel_ita());
        assert!(!Env::parse("pr-42").unwrap().requires_intel_ita());
        assert!(!Env::parse("bot").unwrap().requires_intel_ita());
    }

    #[test]
    fn ephemerality() {
        assert!(Env::parse("pr-42").unwrap().is_ephemeral());
        assert!(!Env::parse("production").unwrap().is_ephemeral());
        assert!(!Env::parse("bot").unwrap().is_ephemeral());
    }

    #[test]
    fn from_resource_name_attributes_env() {
        let cases = [
            ("dd-production-cp-1a2b", "production"),
            ("dd-production-agent-9f8e", "production"),
            ("dd-pr-42-cp-aaaa", "pr-42"), // hyphenated label recovered
            ("dd-pr-42-agent-bbbb", "pr-42"),
            ("dd-pr-42-api-cccc.devopsdefender.com", "pr-42"), // api hostname
            ("dd-bot-agent-dddd", "bot"),
        ];
        for (name, want) in cases {
            assert_eq!(
                Env::from_resource_name(name).unwrap().label(),
                want,
                "name={name}"
            );
        }
        // Non-conforming names → None (caller buckets as unattributed).
        assert!(Env::from_resource_name("app.devopsdefender.com").is_none());
        assert!(Env::from_resource_name("some-other-tunnel").is_none());
        assert!(Env::from_resource_name("dd-no-marker-here").is_none());
    }
}
