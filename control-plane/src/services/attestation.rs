use crate::attestation::ita::{AttestationClaims, ItaVerifier};
use crate::common::error::{AppError, AppResult};

/// Runtime environment classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeEnv {
    Staging,
    Production,
}

impl RuntimeEnv {
    /// Detect runtime environment from DD_ENV or DD_CP_ENV env vars.
    /// Panics if neither is set — every deployment must declare its environment.
    pub fn detect() -> Self {
        let val = std::env::var("DD_ENV")
            .or_else(|_| std::env::var("DD_CP_ENV"))
            .expect("DD_ENV or DD_CP_ENV must be set (staging or production)");
        match val.to_lowercase().as_str() {
            "production" | "prod" => RuntimeEnv::Production,
            "staging" | "stage" => RuntimeEnv::Staging,
            other => panic!("unknown DD_ENV value '{other}' — must be 'staging' or 'production'"),
        }
    }
}

/// Verified attestation data extracted from a valid token.
#[derive(Debug, Clone)]
pub struct VerifiedAttestation {
    pub mrtd: Option<String>,
    pub tcb_status: Option<String>,
    pub rtmrs: Vec<String>,
}

/// High-level attestation service that wraps ItaVerifier.
/// There is no insecure mode — every environment requires real attestation.
#[derive(Clone)]
pub struct AttestationService {
    verifier: Option<ItaVerifier>,
}

impl AttestationService {
    pub fn new(verifier: ItaVerifier) -> Self {
        Self {
            verifier: Some(verifier),
        }
    }

    /// Build an AttestationService with no verifier — only for tests.
    /// All registration attempts will be rejected.
    #[cfg(test)]
    pub fn reject_all() -> Self {
        Self { verifier: None }
    }

    /// Build from environment. Uses ITA verifier when DD_INTEL_API_KEY is set.
    /// Without the key, attestation verification will reject all tokens —
    /// this is intentional: there is no "insecure" mode.
    ///
    /// Panics if DD_ENV is not set (ensures every deployment declares its environment).
    pub fn from_env() -> Self {
        // Force environment declaration — no silent fallback to "local".
        let _env = RuntimeEnv::detect();

        if let Ok(api_key) = std::env::var("DD_INTEL_API_KEY") {
            let jwks_url = std::env::var("DD_ITA_JWKS_URL")
                .unwrap_or_else(|_| "https://portal.trustauthority.intel.com/certs".into());
            let issuer = std::env::var("DD_ITA_ISSUER").ok();
            let audience = std::env::var("DD_ITA_AUDIENCE").ok().or(Some(api_key));
            Self {
                verifier: Some(ItaVerifier::new(jwks_url, issuer, audience)),
            }
        } else {
            eprintln!("dd-cp: DD_INTEL_API_KEY not set — attestation verification will reject all registration attempts");
            Self { verifier: None }
        }
    }

    /// Validate that runtime requirements are met for the current environment.
    /// All environments require a configured ITA verifier — there is no insecure mode.
    pub fn validate_runtime_requirements(&self) -> AppResult<()> {
        if self.verifier.is_none() {
            return Err(AppError::Config(
                "DD_INTEL_API_KEY is required — attestation verifier must be configured".into(),
            ));
        }
        Ok(())
    }

    /// Verify an agent registration token, returning attestation data.
    pub async fn verify_registration_token(&self, token: &str) -> AppResult<VerifiedAttestation> {
        if token.is_empty() {
            return Err(AppError::Config("attestation token is required".into()));
        }

        match &self.verifier {
            Some(v) => {
                let claims = v.verify_attestation_token(token).await?;
                Ok(extract_attestation(&claims))
            }
            None => Err(AppError::Config(
                "attestation verifier not configured (DD_INTEL_API_KEY required)".into(),
            )),
        }
    }
}

fn extract_attestation(claims: &AttestationClaims) -> VerifiedAttestation {
    let mut rtmrs = Vec::new();
    for i in 0..4 {
        let key = format!("tdx.rtmr{i}");
        if let Some(val) = claims.extra.get(&key) {
            if let Some(s) = val.as_str() {
                rtmrs.push(s.to_string());
            }
        }
    }

    VerifiedAttestation {
        mrtd: claims.tdx_mrtd.clone(),
        tcb_status: claims.attester_tcb_status.clone(),
        rtmrs,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_verifier_is_rejected() {
        let svc = AttestationService { verifier: None };
        assert!(svc.validate_runtime_requirements().is_err());
    }

    #[test]
    fn empty_token_is_rejected() {
        let svc = AttestationService { verifier: None };
        let result = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(svc.verify_registration_token(""));
        assert!(result.is_err());
    }
}
