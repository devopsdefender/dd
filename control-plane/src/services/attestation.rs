use crate::attestation::ita::{AttestationClaims, ItaVerifier};
use crate::common::error::{AppError, AppResult};

/// Runtime environment classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeEnv {
    Local,
    Staging,
    Production,
}

impl RuntimeEnv {
    /// Detect runtime environment from DD_ENV or DD_CP_ENV env vars.
    pub fn detect() -> Self {
        let val = std::env::var("DD_ENV")
            .or_else(|_| std::env::var("DD_CP_ENV"))
            .unwrap_or_default();
        match val.to_lowercase().as_str() {
            "production" | "prod" => RuntimeEnv::Production,
            "staging" | "stage" => RuntimeEnv::Staging,
            _ => RuntimeEnv::Local,
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

/// High-level attestation service that wraps ItaVerifier with environment-specific policy.
#[derive(Clone)]
pub struct AttestationService {
    verifier: Option<ItaVerifier>,
    env: RuntimeEnv,
}

impl AttestationService {
    pub fn new(verifier: ItaVerifier, env: RuntimeEnv) -> Self {
        Self {
            verifier: Some(verifier),
            env,
        }
    }

    /// Create a service that skips real verification (for tests / local dev).
    pub fn insecure_for_tests() -> Self {
        Self {
            verifier: None,
            env: RuntimeEnv::Local,
        }
    }

    /// Validate that runtime requirements are met for the current environment.
    pub fn validate_runtime_requirements(&self) -> AppResult<()> {
        match self.env {
            RuntimeEnv::Production => {
                if self.verifier.is_none() {
                    return Err(AppError::Config(
                        "production requires a configured ITA verifier".into(),
                    ));
                }
                Ok(())
            }
            RuntimeEnv::Staging => {
                // Staging allows missing verifier but logs a warning
                Ok(())
            }
            RuntimeEnv::Local => Ok(()),
        }
    }

    /// Verify an agent registration token, returning attestation data.
    pub async fn verify_registration_token(&self, token: &str) -> AppResult<VerifiedAttestation> {
        match &self.verifier {
            Some(v) => {
                let claims = v.verify_attestation_token(token).await?;
                Ok(extract_attestation(&claims))
            }
            None => {
                // Insecure mode: accept anything
                Ok(VerifiedAttestation {
                    mrtd: Some("insecure-local-mrtd".into()),
                    tcb_status: Some("UpToDate".into()),
                    rtmrs: vec![],
                })
            }
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

    #[tokio::test]
    async fn insecure_mode_accepts_anything() {
        let svc = AttestationService::insecure_for_tests();
        let result = svc.verify_registration_token("fake-token").await;
        assert!(result.is_ok());
        let att = result.unwrap();
        assert_eq!(att.mrtd, Some("insecure-local-mrtd".into()));
    }

    #[test]
    fn staging_allows_no_verifier() {
        let svc = AttestationService {
            verifier: None,
            env: RuntimeEnv::Staging,
        };
        assert!(svc.validate_runtime_requirements().is_ok());
    }

    #[test]
    fn production_requires_verifier() {
        let svc = AttestationService {
            verifier: None,
            env: RuntimeEnv::Production,
        };
        assert!(svc.validate_runtime_requirements().is_err());
    }
}
