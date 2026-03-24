use crate::attestation::ita::ItaVerifier;
use crate::common::error::{AppError, AppResult};

/// Service for verifying GitHub Actions OIDC JWTs.
#[derive(Clone)]
pub struct GithubOidcService {
    verifier: Option<ItaVerifier>,
}

impl GithubOidcService {
    /// Create the service from environment configuration.
    /// Uses GitHub's JWKS endpoint for token verification.
    pub fn from_env() -> Self {
        let audience = std::env::var("DD_CP_GITHUB_OIDC_AUDIENCE").ok();
        let verifier = ItaVerifier::new(
            "https://token.actions.githubusercontent.com/.well-known/jwks".into(),
            Some("https://token.actions.githubusercontent.com".into()),
            audience,
        );
        Self {
            verifier: Some(verifier),
        }
    }

    /// Verify a GitHub OIDC token and return the claims.
    pub async fn verify_token(&self, token: &str) -> AppResult<serde_json::Value> {
        match &self.verifier {
            Some(v) => {
                let claims = v.verify_attestation_token(token).await?;
                Ok(serde_json::to_value(claims).map_err(|_| AppError::Internal)?)
            }
            None => Err(AppError::Config(
                "GitHub OIDC verification is disabled".into(),
            )),
        }
    }
}
