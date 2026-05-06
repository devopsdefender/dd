//! Method allowlist for EE agent-socket RPCs.
//!
//! Only methods that are safe to expose to an external device are let
//! through. `deploy` in particular stays internal — enclave workload
//! topology is managed by DD's CP + agent, not by end-user CLIs.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Method {
    Attest,
    Attach,
    Exec,
    Health,
    List,
    Logs,
}

impl Method {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Attest => "attest",
            Self::Attach => "attach",
            Self::Exec => "exec",
            Self::Health => "health",
            Self::List => "list",
            Self::Logs => "logs",
        }
    }
}

/// Deserialize just the `method` field from a request envelope and
/// match it against the allowlist. Returns `Err` for unknown or
/// disallowed methods.
pub fn classify(raw: &serde_json::Value) -> Result<Method, ClassifyError> {
    let method = raw
        .get("method")
        .and_then(|v| v.as_str())
        .ok_or(ClassifyError::Missing)?;
    match method {
        "attest" => Ok(Method::Attest),
        "attach" => Ok(Method::Attach),
        "exec" => Ok(Method::Exec),
        "health" => Ok(Method::Health),
        "list" => Ok(Method::List),
        "logs" => Ok(Method::Logs),
        "deploy" => Err(ClassifyError::Disallowed("deploy".into())),
        other => Err(ClassifyError::Unknown(other.into())),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ClassifyError {
    #[error("request envelope missing `method` field")]
    Missing,
    #[error("method `{0}` is not in the allowlist")]
    Disallowed(String),
    #[error("unknown method `{0}`")]
    Unknown(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deploy_blocked() {
        let r = classify(&serde_json::json!({"method": "deploy"}));
        assert!(matches!(r, Err(ClassifyError::Disallowed(_))));
    }

    #[test]
    fn exec_allowed() {
        let r = classify(&serde_json::json!({"method": "exec", "argv": ["ls"]}));
        assert_eq!(r.unwrap(), Method::Exec);
    }

    #[test]
    fn unknown_rejected() {
        let r = classify(&serde_json::json!({"method": "steal"}));
        assert!(matches!(r, Err(ClassifyError::Unknown(_))));
    }

    #[test]
    fn missing_rejected() {
        let r = classify(&serde_json::json!({}));
        assert!(matches!(r, Err(ClassifyError::Missing)));
    }
}
