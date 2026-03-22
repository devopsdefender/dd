use serde::{Deserialize, Serialize};

/// Current operational status of an agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentStatus {
    Undeployed,
    Deploying,
    Deployed,
}

impl std::fmt::Display for AgentStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AgentStatus::Undeployed => write!(f, "undeployed"),
            AgentStatus::Deploying => write!(f, "deploying"),
            AgentStatus::Deployed => write!(f, "deployed"),
        }
    }
}

/// Registration state of an agent going through attestation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentRegistrationState {
    Pending,
    Ready,
    Failed,
}

impl std::fmt::Display for AgentRegistrationState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AgentRegistrationState::Pending => write!(f, "pending"),
            AgentRegistrationState::Ready => write!(f, "ready"),
            AgentRegistrationState::Failed => write!(f, "failed"),
        }
    }
}

/// Lifecycle status of a deployment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentStatus {
    Pending,
    Deploying,
    Running,
    Failed,
    Stopped,
}

impl std::fmt::Display for DeploymentStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeploymentStatus::Pending => write!(f, "pending"),
            DeploymentStatus::Deploying => write!(f, "deploying"),
            DeploymentStatus::Running => write!(f, "running"),
            DeploymentStatus::Failed => write!(f, "failed"),
            DeploymentStatus::Stopped => write!(f, "stopped"),
        }
    }
}

/// Type of account in the system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountType {
    Deployer,
    Agent,
    Contributor,
    Platform,
}

impl std::fmt::Display for AccountType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AccountType::Deployer => write!(f, "deployer"),
            AccountType::Agent => write!(f, "agent"),
            AccountType::Contributor => write!(f, "contributor"),
            AccountType::Platform => write!(f, "platform"),
        }
    }
}
