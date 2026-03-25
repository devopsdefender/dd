-- DevOps Defender Control Plane schema

CREATE TABLE IF NOT EXISTS agents (
    id TEXT PRIMARY KEY,
    vm_name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'undeployed',
    registration_state TEXT NOT NULL DEFAULT 'pending',
    hostname TEXT,
    tunnel_id TEXT,
    mrtd TEXT,
    tcb_status TEXT,
    node_size TEXT,
    datacenter TEXT,
    github_owner TEXT,
    deployment_id TEXT REFERENCES deployments(id),
    created_at TEXT NOT NULL,
    last_heartbeat_at TEXT
);

CREATE TABLE IF NOT EXISTS agent_control_credentials (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL REFERENCES agents(id),
    credential_type TEXT NOT NULL,
    credential_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS deployments (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL REFERENCES agents(id),
    image TEXT NOT NULL,
    env TEXT NOT NULL,
    cmd TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS app_health_checks (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    app_name TEXT,
    health_ok INTEGER NOT NULL DEFAULT 0,
    attestation_ok INTEGER NOT NULL DEFAULT 0,
    failure_reason TEXT,
    checked_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS services (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL REFERENCES agents(id),
    name TEXT NOT NULL,
    image TEXT,
    status TEXT NOT NULL DEFAULT 'unknown',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS apps (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS app_versions (
    id TEXT PRIMARY KEY,
    app_id TEXT NOT NULL REFERENCES apps(id),
    version TEXT NOT NULL,
    compose TEXT NOT NULL,
    config TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS accounts (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    account_type TEXT NOT NULL,
    api_key_hash TEXT NOT NULL,
    api_key_prefix TEXT NOT NULL,
    github_login TEXT,
    github_org TEXT,
    created_at TEXT NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS admin_sessions (
    id TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL,
    token_prefix TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS trusted_mrtds (
    id TEXT PRIMARY KEY,
    mrtd TEXT NOT NULL UNIQUE,
    label TEXT,
    created_at TEXT NOT NULL
);
