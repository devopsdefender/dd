-- App store trust model.
--
-- Three-layer trust:
--   1. Provider: TDX measurement proves the environment is safe to deploy into
--   2. App store: OCI image digest + GitHub provenance proves the code is legitimate
--   3. Owner: app publisher controls who can deploy their app
--
-- TDX measurement is a one-time gate at agent registration. After that,
-- app trust comes from the software supply chain (GitHub/OCI), not hardware.

-- Add owner and image_digest to existing tables
ALTER TABLE apps ADD COLUMN owner_id TEXT;
ALTER TABLE app_versions ADD COLUMN image_digest TEXT;

-- Providers: DC operators or cloud account owners that bring capacity to DD.
-- They measure undeployed agents (TDX attestation) before CP registration.
-- After registration, trust shifts from the enclave to the app store.
CREATE TABLE IF NOT EXISTS providers (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    public_key TEXT NOT NULL,
    agent_id TEXT REFERENCES agents(id),
    mrtd TEXT,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TEXT NOT NULL
);

-- Provider SKUs: capacity types each provider offers.
CREATE TABLE IF NOT EXISTS provider_skus (
    id TEXT PRIMARY KEY,
    provider_id TEXT NOT NULL REFERENCES providers(id),
    name TEXT NOT NULL,
    vcpu INTEGER NOT NULL,
    ram_gb INTEGER NOT NULL,
    gpu TEXT,
    region TEXT,
    available INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TEXT NOT NULL
);

-- Deploy grants: app owner grants deploy rights to specific accounts.
-- Owner-only by default. Unowned apps are open to anyone.
CREATE TABLE IF NOT EXISTS app_deploy_grants (
    id TEXT PRIMARY KEY,
    app_id TEXT NOT NULL REFERENCES apps(id),
    account_id TEXT NOT NULL,
    granted_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(app_id, account_id)
);
