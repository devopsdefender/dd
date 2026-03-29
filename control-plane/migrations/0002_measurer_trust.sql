-- Measurer trust model: replaces MRTD whitelist with CA-like trust delegation.
-- DC operators run node measurers to attest hardware.
-- Security companies run app measurers to audit container images.
-- CP only trusts measurers, not individual measurements.

CREATE TABLE IF NOT EXISTS trusted_measurers (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    public_key TEXT NOT NULL,
    agent_id TEXT REFERENCES agents(id),
    mrtd TEXT,
    measurement_types TEXT NOT NULL DEFAULT 'app',
    status TEXT NOT NULL DEFAULT 'active',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS measurements (
    id TEXT PRIMARY KEY,
    measurer_id TEXT NOT NULL REFERENCES trusted_measurers(id),
    measurement_type TEXT NOT NULL,
    app_id TEXT REFERENCES apps(id),
    version_id TEXT REFERENCES app_versions(id),
    image_digest TEXT,
    agent_id TEXT REFERENCES agents(id),
    node_mrtd TEXT,
    measurement_hash TEXT NOT NULL,
    signature TEXT NOT NULL,
    report TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'valid',
    measured_at TEXT NOT NULL
);
