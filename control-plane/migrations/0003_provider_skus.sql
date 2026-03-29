-- Provider SKUs: capacity types offered by each provider.

CREATE TABLE IF NOT EXISTS provider_skus (
    id TEXT PRIMARY KEY,
    provider_id TEXT NOT NULL REFERENCES trusted_measurers(id),
    name TEXT NOT NULL,
    vcpu INTEGER NOT NULL,
    ram_gb INTEGER NOT NULL,
    gpu TEXT,
    region TEXT,
    available INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TEXT NOT NULL
);
