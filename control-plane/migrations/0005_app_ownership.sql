-- App ownership: publisher controls who can deploy their app.
-- Owner-only by default; owner grants deploy rights to specific accounts.

ALTER TABLE apps ADD COLUMN owner_id TEXT;

CREATE TABLE IF NOT EXISTS app_deploy_grants (
    id TEXT PRIMARY KEY,
    app_id TEXT NOT NULL REFERENCES apps(id),
    account_id TEXT NOT NULL,
    granted_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(app_id, account_id)
);
