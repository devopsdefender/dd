-- Add last_attested_at column to track when an agent last passed re-attestation.
ALTER TABLE agents ADD COLUMN last_attested_at TEXT;
