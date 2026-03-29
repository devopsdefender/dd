-- Store the raw attestation token so deployers can verify independently.
ALTER TABLE agents ADD COLUMN attestation_token TEXT;
