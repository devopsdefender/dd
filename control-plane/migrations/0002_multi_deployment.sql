-- Multi-deployment support: add error tracking and rollback lineage
ALTER TABLE deployments ADD COLUMN error_message TEXT;
ALTER TABLE deployments ADD COLUMN previous_deployment_id TEXT REFERENCES deployments(id);
