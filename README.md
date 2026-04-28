# DevOps Defender

DD is an attested execution layer for open-source agent workloads.

This branch deletes the old v1 control-plane/fleet implementation and keeps the
new core primitive: a small agent with runtime ownership, GitHub OIDC deploys,
and a public proof document.

## What Exists Now

- `crates/dd-agent`: minimal Rust agent.
- `.github/actions/assign`: idempotently assigns an agent to a GitHub principal.
- `.github/actions/deploy`: deploys a workload from the current owner repo.
- `.github/actions/verify`: checks the public agent proof document.
- `docs/spec-v2.md`: product model.
- `docs/threat-model-v2.md`: operator, owner, and verifier boundaries.
- `docs/rewrite-plan.md`: remaining migration plan.

## Model

Every agent has one current owner principal:

- `user:<github_login>#<github_user_id>`
- `org:<github_login>#<github_org_id>`
- `repo:<owner>/<repo>#<github_repo_id>`

Ownership is runtime state. Reboot can clear it. External automation is expected
to call `/owner` repeatedly until the agent's `/health` proof reflects the
desired owner.

The assignment authority and deploy authority are separate:

- `/owner` accepts the assignment authority's GitHub Actions OIDC token.
- `/deploy`, `/logs/{app}`, and `/exec` accept only the current owner's token.
- `/health` is public proof for users and third-party verifiers.

## Agent

Run a local development agent:

```bash
DD_ASSIGNMENT_AUTHORITY_KIND=repo \
DD_ASSIGNMENT_AUTHORITY_NAME=example/assigner \
DD_ASSIGNMENT_AUTHORITY_ID=123456789 \
cargo run -p dd-agent
```

Endpoints:

| Endpoint | Purpose | Auth |
| --- | --- | --- |
| `GET /health` | public proof and liveness | none |
| `POST /owner` | set current owner | assignment authority OIDC |
| `POST /deploy` | launch workload | current owner OIDC |
| `GET /logs/{app}` | read workload logs | current owner OIDC |
| `POST /exec` | optional debug command | current owner OIDC + capability enabled |

## Workload Shape

```json
{
  "app_name": "oracle",
  "cmd": ["/bin/sh", "-c", "echo oracle; sleep 60"],
  "source": {
    "repo": "example/oracle",
    "ref": "refs/heads/main",
    "commit": "..."
  },
  "artifact_digest": "sha256:...",
  "spec_digest": "sha256:..."
}
```

Production workload repositories should own their deploy workflows. The DD repo
provides the substrate and actions; it should not contain production bot,
oracle, or LLM-agent workloads.

## Validation

```bash
cargo fmt --all -- --check
cargo check --workspace
cargo test --workspace
```
