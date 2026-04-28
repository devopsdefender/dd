# DD v2 Product Spec

DD v2 is an attested execution layer for open-source agent workloads.
The core product is not "CI/CD for this repo"; it is a way to lease or
self-run confidential agents whose current deploy authority is a GitHub
principal and whose runtime state can be verified by third parties.

## Core Use Cases

1. **Confidential LLM coding agents**
   - A user assigns an agent to their GitHub user, organization, or repo.
   - Their repo deploys an open-source coding agent workload by GitHub OIDC.
   - The user verifies TDX attestation, source provenance, and live workload state.

2. **Autonomous open-source bots**
   - Projects like OpenClaw or Hermes live in their own repositories.
   - Their own CI deploys to assigned agents; the DD repo is only substrate.
   - Reassignment after reboot is expected and idempotent.

3. **Confidential crypto oracles**
   - Oracle code is public and built from a public repo/ref.
   - Consumers verify the agent, workload source, build provenance, and attestation.
   - Operators may provide infrastructure, but cannot silently become workload owner.

## Product Primitives

### Agent

An agent is a TDX-backed runtime with:

- a stable `agent_id`
- a public `hostname`
- a current owner principal
- an assignment authority
- a current workload set
- a public proof document

An agent does not need durable local ownership state. On reboot it may start
unassigned, then an external assigner reconciles it back to the desired owner.

### Principal

A principal is one of:

- `user:<github_login>#<github_user_id>`
- `org:<github_login>#<github_org_id>`
- `repo:<owner>/<repo>#<github_repo_id>`

The numeric GitHub ID is required. Name-only matching is not sufficient because
deleted or transferred GitHub names can be re-registered.

### Assignment

Assignment sets the agent's current owner principal.

Properties:

- runtime state, not durable VM truth
- idempotent for the same owner and claim
- safe to repeat after every reboot
- authorized by the assignment authority, not by the current owner
- auditable by `claim_id`

The assignment authority may be:

- the self-hosting user
- a managed fleet operator
- a billing/lease controller
- a repo-specific automation account

This is still one product mode. The operator controls infrastructure lifecycle;
the current owner controls workload deployment.

### Workload

A workload is an open-source repo artifact plus runtime spec.

Minimum identity:

- source repository
- git ref or immutable commit
- build workflow identity
- artifact digest
- workload spec digest

The DD repo should not contain production workloads except examples. Real bots,
LLM agents, and oracles live in their own repositories and deploy themselves.

### Proof

Every agent exposes a machine-readable proof document. It should be sufficient
for a verifier to answer:

- which hardware-backed enclave am I talking to?
- who currently owns deploy authority?
- what workload source is claimed?
- what artifact digest is running?
- was the workload deployed by the owner principal?
- are mutation/debug capabilities enabled?

Draft shape:

```json
{
  "service": "dd-agent",
  "agent_id": "dd-agent-...",
  "hostname": "agent.example.com",
  "status": "healthy",
  "owner": {
    "kind": "repo",
    "name": "example/oracle",
    "id": 123456789
  },
  "assignment": {
    "claim_id": "lease_abc123",
    "assigned_at": "2026-04-28T00:00:00Z"
  },
  "attestation": {
    "type": "tdx",
    "quote_b64": "...",
    "mrtd": "...",
    "tcb_status": "UpToDate"
  },
  "workloads": [
    {
      "app_name": "oracle",
      "source_repo": "example/oracle",
      "source_ref": "refs/tags/v1.2.3",
      "source_commit": "...",
      "artifact_digest": "sha256:...",
      "spec_digest": "sha256:...",
      "deployed_by": {
        "repository": "example/oracle",
        "repository_id": 123456789,
        "workflow": "deploy.yml"
      }
    }
  ],
  "capabilities": {
    "runtime_deploy": true,
    "exec": false,
    "interactive_shell": false,
    "logs": true
  }
}
```

## API Surface

### Agent API

The agent should remain small.

| Endpoint | Purpose | Auth |
| --- | --- | --- |
| `GET /health` | public proof and liveness | none |
| `POST /owner` | assign current owner | assignment authority OIDC |
| `POST /deploy` | deploy workload spec | current owner OIDC |
| `GET /logs/{app}` | read workload logs | current owner OIDC |
| `POST /exec` | optional debug command | current owner OIDC + capability enabled |

`POST /owner` is explicitly safe to call repeatedly. Same requested owner and
same `claim_id` should return success without changing runtime state.

### Control Plane API

The control plane is optional coordination, not core trust.

Responsibilities:

- discover agents
- reconcile desired assignments
- provide dashboards
- expose lease/claim state
- route traffic
- collect proof documents

An agent should still be understandable as a standalone product primitive.

## GitHub Actions Model

Each workload repository owns its deploy workflow:

```yaml
permissions:
  id-token: write
  contents: read

steps:
  - uses: actions/checkout@v4
  - uses: devopsdefender/dd-action/deploy@v2
    with:
      agent: https://agent.example.com
      workload: workload.json
```

The action should:

1. mint a GitHub Actions OIDC token
2. resolve or validate the target agent
3. verify the agent's proof document
4. submit the workload spec
5. wait for the proof document to reflect the deployment

## Invariants

- Every deployable agent has one current owner.
- Current owner is the only deploy authority.
- Assignment authority is separate from deploy authority.
- Assignment is idempotent and externally reconciled.
- Workload code is open source.
- Verification does not require trusting DD marketing, dashboards, or CI logs.
- DD infrastructure examples are not the product boundary.

## Non-Goals

- DD v2 is not a general Kubernetes replacement.
- DD v2 is not a secret-bearing CI system.
- DD v2 does not require workloads to live in the DD repo.
- DD v2 does not make VM-local ownership persistence authoritative.
- DD v2 does not require a central hosted control plane for self-hosted agents.
