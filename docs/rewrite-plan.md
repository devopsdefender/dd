# DD v2 Rewrite Plan

The current repository grew organically around DD's own fleet and CI. The v2
rewrite should start from the product primitives instead: agents, assignment,
workloads, and proofs.

## Target Shape

### Crates or Repos

1. `dd-agent`
   - small Rust binary
   - owns attestation, assignment, deploy, logs, proof
   - no Cloudflare-specific fleet assumptions in core logic

2. `dd-cp`
   - optional control plane
   - discovers agents, reconciles assignments, hosts dashboard
   - useful for managed fleets, not required for self-hosted agents

3. `dd-action`
   - GitHub Actions interface
   - `assign`, `deploy`, `verify`
   - stable public API for workload repositories

4. `dd-spec`
   - workload schema
   - proof schema
   - assignment schema
   - verifier rules and examples

5. `examples`
   - confidential coding LLM
   - OpenClaw/Hermes-style bot
   - crypto oracle
   - self-hosted single-agent setup

## Agent Rewrite

Keep the agent intentionally boring.

### State

```rust
struct AgentState {
    agent_id: AgentId,
    assignment_authority: Principal,
    current_owner: Option<Assignment>,
    workloads: WorkloadStore,
    attestation: AttestationBundle,
    capabilities: CapabilitySet,
}
```

`current_owner` is runtime state. It can reset on reboot. The external assigner
is responsible for reconciling desired state.

### Endpoints

- `GET /health`
- `POST /owner`
- `POST /deploy`
- `GET /logs/{app}`
- `POST /exec` if capability-enabled

Everything else belongs in the optional CP or examples.

### Authorization

- `/owner`: assignment authority only
- `/deploy`: current owner only
- `/logs`: current owner only unless workload marks logs public
- `/exec`: current owner only and capability-enabled
- `/health`: public

No endpoint should mean "fleet owner OR tenant owner" for workload control.
There is one current deploy owner.

## Control Plane Rewrite

The CP should not be the trust root for open-source workload verification.
It is coordination.

Responsibilities:

- maintain desired assignment records
- call `/owner` until actual state matches desired state
- index proof documents
- provide dashboards
- manage ingress if configured
- expose assignment audit trails

The CP should tolerate agents that are:

- self-hosted
- managed by another operator
- temporarily unassigned after reboot
- assigned to repo principals outside the DD org

## GitHub Action Rewrite

The action is the product interface for external repos.

Commands:

```yaml
- uses: devopsdefender/dd-action/verify@v2
- uses: devopsdefender/dd-action/deploy@v2
- uses: devopsdefender/dd-action/assign@v2
```

### `verify`

- fetch proof document
- verify TDX quote
- verify owner principal
- verify capabilities against selected profile
- emit normalized JSON for downstream steps

### `deploy`

- mint GitHub OIDC token
- verify proof owner matches caller
- submit workload spec
- poll proof until workload appears
- fail if `deployed_by` does not match caller claims

### `assign`

- resolve GitHub principal IDs
- call `/owner`
- poll proof until owner matches
- safe to repeat forever

## CI/CD Rewrite

Split CI into product concerns and internal fleet concerns.

### Product CI

Runs on every PR:

- format
- lint
- unit tests
- schema validation
- build static artifacts
- generate provenance

### Release CI

Runs on tags or main release branches:

- publish `dd-agent`
- publish `dd-cp`
- publish `dd-action`
- publish schemas
- attach provenance

### Internal Fleet CI

Runs only for DD-operated infra:

- deploy DD's own CP
- relaunch DD's own demo agents
- clean up preview infrastructure

This should live under a clearly named internal workflow boundary. It should
not define how user workloads are expected to deploy.

## Migration Steps

1. Keep the v1 deletion landed so old fleet assumptions do not keep shaping new code.
2. Extract principal parsing and GitHub OIDC verification into a small reusable module.
3. Harden the proof schema and verifier action.
4. Add TDX quote capture and verification to `dd-agent`.
5. Port EasyEnclave workload execution behind the current-owner-only API.
6. Build a small reconciler that repeatedly assigns owners.
7. Port only necessary Cloudflare/ingress code into `dd-cp`.
8. Move examples into standalone workload repositories.
9. Add release provenance for the agent and action surfaces.

## Design Rules

- Do not optimize for DD's own tdx2 host in core code.
- Do not make workload repos depend on the DD repo's CI.
- Do not persist owner locally as source of truth.
- Do not give operators deploy authority unless they are current owner.
- Do not hide mutability behind marketing terms like "confidential."
- Do expose enough proof for external verifiers to reject unsafe agents.

## First Implementation Milestone

A useful v2 alpha is:

- single self-hosted agent
- runtime assignment
- GitHub OIDC deploy from an external repo
- public proof document
- verifier action

No dashboard, no fleet cleanup, no GPU demo, no preview environments. Those can
come after the primitive works.

## Current Alpha Slice

This repo now carries the v2 alpha as the only Rust build target:

- `crates/dd-agent` implements the minimal agent primitive.
- `.github/actions/assign` reconciles runtime owner assignment.
- `.github/actions/deploy` deploys from an external workload repo.
- `.github/actions/verify` checks the public proof document.

The v1 control plane, fleet workflows, EasyEnclave app examples, and
tdx2-specific scripts have been removed from this branch. The remaining work is
to port only the parts that fit the v2 model: TDX proof, EasyEnclave execution,
Cloudflare ingress, and managed-fleet reconciliation.
