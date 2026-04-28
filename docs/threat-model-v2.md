# DD v2 Threat Model

DD v2 separates three roles that the current codebase tends to blend together:

- **operator**: runs hardware, networking, billing, and assignment automation
- **owner**: current GitHub principal allowed to deploy workloads
- **verifier**: user or protocol participant checking what is running

The design goal is not to eliminate operator power over infrastructure. It is
to make workload authority and runtime proof explicit enough that a verifier can
detect the relevant trust boundary.

## Assets

- current owner principal
- assignment claim history
- workload source identity
- workload artifact digest
- TDX quote and measurements
- agent signing/noise key material
- runtime logs and output
- ingress routes for workload endpoints

## Trust Boundaries

### Operator Boundary

The operator can:

- start and stop machines
- replace a VM
- route or de-route hostnames
- assign an agent if authorized by the assignment system
- observe public proof documents and exposed traffic metadata

The operator should not be able to:

- deploy a workload unless they are also current owner
- silently impersonate a repo owner through GitHub OIDC
- make a verifier accept a workload without matching proof
- mutate owner state without an assignment event

### Owner Boundary

The owner can:

- deploy workloads from matching GitHub Actions OIDC claims
- read logs if the agent exposes logs
- use debug routes only if the agent capability set allows it

The owner should not be able to:

- change assignment authority
- claim ownership of other agents
- forge attestation or artifact provenance

### Verifier Boundary

The verifier can:

- fetch `GET /health`
- verify TDX attestation
- compare owner principal to expected GitHub identity
- compare workload source, ref, and digest to expected open-source code
- reject agents with unsafe capabilities

The verifier should not need:

- DD repo write access
- Cloudflare dashboard access
- SSH to the host
- trust in CI log screenshots

## Primary Risks

### Name Squatting

Risk: GitHub login or repo name changes hands.

Mitigation:

- principal matching requires numeric GitHub IDs
- proof documents expose IDs, not just names
- assignment records store IDs

### Reboot Loses Owner

Risk: runtime owner disappears after VM reboot.

Mitigation:

- this is expected behavior
- assignment is desired state outside the VM
- reconcilers repeatedly call `POST /owner`
- deploy workflows wait for `health.owner == expected`

### Operator Deploys Customer Workload

Risk: managed operator deploys or changes workload after assignment.

Mitigation:

- deploy endpoint accepts current owner only
- operator assignment authority is not deploy authority
- proof exposes `deployed_by` GitHub claims

### Runtime Debug Invalidates Confidentiality

Risk: `/exec`, terminal, or mutable deployment channels undermine oracle claims.

Mitigation:

- proof exposes capability flags
- oracle profiles should disable `exec` and interactive shell
- verifier policy rejects unexpected capabilities

### Closed-Source or Ambiguous Artifact

Risk: verifier cannot map runtime artifact to public source.

Mitigation:

- workload proof includes repo/ref/commit/artifact digest
- deploy action should attach build provenance
- examples and docs require OSS repos for production workloads

### Stale or Forked Agent

Risk: old code keeps serving a convincing dashboard.

Mitigation:

- verifier checks TDX quote and measurement policy
- proof schema is machine-readable
- deployment action verifies proof before and after deploy

## Capability Profiles

### Coding Agent

Expected capabilities:

- `runtime_deploy: true`
- `logs: true`
- `exec: optional`
- `interactive_shell: optional`

Verifier posture: user trusts their own assigned agent but still wants
attestation and source provenance.

### Bot Agent

Expected capabilities:

- `runtime_deploy: true`
- `logs: true`
- `exec: false` by default
- `interactive_shell: false` by default

Verifier posture: project maintainers check assignment and deployment source.

### Oracle Agent

Expected capabilities:

- `runtime_deploy: false` after boot or controlled redeploy only
- `logs: limited`
- `exec: false`
- `interactive_shell: false`

Verifier posture: third parties reject mutable/debuggable agents unless the
oracle protocol explicitly permits those capabilities.

## Security Invariants

- Assignment authority and workload authority are separate.
- Current owner is the only deploy authority.
- GitHub principal IDs are mandatory.
- Reassignment is idempotent and auditable.
- Proof is public and machine-readable.
- Confidentiality claims are tied to capabilities, not branding.
