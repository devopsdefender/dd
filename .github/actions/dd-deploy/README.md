# dd-deploy

GitHub Action that deploys a workload JSON to a DD agent using a **per-job GitHub Actions OIDC token**. No shared secrets to configure — the agent verifies the token against GitHub's JWKS and checks that `repository_owner == DD_OWNER`.

## Usage

```yaml
jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      id-token: write   # required to mint the OIDC token
      contents: read
    steps:
      - uses: actions/checkout@v4
      - uses: devopsdefender/dd/.github/actions/dd-deploy@main
        with:
          cp-url: https://app.devopsdefender.com
          vm-name: dd-local-prod
          workload: apps/myapp/workload.json
```

The action will:

1. Look up the current hostname for your target agent via the CP's `/api/agents`.
2. Mint a GitHub Actions OIDC JWT with `audience: dd-agent`.
3. POST the baked workload JSON to `https://<agent>/deploy` with `Authorization: Bearer <oidc>`.
4. Poll the agent's `/health` until the deployment appears (or fail after `wait-for-deployment-seconds`).

## Inputs

| name | required | default | description |
| --- | --- | --- | --- |
| `cp-url` | yes | — | Control-plane URL (e.g. `https://app.devopsdefender.com`) |
| `vm-name` | yes | — | Target agent `vm_name` as reported on `/api/agents` |
| `workload` | yes | — | Path to the workload JSON spec |
| `audience` | no | `dd-agent` | OIDC audience the agent expects |
| `wait-for-deployment-seconds` | no | `120` | Poll `/health` until `app_name` appears. `0` disables waiting. |

## Outputs

| name | description |
| --- | --- |
| `agent-host` | Hostname the workload landed on |
| `app-name` | `app_name` parsed from the workload JSON |

## Trust model

The agent's `/deploy` endpoint is CF-Access-bypassed and gated entirely by an in-code OIDC check:

- Issuer must be `https://token.actions.githubusercontent.com`
- Signature must verify against GitHub's live JWKS
- `repository_owner` claim must equal `DD_OWNER` (set on the CP at boot)
- `audience` claim must match the agent's configured audience

This means **any workflow in the DD GitHub organization can deploy, with no credentials stored anywhere**. Workflows in a different org (including forks) fail the `repository_owner` check and get 401.

## Example: deploy on PR merge

```yaml
name: deploy-myapp

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
    steps:
      - uses: actions/checkout@v4
      - uses: devopsdefender/dd/.github/actions/dd-deploy@main
        with:
          cp-url: https://app.devopsdefender.com
          vm-name: dd-local-prod
          workload: apps/myapp/workload.json
          wait-for-deployment-seconds: 300
```
