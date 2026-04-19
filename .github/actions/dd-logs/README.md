# dd-logs

GitHub Action that pulls a workload's stdout from a DD agent using a **per-job GitHub Actions OIDC token**. No shared secrets — the agent verifies the token against GitHub's JWKS and checks `repository_owner == DD_OWNER`.

Good for:
- Debugging a failed deploy (`dd-deploy` also uses this path internally on timeout).
- Watching a long-running workload without opening an interactive session.
- Pulling `dd-agent`'s own startup output when a newly-registered agent misbehaves.

## Usage

```yaml
jobs:
  tail-hello-world:
    runs-on: ubuntu-latest
    permissions:
      id-token: write   # required to mint the OIDC token
      contents: read
    steps:
      - uses: devopsdefender/dd/.github/actions/dd-logs@main
        with:
          cp-url: https://app.devopsdefender.com
          vm-name: dd-local-prod
          app: hello-world
```

The action will:

1. Look up the current hostname for your target agent via the CP's `/api/agents`.
2. Mint a GitHub Actions OIDC JWT with `audience: dd-agent`.
3. GET `https://<agent>/logs/<app>` with `Authorization: Bearer <oidc>`.
4. Print each line of `.lines[]` to the job log (or the raw JSON body if the shape is unexpected).

## Inputs

| name | required | default | description |
| --- | --- | --- | --- |
| `cp-url` | yes | — | Control-plane URL (e.g. `https://app.devopsdefender.com`) |
| `vm-name` | yes | — | Target agent `vm_name` as reported on `/api/agents` |
| `app` | yes | — | `app_name` of the deployment |
| `audience` | no | `dd-agent` | OIDC audience the agent expects |

## Outputs

| name | description |
| --- | --- |
| `agent-host` | Hostname the log was pulled from |

## Trust model

Same as [`dd-deploy`](../dd-deploy/README.md). The agent's `/logs/{app}` endpoint is CF-Access-bypassed and gated in code by a GitHub Actions OIDC JWT; any workflow in the DD GitHub organization can read logs, no one else can. Returns 404 if no deployment with that `app_name` exists.
