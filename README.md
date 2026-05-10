# DevOps Defender

Confidential computing marketplace. Run AI workloads on hardware-sealed Intel TDX VMs with cryptographic attestation.

## Architecture

One Cargo crate, one static musl binary, two run modes:

```
DD_MODE=cp      devopsdefender    # control-plane (dashboard, register, collector, STONITH)
DD_MODE=agent   devopsdefender    # in-VM agent   (dashboard, /deploy, /logs, metrics)
```

Source layout (all under `src/`, flat module tree):

| Module | Responsibility |
|---|---|
| `cp.rs` | CP HTTP: fleet dashboard, `/register` for agents, `/api/agents` public read, `/cp/attest`. Runs the collector, Cloudflare tunnel/DNS setup, legacy Access cleanup, and STONITH. |
| `agent.rs` | Agent HTTP: per-VM dashboard, `/deploy` + `/exec` + `/logs/{app}` + `/ingress/replace`, GitHub-OIDC and ITA verification. |
| `cf.rs` | Cloudflare API: tunnel CRUD, DNS CNAME, legacy Access app cleanup, flat `label_hostname`, orphan reaping. |
| `ee.rs` | Thin client for [EasyEnclave Mini](https://github.com/easyenclave/easyenclave-mini)'s unix socket — `Deploy`, `List`, `Logs`. |
| `ita.rs` | Mint + verify Intel Trust Authority tokens (quote-v4 MRTD extraction). |
| `gh_oidc.rs` | Verify GitHub Actions OIDC JWTs against GitHub's JWKS (`repository_owner == DD_OWNER`). |
| `collector.rs` | CP-side scrape of agent `/health` over the tunnel; tracks claims + ingress. |
| `stonith.rs` | On CP boot, delete old tunnel → old cloudflared dies → old CP observes and `poweroff`s. |
| `metrics.rs` | Per-host CPU/disk/net via the `sysinfo` crate. |
| `config.rs` | Env → typed config for both modes. |
| `html.rs` | Dashboard templates. |

The sealed enclave runtime is [EasyEnclave Mini](https://github.com/easyenclave/easyenclave-mini) — a separate project.

## Public website

[**devopsdefender.com**](https://devopsdefender.com) is a static site that lives in its own repo: [`devopsdefender/devopsdefender.com`](https://github.com/devopsdefender/devopsdefender.com). It's the **only** place public-facing marketing copy lives — the CP binary serves operator dashboards behind DD's GitHub App auth and is never the right home for public prose.

To change the website: PR against the [`devopsdefender.com`](https://github.com/devopsdefender/devopsdefender.com) repo, not this one.

## Deployment

Every fleet VM boots from a sealed easyenclave-mini image published by [easyenclave/easyenclave-mini](https://github.com/easyenclave/easyenclave-mini/releases). No cloud-init, no stock Ubuntu, no runtime `apt-get install`. The local TDX base qcow2 is synced from the latest `stable` or `staging` mini release channel by `apps/_infra/ee-sync.sh`, attestable against a single UKI SHA256.

Every workload is a JSON spec consumed by easyenclave's `DeployRequest`. Boot-time and runtime-deployed workloads share one schema; both the `devopsdefender` binary and `cloudflared` ship as **GitHub release assets** — not OCI images — and easyenclave fetches them via its `github_release` source. The full set of specs and a guide to writing your own lives in [`apps/README.md`](apps/README.md).

Per-VM configuration (CF credentials, GitHub OAuth, the workload spec itself) is passed to easyenclave-mini at boot via the local config disk consumed by the qemu vendor stage. The deploy/relaunch scripts build `agent.env`, sync the mini qcow2 base, and recreate the matching local TDX VM.

## CI/CD

```
PR              → pre-release tagged pr-{sha12}, then ephemeral preview at pr-{N}.{domain}
branch deleted  → pr-teardown.yml deletes the preview's VM, CF tunnel, and DNS
push to main    → rolling `latest` release, then auto-deploy to production
push v* tag     → versioned release (no auto-deploy)
manual dispatch → redeploy any existing tag to production (rollback tool)
```

Every path lives in `.github/workflows/release.yml`: one `build` job, then either `deploy-preview` (PR) or `deploy-production` (main / dispatch), both calling the reusable `deploy-cp.yml` with env-specific inputs. Each cascades into a relaunch of the matching `dd-local-{env}` VM on the tdx2 host — the Release run only goes green when that agent re-registers with the freshly-deployed CP. Verifications along the way:

1. `/health` via the Cloudflare tunnel (public)
2. `/cp/attest` returning a real TDX MRTD (the quote is self-authenticating — old VMs don't have the endpoint and return 404)
3. Dashboard `/` returning a DD GitHub App auth redirect (HTTP 302) to the broker
4. No other `dd-{env}-*` VM is RUNNING after deploy (STONITH must have halted the previous instance)
5. `dd-local-{env}` re-registers with the new CP within 5 min

`dd-local-dogfood` is the exception: it is a manually managed production
development agent for real Codex/Podman work. Release deploys never recreate
it. Launch or refresh it explicitly with `apps/_infra/dd-dogfood.sh`; it keeps
its workload disk and reconnects to production across CP redeploys.

## Auth

Zero shared secrets. Cloudflare handles tunnel/DNS routing only; DD owns auth in-process with signed browser sessions, ITA tokens, GitHub Actions OIDC tokens, and Noise device keys.

| Caller | Endpoint | Auth |
| --- | --- | --- |
| Human browser | CP `/`, agent `/`, dd-shell terminal | DD GitHub App OAuth broker + signed DD session cookie |
| Agent → CP | `/register`, `/ingress/replace` | Intel ITA token verified in-code |
| CI → agent | `/deploy`, `/exec`, `/logs/{app}` | GitHub Actions OIDC JWT verified in-code (`repository_owner == DD_OWNER`) |
| Anyone | `/health`, `/cp/attest`, `/api/agents`, workload URLs | Public read-only or self-authenticating content |

No PATs. No Cloudflare service tokens. No Worker. Agents ship with nothing but an ITA API key; CI ships with nothing but its per-job GitHub OIDC token.

Cloudflare Access is not part of request routing. DD uses Cloudflare for tunnels and DNS only, and cleans up old Access applications left by previous deployments so they cannot intercept DD-owned auth routes.

First-time setup:
1. Create the staging and production GitHub Apps with callback URL `https://app.devopsdefender.com/auth/github/callback`.
2. Store the app client ids/secrets and `DD_AUTH_COOKIE_SECRET` in GitHub repo vars/secrets.
3. Ensure `DD_CF_API_TOKEN` can manage Cloudflare tunnels, DNS, and legacy Access application cleanup.
4. Deploy. No per-deploy OAuth callback setup.

## Deploy a workload from GitHub Actions

The [`dd-deploy`](.github/actions/dd-deploy/README.md) composite action mints a per-job OIDC token and POSTs any workload JSON to a DD agent. Works from any repository in the `DD_OWNER` GitHub org with zero stored credentials:

```yaml
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
```

The agent verifies the OIDC token against GitHub's JWKS, checks `repository_owner == DD_OWNER`, and launches the workload. Full inputs/outputs in [`.github/actions/dd-deploy/README.md`](.github/actions/dd-deploy/README.md). On deploy timeout, `dd-deploy` fetches `/logs/dd-agent` over the same OIDC auth so CI logs show agent-side ground truth without an SSH hop.

## Terminal access

Each VM runs `dd-sessiond` as the local session supervisor. `dd-sessiond` owns
PTYs, child process groups, resize/close control, and encrypted transcript
history inside the enclave.

Native clients use a paired device key against the agent's `/noise/ws` endpoint.
The bootstrap flow fetches `/health`, appraises `noise.quote_b64` with Intel
Trust Authority, checks that the quote binds `noise.pubkey_hex` into TDX
`report_data`, and then runs Noise_IK over WebSocket. The exposed session RPC surface is
`shell.list_recipes`, `shell.list_sessions`, `shell.create_session`,
`shell.replay_session`, `shell.resize_session`, `shell.close_session`, and the
streaming `shell.attach_session` method. Session control and PTY bytes flow
inside the Noise transport to the agent and then to local `dd-sessiond`; the CP
is used for enrollment and route discovery, not for shell/log/session bytes.

The bundled native CLI exercises that path directly:

```bash
devopsdefender noise keygen --cp-url https://app.devopsdefender.com --label laptop
devopsdefender noise recipes --url https://<agent-host>
devopsdefender noise shell --url https://<agent-host> --recipe shell
```

The CLI uses `DD_ITA_API_KEY` for quote appraisal. `DD_ITA_BASE_URL`,
`DD_ITA_JWKS_URL`, and `DD_ITA_ISSUER` default to Intel Trust Authority's
production endpoints and can be overridden when needed. Local preview/dev runs
without ITA credentials must pass `--insecure-skip-quote-verify` explicitly.

The web shell should become another client implementation of the same protocol:
it keeps its own paired device identity, asks CP for current routes, and opens
Noise directly to the agent. The existing cookie-auth browser shell remains a
compatibility surface while that client-side Noise implementation lands.

## STONITH

When a new CP boots, it needs to kick out the old one. It does this by deleting the old tunnel via the Cloudflare API — when the old `cloudflared` loses its tunnel, it exits, and the old CP observes the exit and calls `poweroff`. The old VM shuts down, GCP marks it TERMINATED.

Old tunnels are identified by their **ingress configuration** (which hostname they serve), not by reconstructing a hostname from the tunnel name. This is the correct identifier because CP tunnels all serve `app-{env}.{domain}` regardless of their individual tunnel name.

If STONITH fails, `release.yml` detects the surviving VM and fails the deploy — loud signal, no silent accumulation.

## Build

```bash
cargo build --release
# Produces: target/release/devopsdefender
```

For local dev you can also build the Dockerfile (`docker build -t dd .`) but CI/CD does not — production deploys consume the GitHub release asset directly.

## License

MIT
