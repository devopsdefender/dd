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
| `cp.rs` | CP HTTP: fleet dashboard, `/register` for agents, `/api/agents` public read, `/cp/attest`. Runs the collector + per-agent CF Access app + STONITH. |
| `agent.rs` | Agent HTTP: per-VM dashboard, `/deploy` + `/exec` + `/logs/{app}` + `/ingress/replace`, GitHub-OIDC and ITA verification. |
| `cf.rs` | Cloudflare API: tunnel CRUD, DNS CNAME, Access app provisioning, flat `label_hostname`, orphan reaping. |
| `ee.rs` | Thin client for [EasyEnclave](https://github.com/easyenclave/easyenclave)'s unix socket — `Deploy`, `List`, `Logs`. |
| `ita.rs` | Mint + verify Intel Trust Authority tokens (quote-v4 MRTD extraction). |
| `gh_oidc.rs` | Verify GitHub Actions OIDC JWTs against GitHub's JWKS (`repository_owner == DD_OWNER`). |
| `collector.rs` | CP-side scrape of agent `/health` over the tunnel; tracks claims + ingress. |
| `stonith.rs` | On CP boot, delete old tunnel → old cloudflared dies → old CP observes and `poweroff`s. |
| `metrics.rs` | Per-host CPU/disk/net via the `sysinfo` crate. |
| `config.rs` | Env → typed config for both modes. |
| `html.rs` | Dashboard templates. |

The sealed enclave runtime is [EasyEnclave](https://github.com/easyenclave/easyenclave) — a separate project.

## Public website

[**devopsdefender.com**](https://devopsdefender.com) is a static site served from this repo's [`gh-pages` branch](https://github.com/devopsdefender/dd/tree/gh-pages) (CNAME pinned there). It's the **only** place public-facing marketing copy lives — the CP binary serves operator dashboards behind CF Access and is never the right home for public prose.

To change the website: PR against `gh-pages` (not `main`). The branch's own `.github/workflows/website-preview.yml` auto-deploys each PR to `devopsdefender.com/pr-preview/<N>/` via [`rossjrw/pr-preview-action`](https://github.com/rossjrw/pr-preview-action); merging to `gh-pages` publishes to root.

## Deployment

Every fleet VM boots from a sealed easyenclave image published by [easyenclave/easyenclave](https://github.com/easyenclave/easyenclave/releases). No cloud-init, no stock Ubuntu, no runtime `apt-get install`. The TDX VM's rootfs is the latest image in the `easyenclave-staging` (or `-stable`) family, attestable against a single UKI SHA256.

Every workload is a JSON spec consumed by easyenclave's `DeployRequest`. Boot-time and runtime-deployed workloads share one schema; both the `devopsdefender` binary and `cloudflared` ship as **GitHub release assets** — not OCI images — and easyenclave fetches them via its `github_release` source. The full set of specs and a guide to writing your own lives in [`apps/README.md`](apps/README.md).

Per-VM configuration (CF credentials, GitHub OAuth, the workload spec itself) is passed to easyenclave at boot via **GCE instance metadata** (`ee-config` attribute), read by `easyenclave::init::fetch_gce_metadata_config()` and applied as env vars. The CP-deploy step in `.github/workflows/deploy-cp.yml` builds the spec and invokes `gcloud compute instances create --image-family=easyenclave-staging --metadata-from-file=ee-config=...`.

## CI/CD

```
PR              → pre-release tagged pr-{sha12}, then ephemeral preview at pr-{N}.{domain}
branch deleted  → pr-teardown.yml deletes the preview's VM, CF tunnel, and DNS
push to main    → rolling `latest` release, then auto-deploy to production
push v* tag     → versioned release (no auto-deploy)
manual dispatch → redeploy any existing tag to production (rollback tool)
```

Every path lives in `.github/workflows/release.yml`: one `build` job, then either `deploy-preview` (PR) or `deploy-production` (main / dispatch), both calling the reusable `deploy-cp.yml` with env-specific inputs. Each cascades into a relaunch of the matching `dd-local-{env}` VM on the tdx2 host — the Release run only goes green when that agent re-registers with the freshly-deployed CP. Verifications along the way:

1. `/health` via the Cloudflare tunnel (CF Access bypass; public)
2. `/cp/attest` returning a real TDX MRTD (CF Access bypass; the quote is self-authenticating — old VMs don't have the endpoint and return 404)
3. Dashboard `/` returning a CF Access redirect (HTTP 302) to the Cloudflare login flow
4. No other `dd-{env}-*` VM is RUNNING after deploy (STONITH must have halted the previous instance)
5. `dd-local-{env}` re-registers with the new CP within 5 min

## Auth

Zero shared secrets. Every CP and agent URL is fronted by [Cloudflare Access](https://developers.cloudflare.com/cloudflare-one/applications/); everything else is gated by signed tokens validated in code.

| Caller | Endpoint | Auth |
| --- | --- | --- |
| Human browser | CP `/`, agent `/`, ttyd terminal | CF Access → GitHub OAuth → `github-organization:DD_OWNER` or `emails:DD_ACCESS_ADMIN_EMAIL` |
| Agent → CP | `/register`, `/ingress/replace` | CF Access bypass + Intel ITA token verified in-code |
| CI → agent | `/deploy`, `/exec`, `/logs/{app}` | CF Access bypass + GitHub Actions OIDC JWT verified in-code (`repository_owner == DD_OWNER`) |
| Anyone | `/health`, `/cp/attest`, `/api/agents`, workload URLs | CF Access bypass; read-only or self-authenticating content |

No PATs. No CF Access service tokens. No Worker. Agents ship with nothing but an ITA API key; CI ships with nothing but its per-job GitHub OIDC token.

CF Access apps are provisioned programmatically by the CP at boot — one application per hostname (CP, agent, each admin-gated workload label like `-term`). Orphan apps from torn-down preview VMs are reaped on the next CP boot.

First-time setup on a fresh Cloudflare account:
1. Zero Trust → Settings → Authentication → Login methods → add GitHub (`read:user` scope only).
2. Extend `DD_CF_API_TOKEN` with **Access: Apps and Policies: Edit** and **Access: Identity Providers: Read**.
3. Set repo var/secret `DD_ACCESS_ADMIN_EMAIL` (break-glass human login).
4. Deploy. No per-deploy bootstrap step.

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

Each VM runs [ttyd](https://github.com/tsl0922/ttyd) as a workload on a `-term` labelled subdomain (e.g. `app-term.devopsdefender.com`, `<agent>-term.devopsdefender.com`). CF Access gates it behind the same GitHub OAuth + admin-email policy as the dashboards — no SSH, no shared keys.

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
