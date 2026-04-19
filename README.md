# DevOps Defender

Confidential computing marketplace. Run AI workloads on hardware-sealed Intel TDX VMs with cryptographic attestation.

## Architecture

A Cargo workspace with one deployable binary and a set of internal crates:

| Crate | Kind | Purpose |
|-------|------|---------|
| `devopsdefender` | binary | Unified entrypoint. `DD_MODE=management` runs the control plane (register + web); default runs the in-VM agent (dd-client). |
| `dd-common` | library | Shared: Noise XX handshake, Cloudflare tunnel CRUD, error types, EeClient for easyenclave's unix socket. |
| `dd-client` | library | Per-VM dashboard, terminal sessions, deploy/exec proxy — runs on every fleet VM. |
| `dd-register` | library | Tunnel provisioning, agent `/register` endpoint (Noise XX over WebSocket), STONITH for old control-plane VMs. |
| `dd-web` | library | Fleet dashboard, GitHub OAuth + Actions OIDC, collector, federation. |

One static musl binary, switched by `DD_MODE` at startup. Management VMs run `dd-web + dd-register + dd-client` concurrently in that single process.

The sealed enclave runtime is [EasyEnclave](https://github.com/easyenclave/easyenclave) — a separate project.

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

1. `/health` via the Cloudflare tunnel (public; CF Access bypass)
2. `/cp/attest` returning a real TDX MRTD, called with a CF Access service token (cryptographic proof the freshly-deployed VM is running — old VMs don't have the endpoint and return 404)
3. Dashboard `/` returning a CF Access redirect (HTTP 302) to the Cloudflare login flow
4. No other `dd-{env}-*` VM is RUNNING after deploy (STONITH must have halted the previous instance)
5. `dd-local-{env}` re-registers with the new CP within 5 min

## Auth

Zero shared secrets. Every CP and agent URL is fronted by [Cloudflare Access](https://developers.cloudflare.com/cloudflare-one/applications/); everything else is gated by signed tokens validated in code.

| Caller | Endpoint | Auth |
| --- | --- | --- |
| Human browser | CP `/`, agent `/`, dashboards | CF Access → GitHub OAuth → `github-organization:DD_OWNER` or `emails:DD_ACCESS_ADMIN_EMAIL` |
| Agent → CP | `/register`, `/ingress/replace` | CF Access bypass + Intel ITA token verified in-code |
| CI → agent | `/deploy`, `/exec` | CF Access bypass + GitHub Actions OIDC JWT verified in-code (`repository_owner == DD_OWNER`) |
| Anyone | `/health`, `/cp/attest`, `/api/agents`, workload URLs | CF Access bypass; read-only or self-authenticating content |

No PATs. No CF Access service tokens. No Worker. Agents ship with nothing but an ITA API key; CI ships with nothing but its per-job GitHub OIDC token.

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

The agent verifies the OIDC token against GitHub's JWKS, checks `repository_owner == DD_OWNER`, and launches the workload. Full inputs/outputs in [`.github/actions/dd-deploy/README.md`](.github/actions/dd-deploy/README.md).

The companion [`dd-logs`](.github/actions/dd-logs/README.md) action pulls any workload's captured stdout from the same agent (`GET /logs/{app}`) using the same OIDC auth. `dd-deploy` also uses it internally to dump `dd-agent`'s own log when a deploy times out, so CI logs show agent-side ground truth without an SSH hop.

## STONITH

When a new management VM boots, `dd-register` needs to kick out the old one. It does this by deleting the old tunnel via the Cloudflare API — when the old `cloudflared` loses its tunnel, it exits, and the old `dd-register` observes the exit and calls `poweroff`. The old VM shuts down, GCP marks it TERMINATED.

Old tunnels are identified by their **ingress configuration** (which hostname they serve), not by reconstructing a hostname from the tunnel name. This is the correct identifier because CP tunnels all serve `app-{env}.{domain}` regardless of their individual tunnel name.

If STONITH fails, `release.yml` detects the surviving VM and fails the deploy — loud signal, no silent accumulation.

## Build

```bash
cargo build --workspace --release
# Produces: target/release/devopsdefender
```

For local dev you can also build the Dockerfile (`docker build -t dd .`) but CI/CD does not — production deploys consume the GitHub release asset directly.

## License

MIT
