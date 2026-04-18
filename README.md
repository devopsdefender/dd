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

The `devopsdefender` binary ships as a **GitHub release asset** — not an OCI image. Easyenclave fetches it directly via its `github_release` boot workload source:

```json
{
  "github_release": {
    "repo": "devopsdefender/dd",
    "asset": "devopsdefender",
    "tag": "latest"
  },
  "cmd": ["devopsdefender"],
  "app_name": "dd-management",
  "env": ["DD_MODE=management", ...]
}
```

`cloudflared` is also pulled directly from `cloudflare/cloudflared`'s GitHub releases as a fetch-only boot workload — no bundling in our image, no Dockerfile step.

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

1. `/health` via the Cloudflare tunnel
2. `/cp/attest` returning a real TDX MRTD (cryptographic proof the freshly-deployed VM is running — old VMs don't have the endpoint and return 404)
3. Dashboard `/` returning HTTP 200 under a Bearer PAT
4. No other `dd-{env}-*` VM is RUNNING after deploy (STONITH must have halted the previous instance)
5. `dd-local-{env}` re-registers with the new CP within 5 min

Browser access to a PR preview goes through `/auth/pat` (paste a GitHub PAT, validated against `DD_OWNER`). OAuth is only wired for production, at `app.{domain}`.

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
