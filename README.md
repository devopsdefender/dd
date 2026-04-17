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

Per-VM configuration (CF credentials, GitHub OAuth, the workload spec itself) is passed to easyenclave at boot via **GCE instance metadata** (`ee-config` attribute), read by `easyenclave::init::fetch_gce_metadata_config()` and applied as env vars. `scripts/gcp-deploy.sh` builds the spec and invokes `gcloud compute instances create --image-family=easyenclave-staging --metadata-from-file=ee-config=...`.

Intel Trust Authority configuration is passed the same way. Set the
environment-scoped GitHub Actions secret `DD_ITA_API_KEY` for staging and
production; `scripts/gcp-deploy.sh` injects it into the management workload as
`DD_ITA_API_KEY` and sets `DD_ITA_URL` to
`https://api.trustauthority.intel.com` by default.

`dd-register` fails closed: without `DD_ITA_API_KEY` it refuses to start
unless `DD_ALLOW_UNVERIFIED_REGISTRATIONS=1` is set (local dev / bring-up
only). When the key is set, every agent registration must present a TDX
quote that ITA verifies and whose REPORT_DATA echoes a fresh handshake
nonce. Measurements (MRTD/RTMR0–3) are logged for each accepted
registration so we can build a pinned policy once a known-good baseline
is captured.

## CI/CD

```
PR              → pre-release tagged pr-{sha12}, then ephemeral preview at pr-{N}.{domain}
branch deleted  → pr-teardown.yml deletes the preview's VM, CF tunnel, and DNS
push to main    → rolling `latest` release, then auto-deploy to production
push v* tag     → versioned release (no auto-deploy)
manual          → production-deploy.yml promotes any existing tag
```

Each PR gets its own isolated env at `pr-{N}.{domain}` with `DD_ENV=pr-{N}` — no more shared staging tier. `.github/workflows/release.yml` builds the static musl binary, publishes it as a GitHub release asset, deploys the PR's preview VM, and posts the URL back to the PR. The preview VM is verified via:

1. `/health` via the Cloudflare tunnel
2. `/cp/attest` returning a real TDX MRTD (cryptographic proof the freshly-deployed VM is running — old VMs don't have the endpoint and return 404)
3. No other `dd-pr-{N}-*` VM is RUNNING after deploy (STONITH must have halted the previous instance of this PR)

Browser access to a PR preview goes through `/auth/pat` (paste a GitHub PAT, validated against `DD_OWNER`). OAuth is only wired for production, which `production-deploy.yml` still targets at `app.{domain}`.

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
