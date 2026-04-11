# DevOps Defender

Confidential computing marketplace. Run AI workloads on hardware-sealed Intel TDX VMs with cryptographic attestation.

## Architecture

4 crates in a Cargo workspace:

| Crate | Binary | Purpose |
|-------|--------|---------|
| `dd-common` | (library) | Shared: Noise XX handshake, CF tunnel CRUD, error types, EeClient |
| `dd-client` | `dd-client` | Agent web UI on a worker VM — proxies to easyenclave via unix socket |
| `dd-register` | `dd-register` | Tunnel provisioning + Noise-XX /register endpoint for agents joining the fleet |
| `dd-web` | `dd-web` | Fleet dashboard, GitHub OAuth, collector, federation |

The enclave runtime itself is [EasyEnclave](https://github.com/easyenclave/easyenclave) — a separate project.

## How it's deployed

Both management VMs (`app.devopsdefender.com`, `app-staging.devopsdefender.com`) and worker VMs **boot from a sealed easyenclave image**. No cloud-init, no stock Ubuntu, no runtime `apt-get install`. The TDX VM's rootfs is the published `easyenclave-<sha>` image from [easyenclave/easyenclave releases](https://github.com/easyenclave/easyenclave/releases), attestable against a single UKI SHA256.

dd's three binaries ship as OCI container images on ghcr.io:

- `ghcr.io/devopsdefender/dd-register` — runs as an easyenclave workload on management VMs
- `ghcr.io/devopsdefender/dd-web` — runs as an easyenclave workload on management VMs
- `ghcr.io/devopsdefender/dd-client` — runs as an easyenclave workload on worker VMs

Image builds: `.github/workflows/push-management-images.yml` (on push to main).

Per-VM configuration (CF credentials, GitHub OAuth, the workload spec itself) is passed to easyenclave at boot via **GCE instance metadata** — the `ee-config` attribute, a JSON object read by `easyenclave::init::fetch_gce_metadata_config()` and applied as env vars. `scripts/gcp-deploy.sh` builds the spec and invokes `gcloud compute instances create --image=easyenclave-<sha> --metadata-from-file=ee-config=...`.

## Build

```bash
cargo build --workspace --release
# Produces: target/release/dd-client, dd-register, dd-web
```

Container images (for deployment) are built by the
`push-management-images.yml` workflow; local `docker build -f crates/dd-register/Dockerfile .`
works too.

## License

MIT
