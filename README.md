# DevOps Defender

Confidential computing marketplace. Run AI workloads on hardware-sealed Intel TDX VMs with cryptographic attestation.

## Architecture

4 crates in a Cargo workspace:

| Crate | Binary | Purpose |
|-------|--------|---------|
| `dd-common` | (library) | Shared: Noise XX handshake, CF tunnel CRUD, error types, EeClient |
| `dd-client` | `dd-client` | Agent web UI inside the enclave — proxies to easyenclave via unix socket |
| `dd-register` | `dd-register` | Tunnel provisioning — 3 endpoints: /register, /deregister, /health |
| `dd-web` | `dd-web` | Fleet dashboard, GitHub OAuth, Prometheus-style collector, federation |

The enclave runtime itself is [EasyEnclave](https://github.com/easyenclave/easyenclave) — a separate project.

## Build

```bash
cargo build --workspace --release
# Produces: target/release/dd-client, dd-register, dd-web
```

## GitHub Actions

Reusable composite actions for CI/CD:

```yaml
- uses: devopsdefender/dd/.github/actions/deploy-workload@main
  with:
    agent-url: https://app.devopsdefender.com
    deploy-spec: apps/myapp/deploy.json

- uses: devopsdefender/dd/.github/actions/verify-deployment@main
  with:
    agent-url: https://app.devopsdefender.com
    deployment: myapp
    timeout: 300
```

`GITHUB_TOKEN` auth works out of the box for repos in the DD_OWNER org.

## License

MIT
