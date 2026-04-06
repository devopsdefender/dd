# DevOps Defender (DD)

A Rust agent that runs on Intel TDX VMs, manages workloads as plain processes or container images, and exposes them through Cloudflare Tunnels with a web dashboard and terminal.

## What it does

- Runs shell commands and container workloads on TDX-protected VMs
- Registers with a fleet dashboard via Noise-encrypted WebSocket
- Gets a public hostname via Cloudflare Tunnel (no open ports)
- Provides a web terminal and dashboard with GitHub OAuth or password auth
- Supports authenticated remote deploy and exec APIs
- Hardware attestation via Intel TDX (configfs-tsm)

## Repository structure

```
dd/
├── agent/    # Rust binary — dd-agent, dd-register
└── scripts/  # GCP VM bootstrap and deploy helpers
```

## Agent modes

Set via `DD_AGENT_MODE`:

| Mode | Purpose |
|------|---------|
| `agent` (default) | Run workloads, serve dashboard, manage tunnels |
| `register` | Fleet dashboard — registers agents, manages tunnels, runs scraper |
| `scraper` | Discovers agents from CF tunnel listing, reports health to register |

## Running locally

```bash
# Agent with a bash shell workload (skip attestation for non-TDX)
DD_OWNER=me DD_BOOT_CMD=bash DD_BOOT_APP=demo cargo run --bin dd-agent

# With password auth
DD_OWNER=me DD_PASSWORD=changeme DD_BOOT_CMD=bash DD_BOOT_APP=demo cargo run --bin dd-agent
```

Then visit `http://localhost:8080` for the dashboard, or `http://localhost:8080/session/demo` for the web terminal.

## Environment variables

### Core

| Variable | Required | Description |
|----------|----------|-------------|
| `DD_OWNER` | Yes | Owner identity (GitHub user/org for OAuth, or just a label) |
| `DD_AGENT_MODE` | No | `agent`, `register`, or `scraper` (default: `agent`) |
| `DD_PORT` | No | HTTP port (default: `8080`) |
| `DD_ENV` | No | Environment label: `staging`, `production`, `dev` |

### Workloads

| Variable | Description |
|----------|-------------|
| `DD_BOOT_CMD` | Shell command to run at startup (e.g. `bash`, `python server.py`) |
| `DD_BOOT_APP` | Name for the boot workload (default: `shell`) |

### Auth

| Variable | Description |
|----------|-------------|
| `DD_PASSWORD` | Shared password for dashboard login |
| `DD_GITHUB_CLIENT_ID` | GitHub OAuth client ID (takes priority over password) |
| `DD_GITHUB_CLIENT_SECRET` | GitHub OAuth client secret |
| `DD_GITHUB_CALLBACK_URL` | GitHub OAuth callback URL |

### Tunnel

| Variable | Description |
|----------|-------------|
| `DD_TUNNEL_TOKEN` | Pre-provisioned Cloudflare tunnel token |
| `DD_REGISTER_URL` | WebSocket URL to register with fleet (e.g. `wss://app.devopsdefender.com/register`) |
| `DD_CF_API_TOKEN` | Cloudflare API token (for self-registration) |
| `DD_CF_ACCOUNT_ID` | Cloudflare account ID |
| `DD_CF_ZONE_ID` | Cloudflare zone ID |
| `DD_CF_DOMAIN` | Domain for tunnel hostnames (default: `devopsdefender.com`) |
| `DD_HOSTNAME` | Public hostname override |

## HTTP endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/` | Yes | Dashboard (agent mode) or fleet view (register mode) |
| GET | `/health` | No | JSON health check |
| GET | `/workload/{id}` | Yes | Workload detail page with logs |
| GET | `/session/{app}` | Yes | Web terminal (xterm.js) |
| GET | `/agent/{id}` | Yes | Agent detail page (register mode) |
| POST | `/deploy` | Localhost or authenticated remote | Deploy a workload: `{"cmd": ["bash"], "app_name": "demo"}` or `{"image": "ghcr.io/me/app:sha", "app_name": "demo"}` |
| GET | `/deployments` | Yes | List deployments (JSON) |
| GET | `/deployments/{id}` | Yes | Get deployment status and metadata |
| GET | `/deployments/{id}/logs` | Yes | Get deployment logs |
| POST | `/exec` | Localhost or authenticated remote | Run a synchronous command: `{"cmd": ["podman", "ps", "-a"]}` |

## Noise protocol

The agent supports an encrypted shell protocol over WebSocket using Noise_XX_25519_ChaChaPoly_SHA256. Commands: `deploy`, `stop`, `jobs`, `fg`, `bg`, `logs`, `exit`.

## Build

```bash
cargo build              # debug build
cargo build --release    # release build
cargo test               # run tests
cargo fmt --check        # check formatting
cargo clippy --workspace --all-targets  # lint (CI uses RUSTFLAGS="-Dwarnings")
```

## CI/CD

- **ci.yml** — fmt, clippy, test on every push/PR
- **staging-deploy.yml** — builds binary, deploys TDX VM to GCP on PRs to main
- **production-deploy.yml** — same, triggered on push to main
- **release.yml** — builds release binaries on version tags

## Under the hood

- **Intel TDX** — hardware attestation via configfs-tsm (`/sys/kernel/config/tsm/report/`)
- **Cloudflare Tunnels** — outbound-only secure networking, no open ports
- **Noise protocol** — end-to-end encrypted shell sessions (snow crate)
- **Axum** — async HTTP/WebSocket server
- **Docker/Podman integration** — optional container deploys via the local engine API
