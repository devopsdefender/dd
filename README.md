# DevOps Defender (DD)

A Rust runtime for Intel TDX VMs that manages workloads, exposes local bootstrap control over a Unix socket, and registers fleets through Cloudflare Tunnels.

## What it does

- Runs shell commands and container workloads on TDX-protected VMs
- Registers with a fleet service via Noise-encrypted WebSocket
- Maintains a renewable registration lease and reconnects on revocation or register epoch change
- Exposes local bootstrap/admin control over a Unix socket for `ddctl`
- Gets public hostnames via Cloudflare Tunnel (no open ports)
- Includes separate binaries for register, scraper, admin, and local control
- Hardware attestation via Intel TDX (configfs-tsm)

## Repository structure

```
dd/
├── agent/    # Rust binaries — dd-agent, dd-register, dd-scraper, ddctl, dd-admin
└── scripts/  # GCP VM bootstrap and deploy helpers
```

## Agent modes

Set via `DD_AGENT_MODE`:

| Mode | Purpose |
|------|---------|
| `agent` (default) | Run workloads, serve local control, manage tunnels |
| `register` | Fleet dashboard and register service |
| `scraper` | Deprecated in `dd-agent`; use the standalone `dd-scraper` binary |

## Running locally

```bash
# Agent without auth (skip attestation for non-TDX)
DD_OWNER=me cargo run --bin dd-agent

# With password auth
DD_OWNER=me DD_PASSWORD=changeme cargo run --bin dd-agent
```

Then use the local control socket via `ddctl`:

```bash
cargo run --bin ddctl -- status
cargo run --bin ddctl -- spawn --app-name demo --cmd bash

# Browser-facing fleet UI
DD_REGISTER_URL=http://127.0.0.1:8080/register cargo run --bin dd-admin

# Optional dd-admin password gate and backend token
DD_ADMIN_PASSWORD=changeme DD_ADMIN_API_TOKEN=secret DD_REGISTER_URL=https://register.example.com/register cargo run --bin dd-admin
```

## Environment variables

### Core

| Variable | Required | Description |
|----------|----------|-------------|
| `DD_OWNER` | Yes | Owner identity (GitHub user/org for OAuth, or just a label) |
| `DD_AGENT_MODE` | No | `agent`, `register`, or `scraper` (default: `agent`) |
| `DD_PORT` | No | HTTP port (default: `8080`) |
| `DD_ENV` | No | Environment label: `staging`, `production`, `dev` |
| `DD_CONTROL_SOCK` | No | Unix socket path for local `ddctl` control (default: `/run/dd-agent/control.sock`) |
| `DD_AGENT_BROWSER_UI` | No | Enable the legacy per-agent HTML/session UI in agent mode (`true`/`1`) |
| `DD_ADMIN_BIND_ADDR` | No | Bind address for `dd-admin` (default: `0.0.0.0`) |
| `DD_ADMIN_PORT` | No | HTTP port for `dd-admin` (default: `9090`) |
| `DD_ADMIN_PASSWORD` | No | Shared password for `dd-admin` browser login |
| `DD_ADMIN_SECURE_COOKIES` | No | Set secure cookies in `dd-admin` (`true`/`1`) |
| `DD_ADMIN_API_TOKEN` | No | Shared bearer token used by `dd-admin` to call register fleet APIs |
| `DD_REGISTER_ADMIN_URL` | No | Explicit register fleet snapshot URL for `dd-admin` (default derived from `DD_REGISTER_URL`) |
| `DD_SCRAPER_BIND_ADDR` | No | Bind address for `dd-scraper` status server (default: `0.0.0.0`) |
| `DD_SCRAPER_PORT` | No | HTTP port for `dd-scraper` status server (default: `8082`) |

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
| `DD_BOOTSTRAP_REGISTER_BINARY_URL` | Optional URL for `dd-agent` to download and launch a local `dd-register` before self-registering |
| `DD_BOOTSTRAP_REGISTER_PORT` | Local bootstrap register port (default: `8081`) |
| `DD_BOOTSTRAP_REGISTER_WAIT_SECS` | How long to wait for the local bootstrap register health check (default: `60`) |
| `DD_REGISTER_URL` | WebSocket URL to register with fleet (e.g. `wss://app.devopsdefender.com/register`) |
| `DD_REGISTER_LEASE_TTL_SECS` | Lease TTL advertised by `dd-register` / register mode (default: `90`) |
| `DD_REGISTER_EPOCH` | Register epoch for takeover/reconnect coordination (default: `1`) |
| `DD_REGISTER_REDIRECT_URL` | Optional replacement register URL advertised to agents during lease renewal/bootstrap |
| `DD_CF_API_TOKEN` | Cloudflare API token (for self-registration) |
| `DD_CF_ACCOUNT_ID` | Cloudflare account ID |
| `DD_CF_ZONE_ID` | Cloudflare zone ID |
| `DD_CF_DOMAIN` | Domain for tunnel hostnames (default: `devopsdefender.com`) |
| `DD_HOSTNAME` | Public hostname override |
| `DD_REGISTER_BIND_ADDR` | Bind address for standalone `dd-register` (default: `0.0.0.0`) |

### Bootstrap styles

- `DD_TUNNEL_TOKEN`: use a pre-provisioned Cloudflare tunnel token.
- `DD_BOOTSTRAP_REGISTER_BINARY_URL`: launch a localhost `dd-register`, wait for `/health`, then self-register against `ws://127.0.0.1:<port>/register`.
- `DD_CF_API_TOKEN` / `DD_CF_ACCOUNT_ID` / `DD_CF_ZONE_ID`: self-register directly with Cloudflare.
- `DD_REGISTER_URL`: register with an already-running remote register service.

When `DD_REGISTER_URL` or `DD_BOOTSTRAP_REGISTER_BINARY_URL` is used, `dd-agent` now keeps a long-lived register session:

- it renews its lease periodically
- it reconnects if the register revokes the agent or drops the session
- it reconnects if the register advertises a higher `DD_REGISTER_EPOCH`
- it can switch to `DD_REGISTER_REDIRECT_URL` when the active register tells it to move

## HTTP endpoints

Legacy agent HTML/session routes are now opt-in in agent mode via `DD_AGENT_BROWSER_UI=1`.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/` | Yes | Dashboard (agent mode) or fleet view (register mode) |
| GET | `/health` | No | JSON health check |
| GET | `/api/fleet` | Localhost or `Bearer <DD_ADMIN_API_TOKEN>` | Fleet snapshot JSON in register mode |
| GET | `/workload/{id}` | Yes | Workload detail page with logs |
| GET | `/session/{app}` | Yes | Web terminal (xterm.js) |
| GET | `/agent/{id}` | Yes | Agent detail page (register mode) |
| POST | `/deploy` | Localhost or authenticated remote | Deploy a workload: `{"cmd": ["bash"], "app_name": "demo"}` or `{"image": "ghcr.io/me/app:sha", "app_name": "demo"}` |
| POST | `/api/fleet/report` | Localhost or `Bearer <DD_SCRAPER_REPORT_TOKEN>` | Accept a scraper fleet report in register mode |
| GET | `/deployments` | Yes | List deployments (JSON) |
| GET | `/deployments/{id}` | Yes | Get deployment status and metadata |
| GET | `/deployments/{id}/logs` | Yes | Get deployment logs |
| POST | `/exec` | Localhost or authenticated remote | Run a synchronous command: `{"cmd": ["podman", "ps", "-a"]}` |

## Local control socket

`dd-agent` now exposes a local Unix socket for bootstrap and same-VM admin operations. `ddctl` uses it for:

- `status`
- `wait-ready`
- `list`
- `spawn`
- `stop`

Example:

```bash
ddctl wait-ready
ddctl spawn --app-name scraper --image ghcr.io/devopsdefender/dd-scraper-ci:latest
```

## Admin and scraper UI

- `dd-admin` serves a browser-facing fleet page and proxies register fleet data from `/api/fleet`.
- `dd-admin` can require a password session if `DD_ADMIN_PASSWORD` is set.
- `dd-register` and register mode can require `Authorization: Bearer <DD_ADMIN_API_TOKEN>` on `/api/fleet` for non-loopback callers.
- `dd-register` and register mode can require `Authorization: Bearer <DD_SCRAPER_REPORT_TOKEN>` on `/api/fleet/report` for non-loopback scraper reports.
- `dd-scraper` now serves:
  - `/`
  - `/health`
  - `/api/status`

## Noise protocol

The agent supports an encrypted shell protocol over WebSocket using Noise_XX_25519_ChaChaPoly_SHA256. Commands: `deploy`, `stop`, `jobs`, `fg`, `bg`, `logs`, `exit`.

Noise sessions now require attestation binding:

- the sender’s Noise static public key hash is embedded into quote report data
- the receiver verifies that the quote and the Noise key match before accepting the session
- unsupported attestation types are rejected for Noise handshakes

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
