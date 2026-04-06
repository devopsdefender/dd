# DevOps Defender (DD)

A confidential computing platform that runs workloads as plain processes on Intel TDX VMs with Cloudflare Tunnel networking and a web dashboard.

**Domain:** devopsdefender.com

## Repository Structure

```
dd/
├── agent/    # Rust binary — dd-agent (workload manager) and dd-register (fleet server)
└── images/   # sealed VM image builder (dm-verity, TDX measurement)
```

## agent/ (Rust)

A daemon that runs on TDX VMs. It manages workloads as plain processes, serves a web dashboard, and provides terminal access via Cloudflare Tunnels.

**Binaries:** `dd-agent`, `dd-register`
**Entry point:** `src/bin/dd-agent/main.rs`

**Operational modes** (set via `DD_AGENT_MODE`):
- **agent** (default) — run workloads, serve dashboard, manage tunnel
- **register** — fleet dashboard, register agents via Noise protocol, manage tunnels for agents
- **scraper** — discover agents from CF tunnel listing, report health to register

**Key modules:**
- `src/bin/dd-agent/main.rs` — startup, mode selection, boot workload, monitoring loop
- `src/bin/dd-agent/config.rs` — config loading from `/etc/devopsdefender/agent.json` + env vars
- `src/bin/dd-register/main.rs` — standalone register binary
- `src/server.rs` — HTTP handlers, dashboard HTML, auth, deploy endpoint, WebSocket sessions
- `src/process.rs` — `spawn_command()`, `kill_process()`, `is_running()` (no container runtime)
- `src/noise.rs` — Noise_XX encrypted shell protocol over WebSocket
- `src/tunnel.rs` — Cloudflare tunnel creation, DNS CNAME management
- `src/attestation/tsm.rs` — TDX quote generation via configfs-tsm

### Auth system

`AuthMode` enum in `server.rs`:
- **GitHub OAuth** — `DD_GITHUB_CLIENT_ID`, `DD_GITHUB_CLIENT_SECRET`, `DD_GITHUB_CALLBACK_URL`
- **Password** — `DD_PASSWORD` (shared password, constant-time comparison)
- **None** — no local auth (dev mode or JWT-only from register)

GitHub OAuth takes priority if both are configured. Register mode issues domain-scoped JWTs (`dd_auth` cookie) so agents behind a register can authenticate users without their own OAuth setup.

### Routes

**Agent mode:**
- `GET /` — dashboard (metrics, workload table)
- `GET /workload/{id}` — workload detail with logs
- `GET /session/{app}` — web terminal (xterm.js)
- `GET /ws/session/{app}` — WebSocket for terminal I/O
- `GET /noise/session/{app}` — Noise-encrypted terminal
- `GET /noise/cmd` — Noise-encrypted command channel
- `POST /deploy` — localhost-only, accepts `{"cmd": ["bash"], "app_name": "demo"}`
- `GET /health` — JSON health check (no auth)
- `GET /deployments` — JSON deployment list

**Register mode (additional):**
- `GET /` — fleet dashboard (agents table + own workloads)
- `GET /agent/{id}` — agent detail page
- `GET /register` — WebSocket for agent registration (Noise protocol)
- `GET /scraper` — WebSocket for scraper health reports
- `POST /deregister` — remove agent from fleet

**Auth routes:**
- `GET /auth/login` — password login page
- `POST /auth/login` — password login handler
- `GET /auth/github/start` — GitHub OAuth redirect
- `GET /auth/github/callback` — GitHub OAuth callback
- `GET /auth/logout` — clear session

### Deploy endpoint

`POST /deploy` (localhost only):
```json
{
  "cmd": ["bash", "-c", "echo hello"],
  "app_name": "demo",
  "tty": true,
  "env": ["KEY=VALUE"]
}
```

Workloads are plain processes spawned via `spawn_command()`. No container runtime, no OCI, no chroot. TTY support uses `script(1)`.

### Agent registration flow

1. Agent connects to register via Noise_XX WebSocket (`DD_REGISTER_URL`)
2. Noise handshake with TDX attestation
3. Register creates CF tunnel + DNS CNAME for the agent
4. Agent receives `BootstrapConfig` (tunnel_token, hostname, auth keys)
5. Agent starts cloudflared with the tunnel token
6. Agent appears on fleet dashboard

### Key env vars

| Variable | Description |
|----------|-------------|
| `DD_OWNER` | Owner identity (required to enable auth) |
| `DD_AGENT_MODE` | `agent`, `register`, or `scraper` |
| `DD_BOOT_CMD` | Shell command to run at startup |
| `DD_BOOT_APP` | Name for the boot workload |
| `DD_PASSWORD` | Shared password for dashboard auth |
| `DD_GITHUB_CLIENT_ID` | GitHub OAuth client ID |
| `DD_GITHUB_CLIENT_SECRET` | GitHub OAuth client secret |
| `DD_GITHUB_CALLBACK_URL` | GitHub OAuth callback URL |
| `DD_TUNNEL_TOKEN` | Pre-provisioned CF tunnel token |
| `DD_REGISTER_URL` | Register WebSocket URL |
| `DD_CF_API_TOKEN` | CF API token (self-registration) |
| `DD_CF_ACCOUNT_ID` | CF account ID |
| `DD_CF_ZONE_ID` | CF zone ID |
| `DD_CF_DOMAIN` | Domain for hostnames (default: `devopsdefender.com`) |
| `DD_HOSTNAME` | Public hostname override |
| `DD_PORT` | HTTP port (default: `8080`) |
| `DD_ENV` | Environment label (`staging`, `production`, `dev`) |

## images/ (sealed image builder)

Builds sealed VM images with dd-agent as PID 1.

- `build.sh` — custom raw image builder (static musl binary, initrd, dm-verity)
- `Makefile` — convenience wrapper for staging binaries, building, and upload prep
- `flake.nix` — dev shell for the surviving image-build toolchain

Output: `dd-agent-vm.raw.zst` — reproducible, measured root filesystem verifiable via TDX quote + dm-verity roothash.

## Development Workflow & Branch Rules

### Branch Protection

- **`main` is protected.** All changes require a PR with board member approval.
- **Stale reviews are dismissed** on new pushes.

### Working on Changes

1. Create a feature branch from `main`
2. Run `cargo fmt --check`, `cargo clippy --all-targets`, `cargo test` (with `RUSTFLAGS="-Dwarnings"`)
3. Push and open a PR targeting `main`

### PR Standards

- Title: describe the user-visible change
- Body: problem, root cause, fix, how to verify
- One logical change per PR
- Squash into one commit unless commits are genuinely separate logical steps

### Staging

PRs targeting `main` auto-deploy to staging (`app-staging.devopsdefender.com`). Integration tests run automatically.

## Build & Development

```bash
cargo build                # build
cargo test                 # test
cargo fmt --check          # format check
cargo clippy --all-targets # lint
```

CI enforces `RUSTFLAGS="-Dwarnings"`.

### Running Locally

```bash
# Agent with bash workload
DD_OWNER=me DD_BOOT_CMD=bash DD_BOOT_APP=demo cargo run --bin dd-agent

# With password auth
DD_OWNER=me DD_PASSWORD=changeme DD_BOOT_CMD=bash DD_BOOT_APP=demo cargo run --bin dd-agent
```

## Key Concepts

- **Intel TDX** — hardware-encrypted VMs. CPU generates attestation quotes proving identity/integrity.
- **MRTD** — measurement of the TDX domain (hash of initial VM state).
- **RTMR** — runtime measurement registers (extend-only, track state changes).
- **configfs-tsm** — Linux kernel interface for TDX quotes (`/sys/kernel/config/tsm/report/`).
- **Cloudflare Tunnels** — outbound-only networking, no open ports. Tunnel tokens issued at registration.
- **Noise protocol** — end-to-end encrypted shell sessions (Noise_XX_25519_ChaChaPoly_SHA256).

## Deployments & Operations

All infrastructure is managed through GitHub Actions.

**Health check URLs:**
- Staging: `https://app-staging.devopsdefender.com/health`
- Production: `https://app.devopsdefender.com/health`

```bash
# Trigger staging deploy
gh workflow run staging-deploy.yml --repo devopsdefender/dd

# Trigger production deploy
gh workflow run production-deploy.yml --repo devopsdefender/dd
```

## CI/CD Pipelines

- `ci.yml` — fmt, clippy, test on every push/PR
- `staging-deploy.yml` — build binary, cleanup old GCP VMs, deploy TDX VM, integration test
- `production-deploy.yml` — same, triggered on push to main
- `build-image.yml` — build sealed VM image (custom builder + dm-verity)
- `release.yml` — build release binaries on tag push
