# DevOps Defender

Confidential workloads on Intel TDX. Four kinds, one binary.

## What you can run

| Kind | What it is |
|---|---|
| `oracle` | Long-running attested service that signs and publishes data on-chain. Operator supplies the chain key. Optional signed public log at `<vanity>/log` (anyone can verify the hash chain). |
| `llm` | Local inference (Ollama / vLLM) **or** a TEE-protected proxy to ChatGPT / Claude. Upstream key never leaves the enclave. Optional client-encrypted chat history. |
| `shell` | Per-user attested bash over the web. GitHub login at the CP; PTY runs inside the sealed VM. Optional client-encrypted session recording. |
| `bot` | Autonomous LLM loop with outbound integrations (Signal, WhatsApp, …) inside a TDX-sealed VM. Optional client-encrypted chat history. |

That's the product surface. Anything else is out of scope.

## Architecture

One Cargo crate, one static binary, two modes:

```
DD_MODE=cp     devopsdefender   # control-plane: agent registry, tunnel + DNS, OAuth login
DD_MODE=agent  devopsdefender   # in-VM: registers with CP, runs workloads
```

Each VM gets its own Cloudflare tunnel — no public IPs. The sealed
runtime is [EasyEnclave](https://github.com/easyenclave/easyenclave); dd
adds attestation, fleet registration, and the four typed workload kinds.

### State lives in DNS

The CP doesn't keep a Deployments registry — Cloudflare DNS is the
source of truth. Every CNAME under the fleet zone whose target is an
agent tunnel is a Deployment. Optional `_dd.<vanity>` TXT records
override default failover policy. Killing the CP loses no state; a
freshly-booted CP queries CF and resumes.

## Auth

| Caller | Auth |
|---|---|
| Human browser | GitHub OAuth at the CP → HS256 JWT cookie scoped to the fleet domain |
| Agent → CP | Intel Trust Authority token, verified against Intel JWKS |
| CI → CP / agent | GitHub Actions OIDC JWT, `repository_owner == DD_OWNER` |

No PATs, no service tokens, no Cloudflare Access. The CP is the auth root.

One-time setup: register a GitHub OAuth App in your org with callback
`https://app.<your-domain>/oauth/callback`; set `DD_GH_OAUTH_CLIENT_ID`,
`DD_GH_OAUTH_CLIENT_SECRET`, `DD_FLEET_JWT_SECRET` (32-byte hex), and
`DD_ADMIN_EMAIL` (break-glass) as repo secrets.

## Deploy a workload

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
          vanity: myoracle.devopsdefender.com
          workload: workloads/oracle-example/workload.json
```

The CP picks a healthy host, sends `/deploy` to the agent, upserts the
CNAME, and starts monitoring. If the host goes unhealthy the CP
repoints the CNAME to a fresh host.

## Build

```bash
cargo build --release
# target/release/devopsdefender
```

## Website

[devopsdefender.com](https://devopsdefender.com) is served from
`gh-pages`. Edit there.

## License

MIT
