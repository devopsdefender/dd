# DevOps Defender

**Run anything. Boot instantly. Pay less.**

The cheapest way to run apps and open-source AI models with real security. Your code runs in hardware-encrypted memory that nobody else can read -- not your cloud provider, not us, not anyone.

[Website](https://devopsdefender.com) · [GitHub](https://github.com/devopsdefender/dd)

---

## Why DD?

**Instant boot** -- Your app is live in seconds, not minutes. No cold starts, no waiting for VMs to provision.

**Actually private** -- Every app runs in hardware-encrypted memory. The cloud provider can't read it. We can't read it. Only your code can access your data. This isn't a promise -- it's enforced by Intel's CPU.

**Cheapest anywhere** -- No security tax. No platform markup. Raw compute at the lowest price with hardware security included, not bolted on as an upsell.

## What People Run on DD

- **Open-source AI models** -- Host Llama, Mistral, or any open-weight model privately. Your prompts and data never leave encrypted memory.
- **Apps from Claude Code** -- Built something with Claude Code? Deploy it with a GitHub Action. Code to production in one push.
- **Any Docker app** -- Web apps, APIs, databases, background workers. If it runs in Docker, it works on DD. No SDK, no code changes.

## How It Works

1. **Write your app** -- Build it however you want. If it runs in Docker, you're good.
2. **Push to GitHub** -- Add a one-line GitHub Action. DD deploys automatically. No keys, no config, no secrets.
3. **You're live** -- Instant boot on hardware-encrypted compute. You get a URL, health monitoring, and the guarantee that nobody can peek at your data.

## Get Started

Add this to your repo:

```yaml
# .github/workflows/deploy.yml
name: Deploy
on:
  push:
    branches: [main]

permissions:
  id-token: write

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Deploy to DevOps Defender
        uses: devopsdefender/dd@main
        with:
          app-name: my-app
          image: ghcr.io/myorg/myapp:${{ github.sha }}
```

## Repository

```
dd/
├── agent/          # Runs on secure machines -- manages your workloads
├── control-plane/  # API server -- orchestrates deployments and health checks
├── images/         # VM image definitions
├── infra/          # Infrastructure automation
└── openapi/        # API spec
```

## Website

The landing page at [devopsdefender.com](https://devopsdefender.com) lives on the [`gh-pages`](https://github.com/devopsdefender/dd/tree/gh-pages) branch. PRs targeting `gh-pages` get a preview URL commented automatically.

## Under the Hood

DD uses [Intel TDX](https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/overview.html) (Trust Domain Extensions) for hardware-level encryption, [GitHub OIDC](https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/about-security-hardening-with-openid-connect) for passwordless deploys, and [Cloudflare Tunnels](https://www.cloudflare.com/products/tunnel/) for secure networking with zero open ports. See [CLAUDE.md](CLAUDE.md) for the full technical deep dive.
