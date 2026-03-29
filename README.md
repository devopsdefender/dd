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

Deploy a hello-world app in three steps. No API keys, no config files, no secrets.

This exact flow runs as an integration test on every staging and production deploy (see [staging](/.github/workflows/staging-deploy.yml) and [production](/.github/workflows/production-deploy.yml) pipelines).

### 1. Write your app

Any Docker image works. Here's the simplest possible example:

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY index.html .
EXPOSE 8000
CMD ["python", "-m", "http.server", "8000"]
```

### 2. Add the GitHub Action

Create `.github/workflows/deploy.yml` in your repo:

```yaml
name: Deploy to DevOps Defender
on:
  push:
    branches: [main]

permissions:
  id-token: write    # GitHub OIDC -- DD verifies this, no API keys needed
  packages: write
  contents: read

env:
  IMAGE: ghcr.io/${{ github.repository }}:${{ github.sha }}
  DD_API: https://app.devopsdefender.com

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # Build and push your image to GitHub Container Registry
      - uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - uses: docker/build-push-action@v6
        with:
          push: true
          tags: ${{ env.IMAGE }}

      # Get a short-lived OIDC token (GitHub issues it automatically)
      - name: Get OIDC token
        id: oidc
        uses: actions/github-script@v7
        with:
          script: |
            const token = await core.getIDToken('devopsdefender.com');
            core.setOutput('token', token);

      # Deploy -- one API call, that's it
      - name: Deploy
        id: deploy
        run: |
          resp=$(curl -fsSL "$DD_API/api/v1/deploy" \
            -H "Content-Type: application/json" \
            -H "Authorization: Bearer ${{ steps.oidc.outputs.token }}" \
            -d '{
              "image": "${{ env.IMAGE }}",
              "app_name": "hello-world",
              "ports": ["8000:8000"]
            }')
          echo "$resp" | jq .
          echo "deployment_id=$(echo "$resp" | jq -r .deployment_id)" >> "$GITHUB_OUTPUT"

      # Wait for the agent to pull and start the container
      - name: Wait for deploy
        run: |
          for i in $(seq 1 30); do
            status=$(curl -fsSL "$DD_API/api/v1/deployments/${{ steps.deploy.outputs.deployment_id }}" \
              | jq -r .status)
            echo "  attempt ${i}/30: status=${status}"
            [ "$status" = "running" ] && echo "Deployed!" && exit 0
            [ "$status" = "failed" ] && echo "::error::Deployment failed" && exit 1
            sleep 10
          done
          echo "::error::Timed out waiting for deployment"
          exit 1
```

Push to `main` and that's it -- your app is live on hardware-encrypted compute.

### 3. Verify it's running

```bash
# Check deployment status
curl -s https://app.devopsdefender.com/api/v1/deployments | jq '.[] | {app_name, status}'

# Your app gets a Cloudflare hostname automatically
curl https://hello-world.devopsdefender.com
```

### What happens under the hood

1. **Push to main** -- GitHub Actions builds your image and pushes it to GHCR
2. **OIDC auth** -- GitHub issues a short-lived JWT. DD verifies it -- no stored secrets anywhere
3. **Deploy API** -- DD creates a pending deployment and assigns it to an available TDX agent
4. **Agent picks it up** -- within 30 seconds, the agent pulls your image and starts the container
5. **You're live** -- the agent sets up a Cloudflare Tunnel, giving your app a public URL with zero open ports

### Quick deploy from the CLI

Already have an image pushed somewhere? Deploy it with a single curl:

```bash
curl -X POST https://app.devopsdefender.com/api/v1/deploy \
  -H "Content-Type: application/json" \
  -d '{
    "image": "nginx:alpine",
    "app_name": "my-app",
    "ports": ["80:80"]
  }'
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
