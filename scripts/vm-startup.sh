#!/bin/bash
# vm-startup.sh — Runs inside the GCP TDX VM at boot via startup-script metadata.
# Installs podman, cloudflared, dd-agent, ddctl, and starts the register + scraper.
#
# Required env vars (set by the deploy script):
#   BINARY_URL              — dd-agent binary download URL
#   DDCTL_BINARY_URL        — ddctl binary download URL
#   DD_SCRAPER_IMAGE        — dd-scraper image reference
#   DD_ENV                  — staging or production
#   DD_DOMAIN               — Domain (e.g. devopsdefender.com)
#   DD_HOSTNAME             — Public hostname for this register
#   CLOUDFLARE_API_TOKEN    — CF API token
#   CLOUDFLARE_ACCOUNT_ID   — CF account ID
#   CLOUDFLARE_ZONE_ID      — CF zone ID
#   DD_GITHUB_CLIENT_ID     — GitHub OAuth client ID
#   DD_GITHUB_CLIENT_SECRET — GitHub OAuth client secret
#   DD_GITHUB_CALLBACK_URL  — GitHub OAuth callback URL
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

# ── Install packages ─────────────────────────────────────────────────────
apt-get update -q
apt-get install -y podman
systemctl enable --now podman.socket

# ── Install binaries ─────────────────────────────────────────────────────
curl -fsSL -o /usr/local/bin/cloudflared \
  https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64
chmod +x /usr/local/bin/cloudflared

curl -fsSL -o /usr/local/bin/dd-agent "${BINARY_URL}" -H "Accept: application/octet-stream"
chmod +x /usr/local/bin/dd-agent

curl -fsSL -o /usr/local/bin/ddctl "${DDCTL_BINARY_URL}" -H "Accept: application/octet-stream"
chmod +x /usr/local/bin/ddctl

# ── Start dd-agent (register mode) ──────────────────────────────────────
DD_OWNER=devopsdefender \
DD_AGENT_MODE=register \
DD_ENV="${DD_ENV}" \
DD_CF_API_TOKEN="${CLOUDFLARE_API_TOKEN}" \
DD_CF_ACCOUNT_ID="${CLOUDFLARE_ACCOUNT_ID}" \
DD_CF_ZONE_ID="${CLOUDFLARE_ZONE_ID}" \
DD_CF_DOMAIN="${DD_DOMAIN}" \
DD_HOSTNAME="${DD_HOSTNAME}" \
DD_GITHUB_CLIENT_ID="${DD_GITHUB_CLIENT_ID}" \
DD_GITHUB_CLIENT_SECRET="${DD_GITHUB_CLIENT_SECRET}" \
DD_GITHUB_CALLBACK_URL="${DD_GITHUB_CALLBACK_URL}" \
nohup /usr/local/bin/dd-agent > /var/log/dd-agent.log 2>&1 &

# ── Bootstrap scraper via local ddctl socket ─────────────────────────────
/usr/local/bin/ddctl wait-ready --timeout 60
/usr/local/bin/ddctl spawn \
  --app-name scraper \
  --image "${DD_SCRAPER_IMAGE:-ghcr.io/devopsdefender/dd-scraper-ci:latest}" \
  --env "DD_CF_API_TOKEN=${CLOUDFLARE_API_TOKEN}" \
  --env "DD_CF_ACCOUNT_ID=${CLOUDFLARE_ACCOUNT_ID}" \
  --env "DD_CF_ZONE_ID=${CLOUDFLARE_ZONE_ID}" \
  --env "DD_CF_DOMAIN=${DD_DOMAIN}" \
  --env "DD_ENV=${DD_ENV}" \
  --env "DD_REGISTER_URL=http://localhost:8080"
