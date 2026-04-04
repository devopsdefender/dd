#!/bin/bash
# vm-startup.sh — Runs inside the GCP TDX VM at boot via startup-script metadata.
# Installs podman, cloudflared, dd-agent, and starts the register + scraper.
#
# Required env vars (set by the deploy script):
#   BINARY_URL              — dd-agent binary download URL
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
DD_BOOT_CMD=bash \
DD_BOOT_APP=demo \
nohup /usr/local/bin/dd-agent > /var/log/dd-agent.log 2>&1 &

# ── Deploy scraper container via dd-agent API (localhost, no auth needed) ─
echo "Waiting for agent API..."
for i in $(seq 1 30); do
  curl -fsS http://localhost:8080/health >/dev/null 2>&1 && break
  sleep 2
done

echo "Deploying scraper container..."
curl -sS -X POST http://localhost:8080/deploy \
  -H "Content-Type: application/json" \
  -d "{
    \"image\": \"ghcr.io/devopsdefender/dd-scraper:latest\",
    \"app_name\": \"scraper\",
    \"env\": [
      \"DD_CF_API_TOKEN=${CLOUDFLARE_API_TOKEN}\",
      \"DD_CF_ACCOUNT_ID=${CLOUDFLARE_ACCOUNT_ID}\",
      \"DD_CF_ZONE_ID=${CLOUDFLARE_ZONE_ID}\",
      \"DD_CF_DOMAIN=${DD_DOMAIN}\",
      \"DD_ENV=${DD_ENV}\",
      \"DD_REGISTER_URL=ws://localhost:8080/scraper\"
    ]
  }" && echo "✓ Scraper deployed" || echo "WARNING: scraper deploy failed"
