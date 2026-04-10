#!/bin/bash
# vm-startup.sh — Runs inside the GCP TDX VM at boot via startup-script metadata.
# Installs dd-register + dd-web and starts both.
#
# Required env vars (set by gcp-deploy.sh):
#   BINARY_URL              — dd-client binary download URL (release has all 3)
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

# The release URL points to dd-client; derive dd-register and dd-web URLs from the same release
RELEASE_BASE="${BINARY_URL%/dd-client}"
for bin in dd-client dd-register dd-web; do
  curl -fsSL -o "/usr/local/bin/${bin}" "${RELEASE_BASE}/${bin}" -H "Accept: application/octet-stream"
  chmod +x "/usr/local/bin/${bin}"
done

# ── Start dd-register (tunnel provisioning) ──────────────────────────────
DD_CF_API_TOKEN="${CLOUDFLARE_API_TOKEN}" \
DD_CF_ACCOUNT_ID="${CLOUDFLARE_ACCOUNT_ID}" \
DD_CF_ZONE_ID="${CLOUDFLARE_ZONE_ID}" \
DD_CF_DOMAIN="${DD_DOMAIN}" \
DD_HOSTNAME="${DD_HOSTNAME}" \
DD_ENV="${DD_ENV}" \
DD_PORT=8081 \
nohup /usr/local/bin/dd-register > /var/log/dd-register.log 2>&1 &

# ── Start dd-web (fleet dashboard + collector) ───────────────────────────
DD_CF_API_TOKEN="${CLOUDFLARE_API_TOKEN}" \
DD_CF_ACCOUNT_ID="${CLOUDFLARE_ACCOUNT_ID}" \
DD_CF_ZONE_ID="${CLOUDFLARE_ZONE_ID}" \
DD_CF_DOMAIN="${DD_DOMAIN}" \
DD_HOSTNAME="${DD_HOSTNAME}" \
DD_ENV="${DD_ENV}" \
DD_OWNER=devopsdefender \
DD_GITHUB_CLIENT_ID="${DD_GITHUB_CLIENT_ID}" \
DD_GITHUB_CLIENT_SECRET="${DD_GITHUB_CLIENT_SECRET}" \
DD_GITHUB_CALLBACK_URL="${DD_GITHUB_CALLBACK_URL}" \
DD_PORT=8080 \
nohup /usr/local/bin/dd-web > /var/log/dd-web.log 2>&1 &

echo "dd-register on :8081, dd-web on :8080"
