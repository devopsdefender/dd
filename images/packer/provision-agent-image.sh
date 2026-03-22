#!/usr/bin/env bash
# Provision a VM image with dd-agent, dd-cp (optional), Docker, and cloudflared.
# Called by Packer during image bake.
set -euo pipefail

if [ ! -s /tmp/dd-agent ]; then
  echo "Missing /tmp/dd-agent uploaded by packer file provisioner" >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
  ca-certificates \
  curl \
  gnupg \
  jq \
  lsb-release

# ── Install dd-agent ──────────────────────────────────────────────────────
install -m 0755 /tmp/dd-agent /usr/local/bin/dd-agent
rm -f /tmp/dd-agent

# ── Install dd-cp (optional, for control-plane bootstrap mode) ────────────
if [ -s /tmp/dd-cp ]; then
  install -m 0755 /tmp/dd-cp /usr/local/bin/dd-cp
  rm -f /tmp/dd-cp
fi

# ── Install Docker CE ─────────────────────────────────────────────────────
docker_codename="$(. /etc/os-release && echo "${VERSION_CODENAME:-}")"
if [ -z "${docker_codename}" ]; then
  echo "Missing VERSION_CODENAME for Docker repo setup" >&2
  exit 1
fi
docker_arch="$(dpkg --print-architecture)"
install -d -m 0755 /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod 0644 /etc/apt/keyrings/docker.gpg
cat > /etc/apt/sources.list.d/docker.list <<DOCKERREPO
deb [arch=${docker_arch} signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu ${docker_codename} stable
DOCKERREPO
apt-get update
apt-get install -y --no-install-recommends \
  containerd.io \
  docker-buildx-plugin \
  docker-ce \
  docker-ce-cli

# ── Install cloudflared ───────────────────────────────────────────────────
cloudflare_codename="$(. /etc/os-release && echo "${VERSION_CODENAME:-}")"
if [ -z "${cloudflare_codename}" ]; then
  echo "Missing VERSION_CODENAME for cloudflared repo setup" >&2
  exit 1
fi
curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg | gpg --dearmor -o /etc/apt/keyrings/cloudflare-main.gpg
chmod 0644 /etc/apt/keyrings/cloudflare-main.gpg
cat > /etc/apt/sources.list.d/cloudflared.list <<APTREPO
deb [signed-by=/etc/apt/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared ${cloudflare_codename} main
APTREPO
apt-get update
apt-get install -y --no-install-recommends cloudflared

# ── Create config directory ───────────────────────────────────────────────
install -d -m 0755 /etc/devopsdefender

# ── Create systemd units ─────────────────────────────────────────────────
cat > /etc/systemd/system/devopsdefender-agent.service <<'SERVICEUNIT'
[Unit]
Description=DevOps Defender Agent
After=network-online.target docker.service
Wants=network-online.target docker.service

[Service]
Type=simple
User=root
Environment=DD_AGENT_MODE=agent
Environment=DD_CONFIG=/etc/devopsdefender/agent.json
ExecStart=/usr/local/bin/dd-agent
Restart=on-failure
RestartSec=5
StandardOutput=journal+console
StandardError=journal+console

[Install]
WantedBy=multi-user.target
SERVICEUNIT

cat > /etc/systemd/system/devopsdefender-control-plane.service <<'SERVICEUNIT'
[Unit]
Description=DevOps Defender Control Plane
After=network-online.target docker.service
Wants=network-online.target docker.service

[Service]
Type=simple
User=root
Environment=DD_AGENT_MODE=control-plane
Environment=DD_CONFIG=/etc/devopsdefender/control-plane.json
ExecStart=/usr/local/bin/dd-agent
Restart=on-failure
RestartSec=5
StandardOutput=journal+console
StandardError=journal+console

[Install]
WantedBy=multi-user.target
SERVICEUNIT

# ── Enable services ───────────────────────────────────────────────────────
systemctl daemon-reload
systemctl enable docker
systemctl enable devopsdefender-agent.service
systemctl disable devopsdefender-control-plane.service || true

# ── Cleanup ───────────────────────────────────────────────────────────────
apt-get clean
rm -rf /var/lib/apt/lists/*
