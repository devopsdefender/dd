#!/usr/bin/env bash
# Provision a minimal baremetal VM image with dd-agent, Docker, and cloudflared.
# Leaner than the GCP variant: no buildx, aggressive cleanup, minimal packages.
# Called by Packer during baremetal image bake.
set -euo pipefail

if [ ! -s /tmp/dd-agent ]; then
  echo "Missing /tmp/dd-agent uploaded by packer file provisioner" >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive

# ── Minimal base packages (gnupg/lsb-release only needed for repo setup) ──
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

# ── Install Docker CE (no buildx — agent only pulls/runs, never builds) ──
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

# ── Install NVIDIA Container Toolkit (no-op without a GPU) ────────────────
curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey | gpg --dearmor -o /etc/apt/keyrings/nvidia-container-toolkit.gpg
chmod 0644 /etc/apt/keyrings/nvidia-container-toolkit.gpg
cat > /etc/apt/sources.list.d/nvidia-container-toolkit.list <<NVREPO
deb [signed-by=/etc/apt/keyrings/nvidia-container-toolkit.gpg] https://nvidia.github.io/libnvidia-container/stable/deb/\$(ARCH) /
NVREPO
apt-get update
apt-get install -y --no-install-recommends nvidia-container-toolkit
nvidia-ctk runtime configure --runtime=docker || true

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

# ── Aggressive cleanup (keep the image small) ────────────────────────────
# Remove packages only needed for repo setup
apt-get purge -y --auto-remove gnupg lsb-release
apt-get clean
rm -rf \
  /var/lib/apt/lists/* \
  /usr/share/doc/* \
  /usr/share/man/* \
  /usr/share/locale/* \
  /var/log/*.log \
  /tmp/*
