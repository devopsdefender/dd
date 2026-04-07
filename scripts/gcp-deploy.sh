#!/bin/bash
# gcp-deploy.sh — Create a TDX VM on GCP with dd-agent.
# Called by CI workflows. Requires gcloud CLI authenticated.
#
# Required env vars:
#   GCP_PROJECT_ID          — GCP project ID
#   GCP_ZONE                — GCP zone (e.g. us-central1-c)
#   DD_ENV                  — staging or production
#   DD_DOMAIN               — Domain (e.g. devopsdefender.com)
#   BINARY_URL              — dd-agent binary download URL
#   DDCTL_BINARY_URL        — ddctl binary download URL
#   CLOUDFLARE_API_TOKEN    — CF API token
#   CLOUDFLARE_ACCOUNT_ID   — CF account ID
#   CLOUDFLARE_ZONE_ID      — CF zone ID
#   DD_GITHUB_CLIENT_ID     — GitHub OAuth client ID
#   DD_GITHUB_CLIENT_SECRET — GitHub OAuth client secret
#   DD_GITHUB_CALLBACK_URL  — GitHub OAuth callback URL
#
# Optional env vars:
#   VM_MACHINE_TYPE         — GCP machine type (default: c3-standard-4)
#   VM_DISK_SIZE            — Boot disk size (default: 256GB)
set -euo pipefail

VM_NAME="dd-${DD_ENV}-$(date +%s)"
VM_MACHINE_TYPE="${VM_MACHINE_TYPE:-c3-standard-4}"
VM_DISK_SIZE="${VM_DISK_SIZE:-256GB}"

if [ "${DD_ENV}" = "production" ]; then
  DD_HOSTNAME="app.${DD_DOMAIN}"
  DD_GITHUB_CALLBACK_URL="${DD_GITHUB_CALLBACK_URL:-https://app.${DD_DOMAIN}/auth/github/callback}"
else
  DD_HOSTNAME="app-staging.${DD_DOMAIN}"
fi

# Write the startup script with env vars expanded
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
STARTUP_TEMPLATE="${SCRIPT_DIR}/vm-startup.sh"

# Create a wrapper that sets env vars then sources the startup script
cat > /tmp/startup.sh <<STARTUP
#!/bin/bash
export BINARY_URL="${BINARY_URL}"
export DDCTL_BINARY_URL="${DDCTL_BINARY_URL}"
export DD_ENV="${DD_ENV}"
export DD_DOMAIN="${DD_DOMAIN}"
export DD_HOSTNAME="${DD_HOSTNAME}"
export CLOUDFLARE_API_TOKEN="${CLOUDFLARE_API_TOKEN}"
export CLOUDFLARE_ACCOUNT_ID="${CLOUDFLARE_ACCOUNT_ID}"
export CLOUDFLARE_ZONE_ID="${CLOUDFLARE_ZONE_ID}"
export DD_GITHUB_CLIENT_ID="${DD_GITHUB_CLIENT_ID}"
export DD_GITHUB_CLIENT_SECRET="${DD_GITHUB_CLIENT_SECRET}"
export DD_GITHUB_CALLBACK_URL="${DD_GITHUB_CALLBACK_URL}"
$(cat "${STARTUP_TEMPLATE}")
STARTUP

# Create the VM
gcloud compute instances create "$VM_NAME" \
  --project="$GCP_PROJECT_ID" \
  --zone="$GCP_ZONE" \
  --machine-type="$VM_MACHINE_TYPE" \
  --confidential-compute-type=TDX \
  --maintenance-policy=TERMINATE \
  --boot-disk-size="$VM_DISK_SIZE" \
  --image-family=ubuntu-2404-lts-amd64 \
  --image-project=ubuntu-os-cloud \
  --metadata-from-file=startup-script=/tmp/startup.sh \
  --labels=devopsdefender=managed,dd_env="${DD_ENV}" \
  --tags=dd-agent

EXTERNAL_IP=$(gcloud compute instances describe "$VM_NAME" \
  --project="$GCP_PROJECT_ID" --zone="$GCP_ZONE" \
  --format="value(networkInterfaces[0].accessConfigs[0].natIP)")

echo "VM: $VM_NAME IP: $EXTERNAL_IP"

# Export for CI
if [ -n "${GITHUB_ENV:-}" ]; then
  echo "bootstrap_ip=$EXTERNAL_IP" >> "$GITHUB_ENV"
fi
