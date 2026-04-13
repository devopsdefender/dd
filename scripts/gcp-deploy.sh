#!/bin/bash
# gcp-deploy.sh — Create a TDX management VM on GCP that boots from a
# sealed easyenclave image and runs the dd unified binary as an
# easyenclave workload (OCI container pulled from ghcr.io).
#
# Called by .github/workflows/{staging,production}-deploy.yml. Requires
# gcloud CLI authenticated via Workload Identity Federation (see the
# workflow's `google-github-actions/auth@v2` step).
#
# Per-VM configuration is passed via GCE instance metadata (`ee-config`
# attribute), which easyenclave's init.rs reads at PID 1 boot and
# applies as env vars — in particular EE_BOOT_WORKLOADS, which is the
# JSON workload spec that launches `dd management`.
#
# Required env vars (set by the workflow):
#   GCP_PROJECT_ID          — GCP project where the VM lives
#   GCP_ZONE                — GCP zone (e.g. us-central1-c)
#   DD_ENV                  — staging or production
#   DD_DOMAIN               — Public domain (e.g. devopsdefender.com)
#   CLOUDFLARE_API_TOKEN    — CF API token (dd-register uses it)
#   CLOUDFLARE_ACCOUNT_ID   — CF account ID
#   CLOUDFLARE_ZONE_ID      — CF zone ID
#   DD_GITHUB_CLIENT_ID     — GitHub OAuth client ID (dd-web uses it)
#   DD_GITHUB_CLIENT_SECRET — GitHub OAuth client secret
#
# Optional env vars (override the pinned defaults):
#   EE_IMAGE_FAMILY         — easyenclave GCP image family
#   EE_IMAGE_PROJECT        — project hosting the image
#   DD_IMAGE                — ghcr.io/devopsdefender/dd:<tag>
#   VM_MACHINE_TYPE         — default c3-standard-4
#   VM_DISK_SIZE            — default 10GB (no big rootfs; workload state
#                             lives in /var/lib/easyenclave tmpfs)
#   DD_GITHUB_CALLBACK_URL  — default https://{hostname}/auth/github/callback

set -euo pipefail

# ── easyenclave image family ──────────────────────────────────────────────
# Resolved at deploy time via GCE's image-family selector — picks the
# newest non-deprecated image in the family. No sha12 to hand-bump.
#
#   easyenclave-staging → rolling main, rotates on every push (5 kept)
#   easyenclave-stable  → v* tags, kept forever
#
# For DD production, override to easyenclave-stable once a v-tag exists.
EE_IMAGE_FAMILY="${EE_IMAGE_FAMILY:-easyenclave-staging}"
EE_IMAGE_PROJECT="${EE_IMAGE_PROJECT:-easyenclave}"
DD_IMAGE="${DD_IMAGE:-ghcr.io/devopsdefender/dd:latest}"

VM_NAME="dd-${DD_ENV}-$(date +%s)"
VM_MACHINE_TYPE="${VM_MACHINE_TYPE:-c3-standard-4}"
VM_DISK_SIZE="${VM_DISK_SIZE:-10GB}"

if [ "${DD_ENV}" = "production" ]; then
  DD_HOSTNAME="app.${DD_DOMAIN}"
else
  DD_HOSTNAME="app-staging.${DD_DOMAIN}"
fi
DD_GITHUB_CALLBACK_URL="${DD_GITHUB_CALLBACK_URL:-https://${DD_HOSTNAME}/auth/github/callback}"

# ── Build the workload spec ──────────────────────────────────────────────
# Single workload: `dd management` runs dd-register + dd-web concurrently
# inside one container. Both bind the VM's network namespace directly
# (easyenclave default = host networking).
#
# dd-register listens on :8081 (tunnel provisioning, agent registration)
# dd-web listens on :8080 (fleet dashboard, OAuth, collector)
# dd-web's collector self-monitors the control plane via localhost.
EE_BOOT_WORKLOADS=$(jq -c -n \
  --arg image          "$DD_IMAGE" \
  --arg cf_token       "$CLOUDFLARE_API_TOKEN" \
  --arg cf_account     "$CLOUDFLARE_ACCOUNT_ID" \
  --arg cf_zone        "$CLOUDFLARE_ZONE_ID" \
  --arg domain         "$DD_DOMAIN" \
  --arg hostname       "$DD_HOSTNAME" \
  --arg env            "$DD_ENV" \
  --arg gh_client_id   "$DD_GITHUB_CLIENT_ID" \
  --arg gh_client_secret "$DD_GITHUB_CLIENT_SECRET" \
  --arg gh_callback    "$DD_GITHUB_CALLBACK_URL" \
  '[
    {
      "image": $image,
      "app_name": "dd-management",
      "env": [
        "DD_MODE=management",
        ("DD_CF_API_TOKEN="   + $cf_token),
        ("DD_CF_ACCOUNT_ID="  + $cf_account),
        ("DD_CF_ZONE_ID="     + $cf_zone),
        ("DD_CF_DOMAIN="      + $domain),
        ("DD_HOSTNAME="       + $hostname),
        ("DD_ENV="            + $env),
        "DD_OWNER=devopsdefender",
        ("DD_GITHUB_CLIENT_ID="     + $gh_client_id),
        ("DD_GITHUB_CLIENT_SECRET=" + $gh_client_secret),
        ("DD_GITHUB_CALLBACK_URL="  + $gh_callback),
        "DD_REGISTER_PORT=8081",
        "DD_OIDC_AUDIENCE=dd-web",
        "DD_PORT=8080"
      ]
    }
  ]')

# ── Wrap into ee-config ───────────────────────────────────────────────────
# Flat JSON map of KEY=VALUE. Each entry becomes an env var inside
# easyenclave at init. EE_BOOT_WORKLOADS is the stringified spec above.
jq -c -n \
  --arg workloads "$EE_BOOT_WORKLOADS" \
  '{ "EE_BOOT_WORKLOADS": $workloads, "EE_OWNER": "devopsdefender" }' \
  > /tmp/ee-config.json

trap 'rm -f /tmp/ee-config.json' EXIT

# ── Create the VM ─────────────────────────────────────────────────────────
gcloud compute instances create "$VM_NAME" \
  --project="$GCP_PROJECT_ID" \
  --zone="$GCP_ZONE" \
  --machine-type="$VM_MACHINE_TYPE" \
  --confidential-compute-type=TDX \
  --maintenance-policy=TERMINATE \
  --boot-disk-size="$VM_DISK_SIZE" \
  --image-family="$EE_IMAGE_FAMILY" \
  --image-project="$EE_IMAGE_PROJECT" \
  --metadata-from-file=ee-config=/tmp/ee-config.json \
  --labels=devopsdefender=managed,dd_env="${DD_ENV}" \
  --tags=dd-management

echo "VM: $VM_NAME"
echo "  image:    family $EE_IMAGE_FAMILY ($EE_IMAGE_PROJECT)"
echo "  hostname: $DD_HOSTNAME"
echo "  workload: dd management"
