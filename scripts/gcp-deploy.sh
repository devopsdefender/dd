#!/bin/bash
# gcp-deploy.sh — Create a TDX management VM on GCP that boots from a
# sealed easyenclave image and runs dd-register + dd-web as easyenclave
# workloads (OCI containers pulled from ghcr.io).
#
# Called by .github/workflows/{staging,production}-deploy.yml. Requires
# gcloud CLI authenticated via Workload Identity Federation (see the
# workflow's `google-github-actions/auth@v2` step).
#
# Per-VM configuration is passed via GCE instance metadata (`ee-config`
# attribute), which easyenclave's init.rs reads at PID 1 boot and
# applies as env vars — in particular EE_BOOT_WORKLOADS, which is the
# JSON workload spec that launches dd-register and dd-web.
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
#   DD_REGISTER_IMAGE       — ghcr.io/devopsdefender/dd-register:<tag>
#   DD_WEB_IMAGE            — ghcr.io/devopsdefender/dd-web:<tag>
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
# dd container images are still sha-pinned (bump when you cut a release).
DD_REGISTER_IMAGE="${DD_REGISTER_IMAGE:-ghcr.io/devopsdefender/dd-register:latest}"
DD_WEB_IMAGE="${DD_WEB_IMAGE:-ghcr.io/devopsdefender/dd-web:latest}"

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
# Two workloads deployed at boot by easyenclave:
#
#   dd-register — provisions the Cloudflare tunnel + DNS for DD_HOSTNAME
#                 and serves the Noise-XX /register endpoint for agents
#                 to join the fleet. Spawns cloudflared as a subprocess.
#
#   dd-web      — the fleet dashboard that operators see at DD_HOSTNAME.
#                 Auth-gated with GitHub OAuth (+ PAT Bearer + OIDC for CI).
#
# Both run with host networking (easyenclave's default) so they bind
# the VM's network namespace directly, just like the pre-rewrite setup.
EE_BOOT_WORKLOADS=$(jq -c -n \
  --arg reg_image      "$DD_REGISTER_IMAGE" \
  --arg web_image      "$DD_WEB_IMAGE" \
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
      "image": $reg_image,
      "app_name": "dd-register",
      "env": [
        ("DD_CF_API_TOKEN="   + $cf_token),
        ("DD_CF_ACCOUNT_ID="  + $cf_account),
        ("DD_CF_ZONE_ID="     + $cf_zone),
        ("DD_CF_DOMAIN="      + $domain),
        ("DD_HOSTNAME="       + $hostname),
        ("DD_ENV="            + $env),
        "DD_PORT=8081"
      ]
    },
    {
      "image": $web_image,
      "app_name": "dd-web",
      "env": [
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
echo "  workloads: dd-register, dd-web"
