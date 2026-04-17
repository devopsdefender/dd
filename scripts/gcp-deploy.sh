#!/bin/bash
# gcp-deploy.sh — Create a TDX management VM on GCP that boots from a
# sealed easyenclave image and runs dd management as a native process.
#
# Both the devopsdefender binary and cloudflared are fetched straight
# from their GitHub releases by easyenclave's github_release workload
# source — no OCI registry, no Dockerfile. Cloudflared is a fetch-only
# boot workload: its binary lands in /var/lib/easyenclave/bin (now on
# PATH) so dd-register can shell out to `cloudflared` by name.
#
# Agent-side mirror: a local TDX guest with a vfio-pci-passed GPU can
# register against the CP this script deploys by using the same
# easyenclave `github_release` workload source for the devopsdefender
# binary, with `DD_REGISTER_URL=wss://{hostname}/register`. See the
# local-GPU demo notes in the commit trail.
#
# Called by .github/workflows/{staging,production}-deploy.yml. Requires
# gcloud CLI authenticated via Workload Identity Federation.
#
# Required env vars (set by the workflow):
#   GCP_PROJECT_ID          — GCP project where the VM lives
#   GCP_ZONE                — GCP zone (e.g. us-central1-c)
#   DD_ENV                  — staging, production, or pr-{num} (ephemeral per-PR)
#   DD_DOMAIN               — Public domain (e.g. devopsdefender.com)
#   CLOUDFLARE_API_TOKEN    — CF API token (dd-register uses it)
#   CLOUDFLARE_ACCOUNT_ID   — CF account ID
#   CLOUDFLARE_ZONE_ID      — CF zone ID
#
# Optional env vars:
#   DD_HOSTNAME             — public hostname override. If unset, derived
#                             from DD_ENV (production → app.$DOMAIN,
#                             anything else → app-staging.$DOMAIN). Set
#                             explicitly for per-PR envs (pr-42.$DOMAIN).
#   DD_GITHUB_CLIENT_ID     — GitHub OAuth client ID. If unset, dd-web
#                             disables OAuth login and only PAT auth works.
#                             Per-PR envs leave this unset.
#   DD_GITHUB_CLIENT_SECRET — GitHub OAuth client secret (paired with above)
#   DD_GITHUB_CALLBACK_URL  — OAuth callback, default https://{hostname}/auth/github/callback
#   EE_IMAGE_FAMILY         — easyenclave GCP image family
#   EE_IMAGE_PROJECT        — project hosting the image
#   DD_RELEASE_TAG          — GitHub release tag on devopsdefender/dd
#                             (defaults to 'latest'; PRs override with pr-{sha12})
#   VM_MACHINE_TYPE         — default c3-standard-4
#   VM_DISK_SIZE            — default 10GB

set -euo pipefail

# ── easyenclave image family ──────────────────────────────────────────────
#   easyenclave-staging → rolling main, rotates on every push (5 kept)
#   easyenclave-stable  → v* tags, kept forever
EE_IMAGE_FAMILY="${EE_IMAGE_FAMILY:-easyenclave-staging}"
EE_IMAGE_PROJECT="${EE_IMAGE_PROJECT:-easyenclave}"
DD_RELEASE_TAG="${DD_RELEASE_TAG:-latest}"

VM_NAME="dd-${DD_ENV}-$(date +%s)"
VM_MACHINE_TYPE="${VM_MACHINE_TYPE:-c3-standard-4}"
VM_DISK_SIZE="${VM_DISK_SIZE:-10GB}"

if [ -z "${DD_HOSTNAME:-}" ]; then
  if [ "${DD_ENV}" = "production" ]; then
    DD_HOSTNAME="app.${DD_DOMAIN}"
  else
    DD_HOSTNAME="app-staging.${DD_DOMAIN}"
  fi
fi
DD_GITHUB_CLIENT_ID="${DD_GITHUB_CLIENT_ID:-}"
DD_GITHUB_CLIENT_SECRET="${DD_GITHUB_CLIENT_SECRET:-}"
DD_GITHUB_CALLBACK_URL="${DD_GITHUB_CALLBACK_URL:-https://${DD_HOSTNAME}/auth/github/callback}"

# Intel Trust Authority — mandatory. DD_ITA_API_KEY must be set in the
# workflow (from secrets.DD_ITA_API_KEY). The CP will refuse to start
# without one. Everything else has a default.
if [ -z "${DD_ITA_API_KEY:-}" ]; then
  echo "DD_ITA_API_KEY is required (configure secrets.DD_ITA_API_KEY)" >&2
  exit 1
fi
DD_ITA_BASE_URL="${DD_ITA_BASE_URL:-https://api.trustauthority.intel.com}"
DD_ITA_JWKS_URL="${DD_ITA_JWKS_URL:-https://portal.trustauthority.intel.com/certs}"
DD_ITA_ISSUER="${DD_ITA_ISSUER:-https://portal.trustauthority.intel.com}"

# ── Build the workload spec ──────────────────────────────────────────────
# Boot workloads come from apps/<name>/workload.{json,json.tmpl}. Same
# file per workload whether this CP runs in prod, staging, or a PR
# preview; only the env-var substitutions differ.
#
#   cloudflared    — fetch-only, puts the binary on PATH for DD to spawn.
#   dd-management  — devopsdefender in DD_MODE=management (CP + dashboard).
#
# Empty ${DD_GITHUB_CLIENT_ID} etc produce empty "KEY=" strings; the
# bake helper strips those so the resulting spec matches the old
# `if $gh_client_id == "" then [] else [...]` conditional.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
# shellcheck source=./workloads.sh
source "$SCRIPT_DIR/workloads.sh"
EE_BOOT_WORKLOADS=$(
  DD_RELEASE_TAG="$DD_RELEASE_TAG" \
  CLOUDFLARE_API_TOKEN="$CLOUDFLARE_API_TOKEN" \
  CLOUDFLARE_ACCOUNT_ID="$CLOUDFLARE_ACCOUNT_ID" \
  CLOUDFLARE_ZONE_ID="$CLOUDFLARE_ZONE_ID" \
  DD_DOMAIN="$DD_DOMAIN" \
  DD_HOSTNAME="$DD_HOSTNAME" \
  DD_ENV="$DD_ENV" \
  DD_GITHUB_CLIENT_ID="$DD_GITHUB_CLIENT_ID" \
  DD_GITHUB_CLIENT_SECRET="$DD_GITHUB_CLIENT_SECRET" \
  DD_GITHUB_CALLBACK_URL="$DD_GITHUB_CALLBACK_URL" \
  DD_ITA_API_KEY="$DD_ITA_API_KEY" \
  DD_ITA_BASE_URL="$DD_ITA_BASE_URL" \
  DD_ITA_JWKS_URL="$DD_ITA_JWKS_URL" \
  DD_ITA_ISSUER="$DD_ITA_ISSUER" \
  join \
    "$REPO_ROOT/apps/cloudflared/workload.json" \
    "$REPO_ROOT/apps/dd-management/workload.json.tmpl"
)
# ollama + openclaw are NOT baked into the CP preview. EE's tmpfs
# /var/lib/easyenclave is too small for the 900 MB container image,
# and attaching a scratch PD here would duplicate what the local
# dd-local-preview VM already provides via its vdc ext4 disk. The
# preview CP stays slim; the ollama+openclaw demo registers from
# dd-local-preview (scripts/local-agents.sh).

# ── Wrap into ee-config ───────────────────────────────────────────────────
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
echo "  dd release: $DD_RELEASE_TAG"
echo "  workload: dd management"
