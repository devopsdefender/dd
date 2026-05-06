#!/usr/bin/env bash
# dd-relaunch-cp.sh — destroy and recreate a local TDX CP VM.
#
# Invoked over SSH by .github/actions/relaunch-cp during the
# `target: ssh` branch of deploy-cp.yml. Mirrors dd-relaunch.sh (the
# agent-side version) — pulls the PR's apps/_infra tree, tears down
# the existing dd-local-{env}-cp VM, runs local-cp.sh to redefine,
# and starts it.
#
#   dd-relaunch-cp.sh <env> <hostname> [ref] [release-tag]
#
# Required env (SSH'd-in from CI secrets):
#   CLOUDFLARE_API_TOKEN, CLOUDFLARE_ACCOUNT_ID, CLOUDFLARE_ZONE_ID
#   DD_ACCESS_ADMIN_EMAIL
#   DD_ITA_API_KEY
#
# DD_RELEASE_TAG (optional) — passed positionally as $4.

set -euo pipefail
export LIBVIRT_DEFAULT_URI="${LIBVIRT_DEFAULT_URI:-qemu:///system}"

ENV_LABEL="${1?usage: dd-relaunch-cp.sh <env> <hostname> [ref] [release-tag]}"
HOSTNAME="${2?hostname required}"
REF="${3:-main}"
export DD_RELEASE_TAG="${4:-${DD_RELEASE_TAG:-latest}}"

: "${CLOUDFLARE_API_TOKEN?}"
: "${CLOUDFLARE_ACCOUNT_ID?}"
: "${CLOUDFLARE_ZONE_ID?}"
: "${DD_ACCESS_ADMIN_EMAIL?}"
: "${DD_ITA_API_KEY?}"

cd "${DD_REPO_ROOT:-/home/tdx2/src/dd}"

# Refresh apps/ from the caller's ref. Limited checkout so unrelated
# dirty state doesn't block the deploy. Matches the agent path.
git fetch --quiet origin "$REF"
git checkout --quiet "origin/$REF" -- apps/
echo "dd-relaunch-cp: refreshed apps/ from origin/$REF"

# Sync the libvirt base qcow2 from the easyenclave-mini release channel
# for this env. `production` tracks `stable` (v*); anything else
# (pr-N, dev) tracks `staging`. `DD_EE_TAG` overrides the channel
# default for pre-flight-testing a candidate release.
# shellcheck source=./ee-sync.sh
. ./apps/_infra/ee-sync.sh
case "$ENV_LABEL" in
  production) export DD_EE_CHANNEL="${DD_EE_CHANNEL:-stable}"  ;;
  *)          export DD_EE_CHANNEL="${DD_EE_CHANNEL:-staging}" ;;
esac
sync_base /var/lib/libvirt/images/easyenclave-local.qcow2
ensure_base_domain /var/lib/libvirt/images/easyenclave-local.qcow2 easyenclave-local

VM="dd-local-$ENV_LABEL-cp"

./apps/_infra/local-cp.sh "$ENV_LABEL" "$HOSTNAME"
virsh start "$VM"
echo "relaunched $VM against https://$HOSTNAME"
