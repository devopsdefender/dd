#!/usr/bin/env bash
# dd-dogfood.sh — define/start the manually managed production dogfood agent.
#
# This is intentionally outside the Release cascade. Production deploys
# recreate dd-local-prod as a canary, but they must not destroy the operator's
# long-lived Codex/Podman development VM. Re-run this script only when you
# explicitly want to redefine/restart dd-local-dogfood; its workload disk is
# preserved across runs.

set -euo pipefail
export LIBVIRT_DEFAULT_URI="${LIBVIRT_DEFAULT_URI:-qemu:///system}"

CP="${1:-https://app.devopsdefender.com}"
: "${DD_ITA_API_KEY?DD_ITA_API_KEY must be set}"
: "${EE_OWNER?EE_OWNER must be set to a GitHub login or owner/repo path}"
: "${DD_AUTH_COOKIE_SECRET?DD_AUTH_COOKIE_SECRET must be set}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT"

# Dogfood is an operator VM, not CI. Prefer the already-synced local EE base
# when present so a manual dogfood refresh does not depend on channel metadata
# moving in easyenclave/easyenclave-mini. Explicit DD_EE_TAG still wins, and
# DD_EE_CHANNEL remains available for deliberate channel refreshes.
if [ -z "${DD_EE_TAG:-}" ] && [ -r /var/lib/libvirt/images/easyenclave-local.qcow2.tag ]; then
  export DD_EE_TAG
  DD_EE_TAG="$(cat /var/lib/libvirt/images/easyenclave-local.qcow2.tag)"
fi
export DD_EE_CHANNEL="${DD_EE_CHANNEL:-staging}"
export DD_RELEASE_TAG="${DD_RELEASE_TAG:-latest}"
export DD_AUTH_BROKER_URL="${DD_AUTH_BROKER_URL:-https://app.devopsdefender.com}"
export DD_AUTH_COOKIE_DOMAIN="${DD_AUTH_COOKIE_DOMAIN:-.devopsdefender.com}"

# shellcheck source=./ee-sync.sh
. ./apps/_infra/ee-sync.sh
sync_base /var/lib/libvirt/images/easyenclave-local.qcow2
ensure_base_domain /var/lib/libvirt/images/easyenclave-local.qcow2 easyenclave-local

./apps/_infra/local-agents.sh "" "" "" "$CP"
virsh start dd-local-dogfood

echo "dogfood agent started against $CP"
echo "console: virsh console dd-local-dogfood"
