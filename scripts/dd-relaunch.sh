#!/usr/bin/env bash
# dd-relaunch.sh — destroy and recreate one local TDX agent VM.
#
# Invoked over SSH by .github/workflows/local-agents.yml after a
# Release / Production Deploy succeeds. Pulls the current main of dd
# (so this script and local-agents.sh are always the latest), tears
# down the existing VM + overlay, runs scripts/local-agents.sh to
# redefine, and starts the VM.
#
#   dd-relaunch.sh prod    https://app.devopsdefender.com
#   dd-relaunch.sh preview https://pr-N.devopsdefender.com
#
# DD_PAT and DD_ITA_API_KEY must be set in the environment.

set -euo pipefail

KIND="${1?usage: dd-relaunch.sh <prod|preview> <cp-url>}"
CP="${2?cp url required}"
: "${DD_PAT?DD_PAT must be set}"
: "${DD_ITA_API_KEY?DD_ITA_API_KEY must be set}"

case "$KIND" in
  prod|preview) ;;
  *) echo "unknown kind: $KIND (want prod|preview)" >&2; exit 2 ;;
esac

cd /home/tdx2/src/dd

# Pull the latest scripts. Limit the checkout to the two scripts so a
# dirty working tree elsewhere doesn't block the deploy. The relaunch
# script itself has already been read into memory by bash, so the
# update takes effect on the *next* invocation.
git fetch --quiet origin main
git checkout --quiet origin/main -- scripts/local-agents.sh scripts/dd-relaunch.sh

vm="dd-local-$KIND"
overlay="/var/lib/libvirt/images/$vm.qcow2"

virsh destroy "$vm" 2>/dev/null || true
virsh undefine "$vm" --managed-save --snapshots-metadata 2>/dev/null || true
rm -f "$overlay"

# Redefine via local-agents.sh; "" skips the other slot.
case "$KIND" in
  prod)    ./scripts/local-agents.sh ""  "$CP" ;;
  preview) ./scripts/local-agents.sh "$CP" "" ;;
esac

virsh start "$vm"
echo "relaunched $vm against $CP"

# Workload lifecycle (ollama deploy/pull/query) runs in a separate
# workflow step over HTTPS — it doesn't need to hold this SSH
# session for the minutes it can take.
