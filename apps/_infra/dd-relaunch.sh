#!/usr/bin/env bash
# dd-relaunch.sh — destroy and recreate one local TDX agent VM.
#
# Invoked over SSH by .github/actions/relaunch-agent during a Release
# cascade. Pulls the PR's (or main's) apps/_infra tree so this script
# and local-agents.sh are always the ones the caller authored. Tears
# down the existing VM + overlay, runs local-agents.sh to redefine,
# and starts the VM.
#
#   dd-relaunch.sh prod    https://app.devopsdefender.com    main
#   dd-relaunch.sh preview https://pr-N.devopsdefender.com   feat/some-pr
#
# DD_ITA_API_KEY must be set in the environment. No GitHub PAT — the
# agent authenticates to the CP via ITA attestation at /register and
# uses a CF Access service token (received in the register response)
# for subsequent machine-to-machine calls.

set -euo pipefail

KIND="${1?usage: dd-relaunch.sh <prod|preview> <cp-url> [ref] [release-tag]}"
CP="${2?cp url required}"
REF="${3:-main}"
# DD_RELEASE_TAG optional — defaults to "latest" (prod cascade) but CI
# passes the PR-specific tag for preview so the agent binary matches
# the CP binary (auth protocol, bootstrap shape, etc.).
export DD_RELEASE_TAG="${4:-${DD_RELEASE_TAG:-latest}}"
: "${DD_ITA_API_KEY?DD_ITA_API_KEY must be set}"

case "$KIND" in
  prod|preview) ;;
  *) echo "unknown kind: $KIND (want prod|preview)" >&2; exit 2 ;;
esac

cd /home/tdx2/src/dd

# Refresh the infra scripts + apps/ tree from the caller's ref. Limited
# checkout so a dirty working tree elsewhere doesn't block the deploy.
# This script is already in memory, so the refresh takes effect on the
# *next* invocation.
git fetch --quiet origin "$REF"
git checkout --quiet "origin/$REF" -- apps/
echo "dd-relaunch: refreshed apps/ from origin/$REF"

vm="dd-local-$KIND"
overlay="/var/lib/libvirt/images/$vm.qcow2"

virsh destroy "$vm" 2>/dev/null || true
virsh undefine "$vm" --managed-save --snapshots-metadata 2>/dev/null || true
rm -f "$overlay"

# Redefine via local-agents.sh; "" skips the other slot.
case "$KIND" in
  prod)    ./apps/_infra/local-agents.sh ""  "$CP" ;;
  preview) ./apps/_infra/local-agents.sh "$CP" "" ;;
esac

virsh start "$vm"
echo "relaunched $vm against $CP"
