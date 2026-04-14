#!/usr/bin/env bash
# test-installer.sh — copy install-agent.sh to a remote target via SSH
# and run it twice: once registering against staging, once against
# production. Verify both agents come up by polling the respective
# fleet view's /federate endpoint.
#
# Usage:
#   test-installer.sh <ssh_target>
#
# Example:
#   test-installer.sh tdx2@localhost

set -euo pipefail

SSH_TARGET="${1:?Usage: $0 <ssh_target> (e.g. tdx2@localhost)}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INSTALLER="$SCRIPT_DIR/install-agent.sh"

[[ -f "$INSTALLER" ]] || { echo "$INSTALLER missing" >&2; exit 1; }

OWNER="${OWNER:-devopsdefender}"
HOST_TAG="$(echo "$SSH_TARGET" | tr '@.' '--' | tr -dc 'a-z0-9-')"
STAGING_NAME="${HOST_TAG}-staging-$(tr -dc a-z0-9 </dev/urandom | head -c 4)"
PRODUCTION_NAME="${HOST_TAG}-prod-$(tr -dc a-z0-9 </dev/urandom | head -c 4)"

ssh_run() {
    # Stream stdout, surface non-zero exit.
    ssh -o StrictHostKeyChecking=accept-new -o BatchMode=yes "$SSH_TARGET" "$@"
}

echo "==> SSH probe: $SSH_TARGET"
ssh_run 'echo OK; uname -a'

echo "==> copying installer"
scp -q -o StrictHostKeyChecking=accept-new "$INSTALLER" "$SSH_TARGET:/tmp/install-agent.sh"

run_installer() {
    local register_url="$1" vm_name="$2"
    echo
    echo "════════════════════════════════════════════════════════════════"
    echo "==> install-agent: vm=$vm_name register=$register_url"
    echo "════════════════════════════════════════════════════════════════"
    ssh_run "sudo bash /tmp/install-agent.sh \
        --register-url '$register_url' \
        --owner '$OWNER' \
        --vm-name '$vm_name'"
}

run_installer "wss://app-staging.devopsdefender.com/register" "$STAGING_NAME"
run_installer "wss://app.devopsdefender.com/register"          "$PRODUCTION_NAME"

# ── Verify registration ─────────────────────────────────────────────────
# /federate is unauthenticated and lists agents the dd-web collector
# has scraped. Wait up to 3 min for each to appear.

verify_registered() {
    local fleet_url="$1" vm_name="$2"
    echo
    echo "==> verifying $vm_name registered at $fleet_url"
    for i in $(seq 1 36); do
        body=$(curl -fsSL "$fleet_url/federate" 2>/dev/null || echo "")
        if echo "$body" | grep -q "\"vm_name\":\"$vm_name\""; then
            echo "    ✓ found after ${i}×5s"
            return 0
        fi
        sleep 5
    done
    echo "    ✗ NOT found within 3min" >&2
    return 1
}

STAGING_OK=1
PROD_OK=1
verify_registered "https://app-staging.devopsdefender.com" "$STAGING_NAME" || STAGING_OK=0
verify_registered "https://app.devopsdefender.com"          "$PRODUCTION_NAME" || PROD_OK=0

echo
echo "════════════════════════════════════════════════════════════════"
echo "Summary"
echo "════════════════════════════════════════════════════════════════"
echo "  staging agent:     $STAGING_NAME    $([ $STAGING_OK -eq 1 ] && echo ok || echo FAILED)"
echo "  production agent:  $PRODUCTION_NAME $([ $PROD_OK -eq 1 ] && echo ok || echo FAILED)"
echo
echo "Cleanup:"
echo "  ssh $SSH_TARGET sudo systemctl disable --now dd-agent@$STAGING_NAME"
echo "  ssh $SSH_TARGET sudo systemctl disable --now dd-agent@$PRODUCTION_NAME"
echo "  ssh $SSH_TARGET sudo rm -rf /var/lib/dd-agent/$STAGING_NAME /var/lib/dd-agent/$PRODUCTION_NAME"

[[ $STAGING_OK -eq 1 && $PROD_OK -eq 1 ]] || exit 1
