#!/usr/bin/env bash
# redeploy-workload.sh — POST one baked workload spec to a live agent's
# /deploy endpoint. Handy for iterating on apps/<name>/workload.json
# without rebuilding the whole config.iso + restarting the VM.
#
# Usage:
#   redeploy-workload.sh <cp_url> <agent_vm_name> <app_path>
#
# Example:
#   DD_PAT=$(gh auth token) \
#     ./scripts/redeploy-workload.sh \
#       https://app.devopsdefender.com \
#       dd-local-prod \
#       apps/openclaw/workload.json.tmpl
#
# Requires DD_PAT in env. Template envs (MODEL, DD_CP_URL, …) must
# also be exported if the referenced workload file is a .tmpl.

set -euo pipefail

CP_URL="${1?usage: redeploy-workload.sh <cp_url> <vm_name> <app_path>}"
VM_NAME="${2?vm_name required (e.g. dd-local-prod)}"
APP_PATH="${3?app_path required (e.g. apps/openclaw/workload.json.tmpl)}"
: "${DD_PAT?set DD_PAT (e.g. DD_PAT=\$(gh auth token))}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./workloads.sh
source "$SCRIPT_DIR/workloads.sh"

AUTH=(-H "Authorization: Bearer $DD_PAT")

# Discover the agent's tunnel hostname via CP's fleet API.
agent_host=$(
  curl -fsS "${AUTH[@]}" "$CP_URL/api/agents" 2>/dev/null \
    | jq -r --arg vm "$VM_NAME" '
        [.[] | select(.vm_name==$vm and .status=="healthy")]
        | sort_by(.last_seen) | reverse | .[0].hostname // empty'
)
if [ -z "$agent_host" ] || [ "$agent_host" = "null" ]; then
  echo "ERROR: no healthy $VM_NAME in $CP_URL/api/agents" >&2
  exit 1
fi
echo "agent: https://$agent_host"

spec=$(bake "$APP_PATH")
echo "redeploying $(echo "$spec" | jq -r .app_name)..."
curl -fsS --max-time 60 "${AUTH[@]}" \
  "https://$agent_host/deploy" \
  -H 'Content-Type: application/json' \
  -d "$spec" | jq -c .
