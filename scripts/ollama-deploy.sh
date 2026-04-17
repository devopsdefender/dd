#!/usr/bin/env bash
# ollama-deploy.sh — deploy ollama into one local agent VM, pull a
# model, and run a sample query to confirm inference works.
#
# Invoked by dd-relaunch.sh after `virsh start` succeeds. Requires
# DD_PAT and DD_ITA_API_KEY in env (same ones the relaunch uses).
#
#   ollama-deploy.sh <kind>
#     kind: prod | preview
#
# Model selection:
#   prod    — llama3.1:8b (~4.7 GB) runs on the H100.
#   preview — qwen2.5:0.5b (~400 MB) runs on CPU.
#
# End-to-end:
#   1. Poll the CP's /api/agents for our vm_name; pick up its hostname.
#   2. POST ollama workload spec to https://{hostname}/deploy.
#   3. Wait until ollama listens on 127.0.0.1:11434 (polled via /exec).
#   4. ollama pull <model> via /exec.
#   5. ollama query via /exec; echo the response.

set -euo pipefail

KIND="${1?usage: ollama-deploy.sh <prod|preview>}"
: "${DD_PAT?}" "${DD_ITA_API_KEY?}"

case "$KIND" in
  prod)    MODEL="llama3.1:8b"    CP_URL="https://app.devopsdefender.com" ;;
  preview) MODEL="qwen2.5:0.5b"   CP_URL="${CP_URL:?need CP_URL for preview}" ;;
  *) echo "unknown kind: $KIND" >&2; exit 2 ;;
esac

VM_NAME="dd-local-$KIND"
AUTH=(-H "Authorization: Bearer $DD_PAT")

echo "== ollama-deploy $VM_NAME (model=$MODEL, cp=$CP_URL) =="

# 1. Discover agent hostname via CP's /api/agents. Prefer healthy
# entries; the store can briefly hold stale duplicates from a prior
# relaunch whose tunnel is already gone.
agent_host=""
for i in $(seq 1 60); do
  agent_host=$(curl -fsS "${AUTH[@]}" "$CP_URL/api/agents" 2>/dev/null \
    | jq -r --arg vm "$VM_NAME" '
        [.[] | select(.vm_name==$vm and .status=="healthy")]
        | sort_by(.agent_id) | reverse | .[0].hostname // empty' 2>/dev/null || true)
  if [ -n "$agent_host" ] && [ "$agent_host" != "null" ]; then
    break
  fi
  echo "  waiting for healthy $VM_NAME in CP fleet... ($i/60)"
  sleep 10
done
if [ -z "$agent_host" ] || [ "$agent_host" = "null" ]; then
  echo "ERROR: $VM_NAME never appeared in CP fleet" >&2
  exit 1
fi
echo "  agent: https://$agent_host"

agent() { curl -fsS --max-time 120 "${AUTH[@]}" "https://$agent_host$1" "${@:2}"; }

# 2. Deploy ollama workload. EE returns a workload id.
SPEC=$(jq -c -n '{
  app_name:"ollama",
  github_release:{repo:"ollama/ollama",asset:"ollama-linux-amd64",rename:"ollama"},
  cmd:["ollama","serve"],
  env:[
    "OLLAMA_HOST=127.0.0.1:11434",
    "OLLAMA_MODELS=/var/lib/easyenclave/ollama"
  ]
}')
echo "  POST /deploy..."
deploy_resp=$(agent /deploy -H 'Content-Type: application/json' -d "$SPEC")
echo "  deploy: $deploy_resp"

# 3. Wait for ollama to listen. Use /exec to probe inside the guest.
echo "  waiting for ollama on 127.0.0.1:11434..."
for i in $(seq 1 60); do
  resp=$(agent /exec -H 'Content-Type: application/json' \
    -d '{"cmd":["/bin/busybox","sh","-c","curl -fsS http://127.0.0.1:11434/api/tags && echo OK || echo NO"],"timeout_secs":10}' \
    2>/dev/null || true)
  if echo "$resp" | grep -q OK; then
    echo "  ollama responding"
    break
  fi
  sleep 5
done

# 4. Pull the model. Ollama streams progress; we just wait for completion.
echo "  pulling $MODEL (this can take a few minutes)..."
pull_resp=$(agent /exec -H 'Content-Type: application/json' \
  -d "$(jq -c -n --arg m "$MODEL" '{
    cmd:["/var/lib/easyenclave/bin/ollama","pull",$m],
    timeout_secs:900
  }')")
echo "  pull: $(echo "$pull_resp" | jq -r '.stdout // "(no stdout)"' | tail -5)"

# 5. Sample query.
echo "  querying $MODEL..."
query_resp=$(agent /exec -H 'Content-Type: application/json' \
  -d "$(jq -c -n --arg m "$MODEL" '{
    cmd:["/bin/busybox","sh","-c",
      "curl -fsS http://127.0.0.1:11434/api/generate -H '"'"'Content-Type: application/json'"'"' -d "
        + ("\"{\\\"model\\\":\\\"" + $m + "\\\",\\\"prompt\\\":\\\"write one sentence about trusted execution environments\\\",\\\"stream\\\":false}\"")
    ],
    timeout_secs:120
  }')")
response=$(echo "$query_resp" | jq -r '.stdout // "{}"' | jq -r '.response // ""')
if [ -z "$response" ]; then
  echo "ERROR: empty inference response"
  echo "raw: $query_resp" | head -c 500
  exit 1
fi
echo
echo "=== $MODEL says ==="
echo "$response"
echo "==================="
