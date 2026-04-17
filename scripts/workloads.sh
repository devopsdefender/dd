#!/usr/bin/env bash
# workloads.sh — shared helpers for assembling EE workload specs.
#
# A DD "workload" is a JSON object with {app_name, github_release,
# cmd, env} that EE's DeployRequest consumes. Each app lives in
# apps/<name>/workload.json (literal) or apps/<name>/workload.json.tmpl
# (with ${VAR} placeholders substituted at bake time from the caller's
# environment).
#
# Public functions:
#   bake <path>           — print one rendered workload to stdout.
#                           Plain .json is emitted as-is; .json.tmpl
#                           gets envsubst + empty-env-entry stripping.
#   join <path> [path…]   — print a JSON array of rendered workloads.
#
# Sourced from scripts/local-agents.sh and scripts/gcp-deploy.sh so
# both scripts share one source of truth for the workload shape.

# Render a single workload file.
# For .json files, passthrough.
# For .json.tmpl files, substitute ${VAR} from the current env, then
# remove any "KEY=" env array entries that ended up with an empty
# value (matches the conditional-include pattern gcp-deploy.sh used
# for DD_GITHUB_CLIENT_ID & co).
bake() {
  local path="$1"
  if [[ "$path" == *.json ]]; then
    jq -c . "$path"
  elif [[ "$path" == *.json.tmpl ]]; then
    envsubst < "$path" \
      | jq -c 'if .env then .env |= map(select(. | test("^[^=]+=.+"))) else . end'
  else
    echo "workloads.sh: unknown workload file type: $path" >&2
    return 1
  fi
}

# Print a JSON array of rendered workloads.
join() {
  local out="["
  local first=1
  for p in "$@"; do
    local rendered
    rendered=$(bake "$p") || return 1
    if [ $first -eq 1 ]; then
      out+="$rendered"
      first=0
    else
      out+=",$rendered"
    fi
  done
  out+="]"
  echo "$out"
}
