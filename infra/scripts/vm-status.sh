#!/usr/bin/env bash
# List running DevOps Defender VMs.
# Usage: ./vm-status.sh
set -euo pipefail

VM_DIR="/var/lib/devopsdefender/vms"

if [ ! -d "$VM_DIR" ]; then
  echo "No VMs found (${VM_DIR} does not exist)"
  exit 0
fi

printf "%-25s %-8s %-15s %-6s %-6s %-8s %s\n" \
  "NAME" "PID" "STATUS" "MEM" "CPUS" "SSH" "STARTED"
printf "%s\n" "$(printf '%.0s-' {1..100})"

found=0
for vm_dir in "${VM_DIR}"/*/; do
  [ -d "$vm_dir" ] || continue

  info_file="${vm_dir}/vm-info.json"
  [ -f "$info_file" ] || continue

  found=1
  name="$(jq -r '.name // "unknown"' "$info_file")"
  pid_file="$(jq -r '.pid_file // ""' "$info_file")"
  memory="$(jq -r '.memory // "?"' "$info_file")"
  cpus="$(jq -r '.cpus // "?"' "$info_file")"
  ssh_port="$(jq -r '.ssh_port // "?"' "$info_file")"
  started="$(jq -r '.started_at // "?"' "$info_file")"

  status="stopped"
  pid="-"
  if [ -n "$pid_file" ] && [ -f "$pid_file" ]; then
    pid="$(cat "$pid_file")"
    if kill -0 "$pid" 2>/dev/null; then
      status="running"
    else
      status="dead"
    fi
  fi

  printf "%-25s %-8s %-15s %-6s %-6s %-8s %s\n" \
    "$name" "$pid" "$status" "$memory" "$cpus" "$ssh_port" "$started"
done

if [ "$found" -eq 0 ]; then
  echo "No VMs found"
fi
