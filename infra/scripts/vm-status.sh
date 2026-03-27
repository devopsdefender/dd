#!/usr/bin/env bash
# List DevOps Defender VMs managed through libvirt.
set -euo pipefail

VM_DIR="/var/lib/devopsdefender/vms"

command -v virsh >/dev/null 2>&1 || {
  echo "Error: virsh is required" >&2
  exit 1
}

if [ ! -d "$VM_DIR" ]; then
  echo "No VMs found (${VM_DIR} does not exist)"
  exit 0
fi

printf "%-25s %-12s %-6s %-6s %-12s %s\n" \
  "NAME" "STATE" "MEM" "CPUS" "NETWORK" "STARTED"
printf "%s\n" "$(printf '%.0s-' {1..90})"

found=0
for vm_dir in "${VM_DIR}"/*/; do
  [ -d "$vm_dir" ] || continue

  info_file="${vm_dir}/vm-info.json"
  [ -f "$info_file" ] || continue

  found=1
  name="$(jq -r '.name // "unknown"' "$info_file")"
  memory="$(jq -r '.memory // "?"' "$info_file")"
  cpus="$(jq -r '.cpus // "?"' "$info_file")"
  network="$(jq -r '.libvirt_network // "?"' "$info_file")"
  started="$(jq -r '.started_at // "?"' "$info_file")"

  state="undefined"
  if virsh dominfo "$name" >/dev/null 2>&1; then
    state="$(virsh domstate "$name" | tr -d '\r' | xargs)"
  fi

  printf "%-25s %-12s %-6s %-6s %-12s %s\n" \
    "$name" "$state" "$memory" "$cpus" "$network" "$started"
done

if [ "$found" -eq 0 ]; then
  echo "No VMs found"
  exit 0
fi

echo
echo "virsh list --all"
virsh list --all
