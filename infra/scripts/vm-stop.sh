#!/usr/bin/env bash
# Stop a libvirt-managed VM by name.
# Usage: ./vm-stop.sh <vm-name> [--clean]
set -euo pipefail

VM_DIR="/var/lib/devopsdefender/vms"
CLEAN=false

VM_NAME="${1:-}"
shift || true

while [[ $# -gt 0 ]]; do
  case "$1" in
    --clean) CLEAN=true; shift ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

if [ -z "$VM_NAME" ]; then
  echo "Usage: $0 <vm-name> [--clean]" >&2
  exit 1
fi

VM_WORK_DIR="${VM_DIR}/${VM_NAME}"

command -v virsh >/dev/null 2>&1 || {
  echo "Error: virsh is required" >&2
  exit 1
}

if ! virsh dominfo "$VM_NAME" >/dev/null 2>&1; then
  echo "No libvirt domain found for VM '${VM_NAME}'" >&2
  exit 1
fi

STATE="$(virsh domstate "$VM_NAME" | tr -d '\r' | xargs)"
echo "==> Stopping VM '${VM_NAME}' (state: ${STATE})"

if [ "$STATE" = "running" ] || [ "$STATE" = "paused" ] || [ "$STATE" = "in shutdown" ]; then
  virsh shutdown "$VM_NAME" >/dev/null || true
  for _ in $(seq 1 30); do
    STATE="$(virsh domstate "$VM_NAME" | tr -d '\r' | xargs)"
    if [ "$STATE" = "shut off" ]; then
      break
    fi
    sleep 1
  done
fi

STATE="$(virsh domstate "$VM_NAME" | tr -d '\r' | xargs)"
if [ "$STATE" != "shut off" ]; then
  echo "    Force destroying domain ${VM_NAME}"
  virsh destroy "$VM_NAME" >/dev/null || true
fi

virsh undefine "$VM_NAME" --nvram >/dev/null 2>&1 || virsh undefine "$VM_NAME" >/dev/null
echo "==> VM '${VM_NAME}' undefined"

if [ "$CLEAN" = true ]; then
  echo "==> Cleaning up VM directory: ${VM_WORK_DIR}"
  rm -rf "$VM_WORK_DIR"
fi
