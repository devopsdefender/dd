#!/usr/bin/env bash
# Stop a VM by name.
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
PID_FILE="${VM_WORK_DIR}/${VM_NAME}.pid"

if [ ! -f "$PID_FILE" ]; then
  echo "No PID file found for VM '${VM_NAME}' at ${PID_FILE}" >&2
  exit 1
fi

PID="$(cat "$PID_FILE")"

if kill -0 "$PID" 2>/dev/null; then
  echo "==> Stopping VM '${VM_NAME}' (PID ${PID})"
  kill "$PID"

  # Wait for process to exit (up to 30s).
  for _ in $(seq 1 30); do
    if ! kill -0 "$PID" 2>/dev/null; then
      break
    fi
    sleep 1
  done

  # Force kill if still running.
  if kill -0 "$PID" 2>/dev/null; then
    echo "    Force killing PID ${PID}"
    kill -9 "$PID" 2>/dev/null || true
  fi

  echo "==> VM '${VM_NAME}' stopped"
else
  echo "VM '${VM_NAME}' is not running (PID ${PID})"
fi

rm -f "$PID_FILE"

if [ "$CLEAN" = true ]; then
  echo "==> Cleaning up VM directory: ${VM_WORK_DIR}"
  rm -rf "$VM_WORK_DIR"
fi
