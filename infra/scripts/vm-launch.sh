#!/usr/bin/env bash
# Launch a QEMU/KVM VM from a baked qcow2 image.
#
# Usage:
#   ./vm-launch.sh --image /path/to/base.qcow2 --name dd-cp-staging \
#     --config /path/to/config.json --memory 8G --cpus 4 \
#     --port-forward 8080:8080
set -euo pipefail

IMAGE=""
VM_NAME=""
CONFIG_FILE=""
MEMORY="4G"
CPUS="2"
PORT_FORWARDS=()
VFIO_DEVICE=""
TDX="false"
VM_DIR="/var/lib/devopsdefender/vms"
CONFIG_MODE="agent"  # agent or control-plane

usage() {
  cat <<EOF
Usage: $0 [options]
  --image PATH          Base qcow2 image (required)
  --name NAME           VM name (required)
  --config PATH         JSON config file to inject via cloud-init (required)
  --config-mode MODE    Config target: agent (default) or control-plane
  --memory SIZE         VM memory (default: 4G)
  --cpus N              VM CPUs (default: 2)
  --port-forward H:G    Forward host port H to guest port G (repeatable)
  --vfio-device ADDR    PCI device to pass through via VFIO (e.g. 0d:00.0)
  --tdx                 Launch as Intel TDX confidential VM (requires TDX host)
EOF
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --image) IMAGE="$2"; shift 2 ;;
    --name) VM_NAME="$2"; shift 2 ;;
    --config) CONFIG_FILE="$2"; shift 2 ;;
    --config-mode) CONFIG_MODE="$2"; shift 2 ;;
    --memory) MEMORY="$2"; shift 2 ;;
    --cpus) CPUS="$2"; shift 2 ;;
    --port-forward) PORT_FORWARDS+=("$2"); shift 2 ;;
    --vfio-device) VFIO_DEVICE="$2"; shift 2 ;;
    --tdx) TDX="true"; shift ;;
    --help|-h) usage ;;
    *) echo "Unknown option: $1" >&2; usage ;;
  esac
done

if [ -z "$IMAGE" ] || [ -z "$VM_NAME" ] || [ -z "$CONFIG_FILE" ]; then
  echo "Error: --image, --name, and --config are required" >&2
  usage
fi

if [ ! -f "$IMAGE" ]; then
  echo "Error: base image not found: $IMAGE" >&2
  exit 1
fi

if [ ! -f "$CONFIG_FILE" ]; then
  echo "Error: config file not found: $CONFIG_FILE" >&2
  exit 1
fi

# Create VM working directory.
VM_WORK_DIR="${VM_DIR}/${VM_NAME}"
mkdir -p "$VM_WORK_DIR"

# Create copy-on-write overlay from base image.
OVERLAY="${VM_WORK_DIR}/${VM_NAME}.qcow2"
if [ ! -f "$OVERLAY" ]; then
  echo "==> Creating overlay image from base"
  qemu-img create -b "$(realpath "$IMAGE")" -F qcow2 -f qcow2 "$OVERLAY"
fi

# Determine config target path inside cloud-init.
if [ "$CONFIG_MODE" = "control-plane" ]; then
  CONFIG_DEST="/etc/devopsdefender/control-plane.json"
  SYSTEMD_ENABLE="devopsdefender-control-plane.service"
  SYSTEMD_DISABLE="devopsdefender-agent.service"
else
  CONFIG_DEST="/etc/devopsdefender/agent.json"
  SYSTEMD_ENABLE="devopsdefender-agent.service"
  SYSTEMD_DISABLE="devopsdefender-control-plane.service"
fi

# Generate cloud-init ISO for config injection.
CIDATA_DIR="${VM_WORK_DIR}/cidata"
mkdir -p "$CIDATA_DIR"

# Escape JSON for embedding in cloud-init write_files.
CONFIG_CONTENT="$(cat "$CONFIG_FILE")"

cat > "${CIDATA_DIR}/user-data" <<USERDATA
#cloud-config
write_files:
  - path: ${CONFIG_DEST}
    permissions: '0600'
    content: |
$(echo "$CONFIG_CONTENT" | sed 's/^/      /')

runcmd:
  - systemctl daemon-reload
  - systemctl disable --now ${SYSTEMD_DISABLE} || true
  - systemctl enable --now ${SYSTEMD_ENABLE}
USERDATA

cat > "${CIDATA_DIR}/meta-data" <<METADATA
instance-id: ${VM_NAME}
local-hostname: ${VM_NAME}
METADATA

CIDATA_ISO="${VM_WORK_DIR}/cidata.iso"
if command -v cloud-localds &>/dev/null; then
  cloud-localds "$CIDATA_ISO" "${CIDATA_DIR}/user-data" "${CIDATA_DIR}/meta-data"
elif command -v genisoimage &>/dev/null; then
  genisoimage -output "$CIDATA_ISO" -volid cidata -joliet -rock \
    "${CIDATA_DIR}/user-data" "${CIDATA_DIR}/meta-data"
else
  echo "Error: need cloud-localds or genisoimage to create cloud-init ISO" >&2
  exit 1
fi

# Build QEMU command.
QEMU_ARGS=(
  qemu-system-x86_64
  -cpu host
  -m "$MEMORY"
  -smp "$CPUS"
  -display none
  -daemonize
  -pidfile "${VM_WORK_DIR}/${VM_NAME}.pid"
)

if [ "$TDX" = "true" ]; then
  # TDX confidential VM: requires TDVF firmware, vsock for quote generation.
  # Use -accel kvm (not -enable-kvm) — required for TDX machine type.
  TDVF_FIRMWARE="/usr/share/ovmf/OVMF.fd"
  if [ ! -f "$TDVF_FIRMWARE" ]; then
    echo "Error: TDVF firmware not found: $TDVF_FIRMWARE" >&2
    exit 1
  fi
  QEMU_ARGS+=(
    -accel kvm
    -object '{"qom-type":"tdx-guest","id":"tdx","quote-generation-socket":{"type":"vsock","cid":"2","port":"4050"}}'
    -machine q35,kernel_irqchip=split,confidential-guest-support=tdx,hpet=off
    -bios "$TDVF_FIRMWARE"
    -device vhost-vsock-pci,guest-cid=3
  )
  echo "    TDX: enabled (confidential VM)"
else
  QEMU_ARGS+=(-accel kvm -machine q35)
fi

QEMU_ARGS+=(
  -drive "file=${OVERLAY},format=qcow2,if=virtio"
  -drive "file=${CIDATA_ISO},format=raw,if=virtio,readonly=on"
  -serial "file:${VM_WORK_DIR}/${VM_NAME}.log"
)

# Pass through VFIO device (GPU) if requested.
if [ -n "$VFIO_DEVICE" ]; then
  QEMU_ARGS+=(-device "vfio-pci,host=${VFIO_DEVICE}")
fi

# Build port forwarding netdev.
HOSTFWD_ARGS=""
for pf in "${PORT_FORWARDS[@]+"${PORT_FORWARDS[@]}"}"; do
  host_port="${pf%%:*}"
  guest_port="${pf##*:}"
  HOSTFWD_ARGS="${HOSTFWD_ARGS},hostfwd=tcp::${host_port}-:${guest_port}"
done

# Always forward SSH on a high port for debugging.
SSH_PORT=$((10000 + RANDOM % 50000))
HOSTFWD_ARGS="${HOSTFWD_ARGS},hostfwd=tcp::${SSH_PORT}-:22"

QEMU_ARGS+=(-netdev "user,id=net0${HOSTFWD_ARGS}" -device "virtio-net-pci,netdev=net0")

echo "==> Launching VM: ${VM_NAME}"
echo "    Memory: ${MEMORY}, CPUs: ${CPUS}"
echo "    Overlay: ${OVERLAY}"
echo "    Config mode: ${CONFIG_MODE}"
echo "    TDX: ${TDX}"
echo "    SSH port: ${SSH_PORT}"
if [ -n "$VFIO_DEVICE" ]; then
  echo "    VFIO device: ${VFIO_DEVICE}"
fi
for pf in "${PORT_FORWARDS[@]+"${PORT_FORWARDS[@]}"}"; do
  echo "    Port forward: ${pf}"
done

"${QEMU_ARGS[@]}" </dev/null

PID_FILE="${VM_WORK_DIR}/${VM_NAME}.pid"
if [ -f "$PID_FILE" ]; then
  PID="$(cat "$PID_FILE")"
  echo "==> VM started with PID ${PID}"
  echo "    PID file: ${PID_FILE}"
  echo "    SSH: ssh -p ${SSH_PORT} ubuntu@localhost"
else
  echo "Warning: PID file not created, VM may not have started" >&2
fi

# Write metadata for vm-status.sh / vm-stop.sh.
cat > "${VM_WORK_DIR}/vm-info.json" <<INFO
{
  "name": "${VM_NAME}",
  "pid_file": "${PID_FILE}",
  "overlay": "${OVERLAY}",
  "config_mode": "${CONFIG_MODE}",
  "memory": "${MEMORY}",
  "cpus": "${CPUS}",
  "ssh_port": ${SSH_PORT},
  "port_forwards": "$(IFS=,; echo "${PORT_FORWARDS[*]+"${PORT_FORWARDS[*]}"}")",
  "vfio_device": "${VFIO_DEVICE}",
  "tdx": ${TDX},
  "started_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
INFO
