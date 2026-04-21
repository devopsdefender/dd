#!/bin/bash
# run-local-vm.sh — boot a local EasyEnclave VM on this baremetal host
# with a persistent workload disk, sized per the DD capacity rule.
#
# Usage:
#   bash scripts/run-local-vm.sh NAME AGENT_ENV [--gpu]
#
# Arguments:
#   NAME       — VM identifier (e.g. "dev-cp-1", "vllm-prod"). Becomes
#                the dir under /data/easyenclave/vms/ that holds the
#                persistent qcow2 workload disk.
#   AGENT_ENV  — path to an agent.env file (EE_* env vars, one per
#                line). Delivered to the VM as an iso9660 config disk.
#
# Flags:
#   --gpu      — pass through the host's H100 (PCI 0d:00.0) and size
#                the VM per the GPU rule (RAM = VRAM+4, disk = 10×(RAM+VRAM)).
#                Without it, general-agent shape.
#
# Shapes (this host: H100 94 GB, 243 GB RAM, 3.3 TB /data free):
#
#   general (default):  16 GB RAM, 4 vCPU, 160 GB disk.
#                        Matches GCE c3-standard-4 — drop-in preview shape.
#
#   --gpu:              98 GB RAM, 16 vCPU, 1.92 TB disk, H100 passthrough.
#                        Follows the 10×(RAM+VRAM) sizing rule.
#
# The qcow2 is created once (pre-formatted ext4 so EE can mount it at
# /var/lib/easyenclave/ollama as /dev/vdc) and reused across boots, so
# container images and model weights survive reboots.
#
# Default boot is non-TDX — the host has kvm_intel.tdx=Y but the exact
# qemu/OVMF combo shipped by the distro here trips on pflash readonly
# memory under TDX. Set DD_TDX=1 if you have a working local TDVF and
# want attestation to succeed.

set -euo pipefail

# ── Args ────────────────────────────────────────────────────────────
if [ $# -lt 2 ]; then
    sed -n '3,20p' "$0" | sed 's/^# \?//'
    exit 2
fi
NAME="$1"
ENV_FILE="$2"
shift 2

GPU=false
for arg in "$@"; do
    case "$arg" in
        --gpu) GPU=true ;;
        *)     echo "unknown arg: $arg" >&2; exit 2 ;;
    esac
done

[ -f "$ENV_FILE" ] || { echo "agent.env not found: $ENV_FILE" >&2; exit 1; }

# ── Shape ───────────────────────────────────────────────────────────
if $GPU; then
    MEM=98G
    VCPU=16
    DISK_GB=1920  # 10 × (RAM 98 + VRAM 94)
    GPU_ARGS="-device vfio-pci,host=0000:0d:00.0"
    echo "Shape: GPU (H100 passthrough) — RAM=$MEM vCPU=$VCPU disk=${DISK_GB}G"
else
    MEM=16G
    VCPU=4
    DISK_GB=160   # 10 × RAM 16
    GPU_ARGS=""
    echo "Shape: general — RAM=$MEM vCPU=$VCPU disk=${DISK_GB}G"
fi

# ── Paths ───────────────────────────────────────────────────────────
VM_DIR="/data/easyenclave/vms/$NAME"
DISK="$VM_DIR/workload.qcow2"
ISO_DIR="${EE_IMAGE_DIR:-/tmp/ee-capture/image/output/local-tdx}"
ISO="$ISO_DIR/easyenclave.iso"

[ -f "$ISO" ] || {
    echo "Missing easyenclave.iso at $ISO — run:"
    echo "  cd \$(dirname \$(readlink -f \$ISO_DIR)) && sudo make build TARGET=local-tdx"
    echo "Or set EE_IMAGE_DIR=<path> if your build is elsewhere."
    exit 1
}

# ── Prereqs ─────────────────────────────────────────────────────────
for cmd in qemu-system-x86_64 qemu-img genisoimage mkfs.ext4; do
    command -v "$cmd" >/dev/null || {
        echo "missing: $cmd" >&2
        echo "  apt install qemu-system-x86 qemu-utils genisoimage e2fsprogs" >&2
        exit 1
    }
done

# ── Persistent workload disk (create once, reuse forever) ───────────
mkdir -p "$VM_DIR"
if [ ! -f "$DISK" ]; then
    echo "Creating workload disk ${DISK_GB}G at $DISK"
    # Sparse qcow2 — only allocates blocks as they're written, so the
    # 1.92 TB GPU disk takes <1 MB until podman starts pulling images.
    qemu-img create -q -f qcow2 "$DISK" "${DISK_GB}G"

    # Pre-format as ext4 inside the qcow2 so EE can mount /dev/vdc at
    # /var/lib/easyenclave/ollama on boot (matches the production
    # baremetal convention that `podman-bootstrap` expects). Without
    # this, first boot lands on a raw block device and podman falls
    # back to vfs-on-tmpfs — the exact failure mode this wrapper is
    # meant to fix.
    NBD_DEV=$(sudo sh -c 'modprobe nbd max_part=8; for n in /dev/nbd*; do [ -b "$n" ] && ! [ -s "/sys/block/$(basename $n)/pid" ] && echo $n && break; done')
    [ -n "$NBD_DEV" ] || { echo "no free /dev/nbd*"; exit 1; }
    sudo qemu-nbd --connect="$NBD_DEV" "$DISK"
    trap 'sudo qemu-nbd --disconnect "$NBD_DEV" >/dev/null 2>&1 || true' EXIT
    sudo mkfs.ext4 -q -L workload "$NBD_DEV"
    sudo qemu-nbd --disconnect "$NBD_DEV"
    trap - EXIT
    echo "ext4 label=workload ready on $DISK"
fi

# ── Build config ISO from agent.env ─────────────────────────────────
CONFIG_ISO=$(mktemp --suffix=.iso)
trap 'rm -f "$CONFIG_ISO"' EXIT
# Filename must be `agent.env` on the ISO — EE's init looks for that.
STAGE=$(mktemp -d)
cp "$ENV_FILE" "$STAGE/agent.env"
genisoimage -quiet -o "$CONFIG_ISO" -V CONFIG -r -J "$STAGE/agent.env"
rm -rf "$STAGE"

# ── TDX flags (opt-in) ──────────────────────────────────────────────
TDX_FLAGS=""
if [ "${DD_TDX:-0}" = "1" ]; then
    TDX_SUPPORT=$(cat /sys/module/kvm_intel/parameters/tdx 2>/dev/null || echo "N")
    if [ "$TDX_SUPPORT" = "Y" ]; then
        TDX_FLAGS="-machine q35,kernel-irqchip=split,confidential-guest-support=tdx -object tdx-guest,id=tdx"
        echo "TDX: enabled (attestation will succeed if TDVF firmware is correct)"
    else
        echo "TDX: requested but kvm_intel.tdx=$TDX_SUPPORT on this host — falling back to non-TDX"
    fi
fi
# Non-TDX fallback keeps the same q35 machine so virtio/pci matches.
[ -z "$TDX_FLAGS" ] && TDX_FLAGS="-machine q35"

# ── Boot ────────────────────────────────────────────────────────────
BIOS="${DD_OVMF:-/usr/share/ovmf/OVMF.fd}"
[ -f "$BIOS" ] || { echo "OVMF firmware not found at $BIOS (set DD_OVMF)"; exit 1; }

echo "Name:    $NAME"
echo "Disk:    $DISK"
echo "ISO:     $ISO"
echo "Config:  $ENV_FILE"
echo "OVMF:    $BIOS"
echo ""
echo "Serial below. Ctrl-A X to quit."
echo "════════════════════════════════════════════════════════════════"

# shellcheck disable=SC2086
exec qemu-system-x86_64 \
    -enable-kvm -cpu host -m "$MEM" -smp "$VCPU" \
    $TDX_FLAGS \
    -bios "$BIOS" \
    -drive "file=$ISO,if=virtio,format=raw,media=cdrom,readonly=on" \
    -drive "file=$CONFIG_ISO,if=virtio,format=raw,media=cdrom,readonly=on" \
    -drive "file=$DISK,if=virtio,format=qcow2" \
    -netdev user,id=n0 -device virtio-net-pci,netdev=n0 \
    $GPU_ARGS \
    -serial mon:stdio -nographic
