#!/usr/bin/env bash
# install-agent.sh — provision a DD fleet agent on this host.
#
# Bootstraps a TDX-capable Linux host into a DD fleet member by:
#   1. installing qemu+ovmf+genisoimage (apt; idempotent)
#   2. fetching easyenclave's published .qcow2 from GitHub releases
#   3. generating an agent.env with DD_REGISTER_URL/OWNER/VM_NAME +
#      EE_BOOT_WORKLOADS pointing at devopsdefender/dd's `latest` release
#   4. wrapping that env into a config.iso (genisoimage)
#   5. installing a systemd unit that boots the qcow2 under
#      QEMU+OVMF+TDX with the config.iso attached
#
# The launched VM:
#   - boots easyenclave from the qcow2's UKI in the ESP partition
#   - reads agent.env from the config.iso and applies as env vars
#   - downloads the devopsdefender binary from GitHub releases
#     (via easyenclave's github_release boot workload source)
#   - registers with dd-register over Noise XX with attestation
#
# Idempotent: rerun with the same --vm-name to recycle that agent;
# rerun with a different --vm-name to add another agent on the host.
#
# Usage:
#   sudo install-agent.sh \
#     --register-url wss://app-staging.devopsdefender.com/register \
#     --owner devopsdefender \
#     --vm-name my-staging-agent

set -euo pipefail

# ── Defaults ─────────────────────────────────────────────────────────────
REGISTER_URL=""
OWNER=""
VM_NAME=""
EE_TAG=""           # default: latest pre-release in easyenclave/easyenclave
DD_TAG="latest"     # the dd binary tag to fetch via github_release
MEM="4096"
VCPU="2"
EE_REPO="easyenclave/easyenclave"
DD_REPO="devopsdefender/dd"
STATE_DIR="/var/lib/dd-agent"
OVMF_CODE="/usr/share/OVMF/OVMF_CODE.fd"

# ── Args ────────────────────────────────────────────────────────────────
usage() {
    cat <<EOF
Usage: $0 --register-url URL --owner OWNER [--vm-name NAME] [options]

Required:
  --register-url URL   wss://app-{env}.devopsdefender.com/register
  --owner OWNER        GitHub user/org gating fleet access (e.g. devopsdefender)

Optional:
  --vm-name NAME       agent identity / systemd instance (default: \$HOSTNAME-\$rand)
  --ee-tag TAG         easyenclave release tag (default: latest pre-release)
  --dd-tag TAG         devopsdefender release tag (default: latest)
  --mem MB             RAM in MB (default: $MEM)
  --vcpu N             vCPU count (default: $VCPU)
EOF
    exit 2
}

while [[ $# -gt 0 ]]; do
    # Support both --key value and --key=value.
    case "$1" in
        --register-url=*) REGISTER_URL="${1#*=}"; shift ;;
        --register-url)   REGISTER_URL="${2:?value}"; shift 2 ;;
        --owner=*)        OWNER="${1#*=}"; shift ;;
        --owner)          OWNER="${2:?value}"; shift 2 ;;
        --vm-name=*)      VM_NAME="${1#*=}"; shift ;;
        --vm-name)        VM_NAME="${2:?value}"; shift 2 ;;
        --ee-tag=*)       EE_TAG="${1#*=}"; shift ;;
        --ee-tag)         EE_TAG="${2:?value}"; shift 2 ;;
        --dd-tag=*)       DD_TAG="${1#*=}"; shift ;;
        --dd-tag)         DD_TAG="${2:?value}"; shift 2 ;;
        --mem=*)          MEM="${1#*=}"; shift ;;
        --mem)            MEM="${2:?value}"; shift 2 ;;
        --vcpu=*)         VCPU="${1#*=}"; shift ;;
        --vcpu)           VCPU="${2:?value}"; shift 2 ;;
        -h|--help)        usage ;;
        *)                echo "unknown arg: $1" >&2; usage ;;
    esac
done

[[ -n "$REGISTER_URL" ]] || { echo "--register-url required" >&2; usage; }
[[ -n "$OWNER" ]] || { echo "--owner required" >&2; usage; }
[[ -n "$VM_NAME" ]] || VM_NAME="$(hostname)-$(tr -dc a-z0-9 </dev/urandom | head -c 6)"

# ── Preflight ───────────────────────────────────────────────────────────
[[ "$(id -u)" -eq 0 ]] || { echo "must run as root (try: sudo $0 …)" >&2; exit 1; }

TDX="$(cat /sys/module/kvm_intel/parameters/tdx 2>/dev/null || echo N)"
if [[ "$TDX" != "Y" ]]; then
    echo "WARNING: kvm_intel.tdx=$TDX — no hardware attestation. Agent will fail to start." >&2
    echo "         (easyenclave refuses to run without TDX)" >&2
fi

echo "==> install-agent: vm=$VM_NAME register=$REGISTER_URL owner=$OWNER"

# ── 1. apt deps (idempotent) ────────────────────────────────────────────
need_pkg() { ! dpkg -s "$1" >/dev/null 2>&1; }
PKGS=()
need_pkg qemu-system-x86 && PKGS+=(qemu-system-x86)
need_pkg ovmf            && PKGS+=(ovmf)
need_pkg genisoimage     && PKGS+=(genisoimage)
need_pkg jq              && PKGS+=(jq)
need_pkg curl            && PKGS+=(curl)
if [[ ${#PKGS[@]} -gt 0 ]]; then
    echo "==> apt-get install: ${PKGS[*]}"
    DEBIAN_FRONTEND=noninteractive apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${PKGS[@]}"
fi
[[ -f "$OVMF_CODE" ]] || { echo "OVMF firmware missing at $OVMF_CODE after install" >&2; exit 1; }

# ── 2. Resolve + cache easyenclave qcow2 ────────────────────────────────
mkdir -p "$STATE_DIR" "$STATE_DIR/$VM_NAME"
QCOW_CACHE="$STATE_DIR/qcow"
mkdir -p "$QCOW_CACHE"

if [[ -z "$EE_TAG" ]]; then
    # Latest release (including pre-releases). Pick the most recent
    # whose tag starts with "image-" — that's the format `image.yml`
    # publishes per-build.
    echo "==> resolving latest easyenclave release"
    EE_TAG="$(curl -fsSL "https://api.github.com/repos/$EE_REPO/releases" \
        | jq -r '[.[] | select(.tag_name | startswith("image-")) | .tag_name][0]')"
    [[ -n "$EE_TAG" && "$EE_TAG" != "null" ]] || { echo "could not resolve EE tag" >&2; exit 1; }
fi
echo "    ee tag: $EE_TAG"

# Asset name pattern: easyenclave-{sha12}.qcow2
QCOW_NAME="$(curl -fsSL "https://api.github.com/repos/$EE_REPO/releases/tags/$EE_TAG" \
    | jq -r '.assets[].name' | grep -E '\.qcow2$' | head -1)"
[[ -n "$QCOW_NAME" ]] || { echo "no .qcow2 asset in $EE_TAG" >&2; exit 1; }

QCOW="$QCOW_CACHE/$QCOW_NAME"
if [[ ! -f "$QCOW" ]]; then
    echo "==> downloading $QCOW_NAME"
    curl -fSL --progress-bar -o "$QCOW.tmp" \
        "https://github.com/$EE_REPO/releases/download/$EE_TAG/$QCOW_NAME"
    mv "$QCOW.tmp" "$QCOW"
fi
echo "    qcow:  $QCOW ($(du -h "$QCOW" | cut -f1))"

# ── 3. agent.env ────────────────────────────────────────────────────────
# EE_BOOT_WORKLOADS launches the dd binary inside the VM. The dd binary
# inherits the DD_* env vars set on the workload.
WORKLOAD_JSON="$(jq -nc \
    --arg dd_tag      "$DD_TAG" \
    --arg owner       "$OWNER" \
    --arg vm_name     "$VM_NAME" \
    --arg register    "$REGISTER_URL" \
    '[{
        "github_release": {
            "repo": "devopsdefender/dd",
            "asset": "devopsdefender",
            "tag": $dd_tag
        },
        "cmd": ["devopsdefender"],
        "app_name": "dd-agent",
        "env": [
            "DD_MODE=agent",
            ("DD_REGISTER_URL=" + $register),
            ("DD_OWNER="        + $owner),
            ("DD_VM_NAME="      + $vm_name)
        ]
    }]')"

ENV_FILE="$STATE_DIR/$VM_NAME/agent.env"
{
    echo "EE_OWNER=$OWNER"
    echo "EE_BOOT_WORKLOADS=$WORKLOAD_JSON"
} > "$ENV_FILE"
chmod 600 "$ENV_FILE"

# ── 4. config.iso ───────────────────────────────────────────────────────
CONFIG_ISO="$STATE_DIR/$VM_NAME/config.iso"
genisoimage -quiet -o "$CONFIG_ISO" -V CONFIG -r -J "$ENV_FILE"

# ── 5. systemd unit ─────────────────────────────────────────────────────
# One unit file (template, %i = vm-name). Per-instance state lives under
# /var/lib/dd-agent/<vm-name>/.
UNIT_PATH="/etc/systemd/system/dd-agent@.service"
if [[ ! -f "$UNIT_PATH" ]]; then
    cat > "$UNIT_PATH" <<'EOF'
[Unit]
Description=DD fleet agent (TDX VM): %i
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/var/lib/dd-agent/%i/launch.env
# Each agent gets its own user-mode network so they don't clash on
# default port-forwards. No host inbound is required — agent talks
# outbound to dd-register over WSS.
ExecStart=/usr/bin/qemu-system-x86_64 \
    -enable-kvm -cpu host -m ${MEM} -smp ${VCPU} \
    -machine q35,kernel-irqchip=split,confidential-guest-support=tdx \
    -object tdx-guest,id=tdx \
    -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE.fd \
    -drive file=${QCOW},if=virtio,format=qcow2,snapshot=on \
    -drive file=${CONFIG_ISO},if=virtio,format=raw,media=cdrom,readonly=on \
    -netdev user,id=n0 -device virtio-net-pci,netdev=n0 \
    -nographic \
    -serial file:/var/log/dd-agent-%i.log
Restart=on-failure
RestartSec=5
# Don't auto-restart when the VM cleanly poweroffs (STONITH via the
# self-watchdog), only on actual crashes.
SuccessExitStatus=0

[Install]
WantedBy=multi-user.target
EOF
fi

LAUNCH_ENV="$STATE_DIR/$VM_NAME/launch.env"
cat > "$LAUNCH_ENV" <<EOF
MEM=$MEM
VCPU=$VCPU
QCOW=$QCOW
CONFIG_ISO=$CONFIG_ISO
EOF
chmod 600 "$LAUNCH_ENV"

systemctl daemon-reload
systemctl enable --now "dd-agent@${VM_NAME}.service"

# ── 6. Wait for register (best-effort) ──────────────────────────────────
echo "==> agent started: dd-agent@${VM_NAME}.service"
echo "    serial log:    /var/log/dd-agent-$VM_NAME.log"
echo "    state dir:     $STATE_DIR/$VM_NAME"
echo
echo "Service status:"
systemctl status --no-pager "dd-agent@${VM_NAME}.service" 2>&1 | head -10 || true
