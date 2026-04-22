#!/usr/bin/env bash
# local-cp.sh — define a local TDX control-plane VM on this host.
#
# Mirrors local-agents.sh but boots dd-management (the CP) instead of
# dd-agent. Used by deploy-cp.yml's `target: ssh` branch — the SSH
# equivalent of spinning up a GCE TDX instance. Provides the same
# `dd-{env}-cp-*` CF tunnel shape prod is used to, so /api/agents,
# /register, /health, etc. work identically to the GCE path.
#
# Usage:
#   apps/_infra/local-cp.sh <env> <hostname>
#     env       pr-N | staging | local-dev — same as DD_ENV
#     hostname  where the CP registers its CF tunnel
#               (e.g. pr-42.devopsdefender.com)
#
# Required env (all from the calling workflow's secrets):
#   CLOUDFLARE_API_TOKEN, CLOUDFLARE_ACCOUNT_ID, CLOUDFLARE_ZONE_ID
#   DD_ACCESS_ADMIN_EMAIL, DD_ITA_API_KEY
#   DD_RELEASE_TAG  (defaults to "latest")
#
# Sizing: 16 GiB RAM / 4 vCPU / 160 GB qcow2 overlay — general shape
# from the DD capacity rule. CP doesn't need GPU; GPU stays on the
# prod agent VM (H100 passthrough).

set -euo pipefail

ENV_LABEL="${1?usage: $0 <env> <hostname>}"
HOSTNAME="${2?hostname required}"
: "${CLOUDFLARE_API_TOKEN?}"
: "${CLOUDFLARE_ACCOUNT_ID?}"
: "${CLOUDFLARE_ZONE_ID?}"
: "${DD_ACCESS_ADMIN_EMAIL?}"
: "${DD_ITA_API_KEY?}"
DD_RELEASE_TAG="${DD_RELEASE_TAG:-latest}"
DD_DOMAIN="${DD_DOMAIN:-devopsdefender.com}"
DD_ITA_BASE_URL="${DD_ITA_BASE_URL:-https://api.trustauthority.intel.com}"
DD_ITA_JWKS_URL="${DD_ITA_JWKS_URL:-https://portal.trustauthority.intel.com/certs}"
DD_ITA_ISSUER="${DD_ITA_ISSUER:-https://portal.trustauthority.intel.com}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

IMG_DIR=/var/lib/libvirt/images
BASE="$IMG_DIR/easyenclave-local.qcow2"
BASE_DOMAIN="easyenclave-local"

NAME="$ENV_LABEL-cp"
VM="dd-local-$NAME"

[ -r "$BASE" ] || { echo "missing $BASE" >&2; exit 1; }
virsh dominfo "$BASE_DOMAIN" >/dev/null 2>&1 || {
  echo "base libvirt domain '$BASE_DOMAIN' not defined — rebuild the EE image first" >&2
  exit 1
}

# Same bake helper as local-agents.sh — envsubst restricted to
# `${VAR}` refs the template declares, empty env entries stripped.
bake() {
  case "$1" in
    *.json.tmpl)
      local vars
      vars=$(grep -oE '\$\{[A-Z_][A-Z0-9_]*\}' "$1" | sort -u | tr -d '\n')
      envsubst "$vars" < "$1" \
        | jq -c 'if .env then .env |= map(select(test("^[^=]+=.+"))) else . end'
      ;;
    *.json)
      jq -c . "$1"
      ;;
    *)
      echo "local-cp.sh: unknown workload file type: $1" >&2
      return 1
      ;;
  esac
}

build_config_iso() {
  local out="$IMG_DIR/$VM-config.iso"
  local tmp
  tmp=$(mktemp -d)
  trap "rm -rf $tmp" RETURN

  local workloads
  workloads=$({
    # mount-data must run before bastion so `/data` is a writable ext4
    # mount by the time bastion tries to mint its noise key there
    # (`--noise-key /data/bastion-noise.key`). Without it, the bastion
    # workload sees /data on the rootfs overlay, which is RO inside
    # EE's workload namespace, and fails with `Read-only file system`.
    bake "$REPO_ROOT/apps/mount-data/workload.json"
    bake "$REPO_ROOT/apps/cloudflared/workload.json"
    DD_RELEASE_TAG="$DD_RELEASE_TAG" \
      CLOUDFLARE_API_TOKEN="$CLOUDFLARE_API_TOKEN" \
      CLOUDFLARE_ACCOUNT_ID="$CLOUDFLARE_ACCOUNT_ID" \
      CLOUDFLARE_ZONE_ID="$CLOUDFLARE_ZONE_ID" \
      DD_DOMAIN="$DD_DOMAIN" \
      DD_HOSTNAME="$HOSTNAME" \
      DD_ENV="$ENV_LABEL" \
      DD_ACCESS_ADMIN_EMAIL="$DD_ACCESS_ADMIN_EMAIL" \
      DD_ITA_API_KEY="$DD_ITA_API_KEY" \
      DD_ITA_BASE_URL="$DD_ITA_BASE_URL" \
      DD_ITA_JWKS_URL="$DD_ITA_JWKS_URL" \
      DD_ITA_ISSUER="$DD_ITA_ISSUER" \
      bake "$REPO_ROOT/apps/dd-management/workload.json.tmpl"
    DD_RELEASE_TAG="$DD_RELEASE_TAG" \
      bake "$REPO_ROOT/apps/bastion/workload.json.tmpl"
  } | jq -cs '.')

  {
    echo "EE_OWNER=devopsdefender"
    echo "EE_BOOT_WORKLOADS=$workloads"
    echo "EE_CAPTURE_SOCKET=/run/ee/capture.sock"
  } > "$tmp/agent.env"

  truncate -s 4M "$out"
  # `-O ^has_journal` — 4 MB is below the ext4 journal min (~8 MB);
  # silence "Filesystem too small for a journal" and skip journaling,
  # which this read-only config volume doesn't need anyway.
  mkfs.ext4 -q -O ^has_journal -d "$tmp" "$out"
  echo "  wrote $out (env=$ENV_LABEL, hostname=$HOSTNAME)"
}

build_overlay() {
  local overlay="$IMG_DIR/$VM.qcow2"
  if [ -f "$overlay" ]; then
    echo "  overlay $overlay already exists (reusing)"
    return
  fi
  # 160 GB — general shape from the DD capacity rule. Sparse qcow2.
  qemu-img create -q -F qcow2 -b "$BASE" -f qcow2 "$overlay" 160G
  echo "  wrote $overlay (160G, backing $BASE)"
}

build_workload_disk() {
  # Persistent ext4 mounted at /data inside the VM via EE's mount-data
  # workload. CP only needs this for small stable state (today: the
  # bastion Noise static key, ~32 bytes). 10G is massively oversized
  # but qcow2 is sparse — actual disk use is ≈1 MB until something
  # writes. Mirrors local-agents.sh's build_workload_disk, just
  # smaller.
  local disk="$IMG_DIR/$VM-workload.qcow2"
  if [ -f "$disk" ]; then
    echo "  workload disk $disk already exists (reusing)"
    return
  fi
  qemu-img create -q -f qcow2 "$disk" 10G
  sudo modprobe nbd max_part=8 2>/dev/null || true
  local nbd
  for n in /dev/nbd*; do
    [ -b "$n" ] || continue
    [ -s "/sys/block/$(basename "$n")/pid" ] && continue
    nbd="$n"
    break
  done
  [ -n "$nbd" ] || { echo "no free /dev/nbd*"; exit 1; }
  sudo qemu-nbd --connect="$nbd" "$disk"
  for _ in 1 2 3 4 5; do
    if sudo mkfs.ext4 -q -L workload "$nbd" 2>/dev/null; then
      break
    fi
    sleep 1
  done
  sudo qemu-nbd --disconnect "$nbd" >/dev/null
  echo "  wrote $disk (10G ext4, label=workload)"
}

render_domain_xml() {
  local out="/tmp/$VM.xml"
  virsh dumpxml "$BASE_DOMAIN" > "$out"

  sed -i "s|<name>$BASE_DOMAIN</name>|<name>$VM</name>|" "$out"
  sed -i '/<uuid>/d' "$out"
  sed -i '/<mac address=/d' "$out"
  sed -i "s|$IMG_DIR/$BASE_DOMAIN.qcow2|$IMG_DIR/$VM.qcow2|g" "$out"
  sed -i "s|$IMG_DIR/$BASE_DOMAIN-config.iso|$IMG_DIR/$VM-config.iso|g" "$out"
  sed -i "s|/var/log/ee-local\\.log|/var/log/ee-local-$NAME.log|g" "$out"

  # Inject the workload disk as /dev/vdc — EE's mount-data workload
  # picks it up by LABEL=workload and mounts at /data. Bastion's
  # --noise-key lives there so the pubkey persists across CP reboots.
  python3 - "$out" "$IMG_DIR/$VM-workload.qcow2" <<'PY'
import re, sys
xml_path, disk_path = sys.argv[1], sys.argv[2]
with open(xml_path) as f: x = f.read()
new_disk = (
    f"    <disk type='file' device='disk'>\n"
    f"      <driver name='qemu' type='qcow2'/>\n"
    f"      <source file='{disk_path}'/>\n"
    f"      <target dev='vdc' bus='virtio'/>\n"
    f"    </disk>\n"
)
x = re.sub(r"(</disk>\n)(?=(?:(?!</disk>).)*?</devices>)", r"\1" + new_disk, x, count=1, flags=re.DOTALL)
with open(xml_path, "w") as f: f.write(x)
PY

  # CP sizing (general shape — no GPU).
  local mem_kib=16777216   # 16 GiB
  local vcpus=4
  sed -i -E "s|<memory unit='KiB'>[0-9]+</memory>|<memory unit='KiB'>$mem_kib</memory>|" "$out"
  sed -i -E "s|<currentMemory unit='KiB'>[0-9]+</currentMemory>|<currentMemory unit='KiB'>$mem_kib</currentMemory>|" "$out"
  sed -i -E "s|<vcpu placement='static'>[0-9]+</vcpu>|<vcpu placement='static'>$vcpus</vcpu>|" "$out"

  # Strip GPU passthrough — CP doesn't need it and having two domains
  # claim the same host device collides.
  # Remove any <hostdev> blocks (vfio-pci H100).
  python3 - "$out" <<'PY'
import re, sys
p = sys.argv[1]
with open(p) as f: x = f.read()
x = re.sub(r"\s*<hostdev[^>]*>.*?</hostdev>\n?", "", x, flags=re.DOTALL)
with open(p, "w") as f: f.write(x)
PY

  # Wire QEMU's tdx-guest to host's QGS unix socket — same treatment
  # local-agents.sh does so ITA quotes work inside the CP VM.
  if grep -q "<launchSecurity type='tdx'/>" "$out"; then
    # Replace the empty launchSecurity with the full form + object.
    python3 - "$out" <<'PY'
import sys
p = sys.argv[1]
with open(p) as f: x = f.read()
x = x.replace(
    "<launchSecurity type='tdx'/>",
    """<launchSecurity type='tdx'>
    <Quote-Generation-Service>vsock:2:4050</Quote-Generation-Service>
  </launchSecurity>""",
)
with open(p, "w") as f: f.write(x)
PY
  fi

  cat "$out"
}

echo "== $VM → https://$HOSTNAME (env=$ENV_LABEL) =="
build_overlay
build_workload_disk
build_config_iso
xml=$(render_domain_xml)
# Destroy any previous instance. rm on /var/log needs sudo (root-owned
# by libvirt); || true so a missing file or permission denial doesn't
# fail the deploy — libvirt will overwrite on domain start anyway.
virsh destroy "$VM" 2>/dev/null || true
virsh undefine "$VM" --managed-save --snapshots-metadata 2>/dev/null || true
sudo rm -f "/var/log/ee-local-$NAME.log" 2>/dev/null || true
echo "$xml" | virsh define /dev/stdin >/dev/null
echo "  defined $VM"
