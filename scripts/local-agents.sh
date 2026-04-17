#!/usr/bin/env bash
# local-agents.sh — define two local TDX agent VMs on this host:
#
#   dd-local-preview : no GPU, registers with the PR-preview CP
#   dd-local-prod    : H100 passthrough, registers with production
#
# Both reuse the existing easyenclave base qcow2 via copy-on-write
# overlays; each gets its own config.iso baking in DD_CP_URL + DD_PAT +
# DD_ITA_API_KEY for that target. Libvirt XML is rendered from the
# existing `easyenclave-local` domain (strip hostdev for preview).
#
# Usage:
#   export DD_PAT="$(gh auth token)"
#   export DD_ITA_API_KEY="$(cat ~/.secrets/ita_api_key)"
#   ./scripts/local-agents.sh https://pr-106.devopsdefender.com https://app.devopsdefender.com
#
# After: virsh start dd-local-preview && virsh start dd-local-prod

set -euo pipefail

PREVIEW_CP="${1?usage: $0 <preview-cp-url> <prod-cp-url>}"
PROD_CP="${2?usage: $0 <preview-cp-url> <prod-cp-url>}"
: "${DD_PAT?set DD_PAT (e.g. DD_PAT=\$(gh auth token))}"
: "${DD_ITA_API_KEY?set DD_ITA_API_KEY}"

IMG_DIR=/var/lib/libvirt/images
BASE="$IMG_DIR/easyenclave-local.qcow2"
BASE_DOMAIN="easyenclave-local"

[ -r "$BASE" ] || { echo "missing $BASE" >&2; exit 1; }
virsh dominfo "$BASE_DOMAIN" >/dev/null 2>&1 || {
  echo "base libvirt domain '$BASE_DOMAIN' not defined — rebuild the EE image first" >&2
  exit 1
}

env_from_url() {
  local h
  h=$(echo "$1" | sed -E 's#https?://##;s#/.*##')
  case "$h" in
    app.*) echo production ;;
    *)     echo "${h%%.*}" ;;
  esac
}

build_config_iso() {
  # $1=name, $2=cp_url, $3=env_label
  local name="$1" cp="$2" env="$3"
  local out="$IMG_DIR/dd-local-$name-config.iso"
  local tmp
  tmp=$(mktemp -d)
  trap "rm -rf $tmp" RETURN

  local workloads
  workloads=$(jq -c -n \
    --arg cp "$cp" --arg pat "$DD_PAT" --arg ita "$DD_ITA_API_KEY" \
    --arg env "$env" --arg vm "dd-local-$name" '[
      {"github_release":{"repo":"cloudflare/cloudflared","asset":"cloudflared-linux-amd64","rename":"cloudflared"},"app_name":"cloudflared"},
      {"github_release":{"repo":"devopsdefender/dd","asset":"devopsdefender","tag":"latest"},
       "cmd":["devopsdefender","agent"],"app_name":"dd-agent",
       "env":[
         "DD_MODE=agent",
         ("DD_CP_URL=" + $cp), ("DD_PAT=" + $pat), ("DD_ITA_API_KEY=" + $ita),
         "DD_ITA_BASE_URL=https://api.trustauthority.intel.com",
         "DD_ITA_JWKS_URL=https://portal.trustauthority.intel.com/certs",
         "DD_ITA_ISSUER=https://portal.trustauthority.intel.com",
         "DD_OWNER=devopsdefender", ("DD_ENV=" + $env), ("DD_VM_NAME=" + $vm),
         "DD_PORT=8080"
       ]}
    ]')

  jq -c -n --arg wl "$workloads" \
    '{EE_OWNER:"devopsdefender",EE_BOOT_WORKLOADS:$wl}' > "$tmp/ee-config.json"

  # ext4 — EE rootfs has no iso9660 module.
  truncate -s 4M "$out"
  mkfs.ext4 -q -d "$tmp" "$out"
  echo "  wrote $out (env=$env)"
}

build_overlay() {
  # $1=name
  local name="$1"
  local overlay="$IMG_DIR/dd-local-$name.qcow2"
  if [ -f "$overlay" ]; then
    echo "  overlay $overlay already exists (reusing)"
    return
  fi
  qemu-img create -q -F qcow2 -b "$BASE" -f qcow2 "$overlay" 10G
  echo "  wrote $overlay (backing $BASE)"
}

render_domain_xml() {
  # $1=name, $2=with_gpu (yes/no)
  local name="$1" with_gpu="$2"
  local out="/tmp/dd-local-$name.xml"

  virsh dumpxml "$BASE_DOMAIN" > "$out"

  # Rename domain, strip UUID (libvirt regens), strip MAC (libvirt regens).
  sed -i "s|<name>$BASE_DOMAIN</name>|<name>dd-local-$name</name>|" "$out"
  sed -i '/<uuid>/d' "$out"
  sed -i '/<mac address=/d' "$out"

  # Rewrite disk paths to this agent's overlay + config.
  sed -i "s|$IMG_DIR/$BASE_DOMAIN.qcow2|$IMG_DIR/dd-local-$name.qcow2|g" "$out"
  sed -i "s|$IMG_DIR/$BASE_DOMAIN-config.iso|$IMG_DIR/dd-local-$name-config.iso|g" "$out"

  if [ "$with_gpu" != "yes" ]; then
    # Strip the <hostdev ...>…</hostdev> block for the preview VM.
    awk 'BEGIN{skip=0}
         /<hostdev /{skip=1}
         !skip{print}
         /<\/hostdev>/{skip=0}' "$out" > "$out.tmp" && mv "$out.tmp" "$out"
  fi

  echo "$out"
}

define_agent() {
  # $1=name, $2=cp_url, $3=with_gpu
  local name="$1" cp="$2" with_gpu="$3"
  local env_label
  env_label=$(env_from_url "$cp")

  echo "== dd-local-$name → $cp (env=$env_label, gpu=$with_gpu) =="
  build_overlay "$name"
  build_config_iso "$name" "$cp" "$env_label"
  local xml
  xml=$(render_domain_xml "$name" "$with_gpu")
  virsh destroy "dd-local-$name" 2>/dev/null || true
  virsh undefine "dd-local-$name" --managed-save --snapshots-metadata 2>/dev/null || true
  virsh define "$xml" >/dev/null
  echo "  defined dd-local-$name (xml at $xml)"
}

define_agent preview "$PREVIEW_CP" no
define_agent prod    "$PROD_CP"    yes

echo
echo "done. start with:"
echo "  virsh start dd-local-preview"
echo "  virsh start dd-local-prod"
echo
echo "watch registration:"
echo "  virsh console dd-local-preview   # Ctrl-] to exit"
echo "  virsh console dd-local-prod"
