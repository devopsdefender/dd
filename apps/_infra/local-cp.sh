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
#   EE_OWNER         GitHub login or owner/repo path (no default).
#                    Resolved at runtime via `gh api` to (id, kind);
#                    DD_OWNER_ID + DD_OWNER_KIND are derived from it.
#   DD_RELEASE_TAG  (defaults to "latest")
#
# Sizing: 16 GiB RAM / 4 vCPU / 160 GB qcow2 overlay.

set -euo pipefail
export LIBVIRT_DEFAULT_URI="${LIBVIRT_DEFAULT_URI:-qemu:///system}"

ENV_LABEL="${1?usage: $0 <env> <hostname>}"
HOSTNAME="${2?hostname required}"
: "${CLOUDFLARE_API_TOKEN?}"
: "${CLOUDFLARE_ACCOUNT_ID?}"
: "${CLOUDFLARE_ZONE_ID?}"
: "${DD_ACCESS_ADMIN_EMAIL?}"
: "${DD_ITA_API_KEY?}"
: "${EE_OWNER?set EE_OWNER (GitHub login or owner/repo path; no default)}"
DD_RELEASE_TAG="${DD_RELEASE_TAG:-latest}"

# Resolve EE_OWNER to (id, kind) via gh api — same idiom as
# local-agents.sh.
command -v gh >/dev/null || { echo "gh CLI required to resolve EE_OWNER" >&2; exit 1; }
if [[ "$EE_OWNER" == */* ]]; then
  EE_OWNER_ID=$(gh api "repos/$EE_OWNER" -q .id) || {
    echo "EE_OWNER='$EE_OWNER' did not resolve via gh api repos/" >&2
    exit 1
  }
  EE_OWNER_KIND=repo
else
  read -r EE_OWNER_ID _gh_type < <(gh api "users/$EE_OWNER" -q '"\(.id) \(.type)"') || {
    echo "EE_OWNER='$EE_OWNER' did not resolve via gh api users/" >&2
    exit 1
  }
  case "$_gh_type" in
    User)         EE_OWNER_KIND=user ;;
    Organization) EE_OWNER_KIND=org ;;
    *) echo "unexpected gh api type: $_gh_type" >&2; exit 1 ;;
  esac
fi
unset _gh_type
echo "  EE_OWNER=$EE_OWNER (kind=$EE_OWNER_KIND, id=$EE_OWNER_ID)"
DD_DOMAIN="${DD_DOMAIN:-devopsdefender.com}"
DD_ITA_BASE_URL="${DD_ITA_BASE_URL:-https://api.trustauthority.intel.com}"
DD_ITA_JWKS_URL="${DD_ITA_JWKS_URL:-https://portal.trustauthority.intel.com/certs}"
DD_ITA_ISSUER="${DD_ITA_ISSUER:-https://portal.trustauthority.intel.com}"
if [ -z "${DD_ITA_MODE:-}" ]; then
  case "$ENV_LABEL" in
    production|staging) DD_ITA_MODE=intel ;;
    *)                  DD_ITA_MODE=local ;;
  esac
fi
echo "  DD_ITA_MODE=$DD_ITA_MODE"

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
    bake "$REPO_ROOT/apps/cloudflared/workload.json"
    DD_RELEASE_TAG="$DD_RELEASE_TAG" \
      CLOUDFLARE_API_TOKEN="$CLOUDFLARE_API_TOKEN" \
      CLOUDFLARE_ACCOUNT_ID="$CLOUDFLARE_ACCOUNT_ID" \
      CLOUDFLARE_ZONE_ID="$CLOUDFLARE_ZONE_ID" \
      DD_DOMAIN="$DD_DOMAIN" \
      DD_HOSTNAME="$HOSTNAME" \
      DD_ENV="$ENV_LABEL" \
      DD_ACCESS_ADMIN_EMAIL="$DD_ACCESS_ADMIN_EMAIL" \
      DD_ITA_MODE="$DD_ITA_MODE" \
      DD_ITA_API_KEY="$DD_ITA_API_KEY" \
      DD_ITA_BASE_URL="$DD_ITA_BASE_URL" \
      DD_ITA_JWKS_URL="$DD_ITA_JWKS_URL" \
      DD_ITA_ISSUER="$DD_ITA_ISSUER" \
      DD_OWNER="$EE_OWNER" \
      DD_OWNER_ID="$EE_OWNER_ID" \
      DD_OWNER_KIND="$EE_OWNER_KIND" \
      bake "$REPO_ROOT/apps/dd-management/workload.json.tmpl"
    bake "$REPO_ROOT/apps/ttyd/workload.json"
  } | jq -cs '.')

  {
    echo "EE_OWNER=$EE_OWNER"
    echo "EE_OWNER_ID=$EE_OWNER_ID"
    echo "EE_OWNER_KIND=$EE_OWNER_KIND"
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

render_domain_xml() {
  local out="/tmp/$VM.xml"
  virsh dumpxml "$BASE_DOMAIN" > "$out"

  sed -i "s|<name>$BASE_DOMAIN</name>|<name>$VM</name>|" "$out"
  sed -i '/<uuid>/d' "$out"
  sed -i '/<mac address=/d' "$out"
  sed -i "s|$IMG_DIR/$BASE_DOMAIN.qcow2|$IMG_DIR/$VM.qcow2|g" "$out"
  sed -i "s|$IMG_DIR/$BASE_DOMAIN-config.iso|$IMG_DIR/$VM-config.iso|g" "$out"
  sed -i "s|/var/log/ee-local\\.log|/var/log/ee-local-$NAME.log|g" "$out"
  sed -i "s|<model type='e1000e'/>|<model type='virtio'/>|g" "$out"

  # The local-tdx-qcow2 UKI is intentionally unsigned; this host's
  # OVMF.tdx.fd rejects it with UEFI "Access Denied". Use the non-secure
  # TDVF build when present while keeping launchSecurity type=tdx below.
  if [ -r /usr/share/ovmf/OVMF.fd ]; then
    sed -i -E "s|<loader([^>]*)>/usr/share/ovmf/OVMF\\.tdx\\.fd</loader>|<loader\\1>/usr/share/ovmf/OVMF.fd</loader>|" "$out"
  fi

  # CP sizing.
  local mem_kib=16777216   # 16 GiB
  local vcpus=4
  sed -i -E "s|<memory unit='KiB'>[0-9]+</memory>|<memory unit='KiB'>$mem_kib</memory>|" "$out"
  sed -i -E "s|<currentMemory unit='KiB'>[0-9]+</currentMemory>|<currentMemory unit='KiB'>$mem_kib</currentMemory>|" "$out"
  sed -i -E "s|<vcpu placement='static'>[0-9]+</vcpu>|<vcpu placement='static'>$vcpus</vcpu>|" "$out"

  # Remove any inherited passthrough / TPM devices from the base domain.
  python3 - "$out" <<'PY'
import re, sys
p = sys.argv[1]
with open(p) as f: x = f.read()
x = re.sub(r"\s*<hostdev[^>]*>.*?</hostdev>\n?", "", x, flags=re.DOTALL)
x = re.sub(r"\s*<tpm[^>]*>.*?</tpm>\n?", "", x, flags=re.DOTALL)
with open(p, "w") as f: f.write(x)
PY

  # Wire QEMU's tdx-guest to host QGS over vsock — same treatment
  # local-agents.sh does so ITA quotes work inside the CP VM. Must use
  # libvirt's schema-valid form from Canonical's TDX templates. The earlier
  # `<Quote-Generation-Service>vsock:2:4050</Quote-Generation-Service>`
  # form is not in libvirt's RNG — `virsh define` accepts it but
  # canonicalizes it away, leaving `<launchSecurity type='tdx'/>` with
  # no QGS wired → guest can't produce a quote → dd-management's ITA
  # mint fails with "Quote cannot be empty" → CP poweroffs.
  if grep -q "<launchSecurity type='tdx'/>" "$out"; then
    sed -i "s|<launchSecurity type='tdx'/>|<launchSecurity type='tdx'><policy>0x10000000</policy><quoteGenerationService><SocketAddress type='vsock' cid='2' port='4050'/></quoteGenerationService></launchSecurity>|" "$out"
  elif grep -q "<launchSecurity type='tdx'>" "$out" && ! grep -q "quoteGenerationService" "$out"; then
    sed -i "s|</launchSecurity>|  <quoteGenerationService><SocketAddress type='vsock' cid='2' port='4050'/></quoteGenerationService>\n  </launchSecurity>|" "$out"
  fi

  cat "$out"
}

echo "== $VM → https://$HOSTNAME (env=$ENV_LABEL) =="
build_overlay
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
