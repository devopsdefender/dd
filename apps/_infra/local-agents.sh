#!/usr/bin/env bash
# local-agents.sh — define local TDX agent VMs on this host:
#
#   dd-local-preview : CPU-only, registers with the PR-preview CP. Bare
#                      agent + podman — no demo workload — so the release
#                      pipeline can prove registration + tunnel end-to-end
#                      against per-PR CPs without special hardware.
#   dd-local-prod    : registers with production. Same CPU-only boot
#                      shape as preview so prod and preview exercise the
#                      easyenclave-mini runtime consistently.
#   dd-local-bot     : CPU-only, registers with production. Dedicated host
#                      for the Sats for Compute bot (or any always-on
#                      operator workload). Started/stopped manually —
#                      CI doesn't reprovision; deploy-bot.yml in the
#                      satsforcompute repo just dd-deploys the bot
#                      workload onto this agent's /deploy. Same boot
#                      chain as preview/prod (cloudflared + dd-agent +
#                      ttyd + podman). Modest sizing.
#
# All three reuse the existing easyenclave base qcow2 via copy-on-write
# overlays; each gets its own config.iso baking in DD_CP_URL +
# DD_ITA_API_KEY for that target. No GitHub PAT — the agent
# authenticates to the CP via ITA attestation at /register and picks
# up a CF Access service token from the register response for all
# subsequent machine-to-machine calls. Libvirt XML is rendered from
# the existing `easyenclave-local` domain.
#
# `EE_OWNER` (required) is the principal authorized to deploy to the
# baked agents — one of:
#   <login>        a GitHub user OR org login (no '/'). Resolved via
#                  `gh api users/<login>` to a numeric id and a
#                  user-vs-org kind.
#   <owner>/<repo> a specific repository. Resolved via
#                  `gh api repos/<owner>/<repo>` to a numeric id.
#                  Strictly tighter than the bare-login form.
# Both DD_OWNER_ID and DD_OWNER_KIND are derived from the resolved
# answer and baked alongside DD_OWNER. There is no default — pick a
# principal explicitly. CF Access dashboard membership only works
# for kind=org; user/repo fall back to admin-email-only.
#
# Usage:
#   export DD_ITA_API_KEY="$(cat ~/.secrets/ita_api_key)"
#   export EE_OWNER="devopsdefender"   # or "alice", "alice/dd-foo", etc.
#   ./apps/_infra/local-agents.sh <preview> <prod> <bot>
#
# Each URL arg is independent — pass "" to skip provisioning that VM:
#   ./apps/_infra/local-agents.sh "" https://app.devopsdefender.com ""                          # prod only
#   ./apps/_infra/local-agents.sh https://pr-N.devopsdefender.com "" ""                         # preview only
#   ./apps/_infra/local-agents.sh "" "" https://app.devopsdefender.com                          # bot only
#   ./apps/_infra/local-agents.sh "" https://app.devopsdefender.com https://app.devopsdefender.com  # prod + bot
#
# After: virsh start dd-local-preview && virsh start dd-local-prod && virsh start dd-local-bot

set -euo pipefail
export LIBVIRT_DEFAULT_URI="${LIBVIRT_DEFAULT_URI:-qemu:///system}"

PREVIEW_CP="${1-}"
PROD_CP="${2-}"
BOT_CP="${3-}"
if [ -z "$PREVIEW_CP" ] && [ -z "$PROD_CP" ] && [ -z "$BOT_CP" ]; then
  echo "usage: $0 <preview-cp-url|\"\"> <prod-cp-url|\"\"> <bot-cp-url|\"\">" >&2
  exit 1
fi
: "${DD_ITA_API_KEY?set DD_ITA_API_KEY}"
: "${EE_OWNER?set EE_OWNER (GitHub login or owner/repo path; no default)}"
# DD_RELEASE_TAG pins which devopsdefender binary the agent downloads.
# Defaults to "latest" for ad-hoc runs; the relaunch-agent action sets
# it to the PR's release tag so preview deploys test the PR binary.
DD_RELEASE_TAG="${DD_RELEASE_TAG:-latest}"

# Resolve EE_OWNER to (id, kind) once via `gh api`. Hard-fails if the
# login or repo doesn't exist — better than baking a typo into a
# config.iso whose agent then 401s every deploy with no signal.
# Run once at script load so all three VMs (preview/prod/bot) share
# the same owner principal.
command -v gh >/dev/null || { echo "gh CLI required to resolve EE_OWNER" >&2; exit 1; }
if [[ "$EE_OWNER" == */* ]]; then
  EE_OWNER_ID=$(gh api "repos/$EE_OWNER" -q .id) || {
    echo "EE_OWNER='$EE_OWNER' (looks like a repo, contains '/') did not resolve via gh api" >&2
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

# Resolve repo root regardless of invoking CWD — the workload specs
# under apps/<name>/ need absolute paths so bake() can find them.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

IMG_DIR=/var/lib/libvirt/images
BASE="$IMG_DIR/easyenclave-local.qcow2"
BASE_DOMAIN="easyenclave-local"

# Render one workload spec. Matches the helper inlined in
# .github/workflows/deploy-cp.yml — same envsubst + empty-entry strip,
# so boot-time (config.iso) and runtime (/deploy) see identical JSON.
#
# envsubst is restricted to the ALL-CAPS `${VAR}` references that
# appear in the template itself. Lowercase `$i`, `${i}`, and bare
# `$((…))` arithmetic inside shell cmd strings are left alone.
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
      echo "local-agents.sh: unknown workload file type: $1" >&2
      return 1
      ;;
  esac
}

# Extract `expose` entries from a stream of baked workloads and emit
# them as a comma-separated `label:port` string — the shape dd-agent
# expects in $DD_EXTRA_INGRESS. Using plain text (not JSON) avoids
# quote-escaping when the value gets substituted into the dd-agent
# workload template's `"DD_EXTRA_INGRESS=${DD_EXTRA_INGRESS}"` env
# entry: embedded `"` would close the outer JSON string early and
# produce invalid JSON (jq: "Invalid numeric literal").
extract_extra_ingress() {
  jq -rs 'map(select(.expose) | "\(.expose.hostname_label):\(.expose.port)") | join(",")'
}

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
  local ita_mode="${DD_ITA_MODE:-}"
  if [ -z "$ita_mode" ]; then
    case "$env" in
      production|staging) ita_mode=intel ;;
      *)                  ita_mode=local ;;
    esac
  fi
  local out="$IMG_DIR/dd-local-$name-config.iso"
  local tmp
  tmp=$(mktemp -d)
  trap "rm -rf $tmp" RETURN

  # Boot workload chain (EE spawns concurrently; dependents self-sequence
  # via `until` loops):
  #   podman-static  — fetch the podman tarball into /var/lib/easyenclave/bin
  #   podman-bootstrap — stage binaries, install /var/lib/easyenclave/bin/podman
  #                    wrapper + containers.conf + policy.json
  #   cloudflared    — fetch binary (agent spawns the tunnel process)
  #   dd-agent       — register with CP, serve workloads. Requests the
  #                    workload ingress via $DD_EXTRA_INGRESS, computed
  #                    below from `expose` entries on baked workloads.
  local bare_workloads
  bare_workloads=$({
    # mount-data runs first so `/dev/vdc` is at `/data` by the time
    # podman-bootstrap reaches its `mountpoint -q` wait (both spawn
    # concurrently but EE's pre-fetch serializes binary downloads
    # before boot-loop).
    bake "$REPO_ROOT/apps/mount-data/workload.json"
    bake "$REPO_ROOT/apps/podman-static/workload.json"
    bake "$REPO_ROOT/apps/podman-bootstrap/workload.json"
    bake "$REPO_ROOT/apps/cloudflared/workload.json"
    bake "$REPO_ROOT/apps/ttyd/workload.json"
  })

  local extra_ingress
  extra_ingress=$(echo "$bare_workloads" | extract_extra_ingress)

  local workloads
  workloads=$({
    echo "$bare_workloads"
    DD_CP_URL="$cp" \
      DD_ITA_MODE="$ita_mode" \
      DD_ITA_API_KEY="$DD_ITA_API_KEY" \
      DD_ENV="$env" \
      DD_VM_NAME="dd-local-$name" \
      DD_EXTRA_INGRESS="$extra_ingress" \
      DD_RELEASE_TAG="$DD_RELEASE_TAG" \
      DD_OWNER="$EE_OWNER" \
      DD_OWNER_ID="$EE_OWNER_ID" \
      DD_OWNER_KIND="$EE_OWNER_KIND" \
      bake "$REPO_ROOT/apps/dd-agent/workload.json.tmpl"
  } | jq -cs '.')

  {
    echo "EE_OWNER=$EE_OWNER"
    echo "EE_OWNER_ID=$EE_OWNER_ID"
    echo "EE_OWNER_KIND=$EE_OWNER_KIND"
    echo "EE_BOOT_WORKLOADS=$workloads"
    # EE capture-socket tee target. Kept for forward compatibility: a
    # future workload (e.g. an attested proxy) can bind + listen on it.
    # Unpatched EE images ignore the variable; patched EE falls back to
    # running without capture when nothing is listening, so the
    # boot-of-the-listener ≠ boot-of-the-writer race is non-fatal.
    echo "EE_CAPTURE_SOCKET=/run/ee/capture.sock"
  } > "$tmp/agent.env"

  # ext4 — EE rootfs has no iso9660 module.
  truncate -s 4M "$out"
  # `-O ^has_journal` — 4 MB is below ext4's journal min (~8 MB),
  # silences "Filesystem too small for a journal". Config volume is
  # read-only so journaling isn't needed anyway.
  mkfs.ext4 -q -O ^has_journal -d "$tmp" "$out"
  echo "  wrote $out (env=$env, ita_mode=$ita_mode, extra_ingress=$extra_ingress)"
}

build_overlay() {
  # $1=name
  #
  # Just the root overlay — small, sparse, tracks EE boot state.
  # Real workload storage (podman images, HF model weights) lives on
  # a SEPARATE workload.qcow2 mounted at /dev/vdc inside the VM and
  # sized per the DD capacity rule — see `build_workload_disk`.
  local name="$1"
  local overlay="$IMG_DIR/dd-local-$name.qcow2"
  if [ -f "$overlay" ]; then
    echo "  overlay $overlay already exists (reusing)"
    return
  fi
  qemu-img create -q -F qcow2 -b "$BASE" -f qcow2 "$overlay" 20G
  echo "  wrote $overlay (20G sparse, backing $BASE)"
}

build_workload_disk() {
  # $1=name   $2=size-spec (e.g. 160G, 1920G)
  #
  # Persistent podman storage as a separate qcow2, ext4-formatted
  # so EE's `mount-data` workload can mount it at `/data` (where
  # podman-bootstrap looks for overlay driver backing).
  # Sparse, so it occupies little space until something actually writes.
  # Uses qemu-nbd + mkfs.ext4 for one-time format.
  local name="$1" size="${2:-160G}"
  local disk="$IMG_DIR/dd-local-$name-workload.qcow2"
  if [ -f "$disk" ]; then
    echo "  workload disk $disk already exists (reusing)"
    return
  fi
  qemu-img create -q -f qcow2 "$disk" "$size"
  # Load nbd + pick first free /dev/nbdN. Idempotent.
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
  # Retry — qemu-nbd returns before the device is fully ready for IO.
  for _ in 1 2 3 4 5; do
    if sudo mkfs.ext4 -q -L workload "$nbd" 2>/dev/null; then
      break
    fi
    sleep 1
  done
  sudo qemu-nbd --disconnect "$nbd" >/dev/null
  echo "  wrote $disk ($size ext4, label=workload)"
}

render_domain_xml() {
  # $1=name
  local name="$1"
  local out="/tmp/dd-local-$name.xml"

  virsh dumpxml "$BASE_DOMAIN" > "$out"

  # Rename domain, strip UUID (libvirt regens), strip MAC (libvirt regens).
  sed -i "s|<name>$BASE_DOMAIN</name>|<name>dd-local-$name</name>|" "$out"
  sed -i '/<uuid>/d' "$out"
  sed -i '/<mac address=/d' "$out"

  # Rewrite disk paths to this agent's overlay + config.
  sed -i "s|$IMG_DIR/$BASE_DOMAIN.qcow2|$IMG_DIR/dd-local-$name.qcow2|g" "$out"
  sed -i "s|$IMG_DIR/$BASE_DOMAIN-config.iso|$IMG_DIR/dd-local-$name-config.iso|g" "$out"

  # Inject the workload disk as /dev/vdc right after the config iso
  # (vdb). podman-bootstrap waits for a `mountpoint` at
  # /data — mount-data satisfies that from
  # this disk. Without it, podman falls back to vfs-on-tmpfs and can't
  # hold a single modern container image.
  python3 - "$out" "$IMG_DIR/dd-local-$name-workload.qcow2" <<'PY'
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
# Append after the last existing <disk>..</disk> block so bus/slot
# assignment stays libvirt's job (no <address> specified).
x = re.sub(r"(</disk>\n)(?=(?:(?!</disk>).)*?</devices>)", r"\1" + new_disk, x, count=1, flags=re.DOTALL)
with open(xml_path, "w") as f: f.write(x)
PY
  # Rewrite the serial/console log file — base XML points at
  # /var/log/ee-local.log, which libvirt opens exclusively. Two VMs
  # sharing the same path collide with "Device or resource busy".
  sed -i "s|/var/log/ee-local\\.log|/var/log/ee-local-$name.log|g" "$out"
  sed -i "s|<model type='e1000e'/>|<model type='virtio'/>|g" "$out"

  # The local-tdx-qcow2 UKI is intentionally unsigned; this host's
  # OVMF.tdx.fd rejects it with UEFI "Access Denied". Use the non-secure
  # TDVF build when present while keeping launchSecurity type=tdx below.
  if [ -r /usr/share/ovmf/OVMF.fd ]; then
    sed -i -E "s|<loader([^>]*)>/usr/share/ovmf/OVMF\\.tdx\\.fd</loader>|<loader\\1>/usr/share/ovmf/OVMF.fd</loader>|" "$out"
  fi

  # CPU-only agent sizing.
  local mem_kib=16777216    # 16 GiB
  local vcpus=4
  sed -i -E "s|<memory unit='KiB'>[0-9]+</memory>|<memory unit='KiB'>$mem_kib</memory>|" "$out"
  sed -i -E "s|<currentMemory unit='KiB'>[0-9]+</currentMemory>|<currentMemory unit='KiB'>$mem_kib</currentMemory>|" "$out"
  sed -i -E "s|<vcpu placement='static'>[0-9]+</vcpu>|<vcpu placement='static'>$vcpus</vcpu>|" "$out"

  # Wire QEMU's tdx-guest to the host's QGS vsock so the guest's
  # TDVMCALL for a quote actually reaches Intel's quote-generation
  # service. Without this, configfs-tsm `outblob` returns 0 bytes →
  # ITA mint POSTs an empty quote → Intel rejects → agent fails to
  # register. Idempotent: skips if the launchSecurity element is
  # already expanded.
  if grep -q "<launchSecurity type='tdx'/>" "$out"; then
    sed -i "s|<launchSecurity type='tdx'/>|<launchSecurity type='tdx'><policy>0x10000000</policy><quoteGenerationService><SocketAddress type='vsock' cid='2' port='4050'/></quoteGenerationService></launchSecurity>|" "$out"
  elif grep -q "<launchSecurity type='tdx'>" "$out" && ! grep -q "quoteGenerationService" "$out"; then
    sed -i "s|</launchSecurity>|  <quoteGenerationService><SocketAddress type='vsock' cid='2' port='4050'/></quoteGenerationService>\n  </launchSecurity>|" "$out"
  fi

  # Strip any inherited passthrough devices from the base domain.
  awk 'BEGIN{skip=0}
       /<hostdev /{skip=1}
       !skip{print}
       /<\/hostdev>/{skip=0}' "$out" > "$out.tmp" && mv "$out.tmp" "$out"
  awk 'BEGIN{skip=0}
       /<tpm/{skip=1}
       !skip{print}
       /<\/tpm>/{skip=0}' "$out" > "$out.tmp" && mv "$out.tmp" "$out"

  echo "$out"
}

undefine_domain() {
  local vm="$1"

  virsh destroy "$vm" 2>/dev/null || true
  virsh dominfo "$vm" >/dev/null 2>&1 || return 0

  virsh undefine "$vm" --managed-save --snapshots-metadata --nvram 2>/dev/null \
    || virsh undefine "$vm" --managed-save --snapshots-metadata 2>/dev/null \
    || virsh undefine "$vm" 2>/dev/null \
    || true

  if virsh dominfo "$vm" >/dev/null 2>&1; then
    echo "failed to undefine existing libvirt domain '$vm'" >&2
    exit 1
  fi
}

define_agent() {
  # $1=name, $2=cp_url
  local name="$1" cp="$2"
  local env_label
  env_label=$(env_from_url "$cp")

  echo "== dd-local-$name → $cp (env=$env_label) =="
  build_overlay "$name"
  # Workload disk (/dev/vdc, ext4, mounted at /data by the mount-data
  # boot workload). Sparse qcow2, so only grows with actual writes.
  build_workload_disk "$name" 160G
  build_config_iso "$name" "$cp" "$env_label"
  local xml
  xml=$(render_domain_xml "$name")
  undefine_domain "dd-local-$name"
  virsh define "$xml" >/dev/null
  echo "  defined dd-local-$name (xml at $xml)"
}

[ -n "$PREVIEW_CP" ] && define_agent preview "$PREVIEW_CP"
[ -n "$PROD_CP"    ] && define_agent prod    "$PROD_CP"
[ -n "$BOT_CP"     ] && define_agent bot     "$BOT_CP"

echo
echo "done. start with:"
[ -n "$PREVIEW_CP" ] && echo "  virsh start dd-local-preview"
[ -n "$PROD_CP"    ] && echo "  virsh start dd-local-prod"
[ -n "$BOT_CP"     ] && echo "  virsh start dd-local-bot"
echo
echo "watch registration (Ctrl-] to exit):"
[ -n "$PREVIEW_CP" ] && echo "  virsh console dd-local-preview"
[ -n "$PROD_CP"    ] && echo "  virsh console dd-local-prod"
[ -n "$BOT_CP"     ] && echo "  virsh console dd-local-bot"

# Explicit 0 — the tail `[ -n "$BOT_CP" ] && …` returns 1 when
# BOT_CP="" (preview/prod-only), bubbling up as the script exit
# status and tripping set -e in dd-relaunch.sh. Force success.
exit 0
