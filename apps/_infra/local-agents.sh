#!/usr/bin/env bash
# local-agents.sh — define two local TDX agent VMs on this host:
#
#   dd-local-preview : no GPU, registers with the PR-preview CP. Bare
#                      agent + podman — no demo workload — so the release
#                      pipeline can prove registration + tunnel end-to-end
#                      against per-PR CPs without needing GPU hardware.
#   dd-local-prod    : H100 passthrough, registers with production. The
#                      web-nvidia-smi demo is NOT a boot workload — it's
#                      deployed post-registration by a Release workflow
#                      step using GitHub Actions OIDC against the agent's
#                      /deploy endpoint. Boot stays fast and minimal.
#
# Both reuse the existing easyenclave base qcow2 via copy-on-write
# overlays; each gets its own config.iso baking in DD_CP_URL +
# DD_ITA_API_KEY for that target. No GitHub PAT — the agent
# authenticates to the CP via ITA attestation at /register and picks
# up a CF Access service token from the register response for all
# subsequent machine-to-machine calls. Libvirt XML is rendered from
# the existing `easyenclave-local` domain (strip hostdev for preview).
#
# Usage:
#   export DD_ITA_API_KEY="$(cat ~/.secrets/ita_api_key)"
#   ./apps/_infra/local-agents.sh https://pr-106.devopsdefender.com https://app.devopsdefender.com
#
# Pass "" for either URL to skip defining that VM:
#   ./apps/_infra/local-agents.sh "" https://app.devopsdefender.com   # prod only
#   ./apps/_infra/local-agents.sh https://pr-N.devopsdefender.com ""  # preview only
#
# After: virsh start dd-local-preview && virsh start dd-local-prod

set -euo pipefail

PREVIEW_CP="${1-}"
PROD_CP="${2-}"
if [ -z "$PREVIEW_CP" ] && [ -z "$PROD_CP" ]; then
  echo "usage: $0 <preview-cp-url|\"\"> <prod-cp-url|\"\">" >&2
  exit 1
fi
: "${DD_ITA_API_KEY?set DD_ITA_API_KEY}"
# DD_RELEASE_TAG pins which devopsdefender binary the agent downloads.
# Defaults to "latest" for ad-hoc runs; the relaunch-agent action sets
# it to the PR's release tag so preview deploys test the PR binary.
DD_RELEASE_TAG="${DD_RELEASE_TAG:-latest}"

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
  # $1=name, $2=cp_url, $3=env_label, $4=with_gpu(yes/no)
  local name="$1" cp="$2" env="$3" with_gpu="$4"
  local out="$IMG_DIR/dd-local-$name-config.iso"
  local tmp
  tmp=$(mktemp -d)
  trap "rm -rf $tmp" RETURN

  # Boot workload chain (EE spawns concurrently; dependents self-sequence
  # via `until` loops):
  #   nv             — insmod nvidia driver (prod only, first so device
  #                    nodes exist by the time web-nvidia-smi runs)
  #   podman-static  — fetch the podman tarball into /var/lib/easyenclave/bin
  #   podman-bootstrap — stage binaries, install /var/lib/easyenclave/bin/podman
  #                    wrapper + containers.conf + policy.json
  #   web-nvidia-smi — prod only. Run nvidia/cuda container, serve
  #                    `nvidia-smi` output on :8081.
  #   cloudflared    — fetch binary (agent spawns the tunnel process)
  #   dd-agent       — register with CP, serve workloads. Requests the
  #                    gpu.<agent-host> ingress via $DD_EXTRA_INGRESS,
  #                    computed below from `expose` entries on the
  #                    baked workloads.
  # web-nvidia-smi is intentionally NOT a boot workload — it's
  # deployed post-registration by the Release workflow via GH OIDC.
  # Boot is: nvidia driver (GPU only), podman runtime, cloudflared.
  local bare_workloads
  bare_workloads=$({
    [ "$with_gpu" = "yes" ] && bake "$REPO_ROOT/apps/nv/workload.json"
    bake "$REPO_ROOT/apps/podman-static/workload.json"
    bake "$REPO_ROOT/apps/podman-bootstrap/workload.json"
    bake "$REPO_ROOT/apps/cloudflared/workload.json"
    # Bastion's template references ${DD_CP_URL} so its SPA can fan
    # out cross-origin to every agent in the fleet.
    DD_CP_URL="$cp" \
      DD_RELEASE_TAG="$DD_RELEASE_TAG" \
      bake "$REPO_ROOT/apps/bastion/workload.json.tmpl"
  })

  local extra_ingress
  extra_ingress=$(echo "$bare_workloads" | extract_extra_ingress)

  local workloads
  workloads=$({
    echo "$bare_workloads"
    DD_CP_URL="$cp" \
      DD_ITA_API_KEY="$DD_ITA_API_KEY" \
      DD_ENV="$env" \
      DD_VM_NAME="dd-local-$name" \
      DD_EXTRA_INGRESS="$extra_ingress" \
      DD_RELEASE_TAG="$DD_RELEASE_TAG" \
      bake "$REPO_ROOT/apps/dd-agent/workload.json.tmpl"
  } | jq -cs '.')

  {
    echo "EE_OWNER=devopsdefender"
    echo "EE_BOOT_WORKLOADS=$workloads"
    # Tells EE (>= capture-socket patch) to tee every spawned workload's
    # stdio to this unix socket. Bastion binds + listens on it; unpatched
    # EE images ignore the variable. Keeps the boot-of-the-listener ≠
    # boot-of-the-writer race non-fatal: EE falls back to running without
    # capture when the socket isn't there yet.
    echo "EE_CAPTURE_SOCKET=/run/ee/capture.sock"
  } > "$tmp/agent.env"

  # ext4 — EE rootfs has no iso9660 module.
  truncate -s 4M "$out"
  mkfs.ext4 -q -d "$tmp" "$out"
  echo "  wrote $out (env=$env, gpu=$with_gpu, extra_ingress=$extra_ingress)"
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
  # Rewrite the serial/console log file — base XML points at
  # /var/log/ee-local.log, which libvirt opens exclusively. Two VMs
  # sharing the same path collide with "Device or resource busy".
  sed -i "s|/var/log/ee-local\\.log|/var/log/ee-local-$name.log|g" "$out"

  # Size the VM for the workload. Base easyenclave-local is 4 GiB /
  # 2 vCPU — fine for a bare agent. The demo workloads are modest
  # (web-nvidia-smi just runs nvidia-smi on demand + one apt-get at
  # boot for netcat). Host has 243 GiB / 64 cores.
  local mem_kib=8388608   # 8 GiB
  local vcpus=8
  sed -i -E "s|<memory unit='KiB'>[0-9]+</memory>|<memory unit='KiB'>$mem_kib</memory>|" "$out"
  sed -i -E "s|<currentMemory unit='KiB'>[0-9]+</currentMemory>|<currentMemory unit='KiB'>$mem_kib</currentMemory>|" "$out"
  sed -i -E "s|<vcpu placement='static'>[0-9]+</vcpu>|<vcpu placement='static'>$vcpus</vcpu>|" "$out"

  # Wire QEMU's tdx-guest to the host's QGS unix socket so the guest's
  # TDVMCALL for a quote actually reaches Intel's quote-generation
  # service. Without this, configfs-tsm `outblob` returns 0 bytes →
  # ITA mint POSTs an empty quote → Intel rejects → agent fails to
  # register. Idempotent: skips if the launchSecurity element is
  # already expanded.
  if grep -q "<launchSecurity type='tdx'/>" "$out"; then
    sed -i "s|<launchSecurity type='tdx'/>|<launchSecurity type='tdx'><quoteGenerationService path='/var/run/tdx-qgs/qgs.socket'/></launchSecurity>|" "$out"
  fi

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
  build_config_iso "$name" "$cp" "$env_label" "$with_gpu"
  local xml
  xml=$(render_domain_xml "$name" "$with_gpu")
  virsh destroy "dd-local-$name" 2>/dev/null || true
  virsh undefine "dd-local-$name" --managed-save --snapshots-metadata 2>/dev/null || true
  virsh define "$xml" >/dev/null
  echo "  defined dd-local-$name (xml at $xml)"
}

[ -n "$PREVIEW_CP" ] && define_agent preview "$PREVIEW_CP" no
[ -n "$PROD_CP"    ] && define_agent prod    "$PROD_CP"    yes

echo
echo "done. start with:"
[ -n "$PREVIEW_CP" ] && echo "  virsh start dd-local-preview"
[ -n "$PROD_CP"    ] && echo "  virsh start dd-local-prod"
echo
echo "watch registration (Ctrl-] to exit):"
[ -n "$PREVIEW_CP" ] && echo "  virsh console dd-local-preview"
[ -n "$PROD_CP"    ] && echo "  virsh console dd-local-prod"

# Explicit 0 — the tail `[ -n "$PROD_CP" ] && …` returns 1 when
# PROD_CP="" (preview-only), bubbling up as the script exit status
# and tripping set -e in dd-relaunch.sh. Force success.
exit 0
