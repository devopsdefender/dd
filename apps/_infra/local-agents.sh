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
: "${DD_PAT?set DD_PAT (e.g. DD_PAT=\$(gh auth token))}"
: "${DD_ITA_API_KEY?set DD_ITA_API_KEY}"

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
# `$((…))` arithmetic inside shell cmd strings are left alone —
# otherwise envsubst would eat shell locals in openclaw's `until`
# loop and produce broken scripts.
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

  # Boot workload chain (EE spawns concurrently; each uses `until`
  # loops to self-sequence):
  #   nv             — insmod nvidia driver (prod only, first so the
  #                    device nodes exist by the time ollama runs)
  #   mount-models   — mount /dev/vdc at /var/lib/easyenclave/ollama
  #   podman-static  — fetch the podman binary tarball into /var/lib/easyenclave/bin
  #   podman-bootstrap — stage binaries, write containers.conf + policy.json,
  #                    install /var/lib/easyenclave/bin/podman as the wrapper
  #                    (symlinked from dd-podman for back-compat)
  #   ollama         — run docker.io/ollama/ollama:latest serve via the wrapper
  #   openclaw       — wait for ollama, pull $MODEL, launch openclaw gateway
  #   cloudflared    — fetch cloudflared binary (dd-register spawns it)
  #   dd-agent       — run devopsdefender agent, register with CP, serve workloads
  #
  # Prod gets the GPU model; preview gets the tiny CPU-friendly one.
  local model ollama_spec
  if [ "$with_gpu" = "yes" ]; then
    model="qwen2.5:7b"
    ollama_spec="$REPO_ROOT/apps/ollama/workload.prod.json"
  else
    model="qwen2.5:0.5b"
    ollama_spec="$REPO_ROOT/apps/ollama/workload.preview.json"
  fi

  local workloads
  workloads=$({
    [ "$with_gpu" = "yes" ] && bake "$REPO_ROOT/apps/nv/workload.json"
    bake "$REPO_ROOT/apps/mount-models/workload.json"
    bake "$REPO_ROOT/apps/podman-static/workload.json"
    bake "$REPO_ROOT/apps/podman-bootstrap/workload.json"
    bake "$ollama_spec"
    MODEL="$model" bake "$REPO_ROOT/apps/openclaw/workload.json.tmpl"
    bake "$REPO_ROOT/apps/cloudflared/workload.json"
    DD_CP_URL="$cp" \
      DD_PAT="$DD_PAT" \
      DD_ITA_API_KEY="$DD_ITA_API_KEY" \
      DD_ENV="$env" \
      DD_VM_NAME="dd-local-$name" \
      bake "$REPO_ROOT/apps/dd-agent/workload.json.tmpl"
  } | jq -cs '.')

  {
    echo "EE_OWNER=devopsdefender"
    echo "EE_BOOT_WORKLOADS=$workloads"
  } > "$tmp/agent.env"

  # ext4 — EE rootfs has no iso9660 module.
  truncate -s 4M "$out"
  mkfs.ext4 -q -d "$tmp" "$out"
  echo "  wrote $out (env=$env, gpu=$with_gpu, model=$model)"
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

# Persistent models disk — survives VM relaunch, so ollama doesn't
# re-download the model each time. Pre-formatted ext4 on the host;
# the guest just mounts it.
build_models_disk() {
  # $1=name, $2=size_gb
  local name="$1" size_gb="$2"
  local models="$IMG_DIR/dd-local-$name-models.qcow2"
  if [ -f "$models" ]; then
    echo "  models disk $models already exists (reusing)"
    return
  fi
  qemu-img create -q -f raw "$models.raw" "${size_gb}G"
  mkfs.ext4 -q -F "$models.raw"
  qemu-img convert -q -f raw -O qcow2 "$models.raw" "$models"
  rm -f "$models.raw"
  echo "  wrote $models (${size_gb}G ext4)"
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
  # 2 vCPU — fine for a bare agent, undersized for podman + ollama
  # + the openclaw gateway on a 900 MB container image. Host has
  # 243 GiB / 64 cores, so we can be generous.
  #
  #   prod:    32 GiB / 16 vCPU  (GPU handles the model; host RAM
  #                               for podman, openclaw, image pull
  #                               scratch, model load spill)
  #   preview: 16 GiB / 8 vCPU   (CPU-only inference; qwen2.5:0.5b
  #                               + 64k ctx + gateway)
  if [ "$with_gpu" = "yes" ]; then
    local mem_kib=33554432  # 32 GiB
    local vcpus=16
  else
    local mem_kib=16777216  # 16 GiB
    local vcpus=8
  fi
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

  # Add a persistent models disk as vdc. EE will mount it at
  # /var/lib/easyenclave/ollama via the mount-models boot workload.
  local models="$IMG_DIR/dd-local-$name-models.qcow2"
  local disk_block="    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2'/>
      <source file='$models'/>
      <target dev='vdc' bus='virtio'/>
    </disk>"
  # Insert before </devices>.
  awk -v block="$disk_block" '
    /<\/devices>/ { print block }
    { print }
  ' "$out" > "$out.tmp" && mv "$out.tmp" "$out"

  echo "$out"
}

define_agent() {
  # $1=name, $2=cp_url, $3=with_gpu
  local name="$1" cp="$2" with_gpu="$3"
  local env_label
  env_label=$(env_from_url "$cp")

  echo "== dd-local-$name → $cp (env=$env_label, gpu=$with_gpu) =="
  build_overlay "$name"
  # Models disk: prod holds the GPU model (few GB), preview holds the small CPU one.
  if [ "$with_gpu" = "yes" ]; then
    build_models_disk "$name" 40
  else
    build_models_disk "$name" 10
  fi
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
