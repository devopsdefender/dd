#!/usr/bin/env bash
# ee-sync.sh — keep `/var/lib/libvirt/images/easyenclave-local.qcow2` on
# the tdx2 host in sync with the right easyenclave-mini release channel.
#
# Sourced by dd-relaunch.sh + dd-relaunch-cp.sh. Each relaunch:
#   1. Resolves the desired EE tag — explicit `DD_EE_TAG` wins, else
#      the latest release matching `DD_EE_CHANNEL` (stable | staging).
#   2. Compares against the sidecar `.tag` file next to the qcow2.
#   3. Downloads + atomic-renames into place if different.
#
# Both prod and preview pass an explicit `DD_EE_TAG` pin from
# release.yml's deploy-production / deploy-preview `with:` blocks.
# Neither env tracks a channel dynamically — the pin only moves when
# release.yml is updated in a PR. `DD_EE_TAG` always wins over
# `DD_EE_CHANNEL` below; the channel-resolver fallback is kept only
# for the workflow_dispatch-with-blank-ee_tag rollback escape-hatch
# and for the (currently unused) GCP image-family path.
#
# The sidecar tag file (`<base>.tag`) is the only persistent state
# besides the qcow2 itself. If it drifts (operator manually SCP'd a
# qcow2 without updating the tag), the next sync that hits a channel
# default will pull the channel's latest and overwrite — cheaper than
# hash-compare over a 300 MB file.

# Intentionally no `set -e` here; callers already run under `set -euo`.
# We return a non-zero code from sync_base on hard failure so the
# caller's pipefail kills the relaunch before anything destructive.

EE_REPO="${EE_REPO:-easyenclave/easyenclave-mini}"
EE_ASSET_PATTERN="${EE_ASSET_PATTERN:-easyenclave*-*-local-tdx-qcow2.qcow2}"

qemu_owner() {
  local conf="/etc/libvirt/qemu.conf"
  local user="" group=""

  if [ -r "$conf" ]; then
    user=$(sed -nE 's/^[[:space:]]*user[[:space:]]*=[[:space:]]*"?([^"#]+)"?.*/\1/p' "$conf" | tail -1)
    group=$(sed -nE 's/^[[:space:]]*group[[:space:]]*=[[:space:]]*"?([^"#]+)"?.*/\1/p' "$conf" | tail -1)
  fi

  printf '%s:%s\n' "${user:-libvirt-qemu}" "${group:-kvm}"
}

ensure_base_domain() {
  local base="${1:?usage: ensure_base_domain <path-to-base-qcow2> [domain-name]}"
  local domain="${2:-easyenclave-local}"
  local img_dir config tmp loader owner

  if virsh dominfo "$domain" >/dev/null 2>&1; then
    return 0
  fi

  [ -r "$base" ] || {
    echo "ee-sync: missing base image $base; cannot define $domain" >&2
    return 1
  }
  command -v virt-install >/dev/null || {
    echo "ee-sync: virt-install required to define missing $domain template" >&2
    return 1
  }

  img_dir="$(dirname "$base")"
  config="$img_dir/$domain-config.iso"
  if [ ! -f "$config" ]; then
    tmp=$(mktemp -d)
    {
      echo "EE_OWNER=bootstrap"
      echo "EE_BOOT_WORKLOADS=[]"
    } > "$tmp/agent.env"
    truncate -s 4M "$config"
    mkfs.ext4 -q -O ^has_journal -d "$tmp" "$config"
    rm -rf "$tmp"
  fi

  owner=$(qemu_owner)
  chown "$owner" "$base" "$config" 2>/dev/null || chmod 0644 "$base" "$config" 2>/dev/null || true

  for loader in /usr/share/ovmf/OVMF.fd /usr/share/ovmf/OVMF.tdx.fd /usr/share/OVMF/OVMF_CODE.fd; do
    [ -r "$loader" ] && break
  done
  [ -r "$loader" ] || {
    echo "ee-sync: no readable OVMF firmware found for $domain" >&2
    return 1
  }

  echo "ee-sync: defining missing libvirt template $domain from $base"
  virt-install \
    --connect "${LIBVIRT_DEFAULT_URI:-qemu:///system}" \
    --name "$domain" \
    --memory 16384 \
    --vcpus 4 \
    --cpu host-passthrough \
    --import \
    --disk "path=$base,format=qcow2,bus=virtio" \
    --disk "path=$config,device=cdrom" \
    --network "network=default,model=virtio" \
    --graphics none \
    --console "pty,target_type=serial,log.file=/var/log/ee-local.log,log.append=on" \
    --boot "loader=$loader,loader.readonly=yes,loader.type=pflash" \
    --launchSecurity type=tdx \
    --osinfo detect=on,require=off \
    --noautoconsole \
    --print-xml \
    | virsh define /dev/stdin >/dev/null
}

sync_base() {
  local base="${1:?usage: sync_base <path-to-base-qcow2>}"
  local channel="${DD_EE_CHANNEL:-staging}"
  local target="${DD_EE_TAG:-}"

  # Resolve target tag from channel if no explicit pin.
  if [ -z "$target" ]; then
    case "$channel" in
      stable)
        # Stable = latest non-prerelease. `--exclude-pre-releases` is a
        # `gh release list` flag.
        target=$(gh release list --repo "$EE_REPO" \
                 --exclude-pre-releases --limit 1 \
                 --json tagName -q '.[0].tagName' 2>/dev/null)
        ;;
      staging)
        # Staging = newest prerelease. NOT `--limit 1` unfiltered: the
        # day easyenclave-mini cuts a `v*` stable tag, that release gets a
        # later `createdAt` than every existing prerelease, and an
        # unfiltered newest-first query would collapse staging onto
        # stable — defeating the whole channel-split. Explicitly keep
        # only `isPrerelease: true` entries. The newest mini prerelease
        # wins, regardless of whether the tag uses `image-*` or
        # `mini-image-*`.
        target=$(gh release list --repo "$EE_REPO" --limit 20 \
                 --json tagName,isPrerelease \
                 -q '[.[] | select(.isPrerelease)][0].tagName' 2>/dev/null)
        ;;
      *)
        echo "ee-sync: unknown DD_EE_CHANNEL=$channel (want stable|staging)" >&2
        return 2
        ;;
    esac
    if [ -z "$target" ]; then
      echo "ee-sync: failed to resolve $channel tag from $EE_REPO (gh auth?)" >&2
      return 2
    fi
  fi

  local current=""
  [ -f "$base.tag" ] && current=$(cat "$base.tag")

  if [ "$target" = "$current" ] && [ -f "$base" ]; then
    echo "ee-sync: $base @ $current (channel=$channel, up to date)"
    return 0
  fi

  local tmp="$base.tmp.$$"
  trap 'rm -f "$tmp"' RETURN
  # Download is best-effort: if the candidate release doesn't yet carry
  # a matching asset (e.g. a partial release-staging failure), keep the
  # existing base rather
  # than aborting the deploy. The tag sidecar is NOT updated in that
  # case, so the next run retries. An existing base is always
  # preferable to no base — worst-case we just keep running slightly
  # stale EE until the asset reappears.
  if ! gh release download "$target" --repo "$EE_REPO" \
         --pattern "$EE_ASSET_PATTERN" --output "$tmp" 2>&1; then
    if [ -f "$base" ]; then
      echo "ee-sync: $target has no '$EE_ASSET_PATTERN' asset yet; keeping existing $base (tag=$current)" >&2
      return 0
    fi
    echo "ee-sync: download failed for $target (pattern=$EE_ASSET_PATTERN), no existing $base to fall back to" >&2
    return 3
  fi

  # Ensure libvirt can read/write it. Some DD hosts run qemu as
  # ubuntu:ubuntu with dynamic ownership disabled; others use the
  # distro default libvirt-qemu:kvm.
  chown "$(qemu_owner)" "$tmp" 2>/dev/null || chmod 0644 "$tmp" 2>/dev/null || true
  mv "$tmp" "$base"
  echo "$target" > "$base.tag"
  echo "ee-sync: $base ${current:-<none>} -> $target (channel=$channel)"
}
