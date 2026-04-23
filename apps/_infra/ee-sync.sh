#!/usr/bin/env bash
# ee-sync.sh — keep `/var/lib/libvirt/images/easyenclave-local.qcow2` on
# the tdx2 host in sync with the right easyenclave release channel.
#
# Sourced by dd-relaunch.sh + dd-relaunch-cp.sh. Each relaunch:
#   1. Resolves the desired EE tag — explicit `DD_EE_TAG` wins, else
#      the latest release matching `DD_EE_CHANNEL` (stable | staging).
#   2. Compares against the sidecar `.tag` file next to the qcow2.
#   3. Downloads + atomic-renames into place if different.
#
# Channel mapping lives in the callers: dd `production` / `dd-local-prod`
# track EE `stable` (v*); everything else tracks EE `staging` (image-*
# prereleases on main). An explicit `DD_EE_TAG` overrides the channel
# default for pre-flight-testing a candidate EE against dd before
# promoting the prerelease.
#
# The sidecar tag file (`<base>.tag`) is the only persistent state
# besides the qcow2 itself. If it drifts (operator manually SCP'd a
# qcow2 without updating the tag), the next sync that hits a channel
# default will pull the channel's latest and overwrite — cheaper than
# hash-compare over a 300 MB file.

# Intentionally no `set -e` here; callers already run under `set -euo`.
# We return a non-zero code from sync_base on hard failure so the
# caller's pipefail kills the relaunch before anything destructive.

EE_REPO="${EE_REPO:-easyenclave/easyenclave}"
EE_ASSET_PATTERN="${EE_ASSET_PATTERN:-easyenclave-*-local-tdx-qcow2.qcow2}"

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
        # day easyenclave cuts a `v*` stable tag, that release gets a
        # later `createdAt` than every existing prerelease, and an
        # unfiltered newest-first query would collapse staging onto
        # stable — defeating the whole channel-split. Explicitly keep
        # only `isPrerelease: true` entries. The first `image-*` tag
        # cut on main before the v* release always wins.
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
  # a matching asset (e.g. a pre-merge-of-easyenclave#87 release, or a
  # partial release-staging failure), keep the existing base rather
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

  # Ensure libvirt can read it — qemu runs as libvirt-qemu:kvm.
  chown libvirt-qemu:kvm "$tmp" 2>/dev/null || true
  mv "$tmp" "$base"
  echo "$target" > "$base.tag"
  echo "ee-sync: $base ${current:-<none>} -> $target (channel=$channel)"
}
