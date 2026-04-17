#!/usr/bin/env bash
# ollama-deploy.sh — run ollama + OpenClaw inside a DD agent VM as
# podman containers. No ollama binary on the guest rootfs (that's
# dynamically linked and fails on EE's busybox rootfs with
# `libstdc++.so.6: cannot open shared object file`). Instead:
#
#   1. Fetch static podman (mgoltzsche/podman-static tarball) as a
#      fetch-only DD workload.
#   2. One-shot bootstrap via /exec — flatten the tarball's nested
#      bin dir into /var/lib/easyenclave/bin and write a minimal
#      /etc/containers/containers.conf (cgroup_manager=cgroupfs so
#      we don't need systemd).
#   3. Deploy the ollama container as a long-running workload
#      (podman run --net=host ...). Prod also passes the three
#      nvidia device nodes for H100 access.
#   4. Pull the right-sized model via `podman exec ollama ollama pull`.
#   5. Launch OpenClaw (a bridge from messaging apps to coding
#      agents; subcommand of ollama, npm-installed on first run) as
#      a second long-running workload using the same container.
#
#   ollama-deploy.sh <kind> <cp_url>
#     kind:    prod | preview
#     cp_url:  https://app.devopsdefender.com | https://pr-N.devopsdefender.com
#
# Requires DD_PAT in the environment (the workflow's GITHUB_TOKEN).

set -euo pipefail

KIND="${1?usage: ollama-deploy.sh <prod|preview> <cp_url>}"
CP_URL="${2?cp_url required}"
: "${DD_PAT?}"

case "$KIND" in
  prod)
    MODEL="llama3.1:8b"
    # GPU passthrough. /dev/nvidia-uvm appears once CUDA is touched;
    # the nv-insmod boot workload in scripts/local-agents.sh loads
    # the kernel module, so the device nodes exist by this point.
    GPU_FLAGS='["--device=/dev/nvidia0","--device=/dev/nvidiactl","--device=/dev/nvidia-uvm"]'
    ;;
  preview)
    MODEL="qwen2.5:0.5b"
    GPU_FLAGS='[]'
    ;;
  *) echo "unknown kind: $KIND" >&2; exit 2 ;;
esac

VM_NAME="dd-local-$KIND"
AUTH=(-H "Authorization: Bearer $DD_PAT")

echo "== ollama-deploy $VM_NAME (model=$MODEL, cp=$CP_URL) =="

# ── 1. Discover the fresh agent registration on the CP ─────────────
# last_seen > started_at_iso filters out stale entries from the VM
# generation we just destroyed during `virsh destroy`.
started_at_iso="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "  waiting for a fresh ${VM_NAME} registration (last_seen > ${started_at_iso})"
agent_host=""
for i in $(seq 1 60); do
  agent_host=$(curl -fsS "${AUTH[@]}" "$CP_URL/api/agents" 2>/dev/null \
    | jq -r --arg vm "$VM_NAME" --arg since "$started_at_iso" '
        [.[] | select(.vm_name==$vm and .status=="healthy" and .last_seen > $since)]
        | sort_by(.last_seen) | reverse | .[0].hostname // empty' 2>/dev/null || true)
  if [ -n "$agent_host" ] && [ "$agent_host" != "null" ]; then
    break
  fi
  sleep 10
done
if [ -z "$agent_host" ] || [ "$agent_host" = "null" ]; then
  echo "ERROR: $VM_NAME never appeared in CP fleet" >&2
  exit 1
fi
echo "  agent: https://$agent_host"

# ── 2. Wait for Cloudflare DNS to propagate ────────────────────────
echo "  waiting for DNS on $agent_host..."
for i in $(seq 1 30); do
  if getent hosts "$agent_host" >/dev/null 2>&1; then
    echo "  DNS resolved"
    break
  fi
  sleep 5
done

agent() { curl -fsS --max-time 300 "${AUTH[@]}" "https://$agent_host$1" "${@:2}"; }

# ── 3. Fetch podman-static (fetch-only DD workload) ────────────────
# Tarball unpacks to /var/lib/easyenclave/bin/podman-linux-amd64/
# with usr/local/bin/{podman,crun,conmon,netavark,...}.
echo "  POST /deploy podman-static..."
A_SPEC=$(jq -c -n '{
  app_name: "podman-static",
  github_release: {
    repo: "mgoltzsche/podman-static",
    asset: "podman-linux-amd64.tar.gz",
    tag: "latest"
  }
}')
agent /deploy -H 'Content-Type: application/json' -d "$A_SPEC" | jq -c '.' || true

echo "  waiting for podman binary to appear..."
podman_path="/var/lib/easyenclave/bin/podman-linux-amd64/usr/local/bin/podman"
for i in $(seq 1 60); do
  resp=$(agent /exec -H 'Content-Type: application/json' \
    -d "$(jq -c -n --arg p "$podman_path" '{cmd:["/bin/busybox","sh","-c",("test -x " + $p + " && echo found")],timeout_secs:5}')" \
    2>/dev/null || true)
  if echo "$resp" | grep -q found; then
    echo "  podman unpacked"
    break
  fi
  sleep 5
done

# ── 4. Bootstrap: flatten bin dir + write containers.conf ──────────
# Rootful podman defaults to the systemd cgroup manager, which we
# don't have. Override to cgroupfs. crun is the default runtime in
# the mgoltzsche tarball; naming it explicitly is belt-and-braces.
echo "  bootstrapping /etc/containers/containers.conf + flattening /var/lib/easyenclave/bin..."
bootstrap_sh='set -e
cp -f /var/lib/easyenclave/bin/podman-linux-amd64/usr/local/bin/* /var/lib/easyenclave/bin/
mkdir -p /etc/containers
cat > /etc/containers/containers.conf <<EOF
[engine]
cgroup_manager = "cgroupfs"
runtime = "crun"
EOF
echo podman-bootstrap: ok'
boot_resp=$(agent /exec -H 'Content-Type: application/json' \
  -d "$(jq -c -n --arg s "$bootstrap_sh" '{cmd:["/bin/busybox","sh","-c",$s],timeout_secs:30}')")
echo "  bootstrap: $(echo "$boot_resp" | jq -r '.stdout // .stderr // ""' | tail -3)"

# ── 5. Launch the ollama container (long-running workload) ─────────
# --net=host  : ollama listens on guest's 127.0.0.1:11434.
# --name      : so we can `podman exec ollama ...` by name.
# --cgroup-manager=cgroupfs: matches containers.conf, still required
#               on the command line because podman doesn't always
#               pick it up from the engine section when invoked
#               outside systemd.
# Volume      : /var/lib/easyenclave/ollama is the persistent vdc
#               ext4 disk (mounted by the mount-models boot workload
#               in local-agents.sh); doubles as ollama's model cache
#               and openclaw's npm prefix.
echo "  POST /deploy ollama container..."
OLLAMA_SPEC=$(jq -c -n --argjson gpu "$GPU_FLAGS" '{
  app_name: "ollama",
  cmd: ([
    "/var/lib/easyenclave/bin/podman", "run",
    "--rm", "--name", "ollama",
    "--net=host",
    "--cgroup-manager=cgroupfs"
  ] + $gpu + [
    "-v", "/var/lib/easyenclave/ollama:/root/.ollama",
    "-e", "OLLAMA_HOST=127.0.0.1:11434",
    "docker.io/ollama/ollama:latest",
    "serve"
  ])
}')
agent /deploy -H 'Content-Type: application/json' -d "$OLLAMA_SPEC" | jq -c '.' || true

# ── 6. Wait for ollama HTTP to come up inside the container ────────
# `podman exec ollama ollama list` exits 0 once the server is ready.
# First run has to pull ~900 MB of container image, so allow plenty.
echo "  waiting for ollama to be ready (first run pulls the image)..."
for i in $(seq 1 120); do
  resp=$(agent /exec -H 'Content-Type: application/json' \
    -d '{"cmd":["/var/lib/easyenclave/bin/podman","exec","ollama","ollama","list"],"timeout_secs":15}' \
    2>/dev/null || true)
  if echo "$resp" | jq -e '.exit_code == 0' >/dev/null 2>&1; then
    echo "  ollama responding"
    break
  fi
  sleep 10
done

# ── 7. Pull the model ──────────────────────────────────────────────
echo "  pulling $MODEL (this can take a few minutes)..."
pull_resp=$(agent /exec -H 'Content-Type: application/json' \
  -d "$(jq -c -n --arg m "$MODEL" '{
    cmd:["/var/lib/easyenclave/bin/podman","exec","ollama","ollama","pull",$m],
    timeout_secs:1800
  }')")
echo "  pull: $(echo "$pull_resp" | jq -r '.stdout // "(no stdout)"' | tail -3)"

# ── 8. Launch OpenClaw ─────────────────────────────────────────────
# `ollama launch openclaw` installs via npm on first run if missing
# and then stays foreground, so we register it as a second long-
# running workload. --yes accepts the install prompt non-interactively.
echo "  POST /deploy openclaw..."
OPENCLAW_SPEC=$(jq -c -n --arg m "$MODEL" '{
  app_name: "openclaw",
  cmd: [
    "/var/lib/easyenclave/bin/podman", "exec", "ollama",
    "ollama", "launch", "openclaw",
    "--model", $m,
    "--yes"
  ]
}')
agent /deploy -H 'Content-Type: application/json' -d "$OPENCLAW_SPEC" | jq -c '.' || true

# ── 9. Confirm openclaw is registered and talking to us ────────────
# Two probes:
#   a) EE lists `openclaw` in /health — proves the workload was
#      accepted (weak — flips on fork, before npm install finishes).
#   b) `openclaw plugins list` inside the container exits 0 — proves
#      the gateway daemon is actually responsive. That subcommand
#      goes through the running gateway, so an unresponsive or
#      still-installing openclaw fails it. Strongest documented probe
#      short of an HTTP port (which the docs don't publish).
echo "  confirming openclaw workload is registered..."
for i in $(seq 1 30); do
  list=$(agent /health 2>/dev/null || true)
  if echo "$list" | jq -e '.deployments // [] | index("openclaw")' >/dev/null 2>&1; then
    echo "  openclaw: registered"
    break
  fi
  sleep 5
done

# First launch can take a while because of the npm install of
# @ollama/openclaw + the web-search/fetch plugin. 5 min ceiling.
echo "  waiting for openclaw gateway to respond to CLI..."
openclaw_ok=0
for i in $(seq 1 60); do
  resp=$(agent /exec -H 'Content-Type: application/json' \
    -d '{"cmd":["/var/lib/easyenclave/bin/podman","exec","ollama","openclaw","plugins","list"],"timeout_secs":15}' \
    2>/dev/null || true)
  if echo "$resp" | jq -e '.exit_code == 0' >/dev/null 2>&1; then
    echo "  openclaw: responding"
    echo "  plugins:"
    echo "$resp" | jq -r '.stdout // ""' | sed 's/^/    /'
    openclaw_ok=1
    break
  fi
  sleep 5
done
if [ "$openclaw_ok" = "0" ]; then
  echo "  WARNING: openclaw plugins list never returned — gateway may still be installing"
  echo "  last /exec response:"
  echo "$resp" | jq -c '.' | head -c 500
fi

echo
echo "=== agent fleet summary ==="
echo "  agent:    https://$agent_host"
echo "  model:    $MODEL"
echo "  ollama:   podman container 'ollama' on host net, :11434"
echo "  openclaw: ollama launch openclaw — plugins listing responded"
echo "==========================="
