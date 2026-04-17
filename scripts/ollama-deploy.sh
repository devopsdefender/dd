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
# NOTE: omit `tag` — EE treats `tag: null` as "GET /releases/latest"
# (the real newest release), while `tag: "latest"` is a literal tag
# lookup and 404s on repos like mgoltzsche/podman-static that version
# their tags as v5.7.1 rather than with a rolling "latest" ref.
echo "  POST /deploy podman-static..."
A_SPEC=$(jq -c -n '{
  app_name: "podman-static",
  github_release: {
    repo: "mgoltzsche/podman-static",
    asset: "podman-linux-amd64.tar.gz"
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

# ── 4. Bootstrap: stage podman's helper binaries ───────────────────
# mgoltzsche's tarball layout:
#   usr/local/bin/                podman, crun, runc, fuse-overlayfs,
#                                 fusermount3, pasta, pasta.avx2
#   usr/local/lib/podman/         conmon, netavark, aardvark-dns,
#                                 rootlessport, catatonit
# EE's guest rootfs has BOTH /usr AND /etc mounted read-only. The
# only writable paths are under /var/lib/easyenclave (on the
# persistent vdc ext4 disk) and /run/tmp-style tmpfs locations. So
# we cannot write a containers.conf anywhere podman looks for one,
# and we cannot cp conmon into any of podman's hardcoded search
# dirs. Every path has to be on the podman CLI directly.
#
# We DO stage the helpers into /var/lib/easyenclave/bin so the
# container workload's `cmd[0]` can reach `podman`, and the
# --conmon / --runtime / --root / --runroot flags on the `podman`
# command (see step 5) point podman at the rest.
echo "  bootstrapping podman (staging binaries to writable dirs)..."
bootstrap_sh='set -e
BIN=/var/lib/easyenclave/bin
SRC=$BIN/podman-linux-amd64
cp -f $SRC/usr/local/bin/* $BIN/
cp -f $SRC/usr/local/lib/podman/conmon $BIN/
cp -f $SRC/usr/local/lib/podman/netavark $BIN/ 2>/dev/null || true
cp -f $SRC/usr/local/lib/podman/aardvark-dns $BIN/ 2>/dev/null || true
cp -f $SRC/usr/local/lib/podman/rootlessport $BIN/ 2>/dev/null || true
mkdir -p /var/lib/easyenclave/containers/storage /var/lib/easyenclave/containers/runroot
echo podman-bootstrap: ok'
boot_resp=$(agent /exec -H 'Content-Type: application/json' \
  -d "$(jq -c -n --arg s "$bootstrap_sh" '{cmd:["/bin/busybox","sh","-c",$s],timeout_secs:30}')")
if ! echo "$boot_resp" | jq -e '.exit_code == 0' >/dev/null 2>&1; then
  echo "ERROR: podman bootstrap failed"
  echo "$boot_resp" | jq .
  exit 1
fi
echo "  bootstrap: $(echo "$boot_resp" | jq -r '.stdout // ""' | tail -1)"

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
# Every writable path (--root, --runroot, --conmon, --runtime) is
# on the CLI because EE's /etc and /usr are read-only — podman
# can't fall back on /etc/containers/containers.conf the way it
# normally does. Storage lives on the persistent vdc disk so the
# 900 MB ollama image pull survives VM relaunches.
# --cgroup-manager=cgroupfs because there's no systemd in the guest.
# --network=host so ollama's :11434 binds on the VM's loopback,
# reachable from other EE workloads (like openclaw) and via /exec.
OLLAMA_SPEC=$(jq -c -n --argjson gpu "$GPU_FLAGS" '{
  app_name: "ollama",
  cmd: ([
    "/var/lib/easyenclave/bin/podman",
    "--conmon=/var/lib/easyenclave/bin/conmon",
    "--runtime=/var/lib/easyenclave/bin/crun",
    "--root=/var/lib/easyenclave/containers/storage",
    "--runroot=/var/lib/easyenclave/containers/runroot",
    "--cgroup-manager=cgroupfs",
    "run",
    "--rm", "--name", "ollama",
    "--network=host"
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
ollama_ready=0
for i in $(seq 1 120); do
  resp=$(agent /exec -H 'Content-Type: application/json' \
    -d '{"cmd":["/var/lib/easyenclave/bin/podman","--root=/var/lib/easyenclave/containers/storage","--runroot=/var/lib/easyenclave/containers/runroot","--cgroup-manager=cgroupfs","exec","ollama","ollama","list"],"timeout_secs":15}' \
    2>/dev/null || true)
  if echo "$resp" | jq -e '.exit_code == 0' >/dev/null 2>&1; then
    echo "  ollama responding"
    ollama_ready=1
    break
  fi
  sleep 10
done
if [ "$ollama_ready" = "0" ]; then
  echo "ERROR: ollama container never became ready (20 min timeout)"
  echo "  most recent /exec response:"
  echo "$resp" | jq .
  echo "  last 30 lines of 'podman ps -a' + 'podman logs ollama':"
  agent /exec -H 'Content-Type: application/json' \
    -d '{"cmd":["/var/lib/easyenclave/bin/podman","--root=/var/lib/easyenclave/containers/storage","--runroot=/var/lib/easyenclave/containers/runroot","ps","-a"],"timeout_secs":10}' | jq -r '.stdout // .stderr // ""'
  agent /exec -H 'Content-Type: application/json' \
    -d '{"cmd":["/var/lib/easyenclave/bin/podman","--root=/var/lib/easyenclave/containers/storage","--runroot=/var/lib/easyenclave/containers/runroot","logs","ollama"],"timeout_secs":10}' 2>&1 | jq -r '.stdout // .stderr // ""' | tail -30
  exit 1
fi

# ── 7. Pull the model ──────────────────────────────────────────────
echo "  pulling $MODEL (this can take a few minutes)..."
pull_resp=$(agent /exec -H 'Content-Type: application/json' \
  -d "$(jq -c -n --arg m "$MODEL" '{
    cmd:["/var/lib/easyenclave/bin/podman","--root=/var/lib/easyenclave/containers/storage","--runroot=/var/lib/easyenclave/containers/runroot","--cgroup-manager=cgroupfs","exec","ollama","ollama","pull",$m],
    timeout_secs:1800
  }')")
if ! echo "$pull_resp" | jq -e '.exit_code == 0' >/dev/null 2>&1; then
  echo "ERROR: ollama pull $MODEL failed"
  echo "$pull_resp" | jq .
  exit 1
fi
echo "  pull: $(echo "$pull_resp" | jq -r '.stdout // "(no stdout)"' | tail -3)"

# ── 8. Launch OpenClaw ─────────────────────────────────────────────
# `ollama launch openclaw` installs via npm on first run if missing
# and then stays foreground, so we register it as a second long-
# running workload. --yes accepts the install prompt non-interactively.
echo "  POST /deploy openclaw..."
OPENCLAW_SPEC=$(jq -c -n --arg m "$MODEL" '{
  app_name: "openclaw",
  cmd: [
    "/var/lib/easyenclave/bin/podman",
    "--root=/var/lib/easyenclave/containers/storage",
    "--runroot=/var/lib/easyenclave/containers/runroot",
    "--cgroup-manager=cgroupfs",
    "exec", "ollama",
    "ollama", "launch", "openclaw",
    "--model", $m,
    "--yes"
  ]
}')
agent /deploy -H 'Content-Type: application/json' -d "$OPENCLAW_SPEC" | jq -c '.' || true

# ── 9. Confirm openclaw is up ─ three probes, weakest → strongest ──
# (a) EE lists `openclaw` in /health — proves the workload was
#     accepted by the in-VM runtime. Flips green on fork, before
#     npm-install finishes, so on its own it's weak.
# (b) GET http://127.0.0.1:18789/healthz (the OpenClaw gateway HTTP
#     endpoint). Docs: https://docs.openclaw.ai/gateway/health.
#     200 with valid JSON = gateway has bound its port and is
#     serving. The ollama container runs with --net=host so the
#     loopback is the VM's loopback; we curl through `podman exec`
#     so we hit the in-container curl (EE's busybox lacks one).
# (c) `openclaw agent --message "ping"` — the documented one-shot
#     CLI. Goes through the running gateway, hands the prompt to
#     the loaded model, returns the assistant reply. Exit 0 AND
#     non-empty stdout = the full ollama → openclaw → model path
#     works end-to-end. The reply gets echoed into the workflow
#     log as proof of life.
echo "  confirming openclaw workload is registered with EE..."
for i in $(seq 1 30); do
  list=$(agent /health 2>/dev/null || true)
  if echo "$list" | jq -e '.deployments // [] | index("openclaw")' >/dev/null 2>&1; then
    echo "  openclaw: registered"
    break
  fi
  sleep 5
done

echo "  waiting for openclaw gateway on http://127.0.0.1:18789/healthz..."
openclaw_live=0
for i in $(seq 1 60); do
  resp=$(agent /exec -H 'Content-Type: application/json' \
    -d '{"cmd":["/var/lib/easyenclave/bin/podman","--root=/var/lib/easyenclave/containers/storage","--runroot=/var/lib/easyenclave/containers/runroot","--cgroup-manager=cgroupfs","exec","ollama","curl","-fsS","http://127.0.0.1:18789/healthz"],"timeout_secs":10}' \
    2>/dev/null || true)
  if echo "$resp" | jq -e '.exit_code == 0' >/dev/null 2>&1; then
    echo "  openclaw: /healthz 200"
    echo "$resp" | jq -r '.stdout // ""' | head -c 200 | sed 's/^/    /'
    echo
    openclaw_live=1
    break
  fi
  sleep 5
done

if [ "$openclaw_live" != "1" ]; then
  echo "ERROR: openclaw /healthz never returned 200 (gateway didn't come up within 5 min)"
  echo "  last /exec response:"
  echo "$resp" | jq -c '.' | head -c 500
  exit 1
fi

echo "  sending a round-trip prompt: 'ping'"
chat=$(agent /exec -H 'Content-Type: application/json' \
  -d '{"cmd":["/var/lib/easyenclave/bin/podman","--root=/var/lib/easyenclave/containers/storage","--runroot=/var/lib/easyenclave/containers/runroot","--cgroup-manager=cgroupfs","exec","ollama","openclaw","agent","--message","ping","--thinking","low"],"timeout_secs":120}' \
  2>/dev/null || true)
reply=$(echo "$chat" | jq -r '.stdout // ""')
if [ -z "$reply" ] || ! echo "$chat" | jq -e '.exit_code == 0' >/dev/null 2>&1; then
  echo "ERROR: openclaw agent --message didn't return a reply"
  echo "  raw: $(echo "$chat" | jq -c '.' | head -c 500)"
  exit 1
fi
echo
echo "=== openclaw replied ==="
echo "$reply"
echo "========================"

echo
echo "=== agent fleet summary ==="
echo "  agent:    https://$agent_host"
echo "  model:    $MODEL"
echo "  ollama:   podman container 'ollama' on host net, :11434"
echo "  openclaw: http://127.0.0.1:18789 (gateway), replied to round-trip ping"
echo "==========================="
