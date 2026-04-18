# apps/ — workload specs

This directory is DD's canonical reference for **how to deploy a workload**. Every directory here is one workload — a process easyenclave runs inside a TDX-sealed VM. The specs are both the live deployment configuration and the worked example for operators writing their own.

## Layout

```
apps/
  <name>/
    workload.json          # literal spec
    workload.json.tmpl     # spec with ${VAR} placeholders (baked at deploy time)
  _infra/                  # host-side scripts; not a deployable workload
```

## What a workload looks like

A **workload** is a JSON object consumed by easyenclave's `DeployRequest` (see `src/easyenclave/src/workload.rs`). Minimum shape:

```json
{
  "app_name": "myapp",
  "cmd": ["/bin/busybox", "sh", "-c", "echo hello; sleep inf"]
}
```

Add `github_release` to fetch a binary asset directly from a GitHub release — no OCI registry, no Dockerfile. The asset lands in `/var/lib/easyenclave/bin/` and is spawned by `cmd`:

```json
{
  "app_name": "cloudflared",
  "github_release": {
    "repo": "cloudflare/cloudflared",
    "asset": "cloudflared-linux-amd64",
    "rename": "cloudflared"
  }
}
```

Add `env` to inject config:

```json
{
  "env": ["MY_ENDPOINT=https://api.example.com", "DEBUG=1"]
}
```

## Templates

Files ending in `.json.tmpl` carry `${VAR}` placeholders. At bake time:

1. `envsubst` substitutes every uppercase `${VAR}` that appears in the template using the caller's environment.
2. `jq` drops env-array entries whose value ended up empty (so you can make OAuth creds / optional secrets conditional by just leaving them unset).
3. The result is a plain `workload.json` ready for EE.

Only uppercase placeholders get substituted — shell locals like `$i` or `$((n+1))` inside `cmd` strings are left alone. The bake helper is duplicated inline in two places so both lifecycle points behave identically:

- `.github/workflows/deploy-cp.yml` (CI, for CP workloads)
- `apps/_infra/local-agents.sh` (tdx2 host, for agent VMs)

## Where each workload runs

| workload | CP VM | agent VM (preview) | agent VM (prod) |
|---|---|---|---|
| `cloudflared` | ✅ | ✅ | ✅ |
| `dd-management` | ✅ | | |
| `dd-agent` | | ✅ | ✅ |
| `mount-models` | | ✅ | ✅ |
| `nv` | | | ✅ (GPU insmod) |
| `podman-static` | | ✅ | ✅ |
| `podman-bootstrap` | | ✅ | ✅ |
| `ollama` | | ✅ (CPU, preview.json) | ✅ (GPU, prod.json) |
| `openclaw` | | ✅ (qwen2.5:0.5b) | ✅ (qwen2.5:7b) |

CP stays slim: just `cloudflared` + `dd-management`. Containerised LLM serving lives on agent VMs where the `vdc` ext4 disk holds models + image storage.

## Ordering

EasyEnclave spawns boot workloads concurrently — there's no declared dependency graph. Dependents self-sequence by polling for their prerequisites. Worked example from this tree:

- `podman-bootstrap` waits for `podman-static`'s tarball (`until [ -x $SRC/usr/local/bin/podman ]; do sleep 1; done`).
- `ollama`'s cmd waits for the wrapper (`until [ -x /var/lib/easyenclave/bin/podman ]; do sleep 2; done`).
- `openclaw`'s cmd waits for ollama's HTTP endpoint (`until wget -q -O- http://127.0.0.1:11434/api/tags; do sleep 5; done`) before pulling the model and launching the gateway.

Costs seconds of wasted polling at boot; easy to reason about; no workload-runner changes needed.

## Deploying your own

1. Copy an existing folder as a starting point:
   ```
   cp -r apps/cloudflared apps/myapp
   $EDITOR apps/myapp/workload.json
   ```
2. Decide where it runs:
   - **CP VM**: add a `bake apps/myapp/workload.json` line to the workload-building `run:` step in `.github/workflows/deploy-cp.yml`.
   - **Agent VM**: add the same call to `apps/_infra/local-agents.sh` in `build_config_iso()`.
   - **Ad-hoc, runtime-only**: POST the baked JSON to `/deploy` on a running agent:
     ```
     curl -H "Authorization: Bearer $DD_PAT" \
          -H "Content-Type: application/json" \
          -d @apps/myapp/workload.json \
          https://<agent-host>/deploy
     ```

## Reference

- Schema source of truth: [`src/easyenclave/src/workload.rs`](../src/easyenclave/src/workload.rs) — the `DeployRequest` struct EE deserializes on `/deploy`.
- CP deploy caller: [`.github/workflows/deploy-cp.yml`](../.github/workflows/deploy-cp.yml) — inline `bake()` + CP workload set.
- Agent VM builder: [`apps/_infra/local-agents.sh`](_infra/local-agents.sh) — inline `bake()` + agent workload set per kind.
