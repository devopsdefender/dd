# apps/ — worked example of a DD agent VM

This directory is **a worked example**, not a bundle dd ships to users. Every
directory here is one easyenclave workload. Together they describe a complete
DD agent VM: the minimum infra to boot podman, run one demo container
(`web-nvidia-smi`), register with a control plane, and expose the demo on a
stable hostname.

The goal is to be the shortest legible "agent VM from scratch" that you can
copy and adapt. For orchestrating many workloads, assembling them from
templates, and the run / teardown lifecycle, see
[slopandmop](https://github.com/slopandmop/slopandmop).

## Layout

```
apps/
  <name>/
    workload.json          # literal spec
    workload.json.tmpl     # spec with ${VAR} placeholders (baked at deploy time)
  _infra/                  # host-side scripts; not a deployable workload
```

## What a workload looks like

A **workload** is a JSON object consumed by easyenclave's `DeployRequest` (see
`src/easyenclave/src/workload.rs`). Minimum shape:

```json
{
  "app_name": "myapp",
  "cmd": ["/bin/busybox", "sh", "-c", "echo hello; sleep inf"]
}
```

Add `github_release` to fetch a binary asset directly from a GitHub release —
no OCI registry, no Dockerfile. The asset lands in `/var/lib/easyenclave/bin/`
and is spawned by `cmd`:

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

Add `expose` to ask DD to route a public hostname to a workload's port:

```json
{
  "app_name": "web-nvidia-smi",
  "expose": { "hostname_label": "gpu", "port": 8081 },
  "cmd": [...]
}
```

At agent boot, `apps/_infra/local-agents.sh` collects every `expose` entry
into `DD_EXTRA_INGRESS`. dd-agent forwards them on `/register` and the CP
prepends them to the agent's cloudflared tunnel ingress. A workload declaring
`{"hostname_label": "gpu", "port": 8081}` becomes reachable at
`gpu.<agent-hostname>` — in addition to the default dashboard at
`<agent-hostname>`. easyenclave itself ignores the field; it's a DD-level
hint about tunnel routing.

Per-workload ingress is **boot-time only** today. Workloads POSTed later via
`/deploy` don't get auto-exposed — declare your exposure on boot workloads in
this tree.

## Templates

Files ending in `.json.tmpl` carry `${VAR}` placeholders. At bake time:

1. `envsubst` substitutes every uppercase `${VAR}` that appears in the
   template using the caller's environment.
2. `jq` drops env-array entries whose value ended up empty (so you can make
   OAuth creds / optional secrets conditional by just leaving them unset).
3. The result is a plain `workload.json` ready for EE.

Only uppercase placeholders get substituted — shell locals like `$i` or
`$((n+1))` inside `cmd` strings are left alone. The bake helper is duplicated
inline in two places so both lifecycle points behave identically:

- `.github/workflows/deploy-cp.yml` (CI, for CP workloads)
- `apps/_infra/local-agents.sh` (tdx2 host, for agent VMs)

## Where each workload runs

| workload | CP VM | agent VM (preview) | agent VM (prod) |
|---|---|---|---|
| `cloudflared` | ✅ | ✅ | ✅ |
| `dd-agent` | | ✅ | ✅ |
| `dd-management` | ✅ | | |
| `nv` | | | ✅ (GPU insmod) |
| `podman-static` | | ✅ | ✅ |
| `podman-bootstrap` | | ✅ | ✅ |
| `web-nvidia-smi` | | | ✅ (`gpu.<agent-host>`) |

CP stays slim: just `cloudflared` + `dd-management`. Preview agent VMs run a
bare agent + podman for CI to prove registration end-to-end. Prod agent VMs
add the GPU insmod and the `web-nvidia-smi` demo on `gpu.<agent-host>`.

## Ordering

EasyEnclave spawns boot workloads concurrently — there's no declared
dependency graph. Dependents self-sequence by polling for their prerequisites.
Worked examples from this tree:

- `podman-bootstrap` waits for `podman-static`'s tarball
  (`until [ -x $SRC/usr/local/bin/podman ]; do sleep 1; done`).
- `web-nvidia-smi`'s cmd waits for the wrapper
  (`until [ -x /var/lib/easyenclave/bin/podman ]; do sleep 2; done`).

Costs seconds of wasted polling at boot; easy to reason about; no
workload-runner changes needed.

## Deploying your own

1. Copy an existing folder as a starting point:
   ```
   cp -r apps/cloudflared apps/myapp
   $EDITOR apps/myapp/workload.json
   ```
2. Decide where it runs:
   - **CP VM**: add a `bake apps/myapp/workload.json` line to the
     workload-building `run:` step in `.github/workflows/deploy-cp.yml`.
   - **Agent VM**: add the same call to `apps/_infra/local-agents.sh` in
     `build_config_iso()`.
   - **Ad-hoc, runtime-only**: POST the baked JSON to `/deploy` on a running
     agent:
     ```
     curl -H "Authorization: Bearer $DD_PAT" \
          -H "Content-Type: application/json" \
          -d @apps/myapp/workload.json \
          https://<agent-host>/deploy
     ```

## Reference

- Schema source of truth:
  [`src/easyenclave/src/workload.rs`](../src/easyenclave/src/workload.rs) —
  the `DeployRequest` struct EE deserializes on `/deploy`. `expose` is not in
  this struct; EE silently ignores it. DD reads it at the bake + register
  boundary.
- CP deploy caller:
  [`.github/workflows/deploy-cp.yml`](../.github/workflows/deploy-cp.yml) —
  inline `bake()` + CP workload set.
- Agent VM builder:
  [`apps/_infra/local-agents.sh`](_infra/local-agents.sh) — inline `bake()` +
  agent workload set per kind.
- Ingress plumbing: `src/cf.rs` (`create()` takes per-workload ingress),
  `src/cp.rs` (`register` handler accepts `extra_ingress`), `src/agent.rs`
  (reads `DD_EXTRA_INGRESS`, forwards on `/register`).
