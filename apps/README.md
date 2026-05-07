# apps/ — worked example of a DD agent VM

This directory is **a worked example**, not a bundle dd ships to users. Every
directory here is one easyenclave workload. Together they describe a complete
DD agent VM: the minimum infra to boot podman, register with a control plane,
and optionally expose workload ports on stable hostnames.

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
  "app_name": "web",
  "expose": { "hostname_label": "web", "port": 8081 },
  "cmd": [...]
}
```

At agent boot, `apps/_infra/local-agents.sh` collects every `expose` entry
into `DD_EXTRA_INGRESS`. dd-agent forwards them on `/register` and the CP
prepends them to the agent's cloudflared tunnel ingress. A workload declaring
`{"hostname_label": "web", "port": 8081}` becomes reachable at
`web.<agent-hostname>` — in addition to the default dashboard at
`<agent-hostname>`. easyenclave itself ignores the field; it's a DD-level
hint about tunnel routing.

Add `oracle` to declare that an exposed workload is a read-only oracle endpoint:

```json
{
  "app_name": "human-readonly",
  "expose": { "hostname_label": "oracle", "port": 8082 },
  "oracle": {
    "title": "Human read-only oracle",
    "path": "/oracle.json",
    "interval_secs": 10
  },
  "cmd": [...]
}
```

At agent boot, DD also extracts these oracle hints into `DD_ORACLES_B64`.
dd-agent scrapes `http://127.0.0.1:<port><path>`, publishes the current oracle
state on `/health` and `/api/oracles`, and lists it in both the agent dashboard
and CP fleet detail page. The vanity URL uses the `expose.hostname_label`
(`oracle.<agent-hostname>` in the example). This is observation-only metadata:
it does not create a read-write terminal or any input path into the workload.

## Terminal access model

DD separates terminal access by capability:

- **Read-only workload terminals** show workload logs in the dd-shell xterm UI.
  They are for oracle-style services where an operator should be able to inspect
  output without sending input, resizing a PTY, interrupting, or closing the
  process. Opening a read-only terminal is observation only, so it leaves the
  workload's user-facing integrity state clean.
- **Read-write PTY sessions** are created inside `dd-shell`. They are for
  confidential shells and ZDR coding agents such as Codex or Claude. These
  sessions are reconnectable and write encrypted transcript records under
  `DD_SHELL_DIR`. A read-write PTY is controlled as soon as it exists because
  the holder can send stdin, resize the terminal, and deliver terminal signals.

The shell UI treats both as terminal views, but only read-write sessions get
WebSocket input, resize, and close controls. Workloads do not opt into
read-write access by putting metadata in `workload.json`; the boundary is the
dd-shell API surface. Internally DD may still call this taint tracking, but the
API/UI should speak in integrity terms: clean for observed-only logs,
controlled for interactive PTYs or other human control paths.

The renderer uses vendored xterm assets and recognizes WezTerm-compatible
notification escapes after the user grants browser notification permission:

```sh
printf '\033]9;%s\033\\' 'job finished'
printf '\033]777;notify;%s;%s\033\\' 'oracle' 'new result available'
```

For mobile web, this is the first step toward a PWA-style shell inbox: read-only
workload cards, read-write Codex/Claude session cards, and push-backed
notifications for long-running jobs.

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
| `dd-shell` | | ✅ | ✅ |
| `human-readonly` | | ✅ | |
| `dd-management` | ✅ | | |
| `podman-static` | | ✅ | ✅ |
| `podman-bootstrap` | | ✅ | ✅ |

Additional examples:

- `apps/human-readonly`: tiny preview-only read-only oracle. It emits logs for
  dd-shell's read-only terminal, serves `/oracle.json` on port 8082, gets a
  vanity `oracle.<agent-hostname>` address, and appears in the dashboards.
- `apps/oracle-readonly`: standalone oracle example with the same scraper and
  vanity-address metadata; copy this shape into real oracle app repos.
- `apps/confidential-shell`: runs dd-shell with
  `DD_SHELL_DIR=/var/lib/easyenclave/data/dd-shell` so read-write PTY
  transcript history survives on the workload disk.
- `apps/codex-podman-shell`: alternative read-write shell workload. It exposes
  the normal `-shell` label, stores encrypted dd-shell history under
  `/var/lib/easyenclave/data/dd-shell`, and makes each new PTY enter a
  Podman-backed Node container.
  The container installs `@openai/codex` on first use and persists login/config
  under `/var/lib/easyenclave/data/codex/home`, so `codex login` can be
  completed interactively from the browser terminal. Use this instead of
  `dd-shell`, not alongside it, unless you give one of them a different
  `hostname_label`.

CP stays slim: just `cloudflared` + `dd-management`. Preview agent VMs run a
small read-only oracle plus agent + podman for CI to prove registration,
scraping, vanity ingress, and dashboards end-to-end. Prod agent VMs use the
same CPU-only boot shape without demo workloads for now.

## Ordering

EasyEnclave spawns boot workloads concurrently — there's no declared
dependency graph. Dependents self-sequence by polling for their prerequisites.
Worked examples from this tree:

- `podman-bootstrap` waits for `podman-static`'s tarball
  (`until [ -x $SRC/usr/local/bin/podman ]; do sleep 1; done`).

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
     agent. The endpoint is CF-Access-bypassed and gated in-code by a
     GitHub Actions OIDC JWT. From inside a GitHub Actions workflow
     running in the `DD_OWNER` org:
     ```
     OIDC=$(curl -fsSL \
       -H "Authorization: Bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" \
       "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=dd-agent" | jq -r .value)
     curl -fsS -X POST https://<agent-host>/deploy \
          -H "Authorization: Bearer ${OIDC}" \
          -H "Content-Type: application/json" \
          -d @apps/myapp/workload.json
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
- Ingress and oracle plumbing: `src/cf.rs` (`create()` takes per-workload
  ingress), `src/cp.rs` (`register` handler accepts `extra_ingress`, dashboard
  renders scraped oracle status), `src/agent.rs` (reads `DD_EXTRA_INGRESS` and
  `DD_ORACLES_B64`, forwards ingress on `/register`, scrapes oracle endpoints).
