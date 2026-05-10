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
  "cmd": ["myapp"]
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

EE does not ship a rootfs shell. If a workload wants shell scripting, fetch a
shell/toolbox as an explicit workload asset first and run that asset:

```json
{
  "app_name": "busybox",
  "github_release": {
    "repo": "devopsdefender/dd",
    "asset": "busybox",
    "tag": "${DD_RELEASE_TAG}"
  }
}
```

Then dependent recipes can use `"cmd": ["busybox", "sh", "-c", "..."]`.
That keeps EE shell-less while letting workload bundles bring their own
userspace when they need scripting.

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

- **Read-only workload terminals** show workload logs in the terminal UI.
  They are for oracle-style services where an operator should be able to inspect
  output without sending input, resizing a PTY, interrupting, or closing the
  process. Opening a read-only terminal is observation only, so it leaves the
  workload's user-facing integrity state clean.
- **Read-write PTY sessions** are owned by `dd-sessiond`. They are for
  confidential shells and ZDR coding agents such as Codex or Claude. These
  sessions are reconnectable and write encrypted transcript records. A
  read-write PTY is controlled as soon as it exists because the holder can send
  stdin, resize the terminal, and deliver terminal signals.

The shell UI treats both as terminal views, but only read-write sessions get
WebSocket input, resize, and close controls. Workloads do not opt into
read-write access by putting metadata in `workload.json`; the boundary is the
session protocol exposed by `dd-agent` over Noise. The current browser shell
HTTP/WebSocket APIs are compatibility only while web/PWA moves to direct Noise.
Internally DD may still call this taint tracking, but the API/UI should speak in
integrity terms: clean for observed-only logs, controlled for interactive PTYs
or other human control paths.

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

| workload | CP VM | agent VM (preview) | agent VM (prod / dogfood) |
|---|---|---|---|
| `busybox` | | ✅ | ✅ |
| `cloudflared` | ✅ | ✅ | ✅ |
| `dd-agent` | | ✅ | ✅ |
| `dd-sessiond` | ✅ | ✅ | ✅ |
| `dd-shell` | ✅ | ✅ | ✅ |
| `human-readonly` | | ✅ | |
| `dd-management` | ✅ | | |
| `podman-static` | | ✅ | ✅ |
| `ca-certificates` | | ✅ | ✅ |
| `podman-bootstrap` | | ✅ | ✅ |

Additional examples:

- `apps/human-readonly`: tiny preview-only read-only oracle. It emits logs for
  dd-shell's read-only terminal, serves `/oracle.json` on port 8082, gets a
  vanity `oracle.<agent-hostname>` address, and appears in the dashboards. It
  is a shell workload recipe, not a `devopsdefender` binary subcommand.
- `apps/oracle-readonly`: standalone oracle example with the same scraper and
  vanity-address metadata; copy this shape into real oracle app repos.
- `apps/confidential-shell`: legacy standalone shell workload for deployments
  that still run the browser shell and PTY supervisor in one process. Scheduled
  for removal once all clients use `dd-sessiond` over Noise.
- `apps/codex-podman-shell`: legacy read-write shell workload. It exposes the
  normal `-shell` label and carries an older self-contained Codex recipe path.
  Scheduled for removal; new deployments should use `dd-sessiond`.

CP stays slim: `cloudflared` + `dd-management` + static/web client assets as
needed. It must not carry shell, log, transcript, or PTY bytes.
Preview agent VMs run a small read-only oracle plus agent + podman for CI to
prove registration, scraping, vanity ingress, and dashboards end-to-end. Prod
agent VMs use the
same CPU-only boot shape without demo workloads for now. `dd-local-dogfood`
uses that same prod boot chain but is manually managed, sized larger by
default, and not relaunched by CI.

## Production dogfood agent

Use `apps/_infra/dd-dogfood.sh` when you want a real, long-lived local VM
registered to production for Codex/Podman development:

```bash
export DD_ITA_API_KEY="$(cat ~/.secrets/ita_api_key)"
export DD_AUTH_COOKIE_SECRET="$(cat ~/.secrets/dd_auth_cookie_secret)"
export EE_OWNER="posix4e" # or an org/repo principal
./apps/_infra/dd-dogfood.sh
```

The script defines and starts `dd-local-dogfood` against
`https://app.devopsdefender.com`. It follows the production stable EE image and
the `latest` DD release by default. It preserves
`/var/lib/libvirt/images/dd-local-dogfood-workload.qcow2` across runs, so
Podman images, shell transcript storage, and Codex login state survive explicit
operator refreshes. Production deploys do not call this script and do not
destroy the dogfood VM.

Optional sizing knobs:

```bash
DD_DOGFOOD_DISK_SIZE=1024G DD_DOGFOOD_MEM_KIB=67108864 DD_DOGFOOD_VCPUS=12 \
  ./apps/_infra/dd-dogfood.sh
```

## Ordering

EasyEnclave spawns boot workloads concurrently — there's no declared
dependency graph. Dependents self-sequence by polling for their prerequisites.
- `podman-bootstrap` waits for `podman-static`'s tarball, copies the
  `ca-certificates` release asset into Podman's persistent config, then stages
  `podman`, `conmon`, `crun`, config, and the `podman` wrapper script.
- Shell-based recipes wait for `busybox` by depending on the fetch-only
  `busybox` workload in the boot set.

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
     agent. The endpoint is gated in-code by a
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
