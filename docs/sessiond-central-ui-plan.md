# Sessiond + Native Client Plan

## Goal

Accept one disruptive dogfood redeploy to install a durable session backend.
After that, iterate on desktop/mobile/assistant clients without restarting the
dogfood VM or killing active Codex/Claude sessions.

## Target Shape

```text
native desktop/mobile client or CLI
  -> CP route discovery + enrollment broker
  -> selected agent /noise/ws
  -> dd-sessiond Unix socket on that VM
  -> PTY + child process group
```

Agent VM responsibilities:

- `dd-sessiond` owns live sessions, PTYs, child process groups, transcripts,
  recipes, session metadata, and notification/input-needed state.
- `dd-agent` owns the remote HTTPS/tunnel API surface, authorization,
  attestation/noise integration, and proxying to local `dd-sessiond`.
- The old agent-local `dd-shell` UI becomes temporary/minimal and no longer
  owns PTYs.

Control-plane responsibilities:

- Broker device enrollment and own route discovery.
- Serve dashboards and enrollment broker pages.
- Never carry shell, log, transcript, or PTY bytes.

Client responsibilities:

- Hold a paired device identity.
- Ask CP for current routes and capabilities.
- Connect directly to the selected agent over Noise for runtime data.

## Non-Goals

- No fleet-wide self-upgrade machinery.
- No hot-swappable UI directory as the primary mechanism.
- No fallback in-process PTY mode once `dd-sessiond` is introduced.
- No CRIU/checkpoint work in the first implementation.
- No CP relay or mailbox relay for shell/log/session bytes.
- No browser/PWA shell client. Browser stays dashboard/enrollment only; the
  session client is native app/CLI.
- No bundled client CLI in `dd`. Client core, CLI, and native app live in
  [`devopsdefender/dd-client`](https://github.com/devopsdefender/dd-client).

## Phase 1: One Disruptive Dogfood Upgrade

Ship the new backend shape to dogfood, accepting that existing live dogfood
sessions will be lost during this rollout.

Deliverables:

- Add `DD_MODE=sessiond`. Implemented in this branch.
- Add a `dd-sessiond` boot workload for dogfood agents. Implemented in this branch.
- Change interactive sessions so `dd-sessiond` owns PTYs. Implemented for `dd-shell`
  by proxying session create/list/attach/resize/close/replay to sessiond.
- Change `dd-agent` to proxy session APIs to `dd-sessiond`. Implemented over
  paired-device Noise for the first durable client path.
- Keep Codex launch working through the session manager.
- Preserve persistent disk state, including Codex/npm/login state.

Acceptance:

- Dogfood agent is healthy after redeploy.
- Codex launches through `dd-sessiond`.
- Existing session metadata and transcripts are visible through the session API.
- Restarting only the web/UI layer does not kill a running Codex session.

## Phase 2: Stable Client Protocol

Expose session functionality through `dd-agent` Noise, backed by local
`dd-sessiond`. The stable remote surface is the paired-device protocol, not
cookie-auth HTTP session routes.

Initial protocol:

```text
shell.list_recipes
shell.list_sessions
shell.create_session
shell.replay_session
shell.resize_session
shell.close_session
shell.attach_session
exec
```

Implementation notes:

- `dd-sessiond` listens only on a Unix socket on the VM.
- `dd-agent` is the only remote session gateway.
- Multiple clients may attach to the same session.
- Transcript and events are canonical session state, not UI state.
- Mobile clients should not resize the canonical PTY by default.
- Browser-shell interactive attach is removed. Do not add new client features
  there; active shell UI work belongs in `devopsdefender/dd-client`.

## Phase 3: Native Fleet Client

Move active shell UI development to a native client that uses CP only for
routes and enrollment brokering.

Deliverables:

- Add CP route discovery for agent sessions.
- Native app lists sessions for the selected agent.
- Native app can create, attach, input, resize, close, and replay sessions by
  opening Noise directly to the selected agent.
- Desktop terminal view remains raw PTY-first.
- Mobile app can add touch controls, smart sizing, notifications, and
  assistant-style rendering without changing agent-side session ownership.
- Browser dashboard links users to the native app/CLI enrollment and route
  discovery flows; it does not become a terminal/PWA client.

Acceptance:

- Updating the native app updates shell/mobile experience without changing the
  agent/sessiond data plane.
- Active dogfood Codex sessions survive web/client updates.

Status:

- Native CLI exists in `devopsdefender/dd-client`. Browser shell attach and
  cookie-auth session control have been removed from this repo.

## Phase 4: Auth, Attestation, And Noise

Start simple:

- CP brokers enrollment by redirecting to the selected agent and exposes
  current routes.
- Agents hold the trusted device set they enforce for direct Noise sessions.
- Native CLI/desktop/mobile clients from `dd-client` use direct `/noise/ws`
  channels for session RPCs.

Then strengthen:

- Clients verify the agent quote and pin the attested Noise public key.
- Native desktop/mobile apps reuse the same direct agent Noise path as the
  `dd-client` CLI.
- Pairing survives CP redeploys without putting shell/session state in CP. A
  paired native/web/mobile client must not need to re-pair just because preview
  or production CP was relaunched.

Implemented first slice:

- `/health` exposes the quote and Noise public key that clients verify and pin.
- A paired device can send `shell.list_recipes`, `shell.list_sessions`,
  `shell.create_session`, `shell.replay_session`, `shell.resize_session`, and
  `shell.close_session` JSON requests over Noise.
- `shell.attach_session` returns one JSON ack, then switches the same Noise
  session into encrypted raw PTY byte streaming to local `dd-sessiond`.
- CP does not run the client Noise gateway. Agent Noise endpoints wire the
  sessiond adapter in.

Design rule:

```text
remote clients never trust naked tunnel DNS
remote clients trust paired device identity plus attested agent keys
CP is route/key authority only, never a session data plane
dd-sessiond stays local-only
dd-agent is the policy/encryption gateway
```

## Removal Plan

Now that the durable session owner is `dd-sessiond` and native clients can use
direct Noise, remove the old shell stack in this order:

1. Remove cookie-auth browser shell attach and session control APIs.
2. Remove old env compatibility names. `DD_SESSIOND_HISTORY_KEY` is the only
   transcript-key override; do not continue accepting `DD_SHELL_HISTORY_KEY`.
3. Fix pairing durability without making CP a shell/session state owner. CP can
   broker enrollment, but durable paired-device trust must live with the
   enforcement point or an explicitly chosen non-CP store.
4. Build out [`devopsdefender/dd-client`](https://github.com/devopsdefender/dd-client)
   with shared client core, CLI, and native app. Store paired device keys in OS
   secure storage, use CP only for enrollment and route discovery, then connect
   to the selected agent `/noise/ws` for session RPCs and PTY bytes.
5. Delete server-side browser shell proxying. Remove `src/shell.rs` entirely
   once the shell subdomain is no longer needed as an authenticated endpoint.
6. Delete agent HTTP session proxying. Remove `/api/sessions*` from `dd-agent`
   once native clients use Noise for session control.
7. Retire legacy combined shell workloads. Remove `apps/confidential-shell` and
   `apps/codex-podman-shell` after deploy templates and docs no longer point at
   `DD_MODE=shell` as a PTY owner.
8. Rename remaining storage paths only with an explicit data migration. The
   current `dd-shell` path names are confusing but may contain persistent
   transcripts; do not silently strand them.

Keep these pieces:

- `dd-sessiond` and its local-only API. It is the session owner, not a fallback.
- CP route discovery and enrollment brokering. CP stays in the trust/control
  path, not the shell data path or shell state path.

## Risks And Open Questions

- How to model recipes so CP UI and `dd-sessiond` agree on available launchers.
- How to represent "input requested" events for Codex/Claude without making
  terminal parsing authoritative.
- Whether `dd-sessiond` should support graceful self-upgrade later via fd
  passing or exec handoff.
- How much of the existing transcript encryption format should move unchanged
  into `dd-sessiond`.
- Where durable paired-device trust should live if CP only brokers enrollment
  and route discovery.
- Native app shell: Tauri/Rust shell versus platform-native UI around the
  `dd-client` Rust core.
