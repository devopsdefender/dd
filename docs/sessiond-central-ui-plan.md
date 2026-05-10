# Sessiond + Central UI Plan

## Goal

Accept one disruptive dogfood redeploy to install a durable session backend.
After that, iterate on desktop/mobile/assistant clients without restarting the
dogfood VM or killing active Codex/Claude sessions.

## Target Shape

```text
native/web/mobile client
  -> CP route discovery + device enrollment
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

- Own device enrollment, revocation, policy, and route discovery.
- Optionally serve static web/PWA assets.
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
- No full browser-side Noise handshake in the first implementation; native CLI
  is the first protocol exerciser.

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
- The existing `/api/sessions*` and `/ws/sessions*` browser-shell routes are
  transitional compatibility only. Do not add new client features there.

## Phase 3: Client-Side Fleet UI

Move active shell UI development to clients that use CP only for routes and
agent/device policy.

Deliverables:

- Add CP route discovery for agent sessions.
- UI lists sessions for the selected agent.
- UI can create, attach, input, resize, close, and replay sessions by opening
  Noise directly to the selected agent.
- Desktop terminal view remains raw PTY-first.
- Mobile view can add touch controls, smart sizing, and assistant-style
  rendering without changing agent-side session ownership.
- The web/PWA interface becomes a client implementation of the same protocol,
  not a server-side shell proxy.

Acceptance:

- Updating static web/PWA assets updates the browser shell/mobile experience.
- No dogfood agent restart is needed for UI-only changes.
- Active dogfood Codex sessions survive web/client updates.

Status:

- Not implemented in the first branch slice. The native CLI is present so the
  client-side protocol can be tested before replacing the browser shell proxy.

## Phase 4: Auth, Attestation, And Noise

Start simple:

- CP enrolls paired device public keys and exposes current routes.
- Agents poll CP for the trusted device set and route/policy freshness.
- Native CLI/desktop/mobile clients use direct `/noise/ws` channels for
  session RPCs.

Then strengthen:

- Clients verify the agent quote and pin the attested Noise public key.
- Browser/PWA uses the same direct agent Noise path once the browser crypto or
  WASM client is in place.

Implemented first slice:

- `/health` exposes the quote and Noise public key that clients verify and pin.
- A paired device can send `shell.list_recipes`, `shell.list_sessions`,
  `shell.create_session`, `shell.replay_session`, `shell.resize_session`, and
  `shell.close_session` JSON requests over Noise.
- `shell.attach_session` returns one JSON ack, then switches the same Noise
  session into encrypted raw PTY byte streaming to local `dd-sessiond`.
- Native `exec`, `replay`, `resize`, and `close` commands exercise the same
  direct Noise path as `shell`.
- CP Noise endpoints reject shell methods because they have no local sessiond
  adapter; agent Noise endpoints wire the adapter in.
- The native CLI appraises the agent quote with Intel Trust Authority by
  default and requires an explicit insecure flag for local preview/dev.

Design rule:

```text
remote clients never trust naked tunnel DNS
remote clients trust CP-enrolled device identity plus attested agent keys
CP is route/key authority only, never a session data plane
dd-sessiond stays local-only
dd-agent is the policy/encryption gateway
```

## Removal Plan

Now that the durable session owner is `dd-sessiond` and native clients can use
direct Noise, remove the old shell stack in this order:

1. Freeze cookie-auth browser shell APIs. Treat `src/shell.rs` routes
   `/api/sessions*` and `/ws/sessions*` as compatibility only until the web/PWA
   client speaks Noise directly.
2. Remove old env compatibility names. `DD_SESSIOND_HISTORY_KEY` is the only
   transcript-key override; do not continue accepting `DD_SHELL_HISTORY_KEY`.
3. Move web/PWA to direct Noise. Store a paired device key in browser storage,
   use CP only for enrollment and route discovery, then connect to the selected
   agent `/noise/ws` for session RPCs and PTY bytes.
4. Delete server-side browser shell proxying. Remove `src/shell.rs` session
   proxy routes and WebSocket attach path once the web/PWA client uses direct
   Noise. Keep only static asset serving if needed.
5. Delete agent HTTP session proxying. Remove `/api/sessions*` from `dd-agent`
   once native and web clients both use Noise for session control.
6. Retire legacy combined shell workloads. Remove `apps/confidential-shell` and
   `apps/codex-podman-shell` after deploy templates and docs no longer point at
   `DD_MODE=shell` as a PTY owner.
7. Rename remaining storage paths only with an explicit data migration. The
   current `dd-shell` path names are confusing but may contain persistent
   transcripts; do not silently strand them.

Keep these pieces:

- `dd-sessiond` and its local-only API. It is the session owner, not a fallback.
- `shell_unavailable` on CP Noise endpoints. It is an explicit rejection for a
  process that intentionally has no local sessiond.
- CP route discovery and enrollment. CP stays in the trust/control path, not
  the shell data path.

## Risks And Open Questions

- How to model recipes so CP UI and `dd-sessiond` agree on available launchers.
- How to represent "input requested" events for Codex/Claude without making
  terminal parsing authoritative.
- Whether `dd-sessiond` should support graceful self-upgrade later via fd
  passing or exec handoff.
- How much of the existing transcript encryption format should move unchanged
  into `dd-sessiond`.
- Browser Noise implementation choice: pure JS library versus small WASM client.
