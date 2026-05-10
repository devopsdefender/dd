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

## Phase 2: Stable Session API

Expose session functionality through `dd-agent`, backed by local
`dd-sessiond`.

Initial API:

```text
GET  /api/sessions
POST /api/sessions
GET  /api/sessions/:id
WS   /api/sessions/:id/attach
POST /api/sessions/:id/input
POST /api/sessions/:id/resize
POST /api/sessions/:id/close
GET  /api/sessions/:id/transcript
WS   /api/session-events
```

Implementation notes:

- `dd-sessiond` listens only on a Unix socket on the VM.
- `dd-agent` is the only remote gateway.
- Multiple clients may attach to the same session.
- Transcript and events are canonical session state, not UI state.
- Mobile clients should not resize the canonical PTY by default.

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
- CP Noise endpoints reject shell methods because they have no local sessiond
  adapter; agent Noise endpoints wire the adapter in.

Design rule:

```text
remote clients never trust naked tunnel DNS
remote clients trust CP-enrolled device identity plus attested agent keys
CP is route/key authority only, never a session data plane
dd-sessiond stays local-only
dd-agent is the policy/encryption gateway
```

## Risks And Open Questions

- Whether to keep a minimal cookie-auth shell UI only as temporary emergency
  compatibility.
- How to model recipes so CP UI and `dd-sessiond` agree on available launchers.
- How to represent "input requested" events for Codex/Claude without making
  terminal parsing authoritative.
- Whether `dd-sessiond` should support graceful self-upgrade later via fd
  passing or exec handoff.
- How much of the existing transcript encryption format should move unchanged
  into `dd-sessiond`.
- Browser Noise implementation choice: pure JS library versus small WASM client.
