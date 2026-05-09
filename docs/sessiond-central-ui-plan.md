# Sessiond + Central UI Plan

## Goal

Accept one disruptive dogfood redeploy to install a durable session backend.
After that, iterate on desktop/mobile/assistant UI from the centralized fleet
control plane without restarting the dogfood VM or killing active Codex/Claude
sessions.

## Target Shape

```text
browser
  -> app.devopsdefender.com fleet UI
  -> selected agent session gateway
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

- Serve the desktop shell UI, mobile UI, and Claude-style assistant view.
- Let users select a fleet agent and attach to sessions through that agent's
  session API.
- Ship UI updates via normal CP/web deploys, without touching agent VMs.

## Non-Goals

- No fleet-wide self-upgrade machinery.
- No hot-swappable UI directory as the primary mechanism.
- No fallback in-process PTY mode once `dd-sessiond` is introduced.
- No CRIU/checkpoint work in the first implementation.
- No full browser-side Noise handshake in the first implementation.

## Phase 1: One Disruptive Dogfood Upgrade

Ship the new backend shape to dogfood, accepting that existing live dogfood
sessions will be lost during this rollout.

Deliverables:

- Add `DD_MODE=sessiond`. Implemented in this branch.
- Add a `dd-sessiond` boot workload for dogfood agents. Implemented in this branch.
- Change interactive sessions so `dd-sessiond` owns PTYs. Implemented for `dd-shell`
  by proxying session create/list/attach/resize/close/replay to sessiond.
- Change `dd-agent` to proxy session APIs to `dd-sessiond`. Implemented with
  browser-auth-gated routes for the first cut.
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

## Phase 3: Centralized Fleet UI

Move active shell UI development to the CP/fleet dashboard.

Deliverables:

- Add CP route for agent sessions.
- UI lists sessions for the selected agent.
- UI can create, attach, input, resize, close, and replay sessions.
- Desktop terminal view remains raw PTY-first.
- Mobile view can add touch controls, smart sizing, and assistant-style
  rendering without changing agent-side session ownership.

Acceptance:

- Updating CP UI via PR/release updates the shell/mobile experience.
- No dogfood agent restart is needed for UI-only changes.
- Active dogfood Codex sessions survive CP UI updates.

Status:

- Not implemented in the first branch slice. The agent-side session gateway is
  present so the CP UI can target it next.

## Phase 4: Auth, Attestation, And Noise

Start simple:

- CP issues short-lived scoped session tokens.
- Tokens bind user, agent id, session/action scope, and expiry.
- `dd-agent` validates tokens before proxying to `dd-sessiond`.

Then strengthen:

- Bind session authorization to the attested agent Noise public key.
- CP tracks agent attestation and `noise_pubkey`.
- Desktop/CLI clients can eventually use a direct Noise channel.
- Browser UI can stay token-over-HTTPS until custom browser crypto is worth it.

Design rule:

```text
remote clients never trust naked tunnel DNS
remote clients trust CP-issued scoped authorization and, later, attested keys
dd-sessiond stays local-only
dd-agent is the policy/encryption gateway
```

## Risks And Open Questions

- Whether to keep a minimal agent-local shell UI for emergency access.
- How to model recipes so CP UI and `dd-sessiond` agree on available launchers.
- How to represent "input requested" events for Codex/Claude without making
  terminal parsing authoritative.
- Whether `dd-sessiond` should support graceful self-upgrade later via fd
  passing or exec handoff.
- How much of the existing transcript encryption format should move unchanged
  into `dd-sessiond`.
