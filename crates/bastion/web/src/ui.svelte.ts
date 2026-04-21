import type { Agent, BlockRecord, SessionInfo } from "./types";
import type { Connector } from "./connectors";
import {
  listConnectors,
  seedFromAgents,
  addConnector,
  fetchAttest,
  patchConnectorConfig,
} from "./connectors";
import { loadIdentitySeed, fingerprint } from "./identity";

/// Composite key so session ids from different connectors can't collide.
export type RowId = string; // `${connector.label}/${session_id}`

export interface Row {
  /// Connector this session came from. The SPA keeps a direct
  /// reference (rather than a connector id) so row operations don't
  /// need to re-look-up the connector.
  connector: Connector;
  /// Origin this row's WS/API calls target. For `dd-enclave` this
  /// comes from `connector.config.origin`; future kinds (SSH,
  /// Anthropic) compute it differently.
  origin: string;
  info: SessionInfo;
  blocks: BlockRecord[];
  /// Live WS to the owning origin. `null` until first activation.
  ws: WebSocket | null;
  /// xterm.js instance. `null` until first activation.
  term: import("@xterm/xterm").Terminal | null;
  fit: import("@xterm/addon-fit").FitAddon | null;
}

function rowKey(connector: Connector, sessionId: string): RowId {
  return `${connector.label}/${sessionId}`;
}

/// Svelte 5 runes-based reactive UI state. One flat Map of rows plus
/// the client-held connector list. Named `ui` (not `state`) to avoid
/// ambiguity with Svelte's `$state` rune when consumers also use
/// runes locally.
export const ui = $state<{
  rows: Map<RowId, Row>;
  active: RowId | null;
  connectors: Connector[];
  /// Short visual device-id fingerprint — rendered in the sidebar
  /// header. Derived from the identity seed persisted in
  /// localStorage (see `identity.ts`).
  deviceFp: string;
  /// True once the first `bootstrap()` call finishes. UI can use
  /// this to show a spinner on initial load.
  ready: boolean;
}>({
  rows: new Map(),
  active: null,
  connectors: [],
  deviceFp: "",
  ready: false,
});

/// One-time setup at app load: mint/load the device identity, pull
/// the connector list from IndexedDB (seed on first run from the
/// server-injected `__DD_AGENTS__`), and fan out to each connector
/// to populate `ui.rows`. Also kicks off a background `/attest`
/// fetch per enclave so Phase 2b's Noise_KK handshake has the
/// server pubkey ready.
export async function bootstrap(): Promise<void> {
  ui.deviceFp = fingerprint(loadIdentitySeed());
  if (window.__DD_AGENTS__ && window.__DD_AGENTS__.length > 0) {
    await seedFromAgents(window.__DD_AGENTS__);
  }
  await refreshConnectors();
  // Fire-and-forget — attest can be slow/cross-origin-blocked and
  // the sidebar shouldn't wait for it. Phase 2b will gate session
  // connections on the pubkey being cached.
  void refreshAttest();
  ui.ready = true;
}

/// Fetch `/attest` for every `dd-enclave` connector and merge the
/// returned Noise pubkey into its config. Idempotent; runs quietly
/// in the background on bootstrap. Console-logs the pubkey so
/// Phase 2a can be visually verified before Phase 2b wires it up.
async function refreshAttest(): Promise<void> {
  for (const c of ui.connectors) {
    if (c.kind !== "dd-enclave") continue;
    const origin = c.config.origin as string | undefined;
    if (!origin) continue;
    const attest = await fetchAttest(origin);
    if (!attest) continue;
    const known = c.config.serverNoisePubkeyHex as string | undefined;
    if (known === attest.noise_pubkey_hex) continue;
    console.log(
      `bastion: ${c.label} noise pubkey ${attest.noise_pubkey_hex.slice(0, 16)}… (${attest.source})`,
    );
    await patchConnectorConfig(c.id, {
      serverNoisePubkeyHex: attest.noise_pubkey_hex,
    });
  }
  // Re-read so `ui.connectors` has the patched config for Phase 2b.
  ui.connectors = await listConnectors();
}

/// Reload connectors from IndexedDB and re-fetch sessions from each.
/// Called after add/remove.
export async function refreshConnectors(): Promise<void> {
  ui.connectors = await listConnectors();
  await reloadSessions();
}

async function reloadSessions(): Promise<void> {
  const all = await Promise.all(
    ui.connectors.map(async (c): Promise<Row[]> => {
      if (c.kind === "dd-enclave") {
        return fetchDdEnclave(c);
      }
      // Every other connector kind is a Phase-3 TODO. Keep the row
      // for sidebar discoverability but don't try to fetch.
      return [];
    }),
  );
  const next = new Map<RowId, Row>();
  for (const bucket of all) {
    for (const row of bucket) {
      next.set(rowKey(row.connector, row.info.id), row);
    }
  }
  ui.rows = next;
}

/// Fetch an enclave's live sessions. Cross-origin failures
/// (CF-Access bounce, CORS reject, offline) degrade to "no rows" for
/// that enclave rather than propagating — the sidebar still shows
/// every connector the user configured, just empty for unreachable
/// ones. Phase 2 replaces this with a Noise_KK channel that isn't
/// subject to the same browser same-origin rules.
async function fetchDdEnclave(c: Connector): Promise<Row[]> {
  const origin = (c.config.origin as string | undefined) ?? "";
  if (!origin) return [];
  try {
    const resp = await fetch(`${origin}/api/sessions`, {
      credentials: "include",
    });
    if (!resp.ok) return [];
    const sessions: SessionInfo[] = await resp.json();
    return sessions.map((info) => ({
      connector: c,
      origin,
      info,
      blocks: [],
      ws: null,
      term: null,
      fit: null,
    }));
  } catch {
    return [];
  }
}

export async function createShell(c: Connector): Promise<void> {
  if (c.kind !== "dd-enclave") return;
  const origin = (c.config.origin as string | undefined) ?? "";
  if (!origin) return;
  try {
    const resp = await fetch(`${origin}/api/sessions`, {
      method: "POST",
      credentials: "include",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ title: "shell" }),
    });
    if (!resp.ok) {
      console.warn(`createShell: ${origin} → ${resp.status}`);
      return;
    }
    const info: SessionInfo = await resp.json();
    const id = rowKey(c, info.id);
    const rows = new Map(ui.rows);
    rows.set(id, {
      connector: c,
      origin,
      info,
      blocks: [],
      ws: null,
      term: null,
      fit: null,
    });
    ui.rows = rows;
    ui.active = id;
  } catch (e) {
    // Cross-origin + CF Access fails here with a TypeError before
    // fetch even reaches the origin. Swallow it — the sidebar falls
    // back to "no new shell, try again" rather than throwing a red
    // Uncaught (in promise) from a click handler.
    console.warn(`createShell: ${origin} cross-origin blocked`, e);
  }
}

/// Pick the enclave to create new shells on. Same-origin first —
/// clicking "+" on an agent's bastion creates a shell on THAT
/// agent, not on whichever connector happens to be first in the
/// list (usually the CP, which fails CORS from an agent origin).
/// Falls back to the first `dd-enclave` connector if none match.
export function pickShellConnector(): Connector | null {
  const here = location.origin;
  const dd = ui.connectors.filter((c) => c.kind === "dd-enclave");
  const sameOrigin = dd.find((c) => {
    const o = c.config.origin as string | undefined;
    return typeof o === "string" && o.replace(/\/+$/, "") === here;
  });
  return sameOrigin ?? dd[0] ?? null;
}

export async function killShell(row: Row): Promise<void> {
  if (row.connector.kind !== "dd-enclave") {
    destroyRow(rowKey(row.connector, row.info.id));
    return;
  }
  try {
    await fetch(`${row.origin}/api/sessions/${row.info.id}`, {
      method: "DELETE",
      credentials: "include",
    });
  } catch {
    // Not fatal — the session might be gone already; the UI cleanup
    // below runs either way.
  }
  destroyRow(rowKey(row.connector, row.info.id));
}

export function destroyRow(id: RowId): void {
  const row = ui.rows.get(id);
  if (!row) return;
  try {
    row.ws?.close();
  } catch {
    // Already closed; nothing to do.
  }
  try {
    row.term?.dispose();
  } catch {
    // Already disposed; nothing to do.
  }
  const rows = new Map(ui.rows);
  rows.delete(id);
  ui.rows = rows;
  if (ui.active === id) {
    ui.active = null;
  }
}

/// Re-export for the sidebar's "Add enclave" dialog.
export { addConnector };
