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
import { openTunnel, Tunnel } from "./tunnel";

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
  /// Plain `/ws/{id}` WebSocket — used for same-origin loads where
  /// CF Access already covers the upgrade. `null` until first
  /// activation, or when the row is served over the Noise shell
  /// tunnel instead.
  ws: WebSocket | null;
  /// Noise-tunneled PTY stream for cross-origin enclaves. Mutually
  /// exclusive with `ws` — whichever was opened first wins.
  shell: import("./tunnel").ShellTunnel | null;
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

/// Lazy per-connector Noise tunnel cache. Opened on first use by
/// [`getTunnel`]; kept open for subsequent RPCs. Recreated
/// transparently if the underlying socket dies.
const tunnels = new Map<string, Promise<Tunnel>>();

/// Open (or re-use) a Noise tunnel for `c`. Returns `null` if the
/// server hasn't advertised a pubkey yet (Phase 2a hasn't run on
/// this origin) or the handshake fails for any reason — callers
/// should fall back to plain `fetch` in that case.
async function getTunnel(c: Connector): Promise<Tunnel | null> {
  const origin = (c.config.origin as string | undefined) ?? "";
  const pubkey = c.config.serverNoisePubkeyHex as string | undefined;
  if (!origin || !pubkey) return null;
  const existing = tunnels.get(c.id);
  if (existing) {
    return existing.catch(() => {
      tunnels.delete(c.id);
      return null;
    });
  }
  const p = openTunnel(origin, pubkey).catch((e) => {
    console.warn(`tunnel: open ${origin} failed`, e);
    tunnels.delete(c.id);
    throw e;
  });
  tunnels.set(c.id, p);
  try {
    return await p;
  } catch {
    return null;
  }
}

/// Fetch an enclave's live sessions. Prefers the Noise tunnel (no
/// CORS preflight, no CF Access bounce); falls back to plain fetch
/// for same-origin connectors or origins that predate Phase 2a.
/// Either failure path degrades to "no rows" so the sidebar still
/// shows every connector the user configured.
async function fetchDdEnclave(c: Connector): Promise<Row[]> {
  const origin = (c.config.origin as string | undefined) ?? "";
  if (!origin) return [];
  const tunnel = await getTunnel(c);
  const sessions = await (tunnel
    ? tunnel.sessionsList().catch((): SessionInfo[] => [])
    : fetch(`${origin}/api/sessions`, { credentials: "include" })
        .then((r) => (r.ok ? r.json() : []))
        .catch((): SessionInfo[] => []));
  return sessions.map((info: SessionInfo) => ({
    connector: c,
    origin,
    info,
    blocks: [],
    ws: null,
    shell: null,
    term: null,
    fit: null,
  }));
}

export async function createShell(c: Connector): Promise<void> {
  if (c.kind !== "dd-enclave") return;
  const origin = (c.config.origin as string | undefined) ?? "";
  if (!origin) return;
  const tunnel = await getTunnel(c);
  try {
    const info: SessionInfo = tunnel
      ? await tunnel.sessionsCreate("shell")
      : await (async () => {
          const resp = await fetch(`${origin}/api/sessions`, {
            method: "POST",
            credentials: "include",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ title: "shell" }),
          });
          if (!resp.ok) throw new Error(`${origin} → ${resp.status}`);
          return resp.json();
        })();
    const id = rowKey(c, info.id);
    const rows = new Map(ui.rows);
    rows.set(id, {
      connector: c,
      origin,
      info,
      blocks: [],
      ws: null,
      shell: null,
      term: null,
      fit: null,
    });
    ui.rows = rows;
    ui.active = id;
  } catch (e) {
    // Cross-origin + CF Access fails plain fetch with a TypeError
    // before it reaches the origin; the tunnel path would have
    // rejected instead. Either way we swallow so the click handler
    // doesn't throw red in the console.
    console.warn(`createShell: ${origin}`, e);
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
  const tunnel = await getTunnel(row.connector);
  try {
    if (tunnel) {
      await tunnel.sessionsDelete(row.info.id);
    } else {
      await fetch(`${row.origin}/api/sessions/${row.info.id}`, {
        method: "DELETE",
        credentials: "include",
      });
    }
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
    row.shell?.close();
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
