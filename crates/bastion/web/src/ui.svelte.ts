import type { Agent, BlockRecord, SessionInfo } from "./types";

/// Composite key so session ids from different agents can't collide.
export type RowId = string; // `${vm_name}/${session_id}`

export interface Row {
  /// Node this session lives on.
  agent: Agent;
  info: SessionInfo;
  blocks: BlockRecord[];
  /// Live WS to the owning agent. `null` until first activation.
  ws: WebSocket | null;
  /// xterm.js instance. `null` until first activation.
  term: import("@xterm/xterm").Terminal | null;
  fit: import("@xterm/addon-fit").FitAddon | null;
}

function rowKey(agent: Agent, sessionId: string): RowId {
  return `${agent.vm_name}/${sessionId}`;
}

/// Svelte 5 runes-based reactive ui. One flat Map of rows, keyed by
/// `${vm_name}/${id}`, populated by fan-out in unified mode or a single
/// fetch in single-node mode.
///
/// Named `ui` (not `state`) to avoid ambiguity with Svelte's `$state`
/// rune when consumers also use runes locally.
export const ui = $state<{
  rows: Map<RowId, Row>;
  active: RowId | null;
  agents: Agent[];
  unified: boolean;
}>({
  rows: new Map(),
  active: null,
  agents: [],
  unified: false,
});

/// Agents to query. In unified mode comes from `window.__DD_AGENTS__`;
/// otherwise a single-element list representing the current origin.
export function resolveAgents(): Agent[] {
  if (window.__DD_AGENTS__ && window.__DD_AGENTS__.length > 0) {
    ui.unified = true;
    return window.__DD_AGENTS__;
  }
  ui.unified = false;
  return [{ vm_name: location.hostname, origin: location.origin }];
}

export async function loadSessions(): Promise<void> {
  ui.agents = resolveAgents();
  const all = await Promise.all(
    ui.agents.map(async (agent): Promise<Row[]> => {
      try {
        const resp = await fetch(`${agent.origin}/api/sessions`, {
          credentials: "include",
        });
        if (!resp.ok) return [];
        const sessions: SessionInfo[] = await resp.json();
        return sessions.map((info) => ({
          agent,
          info,
          blocks: [],
          ws: null,
          term: null,
          fit: null,
        }));
      } catch {
        return [];
      }
    })
  );
  const next = new Map<RowId, Row>();
  for (const bucket of all) {
    for (const row of bucket) {
      next.set(rowKey(row.agent, row.info.id), row);
    }
  }
  ui.rows = next;
}

export async function createShell(agent: Agent): Promise<void> {
  const resp = await fetch(`${agent.origin}/api/sessions`, {
    method: "POST",
    credentials: "include",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ title: "shell" }),
  });
  if (!resp.ok) return;
  const info: SessionInfo = await resp.json();
  const id = rowKey(agent, info.id);
  const rows = new Map(ui.rows);
  rows.set(id, {
    agent,
    info,
    blocks: [],
    ws: null,
    term: null,
    fit: null,
  });
  ui.rows = rows;
  ui.active = id;
}

export async function killShell(row: Row): Promise<void> {
  try {
    await fetch(`${row.agent.origin}/api/sessions/${row.info.id}`, {
      method: "DELETE",
      credentials: "include",
    });
  } catch {
    // Not fatal — the session might be gone already; the UI cleanup
    // below runs either way.
  }
  destroyRow(rowKey(row.agent, row.info.id));
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
