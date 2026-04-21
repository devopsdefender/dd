/**
 * Client-side connector registry — the source of truth for what
 * shows up in the sidebar.
 *
 * Each entry is one *source* of sessions: a DD enclave, an SSH host,
 * an Anthropic API key, a GitHub token, a local shell (Tauri only).
 * The Svelte UI iterates connectors and, per kind, knows how to
 * populate `ui.rows` with the connector's sessions.
 *
 * Persistence: IndexedDB object store `connectors`, keyed by `id`.
 * Stays on the device. Phase 3 will replicate it across the user's
 * other devices via an encrypted sync channel keyed by the identity
 * key (see `identity.ts`).
 */

import type { Agent } from "./types";

export type ConnectorKind =
  | "dd-enclave"
  | "ssh-host"
  | "anthropic"
  | "github"
  | "local-shell";

export interface Connector {
  id: string; // opaque client-generated uuid
  kind: ConnectorKind;
  label: string;
  config: Record<string, unknown>;
  created_at_ms: number;
}

const DB_NAME = "bastion";
const DB_STORE = "connectors";
const DB_VERSION = 1;

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(DB_STORE)) {
        db.createObjectStore(DB_STORE, { keyPath: "id" });
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

export async function listConnectors(): Promise<Connector[]> {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(DB_STORE, "readonly");
    const req = tx.objectStore(DB_STORE).getAll();
    req.onsuccess = () => resolve(req.result as Connector[]);
    req.onerror = () => reject(req.error);
  });
}

export async function addConnector(c: Connector): Promise<void> {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(DB_STORE, "readwrite");
    tx.objectStore(DB_STORE).put(c);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

export async function removeConnector(id: string): Promise<void> {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(DB_STORE, "readwrite");
    tx.objectStore(DB_STORE).delete(id);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

function newId(): string {
  // `crypto.randomUUID` is available in every browser Tauri v2
  // supports; don't bother polyfilling.
  return crypto.randomUUID();
}

/// One-shot seed: on first run, convert whatever agents the CP's
/// page-time fetch already injected into `window.__DD_AGENTS__` into
/// persistent connector entries. Idempotent — subsequent calls no-op
/// if the store is non-empty.
export async function seedFromAgents(agents: Agent[]): Promise<void> {
  const existing = await listConnectors();
  if (existing.length > 0) return;
  const now = Date.now();
  for (const a of agents) {
    await addConnector({
      id: newId(),
      kind: "dd-enclave",
      label: a.vm_name,
      config: { vm_name: a.vm_name, origin: a.origin },
      created_at_ms: now,
    });
  }
}

/// Add a DD enclave via its public bastion origin
/// (e.g. `https://dd-prod-agent-abc-block.devopsdefender.com`).
/// Label defaults to the origin host if not provided.
export async function addDdEnclave(
  origin: string,
  label?: string,
): Promise<Connector> {
  const trimmed = origin.trim().replace(/\/+$/, "");
  const vm = label?.trim() || new URL(trimmed).hostname;
  const c: Connector = {
    id: newId(),
    kind: "dd-enclave",
    label: vm,
    config: { vm_name: vm, origin: trimmed },
    created_at_ms: Date.now(),
  };
  await addConnector(c);
  return c;
}

/// Fetch a DD enclave's long-term Noise pubkey via `GET /attest`.
/// Returns `null` on any error (cross-origin CF-Access bounce,
/// connector offline, server missing `--noise-key`). Phase 2b uses
/// the returned pubkey as the responder static for the Noise_KK
/// handshake; Phase 2d adds a TDX quote to the same response that
/// binds the pubkey into `REPORT_DATA` so clients can verify.
export async function fetchAttest(
  origin: string,
): Promise<{ noise_pubkey_hex: string; source: string } | null> {
  try {
    const resp = await fetch(`${origin}/attest`, { credentials: "include" });
    if (!resp.ok) return null;
    const body = await resp.json();
    if (typeof body?.noise_pubkey_hex !== "string") return null;
    return {
      noise_pubkey_hex: body.noise_pubkey_hex,
      source: typeof body?.source === "string" ? body.source : "unknown",
    };
  } catch {
    return null;
  }
}

/// Merge `patch` into an existing connector's `config` and persist.
/// Used by the attest cache to remember server Noise pubkeys across
/// page loads. Silent no-op if the connector isn't in IDB.
export async function patchConnectorConfig(
  id: string,
  patch: Record<string, unknown>,
): Promise<void> {
  const db = await openDb();
  const existing: Connector | undefined = await new Promise(
    (resolve, reject) => {
      const tx = db.transaction(DB_STORE, "readonly");
      const req = tx.objectStore(DB_STORE).get(id);
      req.onsuccess = () => resolve(req.result as Connector | undefined);
      req.onerror = () => reject(req.error);
    },
  );
  if (!existing) return;
  existing.config = { ...existing.config, ...patch };
  await addConnector(existing);
}
