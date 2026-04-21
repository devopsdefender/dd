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
