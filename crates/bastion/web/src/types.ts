export interface SessionInfo {
  id: string;
  kind: string;
  title: string;
  created_at_ms: number;
  next_seq: number;
}

export interface BlockRecord {
  session_id: string;
  kind: string;
  seq: number;
  started_at_ms: number;
  ended_at_ms: number;
  command: string;
  output_b64: string;
  exit_code: number;
}

/// One node (agent or CP) the unified view fans out to.
/// `origin` is the full `https://…` base for `fetch` / `wss://` URLs.
export interface Agent {
  vm_name: string;
  origin: string;
}

declare global {
  interface Window {
    /// Injected by the CP `/bastion` handler. When present, the SPA
    /// enters unified mode and fans out to every listed node. When
    /// absent, the SPA stays in single-node mode (agent-local bastion).
    __DD_AGENTS__?: Agent[];
  }
}
