/**
 * Typed RPC over a Noise_IK-tunneled WebSocket.
 *
 * Wraps the raw `Transport` from `noise.ts` with a request/response
 * correlator (`id` → Promise) so callers write `tunnel.sessions.list()`
 * instead of hand-rolling the JSON envelope + encrypt + await.
 *
 * Matches the server-side `NoiseReq` / `NoiseResp` enums in
 * `crates/bastion/src/lib.rs`. Phase 2b scope:
 * `sessions.list` / `sessions.create` / `sessions.delete` / `ping`.
 */

import { connectNoise, keypairFromSeed, Transport } from "./noise";
import { loadIdentitySeed } from "./identity";
import type { SessionInfo } from "./types";

type Resolve = (body: any) => void;
type Reject = (err: unknown) => void;

interface Pending {
  resolve: Resolve;
  reject: Reject;
}

/// Live Noise tunnel. Own the socket, the transport, and a
/// `request_id → Promise<resolver>` map. Requests are fire-and-await
/// serialized JSON; responses come back keyed by id.
export class Tunnel {
  private nextId = 1n;
  private pending = new Map<bigint, Pending>();
  private closed = false;

  constructor(
    private socket: WebSocket,
    private transport: Transport,
  ) {
    socket.addEventListener("message", (ev) => this.onFrame(ev));
    socket.addEventListener("close", () => this.onClose(new Error("tunnel closed")));
    socket.addEventListener("error", () => this.onClose(new Error("tunnel error")));
  }

  private onFrame(ev: MessageEvent): void {
    if (!(ev.data instanceof ArrayBuffer)) return;
    let body: any;
    try {
      const plain = this.transport.recv(new Uint8Array(ev.data));
      body = JSON.parse(new TextDecoder().decode(plain));
    } catch (e) {
      console.warn("tunnel: bad frame", e);
      return;
    }
    const id = BigInt(body.id ?? 0);
    const p = this.pending.get(id);
    if (!p) return;
    this.pending.delete(id);
    p.resolve(body);
  }

  private onClose(err: unknown): void {
    if (this.closed) return;
    this.closed = true;
    for (const p of this.pending.values()) p.reject(err);
    this.pending.clear();
  }

  private call<T>(op: string, extra: Record<string, unknown> = {}): Promise<T> {
    if (this.closed) return Promise.reject(new Error("tunnel closed"));
    const id = this.nextId++;
    const frame = { id: Number(id), op, ...extra };
    const plain = new TextEncoder().encode(JSON.stringify(frame));
    const cipher = this.transport.send(plain);
    return new Promise<T>((resolve, reject) => {
      this.pending.set(id, {
        resolve: (body) => {
          if (body.kind === "err") reject(new Error(body.msg));
          else resolve(body as T);
        },
        reject,
      });
      this.socket.send(cipher);
    });
  }

  sessionsList(): Promise<SessionInfo[]> {
    return this.call<{ kind: "sessions"; sessions: SessionInfo[] }>("sessions_list").then(
      // Server uses `kind` as discriminator and flattens the vec as
      // `{kind:"sessions",sessions:[...]}` because serde's flatten +
      // tuple variant would need a named field.
      // Match on shape: the Rust side's `NoiseRespBody::Sessions(Vec)`
      // serializes as `{"kind":"sessions"}` + the inner vec spread;
      // we read it as `.sessions` if present, else as the value.
      (body: any) => (Array.isArray(body?.sessions) ? body.sessions : []),
    );
  }

  sessionsCreate(title?: string): Promise<SessionInfo> {
    return this.call<any>("sessions_create", { title: title ?? null }).then((body: any) => {
      if (body.kind !== "session") throw new Error(`unexpected resp kind: ${body.kind}`);
      return body.session ?? body;
    });
  }

  sessionsDelete(sessionId: string): Promise<void> {
    return this.call<any>("sessions_delete", { session_id: sessionId }).then(() => undefined);
  }

  ping(): Promise<number> {
    return this.call<any>("ping").then((body: any) => body.server_time_ms as number);
  }

  close(): void {
    this.closed = true;
    try {
      this.socket.close();
    } catch {
      // already closed
    }
  }
}

/// Open a tunnel to `origin`, using the device's identity seed for
/// the client's long-term static and the server pubkey from the
/// connector config. Rejects if the server doesn't support Noise,
/// if the handshake fails, or if the WS can't be established.
export async function openTunnel(
  origin: string,
  serverPubkeyHex: string,
): Promise<Tunnel> {
  const trimmed = origin.replace(/\/+$/, "");
  const wssUrl = trimmed.replace(/^http(s)?:/, (m) => (m === "http:" ? "ws:" : "wss:")) +
    "/noise/ws";
  const seed = loadIdentitySeed();
  const client = keypairFromSeed(seed);
  const serverPub = decodeHex(serverPubkeyHex);
  const { socket, transport } = await connectNoise(wssUrl, client, serverPub);
  return new Tunnel(socket, transport);
}

function decodeHex(hex: string): Uint8Array {
  if (hex.length !== 64) throw new Error(`pubkey: expected 64 hex chars, got ${hex.length}`);
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}
