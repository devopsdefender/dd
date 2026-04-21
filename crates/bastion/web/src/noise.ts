/**
 * Noise_IK_25519_ChaChaPoly_SHA256 — initiator state machine.
 *
 * Browser-side counterpart to the Rust responder in
 * `crates/dd-common/src/noise_tunnel.rs`. Small hand-rolled
 * implementation of §5 of the Noise Protocol spec, pattern IK only.
 *
 * Why hand-rolled: the two popular npm packages (`noise-protocol`,
 * `noise-handshake`) both pull `sodium-universal` + `libsodium.js`
 * into the bundle. Building on `@noble/*` primitives keeps the SPA
 * payload ~40 KB instead of ~250 KB and avoids a wasm runtime.
 *
 * Spec references are to
 * https://noiseprotocol.org/noise.html rev-34.
 */

import { x25519 } from "@noble/curves/ed25519.js";
import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { hmac } from "@noble/hashes/hmac.js";

const PROTOCOL_NAME = "Noise_IK_25519_ChaChaPoly_SHA256";
const HASHLEN = 32;
const DHLEN = 32;

/// Concatenate two byte arrays into a new one. Explicitly-typed
/// return so TS 5.7's stricter `Uint8Array<ArrayBuffer>` inference
/// doesn't downgrade callers to `Uint8Array<ArrayBufferLike>`.
function concat(a: Uint8Array, b: Uint8Array): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

function equal(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/// 12-byte ChaCha20-Poly1305 nonce per §5.2: 4 zero bytes followed by
/// the 64-bit counter in little-endian order.
function nonce12(n: bigint): Uint8Array {
  const out = new Uint8Array(12);
  const view = new DataView(out.buffer);
  // First 4 bytes stay zero.
  view.setBigUint64(4, n, true);
  return out;
}

/// HKDF-with-HMAC-SHA256 as the Noise spec defines it — returns 1, 2,
/// or 3 32-byte outputs depending on `num_outputs`.
function hkdf(
  chainingKey: Uint8Array,
  inputKeyMaterial: Uint8Array,
  numOutputs: 1 | 2 | 3,
): Uint8Array[] {
  const tempKey = hmac(sha256, chainingKey, inputKeyMaterial);
  const out1 = hmac(sha256, tempKey, new Uint8Array([0x01]));
  if (numOutputs === 1) return [out1];
  const out2 = hmac(sha256, tempKey, concat(out1, new Uint8Array([0x02])));
  if (numOutputs === 2) return [out1, out2];
  const out3 = hmac(sha256, tempKey, concat(out2, new Uint8Array([0x03])));
  return [out1, out2, out3];
}

/**
 * CipherState — §5.1. Wraps a 32-byte key and a 64-bit counter.
 * Nonce overflow (after 2^64-1 messages) is fatal per spec. The
 * `hasKey` gating mirrors the spec's `k == empty` sentinel.
 */
class CipherState {
  k: Uint8Array | null = null;
  n: bigint = 0n;

  initializeKey(k: Uint8Array | null): void {
    this.k = k;
    this.n = 0n;
  }

  hasKey(): boolean {
    return this.k !== null;
  }

  encryptWithAd(ad: Uint8Array, plaintext: Uint8Array): Uint8Array {
    if (!this.k) return plaintext;
    // @noble/ciphers factory takes AAD as the 3rd arg (not `encrypt`).
    const cipher = chacha20poly1305(this.k, nonce12(this.n), ad);
    const ct = cipher.encrypt(plaintext);
    this.n += 1n;
    return ct;
  }

  decryptWithAd(ad: Uint8Array, ciphertext: Uint8Array): Uint8Array {
    if (!this.k) return ciphertext;
    const cipher = chacha20poly1305(this.k, nonce12(this.n), ad);
    const pt = cipher.decrypt(ciphertext);
    this.n += 1n;
    return pt;
  }
}

/**
 * SymmetricState — §5.2. Owns the chaining key, transcript hash,
 * and the currently-active CipherState. Drives the MixHash / MixKey
 * flow that IK's message tokens translate into.
 */
class SymmetricState {
  ck: Uint8Array;
  h: Uint8Array;
  cs: CipherState;

  constructor() {
    const name = new TextEncoder().encode(PROTOCOL_NAME);
    // Protocol name fits in HASHLEN? §5.2: "If protocol_name is less
    // than or equal to HASHLEN bytes in length, sets h equal to
    // protocol_name with zero bytes appended to make HASHLEN bytes.
    // Otherwise sets h = HASH(protocol_name)." Ours is 32 bytes on the
    // nose, so zero-pad (no-op) and done.
    if (name.length <= HASHLEN) {
      this.h = new Uint8Array(HASHLEN);
      this.h.set(name, 0);
    } else {
      this.h = sha256(name);
    }
    this.ck = new Uint8Array(this.h);
    this.cs = new CipherState();
  }

  mixHash(data: Uint8Array): void {
    this.h = sha256(concat(this.h, data));
  }

  mixKey(ikm: Uint8Array): void {
    const [newCk, tempK] = hkdf(this.ck, ikm, 2);
    this.ck = newCk;
    this.cs.initializeKey(tempK);
  }

  encryptAndHash(plaintext: Uint8Array): Uint8Array {
    const ct = this.cs.encryptWithAd(this.h, plaintext);
    this.mixHash(ct);
    return ct;
  }

  decryptAndHash(ciphertext: Uint8Array): Uint8Array {
    const pt = this.cs.decryptWithAd(this.h, ciphertext);
    this.mixHash(ciphertext);
    return pt;
  }

  /// Finalize into two CipherStates per §5.2's Split(): one for each
  /// direction. For the initiator, `c1` encrypts outbound, `c2`
  /// decrypts inbound.
  split(): [CipherState, CipherState] {
    const [k1, k2] = hkdf(this.ck, new Uint8Array(0), 2);
    const c1 = new CipherState();
    const c2 = new CipherState();
    c1.initializeKey(k1);
    c2.initializeKey(k2);
    return [c1, c2];
  }
}

export interface Keypair {
  secretKey: Uint8Array;
  publicKey: Uint8Array;
}

/// Derive the client's X25519 keypair from a stable 32-byte seed.
/// Same seed → same keypair, so the SPA's identity (stored in
/// localStorage as `dd-identity-seed`) survives reloads.
export function keypairFromSeed(seed: Uint8Array): Keypair {
  if (seed.length !== 32) {
    throw new Error(`expected 32-byte seed, got ${seed.length}`);
  }
  // x25519 clamps the scalar internally, so any 32 random bytes
  // produce a valid keypair. HMAC-SHA256 the seed with a domain tag
  // so the Noise key is distinct from anything else the seed is used
  // to derive (device fingerprint, at-rest ciphertext key, etc.).
  const secretKey = hmac(sha256, seed, new TextEncoder().encode("dd-noise-static-v1"));
  const publicKey = x25519.getPublicKey(secretKey);
  return { secretKey, publicKey };
}

/// Generate a fresh throwaway keypair — used as the handshake
/// ephemeral `e`.
export function randomKeypair(): Keypair {
  const { secretKey, publicKey } = x25519.keygen();
  return { secretKey, publicKey };
}

/**
 * Initiator-side IK handshake driver. Pattern messages per §7.5:
 *
 * ```
 * IK:
 *   <- s
 *   ...
 *   -> e, es, s, ss
 *   <- e, ee, se
 * ```
 *
 * `<- s` is a pre-message: the initiator knows the responder's
 * static pubkey up front (fetched via `GET /attest`).
 */
export class IkInitiator {
  private sym: SymmetricState;
  private s: Keypair;
  private e: Keypair | null = null;
  private rs: Uint8Array;

  constructor(s: Keypair, rs: Uint8Array, prologue: Uint8Array = new Uint8Array(0)) {
    if (rs.length !== DHLEN) throw new Error(`rs: expected ${DHLEN} bytes`);
    this.sym = new SymmetricState();
    this.sym.mixHash(prologue);
    // `<- s` pre-message: hash the responder's static into the
    // transcript.
    this.sym.mixHash(rs);
    this.s = s;
    this.rs = rs;
  }

  /// Produce the first handshake message `-> e, es, s, ss`.
  /// `payload` is application data carried inside the encrypted
  /// handshake — typically empty in our deployment.
  writeMessage(payload: Uint8Array): Uint8Array {
    this.e = randomKeypair();
    // -> e
    let buf = new Uint8Array(this.e.publicKey);
    this.sym.mixHash(this.e.publicKey);
    // -> es
    this.sym.mixKey(x25519.getSharedSecret(this.e.secretKey, this.rs));
    // -> s (encrypted)
    const sCt = this.sym.encryptAndHash(this.s.publicKey);
    buf = concat(buf, sCt);
    // -> ss
    this.sym.mixKey(x25519.getSharedSecret(this.s.secretKey, this.rs));
    // -> payload (encrypted)
    const payloadCt = this.sym.encryptAndHash(payload);
    return concat(buf, payloadCt);
  }

  /// Consume the responder's reply `<- e, ee, se` and finalize the
  /// handshake. Returns the decrypted payload and the two transport
  /// CipherStates ([send, recv] from the initiator's perspective).
  readMessage(message: Uint8Array): {
    payload: Uint8Array;
    send: CipherState;
    recv: CipherState;
  } {
    if (!this.e) throw new Error("readMessage before writeMessage");
    if (message.length < DHLEN) throw new Error("msg2 too short");
    // <- e
    const re = message.slice(0, DHLEN);
    this.sym.mixHash(re);
    // <- ee
    this.sym.mixKey(x25519.getSharedSecret(this.e.secretKey, re));
    // <- se (initiator uses its static, responder their ephemeral)
    this.sym.mixKey(x25519.getSharedSecret(this.s.secretKey, re));
    // <- payload
    const rest = message.slice(DHLEN);
    const payload = this.sym.decryptAndHash(rest);
    const [send, recv] = this.sym.split();
    return { payload, send, recv };
  }
}

/**
 * Post-handshake transport. Wraps a pair of CipherStates and
 * exposes a symmetric `send` / `recv` API. Matches the Rust
 * `Transport` in `noise_tunnel.rs`.
 */
export class Transport {
  constructor(
    private send_: CipherState,
    private recv_: CipherState,
    readonly peerPubkey: Uint8Array,
  ) {}

  send(plaintext: Uint8Array): Uint8Array {
    return this.send_.encryptWithAd(new Uint8Array(0), plaintext);
  }

  recv(ciphertext: Uint8Array): Uint8Array {
    return this.recv_.decryptWithAd(new Uint8Array(0), ciphertext);
  }
}

/**
 * Open a Noise-tunneled WebSocket to `wssUrl`. Pins the server's
 * long-term static key via the caller-supplied `serverPubkey` (hex
 * decoded). Once the handshake completes, callers use `tunnel.fetch`
 * and `tunnel.ws` as if they were same-origin HTTP/WS.
 *
 * Rejects with a concrete error so the sidebar can fall back to
 * plain fetch when the origin doesn't support Noise (e.g. an older
 * agent deployed before Phase 2b).
 */
export async function connectNoise(
  wssUrl: string,
  clientStatic: Keypair,
  serverPubkey: Uint8Array,
): Promise<{ socket: WebSocket; transport: Transport }> {
  const socket = new WebSocket(wssUrl);
  socket.binaryType = "arraybuffer";
  await new Promise<void>((resolve, reject) => {
    socket.addEventListener("open", () => resolve(), { once: true });
    socket.addEventListener("error", () => reject(new Error(`ws open: ${wssUrl}`)), {
      once: true,
    });
  });

  const initiator = new IkInitiator(clientStatic, serverPubkey);
  const msg1 = initiator.writeMessage(new Uint8Array(0));
  socket.send(msg1);

  const msg2 = await new Promise<Uint8Array>((resolve, reject) => {
    socket.addEventListener(
      "message",
      (ev) => {
        if (ev.data instanceof ArrayBuffer) resolve(new Uint8Array(ev.data));
        else reject(new Error("msg2 was not binary"));
      },
      { once: true },
    );
    socket.addEventListener("error", () => reject(new Error("ws error during handshake")), {
      once: true,
    });
    socket.addEventListener(
      "close",
      (ev) => reject(new Error(`ws closed during handshake: ${ev.code} ${ev.reason}`)),
      { once: true },
    );
  });

  const { send, recv } = initiator.readMessage(msg2);
  const transport = new Transport(send, recv, serverPubkey);
  return { socket, transport };
}

// --------------------------------------------------------------
// Test-only exports. The build's treeshaker strips these from the
// production bundle when nothing imports them; the unit test in
// `noise.test.ts` is the only consumer.
// --------------------------------------------------------------

/// Responder-side IK driver — only used by the in-browser round-trip
/// test so CI can gate on TS-TS consistency without spawning the
/// Rust server. The real server lives in Rust / `snow`.
export class IkResponder {
  private sym: SymmetricState;
  private s: Keypair;
  private e: Keypair | null = null;
  /// Initiator's ephemeral pubkey — learned from msg1, consumed by
  /// msg2's `ee` + `se` DHs.
  private re: Uint8Array | null = null;
  /// Initiator's static pubkey — decrypted from msg1. Exposed after
  /// the handshake so the caller can pin / authorize the peer.
  private rs: Uint8Array | null = null;

  constructor(s: Keypair, prologue: Uint8Array = new Uint8Array(0)) {
    this.sym = new SymmetricState();
    this.sym.mixHash(prologue);
    // `<- s` pre-message from the responder's view: the responder's
    // own static is pre-known.
    this.sym.mixHash(s.publicKey);
    this.s = s;
  }

  readMessage(message: Uint8Array): Uint8Array {
    if (message.length < DHLEN) throw new Error("msg1 too short");
    // <- e
    this.re = message.slice(0, DHLEN);
    this.sym.mixHash(this.re);
    // <- es
    this.sym.mixKey(x25519.getSharedSecret(this.s.secretKey, this.re));
    // s_ct is DHLEN + 16 bytes (enc pubkey + tag)
    const sCt = message.slice(DHLEN, DHLEN + DHLEN + 16);
    this.rs = this.sym.decryptAndHash(sCt);
    // <- ss
    this.sym.mixKey(x25519.getSharedSecret(this.s.secretKey, this.rs));
    const payloadCt = message.slice(DHLEN + DHLEN + 16);
    const payload = this.sym.decryptAndHash(payloadCt);
    // Mint our ephemeral for the reply.
    this.e = randomKeypair();
    return payload;
  }

  writeMessage(payload: Uint8Array): {
    bytes: Uint8Array;
    send: CipherState;
    recv: CipherState;
    peerPubkey: Uint8Array;
  } {
    if (!this.e || !this.re || !this.rs) {
      throw new Error("writeMessage before readMessage");
    }
    let buf = new Uint8Array(this.e.publicKey);
    this.sym.mixHash(this.e.publicKey);
    // -> ee: responder ephemeral × initiator ephemeral
    this.sym.mixKey(x25519.getSharedSecret(this.e.secretKey, this.re));
    // -> se: responder ephemeral × initiator static
    this.sym.mixKey(x25519.getSharedSecret(this.e.secretKey, this.rs));
    const payloadCt = this.sym.encryptAndHash(payload);
    buf = concat(buf, payloadCt);
    // Split with direction swap — responder's "send" is initiator's
    // "recv" and vice versa.
    const [c1, c2] = this.sym.split();
    return { bytes: buf, send: c2, recv: c1, peerPubkey: this.rs };
  }
}

export { CipherState, SymmetricState, equal, concat };
