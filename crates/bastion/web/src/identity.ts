/**
 * Device identity seed.
 *
 * Persisted in localStorage as a base64-encoded 32-byte random blob.
 * Generated once per browser origin; survives reloads. Future Noise_KK
 * handshake (Phase 2) will derive an X25519 keypair from this seed so
 * the long-term identity is the same across a refresh / a Tauri build
 * reading the same Stronghold slot.
 *
 * For Phase 1 we only need to prove we persist a stable per-device
 * secret — nothing yet consumes the derived keypair. Keeps the scaffold
 * dependency-light.
 */

const KEY = "dd-bastion-identity-seed";

function b64encode(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

function b64decode(s: string): Uint8Array {
  const raw = atob(s);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}

/// Load the identity seed, minting + persisting a new one on first
/// call. Idempotent. Synchronous — localStorage is the source of truth.
export function loadIdentitySeed(): Uint8Array {
  const cached = localStorage.getItem(KEY);
  if (cached) {
    try {
      const bytes = b64decode(cached);
      if (bytes.length === 32) return bytes;
    } catch {
      // Fall through to regenerate — stored blob was corrupt.
    }
  }
  const seed = new Uint8Array(32);
  crypto.getRandomValues(seed);
  localStorage.setItem(KEY, b64encode(seed));
  return seed;
}

/// Short visual fingerprint of the seed, for UI. Not cryptographic —
/// just lets the user eyeball "am I still the same device?" across
/// reloads. 8 hex chars = 32 bits of collision resistance, enough for
/// human recognition, not enough for authentication.
export function fingerprint(seed: Uint8Array): string {
  let hex = "";
  for (let i = 0; i < 4; i++) {
    hex += seed[i].toString(16).padStart(2, "0");
  }
  return hex;
}
