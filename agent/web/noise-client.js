// DD Noise Client — Noise_XX handshake over WebSocket for end-to-end encryption.
//
// This module handles the Noise protocol handshake with the agent and provides
// encrypt/decrypt functions for the application layer.
//
// Requires: noise-c.wasm (loaded via importScripts or bundled)
//
// Usage:
//   const session = await noiseConnect(websocket);
//   // session.attestation contains the agent's attestation payload
//   // session.send(plaintext) encrypts and sends over WebSocket
//   // session.onmessage = (plaintext) => { ... } called on decrypted messages
//
// Wire protocol over WebSocket:
//   Handshake phase: binary frames containing raw Noise handshake messages
//   Transport phase: binary frames containing Noise-encrypted application messages
//   Application messages are length-prefixed JSON: [u32 big-endian length][JSON bytes]

// Placeholder — noise-c.wasm integration goes here.
// For now, this file documents the protocol for when the WASM library is integrated.
//
// The handshake flow (browser = initiator, agent = responder):
//
// 1. Browser generates ephemeral X25519 keypair
// 2. Browser sends msg1 (48 bytes) as binary WebSocket frame
// 3. Agent responds with msg2 (binary frame) containing attestation as payload
// 4. Browser sends msg3 (binary frame)
// 5. Both sides derive transport keys
// 6. All subsequent frames are encrypted
//
// The agent detects the mode by the first WebSocket message:
// - Binary frame starting with Noise handshake bytes → Noise mode
// - Text frame with JSON → plaintext mode (current fallback)

/**
 * @typedef {Object} NoiseSession
 * @property {Object} attestation - Agent attestation payload from handshake
 * @property {function(Uint8Array): void} send - Send encrypted message
 * @property {function(function(Uint8Array): void): void} onmessage - Set decrypted message handler
 * @property {function(): void} close - Close the session
 */

/**
 * Perform Noise_XX handshake over WebSocket and return encrypted session.
 * Falls back to plaintext JSON if noise-c.wasm is not available.
 *
 * @param {string} wsUrl - WebSocket URL
 * @returns {Promise<NoiseSession>}
 */
export async function noiseConnect(wsUrl) {
  // TODO: Load noise-c.wasm, perform Noise_XX handshake
  // For now, return a plaintext session wrapper
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(wsUrl);
    let messageHandler = null;

    ws.onopen = () => {
      resolve({
        attestation: null,
        send: (data) => {
          const msg = JSON.stringify({
            type: 'stdin',
            data: Array.from(data)
          });
          ws.send(msg);
        },
        onmessage: (handler) => { messageHandler = handler; },
        close: () => ws.close(),
        ws: ws,
      });
    };

    ws.onmessage = (event) => {
      if (messageHandler) {
        try {
          const msg = JSON.parse(typeof event.data === 'string' ? event.data : new TextDecoder().decode(event.data));
          if (msg.type === 'attestation') {
            // Store attestation for verification
          } else if (msg.type === 'stdout' || msg.type === 'stderr') {
            const text = typeof msg.data === 'string' ? msg.data : String.fromCharCode(...msg.data);
            messageHandler(new TextEncoder().encode(text));
          }
        } catch {
          messageHandler(typeof event.data === 'string' ? new TextEncoder().encode(event.data) : new Uint8Array(event.data));
        }
      }
    };

    ws.onerror = () => reject(new Error('WebSocket connection failed'));
  });
}
