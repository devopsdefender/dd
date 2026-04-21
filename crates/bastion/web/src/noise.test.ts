import { describe, expect, it } from "vitest";
import {
  IkInitiator,
  IkResponder,
  Transport,
  keypairFromSeed,
  randomKeypair,
  equal,
} from "./noise";

describe("Noise_IK TS round-trip", () => {
  it("initiator ↔ responder hand a payload both ways", () => {
    const server = randomKeypair();
    const client = randomKeypair();

    const responder = new IkResponder(server);
    const initiator = new IkInitiator(client, server.publicKey);

    const msg1 = initiator.writeMessage(new TextEncoder().encode("hello"));
    const seenByServer = responder.readMessage(msg1);
    expect(new TextDecoder().decode(seenByServer)).toBe("hello");

    const msg2Out = responder.writeMessage(new TextEncoder().encode("hi"));
    expect(equal(msg2Out.peerPubkey, client.publicKey)).toBe(true);

    const msg2In = initiator.readMessage(msg2Out.bytes);
    expect(new TextDecoder().decode(msg2In.payload)).toBe("hi");

    // Transport mode: bidirectional.
    const clientTx = new Transport(msg2In.send, msg2In.recv, server.publicKey);
    const serverTx = new Transport(msg2Out.send, msg2Out.recv, client.publicKey);

    const c1 = clientTx.send(new TextEncoder().encode("ping one"));
    expect(new TextDecoder().decode(serverTx.recv(c1))).toBe("ping one");
    const c2 = clientTx.send(new TextEncoder().encode("ping two"));
    expect(new TextDecoder().decode(serverTx.recv(c2))).toBe("ping two");

    const s1 = serverTx.send(new TextEncoder().encode("pong"));
    expect(new TextDecoder().decode(clientTx.recv(s1))).toBe("pong");
  });

  it("a wrong server pubkey fails at decrypt of the static", () => {
    const server = randomKeypair();
    const other = randomKeypair();
    const client = randomKeypair();

    const responder = new IkResponder(server);
    // Initiator points at a different server's static → `es` DH
    // yields the wrong key, so `decryptAndHash(s_ct)` AEAD fails.
    const initiator = new IkInitiator(client, other.publicKey);
    const msg1 = initiator.writeMessage(new Uint8Array(0));
    expect(() => responder.readMessage(msg1)).toThrow();
  });

  it("tampered transport ciphertext is rejected", () => {
    const server = randomKeypair();
    const client = randomKeypair();
    const responder = new IkResponder(server);
    const initiator = new IkInitiator(client, server.publicKey);
    const msg1 = initiator.writeMessage(new Uint8Array(0));
    responder.readMessage(msg1);
    const msg2Out = responder.writeMessage(new Uint8Array(0));
    const msg2In = initiator.readMessage(msg2Out.bytes);

    const clientTx = new Transport(msg2In.send, msg2In.recv, server.publicKey);
    const serverTx = new Transport(msg2Out.send, msg2Out.recv, client.publicKey);

    const frame = clientTx.send(new TextEncoder().encode("payload"));
    frame[0] ^= 0x01;
    expect(() => serverTx.recv(frame)).toThrow();
  });

  it("keypairFromSeed is deterministic", () => {
    const seed = new Uint8Array(32).fill(7);
    const a = keypairFromSeed(seed);
    const b = keypairFromSeed(seed);
    expect(equal(a.publicKey, b.publicKey)).toBe(true);
    expect(equal(a.secretKey, b.secretKey)).toBe(true);
    expect(a.publicKey.length).toBe(32);
  });

  it("different seeds produce different keys", () => {
    const a = keypairFromSeed(new Uint8Array(32).fill(1));
    const b = keypairFromSeed(new Uint8Array(32).fill(2));
    expect(equal(a.publicKey, b.publicKey)).toBe(false);
  });
});
