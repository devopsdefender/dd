//! Noise_IK tunnel primitive (Phase 2b).
//!
//! Wraps `snow` with a small state machine so the axum `/noise/ws`
//! handler and the TS client implementation can stay focused on
//! framing. Pattern is **Noise_IK_25519_ChaChaPoly_SHA256**:
//!
//! - Initiator knows responder's static pubkey up-front (fetched via
//!   `GET /attest` in Phase 2a) — enables server auth on the first
//!   roundtrip with no prior handshake.
//! - Initiator's static pubkey is transmitted inside the handshake
//!   (encrypted under the ephemeral-static DH) — server learns the
//!   client identity after msg1, can pin or accept per policy.
//!
//! IK is 1-RTT: client sends msg1, server sends msg2, both sides
//! are in transport mode. Matches a WebSocket's
//! client-speaks-first model.
//!
//! Pairing / device-key registry is intentionally out of scope here
//! — the server accepts any initiator pubkey today and logs it;
//! Phase 3 adds a pinning layer that rejects unknown keys.

use snow::{params::NoiseParams, HandshakeState, TransportState};
use std::sync::LazyLock;

pub static PARAMS: LazyLock<NoiseParams> = LazyLock::new(|| {
    "Noise_IK_25519_ChaChaPoly_SHA256"
        .parse()
        .expect("valid noise params")
});

/// Established Noise session. Both sides have symmetric ciphers
/// keyed from the handshake; `peer_pubkey` is the counterpart's
/// long-term static (32 raw X25519 bytes).
pub struct Transport {
    state: TransportState,
    peer_pubkey: [u8; 32],
}

impl Transport {
    /// Encrypt + authenticate a payload. Returns the ciphertext to
    /// frame on the wire.
    pub fn send(&mut self, plain: &[u8]) -> Result<Vec<u8>, snow::Error> {
        let mut buf = vec![0u8; plain.len() + 16];
        let len = self.state.write_message(plain, &mut buf)?;
        buf.truncate(len);
        Ok(buf)
    }

    /// Decrypt + verify a ciphertext. Returns the plaintext.
    pub fn recv(&mut self, cipher: &[u8]) -> Result<Vec<u8>, snow::Error> {
        let mut buf = vec![0u8; cipher.len()];
        let len = self.state.read_message(cipher, &mut buf)?;
        buf.truncate(len);
        Ok(buf)
    }

    pub fn peer_pubkey(&self) -> &[u8; 32] {
        &self.peer_pubkey
    }
}

/// Responder (server) side of a Noise_IK handshake. Owns the
/// server's long-term static key and runs exactly one handshake
/// roundtrip per instance.
pub struct Responder {
    state: HandshakeState,
}

impl Responder {
    pub fn new(local_secret: &[u8; 32]) -> Result<Self, snow::Error> {
        let state = snow::Builder::new(PARAMS.clone())
            .local_private_key(local_secret)?
            .build_responder()?;
        Ok(Self { state })
    }

    /// Consume the initiator's first message (`-> e, es, s, ss`).
    /// After this call the responder has the initiator's static
    /// pubkey available via [`Responder::peer_pubkey`].
    pub fn read_msg1(&mut self, msg: &[u8]) -> Result<Vec<u8>, snow::Error> {
        let mut buf = vec![0u8; msg.len()];
        let len = self.state.read_message(msg, &mut buf)?;
        buf.truncate(len);
        Ok(buf)
    }

    /// Produce the responder's reply (`<- e, ee, se`).
    pub fn write_msg2(&mut self, payload: &[u8]) -> Result<Vec<u8>, snow::Error> {
        let mut buf = vec![0u8; payload.len() + 96];
        let len = self.state.write_message(payload, &mut buf)?;
        buf.truncate(len);
        Ok(buf)
    }

    /// Initiator's static pubkey, learned during [`read_msg1`]. Used
    /// by the server for logging + (future) pinning. Returns `None`
    /// if called before msg1 has been consumed.
    pub fn peer_pubkey(&self) -> Option<[u8; 32]> {
        let raw = self.state.get_remote_static()?;
        let mut out = [0u8; 32];
        out.copy_from_slice(raw);
        Some(out)
    }

    /// Transition to transport mode once the handshake is complete.
    /// Caller is responsible for having done one read + one write
    /// in order before calling; `snow` panics otherwise.
    pub fn into_transport(self) -> Result<Transport, snow::Error> {
        let peer = self
            .peer_pubkey()
            .ok_or(snow::Error::State(snow::error::StateProblem::MissingKeyMaterial))?;
        let state = self.state.into_transport_mode()?;
        Ok(Transport {
            state,
            peer_pubkey: peer,
        })
    }
}

/// Initiator (client) side. Used in tests + by CP↔agent peering;
/// the browser implementation is in `crates/bastion/web/src/noise.ts`.
pub struct Initiator {
    state: HandshakeState,
    remote_pub: [u8; 32],
}

impl Initiator {
    pub fn new(local_secret: &[u8; 32], remote_public: &[u8; 32]) -> Result<Self, snow::Error> {
        let state = snow::Builder::new(PARAMS.clone())
            .local_private_key(local_secret)?
            .remote_public_key(remote_public)?
            .build_initiator()?;
        Ok(Self {
            state,
            remote_pub: *remote_public,
        })
    }

    pub fn write_msg1(&mut self, payload: &[u8]) -> Result<Vec<u8>, snow::Error> {
        let mut buf = vec![0u8; payload.len() + 96];
        let len = self.state.write_message(payload, &mut buf)?;
        buf.truncate(len);
        Ok(buf)
    }

    pub fn read_msg2(&mut self, msg: &[u8]) -> Result<Vec<u8>, snow::Error> {
        let mut buf = vec![0u8; msg.len()];
        let len = self.state.read_message(msg, &mut buf)?;
        buf.truncate(len);
        Ok(buf)
    }

    pub fn into_transport(self) -> Result<Transport, snow::Error> {
        let state = self.state.into_transport_mode()?;
        Ok(Transport {
            state,
            peer_pubkey: self.remote_pub,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use x25519_dalek::{PublicKey, StaticSecret};

    fn fresh_keypair() -> ([u8; 32], [u8; 32]) {
        let secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let public = PublicKey::from(&secret);
        (secret.to_bytes(), *public.as_bytes())
    }

    #[test]
    fn ik_round_trip_transport_mode() {
        let (server_sk, server_pk) = fresh_keypair();
        let (client_sk, client_pk) = fresh_keypair();

        let mut responder = Responder::new(&server_sk).unwrap();
        let mut initiator = Initiator::new(&client_sk, &server_pk).unwrap();

        let msg1 = initiator.write_msg1(b"hello").unwrap();
        let prologue_payload = responder.read_msg1(&msg1).unwrap();
        assert_eq!(prologue_payload, b"hello");
        assert_eq!(responder.peer_pubkey().unwrap(), client_pk);

        let msg2 = responder.write_msg2(b"hi").unwrap();
        let reply_payload = initiator.read_msg2(&msg2).unwrap();
        assert_eq!(reply_payload, b"hi");

        let mut server = responder.into_transport().unwrap();
        let mut client = initiator.into_transport().unwrap();
        assert_eq!(server.peer_pubkey(), &client_pk);
        assert_eq!(client.peer_pubkey(), &server_pk);

        // Bidirectional stream — two messages each direction to
        // exercise nonce increment.
        let c1 = client.send(b"ping one").unwrap();
        assert_eq!(server.recv(&c1).unwrap(), b"ping one");
        let c2 = client.send(b"ping two").unwrap();
        assert_eq!(server.recv(&c2).unwrap(), b"ping two");
        let s1 = server.send(b"pong").unwrap();
        assert_eq!(client.recv(&s1).unwrap(), b"pong");
    }

    #[test]
    fn mismatched_server_pubkey_rejects() {
        let (server_sk, _server_pk) = fresh_keypair();
        let (_other_sk, other_pk) = fresh_keypair();
        let (client_sk, _) = fresh_keypair();

        let mut responder = Responder::new(&server_sk).unwrap();
        let mut initiator = Initiator::new(&client_sk, &other_pk).unwrap();

        let msg1 = initiator.write_msg1(b"").unwrap();
        // Server can't decrypt msg1's `s` because the initiator
        // encrypted it against the wrong server pubkey.
        assert!(responder.read_msg1(&msg1).is_err());
    }

    #[test]
    fn tampered_ciphertext_rejects() {
        let (server_sk, server_pk) = fresh_keypair();
        let (client_sk, _) = fresh_keypair();

        let mut responder = Responder::new(&server_sk).unwrap();
        let mut initiator = Initiator::new(&client_sk, &server_pk).unwrap();

        let msg1 = initiator.write_msg1(b"").unwrap();
        responder.read_msg1(&msg1).unwrap();
        let msg2 = responder.write_msg2(b"").unwrap();
        initiator.read_msg2(&msg2).unwrap();

        let mut server = responder.into_transport().unwrap();
        let mut client = initiator.into_transport().unwrap();

        let mut frame = client.send(b"payload").unwrap();
        frame[0] ^= 0x01;
        assert!(server.recv(&frame).is_err());
    }
}
