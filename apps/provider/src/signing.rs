use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

/// Generate a fresh Ed25519 keypair. The private key lives only in memory.
pub fn generate_keypair() -> (SigningKey, VerifyingKey) {
    let signing_key = SigningKey::generate(&mut rand_core::OsRng);
    let verifying_key = signing_key.verifying_key();
    (signing_key, verifying_key)
}

/// Base64-encode the public key for storage/transmission.
pub fn public_key_base64(key: &VerifyingKey) -> String {
    base64::engine::general_purpose::STANDARD.encode(key.as_bytes())
}

/// SHA-256 hash of the public key, for embedding in TDX report_data.
pub fn public_key_hash(key: &VerifyingKey) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    hasher.finalize().into()
}

/// Sign a measurement hash and return the base64-encoded signature.
pub fn sign_measurement(key: &SigningKey, measurement_hash: &[u8]) -> String {
    let signature: Signature = key.sign(measurement_hash);
    base64::engine::general_purpose::STANDARD.encode(signature.to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;

    #[test]
    fn keypair_sign_verify_roundtrip() {
        let (signing_key, verifying_key) = generate_keypair();
        let data = b"test measurement hash";
        let sig_b64 = sign_measurement(&signing_key, data);

        // Decode and verify
        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(&sig_b64)
            .unwrap();
        let signature = Signature::from_bytes(&sig_bytes.try_into().unwrap());
        assert!(verifying_key.verify(data, &signature).is_ok());
    }

    #[test]
    fn public_key_base64_roundtrip() {
        let (_, verifying_key) = generate_keypair();
        let b64 = public_key_base64(&verifying_key);
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&b64)
            .unwrap();
        assert_eq!(decoded.len(), 32);
    }
}
