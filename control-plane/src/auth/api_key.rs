use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};

/// All API keys issued by DevOps Defender start with this prefix.
pub const API_KEY_PREFIX: &str = "dd_live_";

/// Issue a new API key, returning `(raw_key, argon2_hash)`.
pub fn issue_api_key() -> (String, String) {
    let suffix = uuid::Uuid::new_v4().to_string().replace('-', "");
    let raw = format!("{API_KEY_PREFIX}{suffix}");

    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(raw.as_bytes(), &salt)
        .expect("argon2 hash failed")
        .to_string();

    (raw, hash)
}

/// Verify a raw API key against a stored Argon2 hash.
pub fn verify_api_key(raw: &str, hash: &str) -> bool {
    let parsed = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(_) => return false,
    };
    Argon2::default()
        .verify_password(raw.as_bytes(), &parsed)
        .is_ok()
}

/// Extract the first 12 characters of a raw API key as a prefix for lookup.
pub fn key_prefix_from_raw(raw: &str) -> String {
    raw.chars().take(12).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue_and_verify() {
        let (raw, hash) = issue_api_key();
        assert!(raw.starts_with(API_KEY_PREFIX));
        assert!(verify_api_key(&raw, &hash));
        assert!(!verify_api_key("dd_live_wrong_key", &hash));
    }

    #[test]
    fn prefix_extraction() {
        let (raw, _) = issue_api_key();
        let prefix = key_prefix_from_raw(&raw);
        assert_eq!(prefix.len(), 12);
        assert!(prefix.starts_with("dd_live_"));
    }
}
