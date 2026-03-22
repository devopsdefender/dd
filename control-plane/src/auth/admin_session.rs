use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};

/// All admin session tokens start with this prefix.
pub const SESSION_TOKEN_PREFIX: &str = "dds_";

/// Issue a new session token, returning the raw token string.
pub fn issue_session_token() -> String {
    let suffix = uuid::Uuid::new_v4().to_string().replace('-', "");
    format!("{SESSION_TOKEN_PREFIX}{suffix}")
}

/// Hash a session token for storage using Argon2.
pub fn hash_session_token(raw: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    argon2
        .hash_password(raw.as_bytes(), &salt)
        .expect("argon2 hash failed")
        .to_string()
}

/// Verify a raw session token against a stored hash.
pub fn verify_session_token(raw: &str, hash: &str) -> bool {
    let parsed = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(_) => return false,
    };
    Argon2::default()
        .verify_password(raw.as_bytes(), &parsed)
        .is_ok()
}

/// Extract a prefix from a raw session token for indexed lookup.
pub fn token_prefix_from_raw(raw: &str) -> String {
    raw.chars().take(12).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue_and_verify_session() {
        let raw = issue_session_token();
        assert!(raw.starts_with(SESSION_TOKEN_PREFIX));
        let hash = hash_session_token(&raw);
        assert!(verify_session_token(&raw, &hash));
        assert!(!verify_session_token("dds_wrong_token", &hash));
    }

    #[test]
    fn session_prefix_extraction() {
        let raw = issue_session_token();
        let prefix = token_prefix_from_raw(&raw);
        assert_eq!(prefix.len(), 12);
        assert!(prefix.starts_with("dds_"));
    }
}
