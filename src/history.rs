//! Confidential history (bot/llm/shell).
//!
//! The workload calls `POST 127.0.0.1:8080/dd/history/append` over
//! loopback with plaintext. dd-agent encrypts each entry to the
//! deployment's `kind_config.history.client_pubkey` and writes
//! append-only JSONL to `/var/lib/dd/history/<deployment>.jsonl`.
//!
//! Read: `GET /history` is gated by the `dd_session` cookie. Anyone
//! authenticated can fetch the ciphertext blob; only the holder of
//! the matching X25519 privkey can decrypt. Two-stage authz: the
//! cookie gates bandwidth, encryption gates contents.
//!
//! Crypto: X25519 ECDH between an ephemeral sender keypair (per
//! entry) and the recipient's static pubkey, then ChaCha20-Poly1305
//! AEAD with the derived shared secret as the key. Per-entry
//! ephemeral keys mean the resulting ciphertext is non-malleable
//! across entries — losing one shared secret doesn't compromise
//! others.
//!
//! v1 storage is a single append-only JSONL file per deployment.
//! Segment rotation, retention auto-prune, and zstd compression are
//! follow-ups (TODO markers below).

use std::path::PathBuf;
use std::sync::Arc;

use axum::{
    extract::{FromRef, Query, State},
    http::StatusCode,
    response::{IntoResponse, Json, Response},
};
use base64::Engine;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Mutex;

use crate::auth::{CookieAuthState, Identity};
use crate::error::{Error, Result};

/// Per-deployment history store. Holds the recipient pubkey and a
/// mutex over the JSONL file. Multiple workloads cannot share one;
/// each gets its own.
#[derive(Clone)]
pub struct HistoryStore {
    pub recipient_pubkey: [u8; 32],
    pub path: PathBuf,
    write_lock: Arc<Mutex<()>>,
}

impl HistoryStore {
    pub fn new(recipient_pubkey: [u8; 32], path: PathBuf) -> Self {
        Self {
            recipient_pubkey,
            path,
            write_lock: Arc::new(Mutex::new(())),
        }
    }

    pub fn from_pubkey_b64(pubkey_b64: &str, path: PathBuf) -> Result<Self> {
        let raw = base64::engine::general_purpose::STANDARD
            .decode(pubkey_b64.as_bytes())
            .map_err(|e| Error::BadRequest(format!("client_pubkey base64: {e}")))?;
        if raw.len() != 32 {
            return Err(Error::BadRequest(format!(
                "client_pubkey must be 32 bytes (got {})",
                raw.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&raw);
        Ok(Self::new(arr, path))
    }
}

/// Encrypted entry — what gets written to disk + returned by `/history`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedEntry {
    pub ts_unix_ms: u64,
    pub seq: u64,
    /// 32-byte X25519 ephemeral sender pubkey, base64.
    pub eph_pubkey: String,
    /// 12-byte ChaCha20-Poly1305 nonce, base64.
    pub nonce: String,
    /// AEAD ciphertext, base64.
    pub ciphertext: String,
}

/// Append a plaintext entry: derive ephemeral keypair, ECDH against
/// recipient pubkey, ChaCha20-Poly1305 with the shared key. Returns
/// the persisted EncryptedEntry.
pub async fn append(store: &HistoryStore, plaintext: &[u8]) -> Result<EncryptedEntry> {
    use x25519_dalek::{PublicKey, StaticSecret};

    // Ephemeral X25519 keypair (per-entry).
    let mut eph_seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut eph_seed);
    let eph_secret = StaticSecret::from(eph_seed);
    let eph_public = PublicKey::from(&eph_secret);
    let recipient = PublicKey::from(store.recipient_pubkey);
    let shared = eph_secret.diffie_hellman(&recipient);

    // Derive a 32-byte AEAD key by SHA-256 of the shared secret.
    // For v1 this is sufficient; HKDF would be the upgrade.
    let key = Sha256::digest(shared.as_bytes());
    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| Error::Internal(format!("chacha key: {e}")))?;

    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| Error::Internal(format!("chacha encrypt: {e}")))?;

    let ts_unix_ms = chrono::Utc::now().timestamp_millis() as u64;

    let _guard = store.write_lock.lock().await;
    if let Some(parent) = store.path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    // Append. We seq off the current line count for now — fast path
    // for short files; segment rotation will replace this in v1.1.
    let seq = count_lines(&store.path).await? as u64;
    let entry = EncryptedEntry {
        ts_unix_ms,
        seq,
        eph_pubkey: base64::engine::general_purpose::STANDARD.encode(eph_public.as_bytes()),
        nonce: base64::engine::general_purpose::STANDARD.encode(nonce_bytes),
        ciphertext: base64::engine::general_purpose::STANDARD.encode(&ciphertext),
    };
    let mut line = serde_json::to_vec(&entry)?;
    line.push(b'\n');

    let mut f = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&store.path)
        .await?;
    f.write_all(&line).await?;
    f.flush().await?;
    Ok(entry)
}

/// Read the current segment as a vector of EncryptedEntry. Used by
/// `GET /history` after cookie verification. v1 reads everything;
/// `since=<seq>` slicing is a follow-up.
pub async fn read_all(store: &HistoryStore, since: Option<u64>) -> Result<Vec<EncryptedEntry>> {
    let f = match tokio::fs::File::open(&store.path).await {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(Error::Internal(format!("history open: {e}"))),
    };
    let mut reader = BufReader::new(f).lines();
    let mut out = Vec::new();
    while let Some(line) = reader.next_line().await? {
        if line.is_empty() {
            continue;
        }
        let entry: EncryptedEntry = serde_json::from_str(&line)?;
        if let Some(s) = since {
            if entry.seq < s {
                continue;
            }
        }
        out.push(entry);
    }
    Ok(out)
}

/// Truncate the segment. Used by `DELETE /history`.
pub async fn clear(store: &HistoryStore) -> Result<()> {
    let _guard = store.write_lock.lock().await;
    if store.path.exists() {
        tokio::fs::remove_file(&store.path).await?;
    }
    Ok(())
}

async fn count_lines(p: &PathBuf) -> Result<usize> {
    match tokio::fs::File::open(p).await {
        Ok(f) => {
            let mut reader = BufReader::new(f).lines();
            let mut n = 0usize;
            while reader.next_line().await?.is_some() {
                n += 1;
            }
            Ok(n)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(e) => Err(Error::Internal(format!("history count: {e}"))),
    }
}

// ─── HTTP handlers ──────────────────────────────────────────────────────

/// Bundle of per-route state for axum's `State<...>` extractor.
/// Routes can construct this from the agent's St via FromRef.
#[derive(Clone)]
pub struct HistoryState {
    pub store: Option<HistoryStore>,
    pub cookie_auth: CookieAuthState,
}

impl FromRef<HistoryState> for CookieAuthState {
    fn from_ref(s: &HistoryState) -> Self {
        s.cookie_auth.clone()
    }
}

#[derive(Debug, Deserialize)]
pub struct AppendBody {
    /// Caller-provided plaintext (the workload trusts dd-agent to
    /// encrypt). Bytes are accepted as a UTF-8 string for simplicity;
    /// callers needing binary use base64 inline.
    pub plaintext: String,
}

/// `POST /dd/history/append` — loopback-only. The workload writes
/// each chat/PTY frame here; dd encrypts to the registered client
/// pubkey before persisting.
pub async fn append_handler(
    State(s): State<HistoryState>,
    Json(body): Json<AppendBody>,
) -> Response {
    let Some(store) = &s.store else {
        return (
            StatusCode::BAD_REQUEST,
            "history not enabled for this deployment",
        )
            .into_response();
    };
    match append(store, body.plaintext.as_bytes()).await {
        Ok(entry) => Json(entry).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[derive(Debug, Deserialize)]
pub struct ReadQuery {
    #[serde(default)]
    pub since: Option<u64>,
}

/// `GET /history` — cookie-gated. Returns the ciphertext blob.
pub async fn read_handler(
    State(s): State<HistoryState>,
    _ident: Identity,
    Query(q): Query<ReadQuery>,
) -> Response {
    let Some(store) = &s.store else {
        return (StatusCode::NOT_FOUND, "history not enabled").into_response();
    };
    match read_all(store, q.since).await {
        Ok(entries) => Json(entries).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// `DELETE /history` — cookie-gated. Clears the segment.
pub async fn clear_handler(State(s): State<HistoryState>, _ident: Identity) -> Response {
    let Some(store) = &s.store else {
        return (StatusCode::NOT_FOUND, "history not enabled").into_response();
    };
    match clear(store).await {
        Ok(_) => (StatusCode::NO_CONTENT, "").into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use x25519_dalek::{PublicKey, StaticSecret};

    #[tokio::test]
    async fn roundtrip_encrypt_decrypt() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("h.jsonl");

        // Generate a recipient keypair (the user's "client" key).
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        let recipient_secret = StaticSecret::from(seed);
        let recipient_public = PublicKey::from(&recipient_secret);

        let store = HistoryStore::new(*recipient_public.as_bytes(), path.clone());
        let plaintext = b"hello world, encrypted to the user";

        let entry = append(&store, plaintext).await.unwrap();
        assert_eq!(entry.seq, 0);

        // Decrypt as the user would.
        let eph_pub_bytes = base64::engine::general_purpose::STANDARD
            .decode(entry.eph_pubkey.as_bytes())
            .unwrap();
        let mut eph_arr = [0u8; 32];
        eph_arr.copy_from_slice(&eph_pub_bytes);
        let eph_pub = PublicKey::from(eph_arr);
        let shared = recipient_secret.diffie_hellman(&eph_pub);
        let key = Sha256::digest(shared.as_bytes());
        let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
        let nonce_bytes = base64::engine::general_purpose::STANDARD
            .decode(entry.nonce.as_bytes())
            .unwrap();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ct = base64::engine::general_purpose::STANDARD
            .decode(entry.ciphertext.as_bytes())
            .unwrap();
        let recovered = cipher.decrypt(nonce, ct.as_ref()).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[tokio::test]
    async fn read_returns_persisted_entries() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("h.jsonl");
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        let recipient = PublicKey::from(&StaticSecret::from(seed));
        let store = HistoryStore::new(*recipient.as_bytes(), path);

        for i in 0..3 {
            append(&store, format!("msg {i}").as_bytes()).await.unwrap();
        }
        let all = read_all(&store, None).await.unwrap();
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].seq, 0);
        assert_eq!(all[2].seq, 2);

        let since1 = read_all(&store, Some(1)).await.unwrap();
        assert_eq!(since1.len(), 2);
    }

    #[tokio::test]
    async fn operator_sees_only_ciphertext() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("h.jsonl");
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        let recipient = PublicKey::from(&StaticSecret::from(seed));
        let store = HistoryStore::new(*recipient.as_bytes(), path.clone());

        let secret = b"super secret message that the operator cannot see";
        append(&store, secret).await.unwrap();

        let on_disk = tokio::fs::read_to_string(&path).await.unwrap();
        assert!(
            !on_disk.contains("super secret"),
            "plaintext leaked to disk: {on_disk}"
        );
    }
}
