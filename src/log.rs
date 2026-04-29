//! Public oracle log.
//!
//! Workload calls `POST 127.0.0.1:8080/dd/log/append` with plaintext.
//! dd-agent signs each entry with the workload's ed25519 identity
//! key, hash-chains it to the prior entry, and appends NDJSON to
//! `/var/lib/dd/log/<deployment>.ndjson`.
//!
//! Read: `GET /log` is unauth — anyone can mirror it. The signature
//! chain prevents the operator from rewriting history. `GET /log/pubkey`
//! returns the ed25519 pubkey paired with the agent's ITA quote so
//! verifiers can pin the signing identity to an attested measurement.
//!
//! v1 keypair: caller-supplied 32-byte seed. Will derive from TDX
//! measurement once EE's sealed-key-derive lands.

use std::path::PathBuf;
use std::sync::Arc;

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json, Response},
};
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Mutex;

use crate::error::{Error, Result};

/// Per-deployment signed-log store.
#[derive(Clone)]
pub struct LogStore {
    pub signing_key: Arc<SigningKey>,
    pub path: PathBuf,
    write_lock: Arc<Mutex<()>>,
}

impl LogStore {
    pub fn from_seed(seed: [u8; 32], path: PathBuf) -> Self {
        Self {
            signing_key: Arc::new(SigningKey::from_bytes(&seed)),
            path,
            write_lock: Arc::new(Mutex::new(())),
        }
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }
}

/// On-disk + on-wire shape. Each entry includes the prior entry's
/// hash so consumers can verify the chain without state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedEntry {
    pub ts_unix_ms: u64,
    pub seq: u64,
    /// hex-encoded sha256(prev_entry_serialized) — zeros for entry 0.
    pub prev_hash: String,
    pub content: serde_json::Value,
    /// hex-encoded ed25519(prev_hash || ts || seq || content).
    pub signature: String,
}

fn hash_entry(entry: &SignedEntry) -> [u8; 32] {
    // Hash the canonical serialization (sans signature).
    let mut hasher = Sha256::new();
    hasher.update(entry.ts_unix_ms.to_be_bytes());
    hasher.update(entry.seq.to_be_bytes());
    hasher.update(entry.prev_hash.as_bytes());
    hasher.update(serde_json::to_vec(&entry.content).unwrap_or_default());
    hasher.update(entry.signature.as_bytes());
    hasher.finalize().into()
}

fn sign_payload(
    key: &SigningKey,
    prev_hash: &str,
    ts_unix_ms: u64,
    seq: u64,
    content: &serde_json::Value,
) -> String {
    let mut msg = Vec::new();
    msg.extend_from_slice(prev_hash.as_bytes());
    msg.extend_from_slice(&ts_unix_ms.to_be_bytes());
    msg.extend_from_slice(&seq.to_be_bytes());
    msg.extend_from_slice(&serde_json::to_vec(content).unwrap_or_default());
    let sig = key.sign(&msg);
    hex::encode(sig.to_bytes())
}

/// Append a content blob. Hash-chains to the prior entry and signs.
pub async fn append(store: &LogStore, content: serde_json::Value) -> Result<SignedEntry> {
    let _guard = store.write_lock.lock().await;
    if let Some(parent) = store.path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let (seq, prev_hash) = match read_last(&store.path).await? {
        Some(prev) => (prev.seq + 1, hex::encode(hash_entry(&prev))),
        None => (0u64, hex::encode([0u8; 32])),
    };
    let ts_unix_ms = chrono::Utc::now().timestamp_millis() as u64;
    let signature = sign_payload(&store.signing_key, &prev_hash, ts_unix_ms, seq, &content);
    let entry = SignedEntry {
        ts_unix_ms,
        seq,
        prev_hash,
        content,
        signature,
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

async fn read_last(p: &PathBuf) -> Result<Option<SignedEntry>> {
    let f = match tokio::fs::File::open(p).await {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(Error::Internal(format!("log open: {e}"))),
    };
    let mut reader = BufReader::new(f).lines();
    let mut last: Option<SignedEntry> = None;
    while let Some(line) = reader.next_line().await? {
        if line.is_empty() {
            continue;
        }
        last = Some(serde_json::from_str(&line)?);
    }
    Ok(last)
}

pub async fn read_all(store: &LogStore) -> Result<Vec<SignedEntry>> {
    let f = match tokio::fs::File::open(&store.path).await {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(Error::Internal(format!("log open: {e}"))),
    };
    let mut reader = BufReader::new(f).lines();
    let mut out = Vec::new();
    while let Some(line) = reader.next_line().await? {
        if line.is_empty() {
            continue;
        }
        out.push(serde_json::from_str(&line)?);
    }
    Ok(out)
}

// ─── HTTP handlers ──────────────────────────────────────────────────────

#[derive(Clone)]
pub struct LogState {
    pub store: Option<LogStore>,
}

#[derive(Debug, Deserialize)]
pub struct AppendBody {
    pub content: serde_json::Value,
}

/// `POST /dd/log/append` — loopback only. Workload writes plaintext;
/// dd signs and appends.
pub async fn append_handler(State(s): State<LogState>, Json(body): Json<AppendBody>) -> Response {
    let Some(store) = &s.store else {
        return (StatusCode::BAD_REQUEST, "public log not enabled").into_response();
    };
    match append(store, body.content).await {
        Ok(entry) => Json(entry).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// `GET /log` — unauth, NDJSON.
pub async fn read_handler(State(s): State<LogState>) -> Response {
    let Some(store) = &s.store else {
        return (StatusCode::NOT_FOUND, "public log not enabled").into_response();
    };
    match read_all(store).await {
        Ok(entries) => {
            let mut body = String::new();
            for e in entries {
                if let Ok(line) = serde_json::to_string(&e) {
                    body.push_str(&line);
                    body.push('\n');
                }
            }
            (
                StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, "application/x-ndjson")],
                body,
            )
                .into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// `GET /log/pubkey` — unauth, returns the ed25519 pubkey so
/// consumers can verify signatures. Pair with `/health.ita_token`
/// for measurement-bound trust.
pub async fn pubkey_handler(State(s): State<LogState>) -> Response {
    let Some(store) = &s.store else {
        return (StatusCode::NOT_FOUND, "public log not enabled").into_response();
    };
    let vk = store.verifying_key();
    let body = serde_json::json!({
        "alg": "ed25519",
        "pubkey_b64": base64::engine::general_purpose::STANDARD.encode(vk.to_bytes()),
        "pubkey_hex": hex::encode(vk.to_bytes()),
    });
    Json(body).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;
    use tempfile::TempDir;

    #[tokio::test]
    async fn signs_and_chains() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("log.ndjson");
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        let store = LogStore::from_seed(seed, path);

        let e0 = append(&store, serde_json::json!({"x": 1})).await.unwrap();
        let e1 = append(&store, serde_json::json!({"x": 2})).await.unwrap();
        let e2 = append(&store, serde_json::json!({"x": 3})).await.unwrap();
        assert_eq!(e0.seq, 0);
        assert_eq!(e1.seq, 1);
        assert_eq!(e2.seq, 2);
        assert_eq!(e0.prev_hash, hex::encode([0u8; 32]));
        assert_eq!(e1.prev_hash, hex::encode(hash_entry(&e0)));
        assert_eq!(e2.prev_hash, hex::encode(hash_entry(&e1)));
    }

    #[tokio::test]
    async fn signature_verifies() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("log.ndjson");
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        let store = LogStore::from_seed(seed, path);
        let entry = append(&store, serde_json::json!({"v": "data"}))
            .await
            .unwrap();

        // Reconstruct the signed message and verify.
        let mut msg = Vec::new();
        msg.extend_from_slice(entry.prev_hash.as_bytes());
        msg.extend_from_slice(&entry.ts_unix_ms.to_be_bytes());
        msg.extend_from_slice(&entry.seq.to_be_bytes());
        msg.extend_from_slice(&serde_json::to_vec(&entry.content).unwrap());

        let sig_bytes = hex::decode(&entry.signature).unwrap();
        let sig = ed25519_dalek::Signature::from_bytes(sig_bytes.as_slice().try_into().unwrap());
        store.verifying_key().verify(&msg, &sig).unwrap();
    }

    use rand::RngCore;
}
