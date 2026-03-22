use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Result of attempting to consume a nonce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsumeResult {
    Ok,
    Missing,
    Expired,
}

struct NonceEntry {
    expires_at: chrono::DateTime<chrono::Utc>,
}

/// Service for issuing and consuming single-use nonces with TTL.
#[derive(Clone)]
pub struct NonceService {
    store: Arc<Mutex<HashMap<String, NonceEntry>>>,
    ttl_secs: u64,
}

impl NonceService {
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            store: Arc::new(Mutex::new(HashMap::new())),
            ttl_secs,
        }
    }

    /// Issue a new nonce, returning the nonce string.
    pub async fn issue(&self) -> String {
        let nonce = uuid::Uuid::new_v4().to_string();
        let expires_at = chrono::Utc::now() + chrono::Duration::seconds(self.ttl_secs as i64);
        let mut store = self.store.lock().await;
        store.insert(nonce.clone(), NonceEntry { expires_at });
        nonce
    }

    /// Consume a nonce. Returns Ok if valid, Missing if not found, Expired if past TTL.
    pub async fn consume(&self, nonce: &str) -> ConsumeResult {
        let mut store = self.store.lock().await;
        match store.remove(nonce) {
            None => ConsumeResult::Missing,
            Some(entry) => {
                if chrono::Utc::now() > entry.expires_at {
                    ConsumeResult::Expired
                } else {
                    ConsumeResult::Ok
                }
            }
        }
    }

    /// Remove expired entries from the store.
    pub async fn cleanup_expired(&self) {
        let mut store = self.store.lock().await;
        let now = chrono::Utc::now();
        store.retain(|_, entry| entry.expires_at > now);
    }

    /// Return the configured TTL in seconds.
    pub fn ttl_seconds(&self) -> u64 {
        self.ttl_secs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn nonce_single_use() {
        let svc = NonceService::new(300);
        let nonce = svc.issue().await;

        // First consume succeeds
        assert_eq!(svc.consume(&nonce).await, ConsumeResult::Ok);
        // Second consume fails (already used)
        assert_eq!(svc.consume(&nonce).await, ConsumeResult::Missing);
    }

    #[tokio::test]
    async fn nonce_expiry() {
        // TTL of 0 seconds means it expires immediately
        let svc = NonceService::new(0);
        let nonce = svc.issue().await;

        // Small sleep so the expiry is in the past
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        assert_eq!(svc.consume(&nonce).await, ConsumeResult::Expired);
    }
}
