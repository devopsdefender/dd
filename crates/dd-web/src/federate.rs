//! Federation -- horizontal scaling by querying peer dd-web instances.

use axum::extract::State;
use axum::Json;

use crate::state::{AgentSnapshot, WebState};

/// GET /federate -- return local AgentStore as JSON for peer consumption.
pub async fn federate(State(state): State<WebState>) -> Json<Vec<AgentSnapshot>> {
    let agents = state.agents.lock().await;
    Json(agents.values().cloned().collect())
}

/// Query all configured peers for their agent snapshots.
/// Returns the merged list (does not deduplicate -- caller is responsible).
pub async fn query_peers(state: &WebState) -> Vec<AgentSnapshot> {
    if state.config.peers.is_empty() {
        return Vec::new();
    }

    // Builder failure is a programming bug, not a runtime condition.
    // Previously fell back to a client without the 5s timeout, which
    // would mask the real bug AND potentially hang federated requests
    // forever.
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .expect("reqwest client builder");

    let futures: Vec<_> = state
        .config
        .peers
        .iter()
        .map(|peer_url| {
            let http = http.clone();
            let url = format!("{}/federate", peer_url.trim_end_matches('/'));
            async move {
                match http.get(&url).send().await {
                    Ok(resp) if resp.status().is_success() => {
                        resp.json::<Vec<AgentSnapshot>>().await.unwrap_or_default()
                    }
                    Ok(resp) => {
                        eprintln!("dd-web: federation peer {url} returned {}", resp.status());
                        Vec::new()
                    }
                    Err(e) => {
                        eprintln!("dd-web: federation peer {url} error: {e}");
                        Vec::new()
                    }
                }
            }
        })
        .collect();

    let results = futures_util::future::join_all(futures).await;
    results.into_iter().flatten().collect()
}
