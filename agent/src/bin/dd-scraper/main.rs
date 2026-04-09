//! dd-scraper — receives agent list from register and reports health.
//!
//! No Cloudflare credentials needed. The register pushes agent shards to
//! connected scrapers; the scraper scrapes each hostname's /health and
//! reports results back. On disconnect, the scraper keeps scraping its
//! cached shard until the register reconnects.

use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite;

#[derive(Debug, Clone, serde::Deserialize)]
struct ShardAssignment {
    shard: Vec<AgentEntry>,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct AgentEntry {
    hostname: String,
    #[allow(dead_code)]
    agent_id: String,
}

#[tokio::main]
async fn main() {
    let register_url = std::env::var("DD_REGISTER_URL").unwrap_or_else(|_| {
        eprintln!("dd-scraper: DD_REGISTER_URL required");
        std::process::exit(1);
    });

    let scrape_interval = std::time::Duration::from_secs(30);
    let scrape_timeout = std::time::Duration::from_secs(3);

    let attestation = dd_agent::attestation::detect();
    eprintln!(
        "dd-scraper: starting (attestation={})",
        attestation.attestation_type()
    );

    let ws_url = register_url.replace("/register", "/scraper");
    let ws_url = if ws_url.ends_with("/scraper") {
        ws_url
    } else {
        format!("{ws_url}/scraper")
    };

    let mut cached_shard: Vec<AgentEntry> = Vec::new();

    loop {
        eprintln!("dd-scraper: connecting to register at {ws_url}");
        match connect_and_scrape(
            &ws_url,
            &mut cached_shard,
            scrape_interval,
            scrape_timeout,
            attestation.as_ref(),
        )
        .await
        {
            Ok(()) => eprintln!("dd-scraper: session ended, reconnecting..."),
            Err(e) => {
                eprintln!("dd-scraper: error: {e}");
                // Keep scraping cached shard while disconnected
                if !cached_shard.is_empty() {
                    eprintln!(
                        "dd-scraper: scraping {} cached agents while disconnected",
                        cached_shard.len()
                    );
                    scrape_cached(&cached_shard, scrape_timeout).await;
                }
                eprintln!("dd-scraper: reconnecting in 10s...");
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
    }
}

async fn scrape_cached(shard: &[AgentEntry], timeout: std::time::Duration) {
    let http = reqwest::Client::builder().timeout(timeout).build().unwrap();

    let futures: Vec<_> = shard
        .iter()
        .map(|agent| {
            let http = http.clone();
            let hostname = agent.hostname.clone();
            async move {
                let url = format!("https://{hostname}/health");
                match http.get(&url).send().await {
                    Ok(resp) if resp.status().is_success() => {
                        eprintln!("dd-scraper: (cached) {hostname} healthy");
                    }
                    Ok(resp) => {
                        eprintln!("dd-scraper: (cached) {hostname} status {}", resp.status());
                    }
                    Err(e) => {
                        eprintln!("dd-scraper: (cached) {hostname} error: {e}");
                    }
                }
            }
        })
        .collect();

    futures_util::future::join_all(futures).await;
}

async fn connect_and_scrape(
    ws_url: &str,
    cached_shard: &mut Vec<AgentEntry>,
    interval: std::time::Duration,
    timeout: std::time::Duration,
    backend: &dyn dd_agent::attestation::AttestationBackend,
) -> Result<(), String> {
    let keypair = dd_agent::noise::generate_keypair()?;
    let attestation = dd_agent::noise::AttestationPayload {
        attestation_type: backend.attestation_type().to_string(),
        vm_name: "scraper".to_string(),
        tdx_quote_b64: backend.generate_quote_b64(),
    };

    let (ws_stream, _) = tokio_tungstenite::connect_async(ws_url)
        .await
        .map_err(|e| format!("ws connect: {e}"))?;
    let (mut ws_tx, mut ws_rx) = ws_stream.split();

    // Noise XX handshake (scraper is initiator)
    let mut noise = snow::Builder::new(dd_agent::noise::NOISE_PATTERN.parse().unwrap())
        .local_private_key(&keypair.private)
        .map_err(|e| format!("key: {e}"))?
        .build_initiator()
        .map_err(|e| format!("init: {e}"))?;

    let mut buf = vec![0u8; 65535];

    // msg1
    let mut msg1 = vec![0u8; 65535];
    let len = noise
        .write_message(&[], &mut msg1)
        .map_err(|e| format!("msg1: {e}"))?;
    ws_tx
        .send(tungstenite::Message::Binary(msg1[..len].to_vec()))
        .await
        .map_err(|e| format!("send msg1: {e}"))?;

    // msg2
    let msg2 = match ws_rx.next().await {
        Some(Ok(tungstenite::Message::Binary(d))) => d.to_vec(),
        other => return Err(format!("expected msg2, got: {other:?}")),
    };
    noise
        .read_message(&msg2, &mut buf)
        .map_err(|e| format!("msg2: {e}"))?;

    // msg3 with attestation
    let att_json = serde_json::to_vec(&attestation).unwrap();
    let mut msg3 = vec![0u8; 65535];
    let len = noise
        .write_message(&att_json, &mut msg3)
        .map_err(|e| format!("msg3: {e}"))?;
    ws_tx
        .send(tungstenite::Message::Binary(msg3[..len].to_vec()))
        .await
        .map_err(|e| format!("send msg3: {e}"))?;

    let mut transport = noise
        .into_transport_mode()
        .map_err(|e| format!("transport: {e}"))?;

    // Read initial shard assignment from register
    let shard_msg = match ws_rx.next().await {
        Some(Ok(tungstenite::Message::Binary(d))) => d.to_vec(),
        other => return Err(format!("expected shard assignment, got: {other:?}")),
    };
    let shard_len = transport
        .read_message(&shard_msg, &mut buf)
        .map_err(|e| format!("decrypt shard: {e}"))?;
    let assignment: ShardAssignment =
        serde_json::from_slice(&buf[..shard_len]).map_err(|e| format!("parse shard: {e}"))?;
    *cached_shard = assignment.shard;
    eprintln!(
        "dd-scraper: received shard of {} agents from register",
        cached_shard.len()
    );

    let http = reqwest::Client::builder()
        .timeout(timeout)
        .build()
        .map_err(|e| format!("http client: {e}"))?;

    let mut ticker = tokio::time::interval(interval);
    loop {
        ticker.tick().await;

        eprintln!("dd-scraper: scraping {} agents", cached_shard.len());

        // Scrape all agents in the shard concurrently
        let scrape_futures: Vec<_> = cached_shard
            .iter()
            .map(|agent| {
                let http = http.clone();
                let hostname = agent.hostname.clone();
                async move {
                    let url = format!("https://{hostname}/health");
                    match http.get(&url).send().await {
                        Ok(resp) if resp.status().is_success() => {
                            let health: serde_json::Value = resp.json().await.unwrap_or_default();
                            (hostname, true, Some(health), None)
                        }
                        Ok(resp) => (
                            hostname,
                            false,
                            None,
                            Some(format!("status {}", resp.status())),
                        ),
                        Err(e) => (hostname, false, None, Some(e.to_string())),
                    }
                }
            })
            .collect();

        let results = futures_util::future::join_all(scrape_futures).await;

        // Build fleet report
        let mut agents = Vec::new();
        for (hostname, healthy, health, error) in &results {
            if *healthy {
                if let Some(h) = health {
                    agents.push(serde_json::json!({
                        "hostname": hostname,
                        "healthy": true,
                        "agent_id": h.get("agent_id").and_then(|v| v.as_str()),
                        "vm_name": h.get("vm_name").and_then(|v| v.as_str()),
                        "attestation_type": h.get("attestation_type").and_then(|v| v.as_str()),
                        "deployment_count": h.get("deployment_count").and_then(|v| v.as_u64()),
                        "cpu_percent": h.get("cpu_percent").and_then(|v| v.as_u64()),
                        "memory_used_mb": h.get("memory_used_mb").and_then(|v| v.as_u64()),
                        "memory_total_mb": h.get("memory_total_mb").and_then(|v| v.as_u64()),
                        "deployments": h.get("deployments"),
                    }));
                }
            } else {
                agents.push(serde_json::json!({
                    "hostname": hostname,
                    "healthy": false,
                    "error": error,
                }));
            }
        }

        let report = serde_json::json!({ "agents": agents });

        eprintln!(
            "dd-scraper: reporting {} agents ({} healthy, {} unhealthy)",
            results.len(),
            results.iter().filter(|r| r.1).count(),
            results.iter().filter(|r| !r.1).count(),
        );

        // Send encrypted report
        let report_json = serde_json::to_vec(&report).unwrap();
        let mut enc = vec![0u8; 65535];
        let len = transport
            .write_message(&report_json, &mut enc)
            .map_err(|e| format!("encrypt: {e}"))?;
        ws_tx
            .send(tungstenite::Message::Binary(enc[..len].to_vec()))
            .await
            .map_err(|e| format!("send: {e}"))?;

        // Wait for ack (which includes an updated shard)
        match tokio::time::timeout(std::time::Duration::from_secs(10), ws_rx.next()).await {
            Ok(Some(Ok(tungstenite::Message::Binary(data)))) => {
                let data = data.to_vec();
                let dec_len = match transport.read_message(&data, &mut buf) {
                    Ok(n) => n,
                    Err(_) => continue,
                };
                // Try to parse updated shard from ack
                if let Ok(assignment) = serde_json::from_slice::<ShardAssignment>(&buf[..dec_len]) {
                    if !assignment.shard.is_empty() {
                        *cached_shard = assignment.shard;
                    }
                }
                // Otherwise it's a plain {"ok":true} ack — keep current shard
            }
            _ => {
                return Err("no ack from register".into());
            }
        }
    }
}
