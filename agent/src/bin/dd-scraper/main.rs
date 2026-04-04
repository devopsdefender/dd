//! dd-scraper — discovers agents from Cloudflare tunnels and reports health to the register.

use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite;

#[tokio::main]
async fn main() {
    let cf = dd_agent::tunnel::CfConfig::from_env().unwrap_or_else(|e| {
        eprintln!("dd-scraper: CF config required: {e}");
        std::process::exit(1);
    });

    let register_url = std::env::var("DD_REGISTER_URL").unwrap_or_else(|_| {
        eprintln!("dd-scraper: DD_REGISTER_URL required");
        std::process::exit(1);
    });

    let env_label = std::env::var("DD_ENV").unwrap_or_else(|_| "dev".into());
    let tunnel_prefix = format!("dd-{env_label}-");
    let scrape_interval = std::time::Duration::from_secs(30);
    let scrape_timeout = std::time::Duration::from_secs(3);

    let attestation = dd_agent::attestation::detect();
    eprintln!(
        "dd-scraper: starting (env={env_label}, attestation={})",
        attestation.attestation_type()
    );

    let ws_url = register_url.replace("/register", "/scraper");
    let ws_url = if ws_url.ends_with("/scraper") {
        ws_url
    } else {
        format!("{ws_url}/scraper")
    };

    loop {
        eprintln!("dd-scraper: connecting to register at {ws_url}");
        match connect_and_scrape(
            &ws_url,
            &cf,
            &tunnel_prefix,
            scrape_interval,
            scrape_timeout,
            attestation.as_ref(),
        )
        .await
        {
            Ok(()) => eprintln!("dd-scraper: session ended, reconnecting..."),
            Err(e) => eprintln!("dd-scraper: error: {e}, reconnecting in 10s..."),
        }
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
    }
}

async fn connect_and_scrape(
    ws_url: &str,
    cf: &dd_agent::tunnel::CfConfig,
    tunnel_prefix: &str,
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

    eprintln!("dd-scraper: connected to register, starting scrape loop");

    let http = reqwest::Client::builder()
        .timeout(timeout)
        .build()
        .map_err(|e| format!("http client: {e}"))?;

    let mut ticker = tokio::time::interval(interval);
    loop {
        ticker.tick().await;

        // List CF tunnels
        let tunnels = list_cf_tunnels(&http, cf, tunnel_prefix).await;
        eprintln!(
            "dd-scraper: found {} tunnels matching {tunnel_prefix}*",
            tunnels.len()
        );

        // Scrape all agents concurrently
        let scrape_futures: Vec<_> = tunnels
            .iter()
            .map(|(name, hostname)| {
                let http = http.clone();
                let hostname = hostname.clone();
                let name = name.clone();
                async move {
                    let url = format!("https://{hostname}/health");
                    match http.get(&url).send().await {
                        Ok(resp) if resp.status().is_success() => {
                            let health: serde_json::Value = resp.json().await.unwrap_or_default();
                            (name, hostname, true, Some(health), None)
                        }
                        Ok(resp) => (
                            name,
                            hostname,
                            false,
                            None,
                            Some(format!("status {}", resp.status())),
                        ),
                        Err(e) => (name, hostname, false, None, Some(e.to_string())),
                    }
                }
            })
            .collect();

        let results = futures_util::future::join_all(scrape_futures).await;

        // Build fleet report
        let mut agents = Vec::new();
        let mut orphan_tunnels = Vec::new();

        for (tunnel_name, hostname, healthy, health, error) in &results {
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
                if error
                    .as_ref()
                    .is_some_and(|e| e.contains("connect") || e.contains("timed out"))
                {
                    orphan_tunnels.push(tunnel_name.clone());
                }
            }
        }

        let report = serde_json::json!({
            "agents": agents,
            "orphan_tunnels": orphan_tunnels,
        });

        eprintln!(
            "dd-scraper: reporting {} agents ({} healthy, {} unhealthy, {} orphans)",
            results.len(),
            results.iter().filter(|r| r.2).count(),
            results.iter().filter(|r| !r.2).count(),
            orphan_tunnels.len(),
        );

        // Send encrypted report to register
        let report_json = serde_json::to_vec(&report).unwrap();
        let mut enc = vec![0u8; 65535];
        let len = transport
            .write_message(&report_json, &mut enc)
            .map_err(|e| format!("encrypt: {e}"))?;
        ws_tx
            .send(tungstenite::Message::Binary(enc[..len].to_vec()))
            .await
            .map_err(|e| format!("send: {e}"))?;

        // Wait for ack
        match tokio::time::timeout(std::time::Duration::from_secs(10), ws_rx.next()).await {
            Ok(Some(Ok(tungstenite::Message::Binary(data)))) => {
                let data = data.to_vec();
                let _ = transport.read_message(&data, &mut buf);
            }
            _ => {
                return Err("no ack from register".into());
            }
        }
    }
}

async fn list_cf_tunnels(
    client: &reqwest::Client,
    cf: &dd_agent::tunnel::CfConfig,
    prefix: &str,
) -> Vec<(String, String)> {
    let url = format!(
        "https://api.cloudflare.com/client/v4/accounts/{}/cfd_tunnel?is_deleted=false",
        cf.account_id
    );

    let resp = match client
        .get(&url)
        .header("Authorization", format!("Bearer {}", cf.api_token))
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("dd-scraper: CF API error: {e}");
            return Vec::new();
        }
    };

    let body: serde_json::Value = resp.json().await.unwrap_or_default();
    let mut tunnels = Vec::new();

    if let Some(results) = body["result"].as_array() {
        for t in results {
            if let Some(name) = t["name"].as_str() {
                if name.starts_with(prefix) {
                    let hostname = format!("{name}.{}", cf.domain);
                    tunnels.push((name.to_string(), hostname));
                }
            }
        }
    }

    tunnels
}
