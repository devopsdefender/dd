//! Bot kind.
//!
//! Long-running LLM agent loop with first-class outbound integrations
//! (Signal, WhatsApp, …). v1 has two kind-specific helpers:
//!
//!   - `wake_loop`: optional tokio interval that pokes the bot's
//!     `/tick` endpoint at `kind_config.wake_schedule` cadence (very
//!     simple "every Ns" parser). The bot can ignore the poke if it
//!     doesn't need a scheduled wakeup.
//!
//!   - `state_volume`: documentation-only here; the agent's deploy
//!     handler propagates the volume name to EE which mounts it.
//!
//! Egress allow-listing is *not* in v1 (deferred hardening).

use std::time::Duration;

use crate::workload::{KindConfig, Workload};

/// Parse a tiny `every Ns` schedule into a Duration. Returns None for
/// any unrecognised format. Accepted: `every 30s`, `every 5m`,
/// `every 1h`. We deliberately do not implement cron — schedules in
/// v1 are coarse periodic pokes.
pub fn parse_schedule(s: &str) -> Option<Duration> {
    let s = s.trim();
    let rest = s.strip_prefix("every ")?;
    let (num, unit) = rest.trim().split_at(rest.trim().len().saturating_sub(1));
    let n: u64 = num.parse().ok()?;
    Some(match unit {
        "s" => Duration::from_secs(n),
        "m" => Duration::from_secs(n * 60),
        "h" => Duration::from_secs(n * 3600),
        _ => return None,
    })
}

/// Run the bot's wake loop. Logs and ignores transient failures.
pub async fn wake_loop(http: reqwest::Client, tick_url: String, period: Duration) {
    let mut interval = tokio::time::interval(period);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        match http.post(&tick_url).send().await {
            Ok(resp) if resp.status().is_success() => {}
            Ok(resp) => eprintln!("bot tick {tick_url}: {}", resp.status()),
            Err(e) => eprintln!("bot tick {tick_url}: {e}"),
        }
    }
}

pub fn extract_schedule(w: &Workload) -> Option<&str> {
    match &w.kind_config {
        KindConfig::Bot { wake_schedule, .. } => wake_schedule.as_deref(),
        _ => None,
    }
}

pub fn extract_state_volume(w: &Workload) -> Option<&str> {
    match &w.kind_config {
        KindConfig::Bot { state_volume, .. } => state_volume.as_deref(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_seconds() {
        assert_eq!(parse_schedule("every 30s"), Some(Duration::from_secs(30)));
    }
    #[test]
    fn parses_minutes() {
        assert_eq!(parse_schedule("every 5m"), Some(Duration::from_secs(300)));
    }
    #[test]
    fn rejects_garbage() {
        assert!(parse_schedule("five seconds").is_none());
        assert!(parse_schedule("every 5x").is_none());
    }
}
