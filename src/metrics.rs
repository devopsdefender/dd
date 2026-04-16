//! Lightweight /proc-derived system metrics for the agent dashboard
//! and the /health JSON. No external process dependencies.

use serde::Serialize;

#[derive(Debug, Clone, Serialize, Default)]
pub struct SysMetrics {
    pub cpu_pct: u64,
    pub mem_used_mb: u64,
    pub mem_total_mb: u64,
    pub load_1m: f64,
}

pub async fn collect() -> SysMetrics {
    let mut m = SysMetrics::default();

    if let Ok(mi) = tokio::fs::read_to_string("/proc/meminfo").await {
        let (mut total, mut avail) = (0u64, 0u64);
        for line in mi.lines() {
            if let Some(v) = line.strip_prefix("MemTotal:") {
                total = v
                    .split_whitespace()
                    .next()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
            } else if let Some(v) = line.strip_prefix("MemAvailable:") {
                avail = v
                    .split_whitespace()
                    .next()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
            }
        }
        if total > 0 {
            m.mem_total_mb = total / 1024;
            m.mem_used_mb = total.saturating_sub(avail) / 1024;
        }
    }

    if let Ok(la) = tokio::fs::read_to_string("/proc/loadavg").await {
        if let Some(v) = la.split_whitespace().next() {
            m.load_1m = v.parse().unwrap_or(0.0);
        }
    }

    if let Ok(stat) = tokio::fs::read_to_string("/proc/stat").await {
        if let Some(line) = stat.lines().next() {
            let vals: Vec<u64> = line
                .split_whitespace()
                .skip(1)
                .filter_map(|v| v.parse().ok())
                .collect();
            if vals.len() >= 4 {
                let total: u64 = vals.iter().sum();
                let idle = vals[3];
                if let Some(idle_pct) = (idle.saturating_mul(100)).checked_div(total) {
                    m.cpu_pct = 100u64.saturating_sub(idle_pct);
                }
            }
        }
    }

    m
}

pub fn format_bytes_mb(mb: u64) -> String {
    if mb >= 1024 {
        format!("{:.1}G", mb as f64 / 1024.0)
    } else {
        format!("{mb}M")
    }
}

pub fn format_duration_secs(s: u64) -> String {
    if s >= 3600 {
        format!("{}h {}m", s / 3600, (s % 3600) / 60)
    } else if s >= 60 {
        format!("{}m", s / 60)
    } else {
        format!("{s}s")
    }
}
