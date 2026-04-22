//! System metrics for the dashboard and `/health` JSON. Most of the
//! work is done by the `sysinfo` crate — we just project its data
//! into our stable wire shape. CPU utilization still comes from
//! `/proc/stat` since `sysinfo` requires a 200 ms sample to report
//! non-zero CPU, and we don't want that delay on every request.

use serde::{Deserialize, Serialize};
use sysinfo::{Disks, Networks, System};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DiskStats {
    pub mount: String,
    pub fstype: String,
    pub used_bytes: u64,
    pub total_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NetStats {
    pub iface: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct SysMetrics {
    pub cpu_pct: u64,
    pub mem_used_mb: u64,
    pub mem_total_mb: u64,
    /// Swap used / total (0 if the VM has no swap).
    pub swap_used_mb: u64,
    pub swap_total_mb: u64,
    pub load_1m: f64,
    pub load_5m: f64,
    pub load_15m: f64,
    /// System uptime in seconds (how long the VM has been booted).
    pub uptime_secs: u64,
    /// Per-interface RX/TX byte counters (excludes `lo`).
    pub nets: Vec<NetStats>,
    /// Per-mount capacity stats (excludes pseudo-filesystems).
    pub disks: Vec<DiskStats>,
}

pub async fn collect() -> SysMetrics {
    let cpu_pct = tokio::fs::read_to_string("/proc/stat")
        .await
        .ok()
        .and_then(|s| cpu_pct_from_stat(&s))
        .unwrap_or(0);

    // sysinfo's API is sync and does blocking I/O; hop off the
    // reactor thread so long /proc walks don't stall the server.
    tokio::task::spawn_blocking(move || {
        let mut sys = System::new();
        sys.refresh_memory();

        let load = System::load_average();
        let uptime_secs = System::uptime();

        let mem_total_mb = sys.total_memory() / 1024 / 1024;
        let mem_used_mb = sys.used_memory() / 1024 / 1024;
        let swap_total_mb = sys.total_swap() / 1024 / 1024;
        let swap_used_mb = sys.used_swap() / 1024 / 1024;

        let nets = Networks::new_with_refreshed_list()
            .iter()
            .filter(|(name, _)| *name != "lo")
            .map(|(name, data)| NetStats {
                iface: name.to_string(),
                rx_bytes: data.total_received(),
                tx_bytes: data.total_transmitted(),
            })
            .collect();

        let mut seen = std::collections::HashSet::new();
        let disks = Disks::new_with_refreshed_list()
            .iter()
            .filter_map(|d| {
                let mount = d.mount_point().to_string_lossy().into_owned();
                if !seen.insert(mount.clone()) {
                    return None;
                }
                let total = d.total_space();
                if total == 0 {
                    return None;
                }
                Some(DiskStats {
                    mount,
                    fstype: d.file_system().to_string_lossy().into_owned(),
                    total_bytes: total,
                    used_bytes: total.saturating_sub(d.available_space()),
                })
            })
            .collect();

        SysMetrics {
            cpu_pct,
            mem_total_mb,
            mem_used_mb,
            swap_total_mb,
            swap_used_mb,
            load_1m: load.one,
            load_5m: load.five,
            load_15m: load.fifteen,
            uptime_secs,
            nets,
            disks,
        }
    })
    .await
    .unwrap_or_default()
}

/// One-shot CPU utilization from `/proc/stat`'s aggregate counters:
/// `(total - idle) / total` over the lifetime of the kernel. Coarse
/// (it's an average, not an instantaneous reading) but doesn't
/// require a two-sample delta like sysinfo's CPU, and matches the
/// historical shape the dashboard has been rendering.
fn cpu_pct_from_stat(stat: &str) -> Option<u64> {
    let line = stat.lines().next()?;
    let vals: Vec<u64> = line
        .split_whitespace()
        .skip(1)
        .filter_map(|v| v.parse().ok())
        .collect();
    if vals.len() < 4 {
        return None;
    }
    let total: u64 = vals.iter().sum();
    let idle = vals[3];
    let idle_pct = (idle.saturating_mul(100)).checked_div(total)?;
    Some(100u64.saturating_sub(idle_pct))
}

pub fn format_bytes_mb(mb: u64) -> String {
    if mb >= 1024 {
        format!("{:.1}G", mb as f64 / 1024.0)
    } else {
        format!("{mb}M")
    }
}

/// Humanise a raw byte count as K/M/G/T. Used for network counters.
pub fn format_bytes_si(b: u64) -> String {
    const K: u64 = 1024;
    const M: u64 = 1024 * K;
    const G: u64 = 1024 * M;
    const T: u64 = 1024 * G;
    if b >= T {
        format!("{:.1}T", b as f64 / T as f64)
    } else if b >= G {
        format!("{:.1}G", b as f64 / G as f64)
    } else if b >= M {
        format!("{:.1}M", b as f64 / M as f64)
    } else if b >= K {
        format!("{:.1}K", b as f64 / K as f64)
    } else {
        format!("{b}B")
    }
}

pub fn format_duration_secs(s: u64) -> String {
    if s >= 86400 {
        format!("{}d {}h", s / 86400, (s % 86400) / 3600)
    } else if s >= 3600 {
        format!("{}h {}m", s / 3600, (s % 3600) / 60)
    } else if s >= 60 {
        format!("{}m", s / 60)
    } else {
        format!("{s}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_pct_computes_from_stat() {
        // user=100 nice=0 system=50 idle=850 … → (150/1000)=15% used.
        let stat = "cpu  100 0 50 850 0 0 0 0 0 0\ncpu0 50 0 25 425 0 0 0 0 0 0";
        assert_eq!(cpu_pct_from_stat(stat), Some(15));
    }

    #[test]
    fn cpu_pct_handles_zero_total() {
        assert_eq!(cpu_pct_from_stat("cpu  0 0 0 0"), None);
    }

    #[test]
    fn format_bytes_si_boundaries() {
        assert_eq!(format_bytes_si(0), "0B");
        assert_eq!(format_bytes_si(1023), "1023B");
        assert_eq!(format_bytes_si(1024), "1.0K");
        assert_eq!(format_bytes_si(1024 * 1024), "1.0M");
        assert_eq!(format_bytes_si(1024u64.pow(3)), "1.0G");
    }

    #[test]
    fn format_duration_shapes() {
        assert_eq!(format_duration_secs(45), "45s");
        assert_eq!(format_duration_secs(3 * 60), "3m");
        assert_eq!(format_duration_secs(2 * 3600 + 30 * 60), "2h 30m");
        assert_eq!(format_duration_secs(3 * 86400 + 5 * 3600), "3d 5h");
    }
}
