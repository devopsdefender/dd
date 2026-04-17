//! Lightweight /proc-derived system metrics for the agent dashboard
//! and the /health JSON. No external process dependencies.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DiskStats {
    pub mount: String,
    pub fstype: String,
    pub used_gb: u64,
    pub total_gb: u64,
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
    pub load_1m: f64,
    /// Per-interface RX/TX byte counters (excludes `lo`).
    pub nets: Vec<NetStats>,
    /// Per-mount capacity stats (excludes pseudo-filesystems).
    pub disks: Vec<DiskStats>,
}

/// /proc-filesystem types we don't want in disk stats. Everything else
/// (ext4, xfs, btrfs, overlay, vfat, …) gets statvfs'd.
const PSEUDO_FSTYPES: &[&str] = &[
    "proc",
    "sysfs",
    "cgroup",
    "cgroup2",
    "tmpfs",
    "devtmpfs",
    "ramfs",
    "devpts",
    "mqueue",
    "tracefs",
    "debugfs",
    "securityfs",
    "pstore",
    "bpf",
    "configfs",
    "autofs",
    "binfmt_misc",
    "hugetlbfs",
    "rpc_pipefs",
    "fusectl",
    "nsfs",
    "squashfs",
    "iso9660",
];

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

    // /proc/net/dev: one row per interface, space-separated counters.
    //   Inter-|   Receive                             ...
    //    face |bytes    packets errs drop fifo frame compressed multicast | bytes ...
    //       lo:  46340 …
    //     eth0:  12345 …
    // Col 0 = RX bytes, col 8 = TX bytes. Skip `lo`.
    if let Ok(dev) = tokio::fs::read_to_string("/proc/net/dev").await {
        for line in dev.lines().skip(2) {
            let Some((iface, rest)) = line.split_once(':') else {
                continue;
            };
            let iface = iface.trim();
            if iface == "lo" || iface.is_empty() {
                continue;
            }
            let cols: Vec<u64> = rest
                .split_whitespace()
                .filter_map(|s| s.parse().ok())
                .collect();
            if cols.len() >= 9 {
                m.nets.push(NetStats {
                    iface: iface.to_string(),
                    rx_bytes: cols[0],
                    tx_bytes: cols[8],
                });
            }
        }
    }

    // /proc/mounts: one row per mount, space-separated:
    //   <source> <mount-point> <fstype> <opts> <dump> <pass>
    // For every mount whose fstype isn't a known pseudo-filesystem, call
    // statvfs to get capacity. libc is already in the tree; one unsafe
    // block per statvfs call.
    if let Ok(mounts) = tokio::fs::read_to_string("/proc/mounts").await {
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        for line in mounts.lines() {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 3 {
                continue;
            }
            let mount = cols[1];
            let fstype = cols[2];
            if PSEUDO_FSTYPES.contains(&fstype) {
                continue;
            }
            // Dedupe — a disk may be bind-mounted multiple times.
            if !seen.insert(mount.to_string()) {
                continue;
            }
            let Ok(cmount) = std::ffi::CString::new(mount) else {
                continue;
            };
            let mut vfs: libc::statvfs = unsafe { std::mem::zeroed() };
            // SAFETY: statvfs writes only to its out param; cmount is a valid C string.
            if unsafe { libc::statvfs(cmount.as_ptr(), &mut vfs) } != 0 {
                continue;
            }
            #[allow(clippy::unnecessary_cast)]
            let frsize: u64 = vfs.f_frsize as u64;
            #[allow(clippy::unnecessary_cast)]
            let blocks: u64 = vfs.f_blocks as u64;
            #[allow(clippy::unnecessary_cast)]
            let bavail: u64 = vfs.f_bavail as u64;
            // Skip 0-sized "filesystems" (often virtual overlays with
            // no meaningful capacity).
            if blocks == 0 {
                continue;
            }
            let gib = 1024u64 * 1024 * 1024;
            m.disks.push(DiskStats {
                mount: mount.to_string(),
                fstype: fstype.to_string(),
                total_gb: frsize.saturating_mul(blocks) / gib,
                used_gb: frsize.saturating_mul(blocks.saturating_sub(bavail)) / gib,
            });
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
    if s >= 3600 {
        format!("{}h {}m", s / 3600, (s % 3600) / 60)
    } else if s >= 60 {
        format!("{}m", s / 60)
    } else {
        format!("{s}s")
    }
}
