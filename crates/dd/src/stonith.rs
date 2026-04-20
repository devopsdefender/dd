//! STONITH: kill old CP VMs so the new one owns `$DD_HOSTNAME`.
//!
//!   1. **Tunnel-delete STONITH at startup** — list CF tunnels, find
//!      CP tunnels (name starts with `dd-{env}-cp-`) that aren't ours,
//!      delete them. Their cloudflared exits; their watchdog picks up
//!      tunnel-gone and `poweroff`s within ~30 s.
//!   2. **Self-watchdog** — poll CF every 8–12 s for our own tunnel.
//!      Three consecutive gone readings → poweroff. Catches the case
//!      where we *are* the old CP being killed.

use std::time::Duration;

use rand::Rng;
use reqwest::Client;

use crate::cf;
use crate::config::CfCreds;

const POLL_BASE_SECS: u64 = 10;
const POLL_JITTER_SECS: u64 = 4;
const INITIAL_MIN_SECS: u64 = 10;
const INITIAL_MAX_SECS: u64 = 25;
const CONSECUTIVE_GONE: u32 = 3;

/// Poweroff via reboot(2). Bypasses busybox's PID-1-is-systemd
/// assumption. Requires CAP_SYS_BOOT (we're root).
pub fn poweroff() -> ! {
    unsafe {
        libc::sync();
        libc::reboot(libc::LINUX_REBOOT_CMD_POWER_OFF);
    }
    std::process::abort();
}

/// Delete any CP tunnel (by name prefix) except our own.
pub async fn kill_old_tunnels(http: &Client, cf: &CfCreds, self_tunnel_id: &str, env: &str) {
    let prefix = cf::cp_prefix(env);
    let Ok(tunnels) = cf::list(http, cf).await else {
        eprintln!("stonith: list failed");
        return;
    };
    for t in &tunnels {
        let Some(id) = t["id"].as_str() else { continue };
        if id == self_tunnel_id {
            continue;
        }
        let Some(name) = t["name"].as_str() else {
            continue;
        };
        if !name.starts_with(&prefix) {
            continue;
        }
        eprintln!("stonith: killing old CP tunnel {name} ({id})");
        cf::delete_by_name(http, cf, name).await;
    }
}

/// Background watchdog — runs until the VM powers off.
pub async fn self_watchdog(cf: CfCreds, self_tunnel_id: String) -> ! {
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());

    let initial = rand::thread_rng().gen_range(INITIAL_MIN_SECS..=INITIAL_MAX_SECS);
    tokio::time::sleep(Duration::from_secs(initial)).await;

    let mut gone: u32 = 0;
    loop {
        match cf::exists(&http, &cf, &self_tunnel_id).await {
            Some(true) => {
                if gone > 0 {
                    eprintln!("stonith: watchdog recovered after {gone} missed check(s)");
                }
                gone = 0;
            }
            Some(false) => {
                gone += 1;
                eprintln!("stonith: watchdog: tunnel gone ({gone}/{CONSECUTIVE_GONE})");
                if gone >= CONSECUTIVE_GONE {
                    eprintln!("stonith: poweroff — tunnel {self_tunnel_id} confirmed deleted");
                    poweroff();
                }
            }
            None => {
                eprintln!("stonith: watchdog: ambiguous check result");
            }
        }
        let jitter = rand::thread_rng().gen_range(0..=POLL_JITTER_SECS);
        let secs = POLL_BASE_SECS + jitter - POLL_JITTER_SECS / 2;
        tokio::time::sleep(Duration::from_secs(secs)).await;
    }
}
