//! Poweroff helper for fatal CP boot failures.
//!
//! STONITH proper — the new-CP-evicts-old-CP fencing (delete the old
//! CP's tunnel by name prefix, plus a self-watchdog that powered the old
//! CP off once it saw its own tunnel vanish) — has been removed for now.
//! It churned the Cloudflare tunnel hand-off (the 502 flap during
//! cutover), and on the SSH/prod path the relaunch already destroys the
//! old CP VM before booting the new one, so the fencing was redundant
//! there. What remains is `poweroff`, used by `cp::run` to halt the VM
//! on unrecoverable boot errors.

/// Poweroff via reboot(2). Bypasses busybox's PID-1-is-systemd
/// assumption. Requires CAP_SYS_BOOT (we're root). Linux-only; on
/// other targets (developer workstations running `cargo test`) we
/// just abort, since there's no enclave to tear down.
#[cfg(target_os = "linux")]
pub fn poweroff() -> ! {
    unsafe {
        libc::sync();
        libc::reboot(libc::LINUX_REBOOT_CMD_POWER_OFF);
    }
    std::process::abort();
}

#[cfg(not(target_os = "linux"))]
pub fn poweroff() -> ! {
    eprintln!("stonith: poweroff called on non-linux target — aborting process");
    std::process::abort();
}
