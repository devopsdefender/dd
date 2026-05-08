use anyhow::{anyhow, bail, Context, Result};
use axum::{extract::State, response::IntoResponse, routing::get, Json, Router};
use chrono::Utc;
use serde_json::json;
use std::{
    ffi::{CString, OsString},
    fs,
    os::unix::{ffi::OsStrExt, fs::PermissionsExt},
    path::Path,
    process::Command,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

const BIN: &str = "/var/lib/easyenclave/bin";
const DATA_DIR: &str = "/var/lib/easyenclave/data";
const PODMAN_SRC: &str = "/var/lib/easyenclave/bin/podman-linux-amd64";

pub async fn mount_data() -> Result<()> {
    let dev = Path::new("/dev/vdc");
    if !dev.exists() {
        println!("mount-data: no /dev/vdc, skipping");
        return Ok(());
    }

    fs::create_dir_all(DATA_DIR).context("create data mountpoint")?;
    if !is_mounted(DATA_DIR) {
        mount(Some("/dev/vdc"), DATA_DIR, Some("ext4"), 0, None).context("mount /dev/vdc")?;
    }
    println!("mount-data: mounted /dev/vdc on {DATA_DIR}");
    Ok(())
}

pub async fn podman_bootstrap() -> Result<()> {
    let raw = Path::new(PODMAN_SRC).join("usr/local/bin/podman");
    while !raw.exists() {
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    if Path::new("/dev/vdc").exists() {
        while !is_mounted(DATA_DIR) {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    fs::create_dir_all(DATA_DIR).context("create podman data dir")?;
    stage_podman_files()?;
    ensure_dev_shm()?;

    let podman_dir = Path::new(DATA_DIR).join(".podman");
    fs::create_dir_all(&podman_dir)?;
    let driver = choose_storage_driver(&podman_dir)?;
    fs::write(podman_dir.join("driver"), driver)?;

    let storage_root = podman_dir.join(format!("storage-{driver}"));
    let runroot = podman_dir.join(format!("runroot-{driver}"));
    fs::create_dir_all(&storage_root)?;
    fs::create_dir_all(&runroot)?;

    let policy = podman_dir.join("policy.json");
    fs::write(
        &policy,
        r#"{"default":[{"type":"insecureAcceptAnything"}]}"#,
    )?;

    let home = Path::new("/var/lib/easyenclave/.home");
    fs::create_dir_all(home.join(".config/containers"))?;
    fs::create_dir_all(home.join("tmp"))?;
    fs::copy(&policy, home.join(".config/containers/policy.json"))?;

    let conf = podman_dir.join("containers.conf");
    fs::write(
        &conf,
        "[engine]\nhelper_binaries_dir = [\"/var/lib/easyenclave/bin\"]\n",
    )?;

    link_wrapper("podman")?;
    link_wrapper("dd-podman")?;

    let status = Command::new(Path::new(BIN).join(".podman-raw"))
        .arg("--version")
        .status()
        .context("run podman --version")?;
    if !status.success() {
        bail!("podman --version failed with {status}");
    }

    println!(
        "podman-bootstrap: ok driver={driver} data={DATA_DIR} root={} runroot={} conf={} policy={}",
        storage_root.display(),
        runroot.display(),
        conf.display(),
        policy.display()
    );
    Ok(())
}

pub fn podman_wrapper(args: Vec<OsString>) -> Result<()> {
    let podman_dir = Path::new(DATA_DIR).join(".podman");
    let driver = fs::read_to_string(podman_dir.join("driver"))
        .unwrap_or_else(|_| "vfs".into())
        .trim()
        .to_string();
    let storage_root = podman_dir.join(format!("storage-{driver}"));
    let runroot = podman_dir.join(format!("runroot-{driver}"));
    let conf = podman_dir.join("containers.conf");
    let home = "/var/lib/easyenclave/.home";

    let status = Command::new(Path::new(BIN).join(".podman-raw"))
        .env("HOME", home)
        .env("TMPDIR", format!("{home}/tmp"))
        .env("CONTAINERS_CONF", &conf)
        .env("PODMAN_IGNORE_CGROUPSV1_WARNING", "1")
        .arg(format!("--conmon={BIN}/conmon"))
        .arg(format!("--runtime={BIN}/crun"))
        .arg(format!("--storage-driver={driver}"))
        .arg(format!("--root={}", storage_root.display()))
        .arg(format!("--runroot={}", runroot.display()))
        .arg("--cgroup-manager=cgroupfs")
        .args(args)
        .status()
        .context("exec podman")?;

    std::process::exit(status.code().unwrap_or(1));
}

pub async fn human_readonly() -> Result<()> {
    oracle_server("human-readonly", "review", "read_only").await
}

pub async fn oracle_readonly() -> Result<()> {
    oracle_server("oracle-readonly", "ok", "read_only").await
}

fn stage_podman_files() -> Result<()> {
    fs::create_dir_all(BIN)?;
    for entry in fs::read_dir(Path::new(PODMAN_SRC).join("usr/local/bin"))
        .context("read podman usr/local/bin")?
    {
        let entry = entry?;
        let name = entry.file_name();
        let dest = if name == "podman" {
            Path::new(BIN).join(".podman-raw")
        } else {
            Path::new(BIN).join(name)
        };
        copy_executable(entry.path(), dest)?;
    }

    for helper in [
        "conmon",
        "netavark",
        "aardvark-dns",
        "rootlessport",
        "slirp4netns",
        "pasta",
    ] {
        let src = Path::new(PODMAN_SRC)
            .join("usr/local/lib/podman")
            .join(helper);
        if src.exists() {
            copy_executable(src, Path::new(BIN).join(helper))?;
        }
    }
    Ok(())
}

fn copy_executable(src: impl AsRef<Path>, dest: impl AsRef<Path>) -> Result<()> {
    fs::copy(src.as_ref(), dest.as_ref()).with_context(|| {
        format!(
            "copy {} to {}",
            src.as_ref().display(),
            dest.as_ref().display()
        )
    })?;
    let mut perms = fs::metadata(dest.as_ref())?.permissions();
    perms.set_mode(perms.mode() | 0o755);
    fs::set_permissions(dest.as_ref(), perms)?;
    Ok(())
}

fn ensure_dev_shm() -> Result<()> {
    if is_mounted("/dev/shm") {
        return Ok(());
    }
    fs::create_dir_all("/dev/shm")?;
    mount(
        Some("tmpfs"),
        "/dev/shm",
        Some("tmpfs"),
        0,
        Some("size=64M"),
    )
    .context("mount tmpfs on /dev/shm")
}

fn choose_storage_driver(podman_dir: &Path) -> Result<&'static str> {
    if !is_mounted(DATA_DIR)
        || !fs::read_to_string("/proc/filesystems")
            .unwrap_or_default()
            .split_whitespace()
            .any(|s| s == "overlay")
    {
        return Ok("vfs");
    }

    let probe = podman_dir.join("overlay-probe");
    let lower = probe.join("lower");
    let upper = probe.join("upper");
    let work = probe.join("work");
    let merged = probe.join("merged");
    fs::create_dir_all(&lower)?;
    fs::create_dir_all(&upper)?;
    fs::create_dir_all(&work)?;
    fs::create_dir_all(&merged)?;
    fs::write(lower.join(".probe"), b"")?;

    let data = format!(
        "lowerdir={},upperdir={},workdir={}",
        lower.display(),
        upper.display(),
        work.display()
    );
    let driver = if mount(Some("overlay"), &merged, Some("overlay"), 0, Some(&data)).is_ok() {
        let _ = umount(&merged);
        "overlay"
    } else {
        "vfs"
    };
    let _ = fs::remove_dir_all(&probe);
    Ok(driver)
}

fn link_wrapper(name: &str) -> Result<()> {
    let link = Path::new(BIN).join(name);
    let _ = fs::remove_file(&link);
    std::os::unix::fs::symlink("devopsdefender", &link)
        .with_context(|| format!("symlink {}", link.display()))
}

async fn oracle_server(
    name: &'static str,
    recommendation: &'static str,
    integrity: &'static str,
) -> Result<()> {
    let tick = Arc::new(AtomicU64::new(0));
    let state = OracleState {
        tick: tick.clone(),
        name,
        recommendation,
        integrity,
    };
    let app = Router::new()
        .route("/oracle.json", get(oracle_json))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8082")
        .await
        .context("bind oracle server")?;

    tokio::spawn(async move {
        loop {
            let n = tick.fetch_add(1, Ordering::Relaxed) + 1;
            let ts = Utc::now().format("%Y-%m-%dT%H:%M:%SZ");
            println!("{name}: tick={n} ts={ts} event=review_needed actor=human status=ok");
            tokio::time::sleep(Duration::from_secs(10)).await;
        }
    });

    axum::serve(listener, app).await.context("serve oracle")
}

#[derive(Clone)]
struct OracleState {
    tick: Arc<AtomicU64>,
    name: &'static str,
    recommendation: &'static str,
    integrity: &'static str,
}

async fn oracle_json(State(state): State<OracleState>) -> impl IntoResponse {
    Json(json!({
        "ok": true,
        "oracle": state.name,
        "tick": state.tick.load(Ordering::Relaxed),
        "ts": Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        "recommendation": state.recommendation,
        "integrity": state.integrity,
    }))
}

fn is_mounted(target: impl AsRef<Path>) -> bool {
    let target = target.as_ref().as_os_str().as_bytes();
    fs::read_to_string("/proc/mounts")
        .unwrap_or_default()
        .lines()
        .filter_map(|line| line.split_whitespace().nth(1))
        .any(|mountpoint| mountpoint.as_bytes() == target)
}

fn mount(
    source: Option<&str>,
    target: impl AsRef<Path>,
    fstype: Option<&str>,
    flags: libc::c_ulong,
    data: Option<&str>,
) -> Result<()> {
    let source = opt_cstring(source)?;
    let target = cstring_path(target.as_ref())?;
    let fstype = opt_cstring(fstype)?;
    let data = opt_cstring(data)?;
    let rc = unsafe {
        libc::mount(
            source
                .as_ref()
                .map(|s| s.as_ptr())
                .unwrap_or(std::ptr::null()),
            target.as_ptr(),
            fstype
                .as_ref()
                .map(|s| s.as_ptr())
                .unwrap_or(std::ptr::null()),
            flags,
            data.as_ref()
                .map(|s| s.as_ptr().cast())
                .unwrap_or(std::ptr::null()),
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(anyhow!(std::io::Error::last_os_error()))
    }
}

fn umount(target: impl AsRef<Path>) -> Result<()> {
    let target = cstring_path(target.as_ref())?;
    let rc = unsafe { libc::umount(target.as_ptr()) };
    if rc == 0 {
        Ok(())
    } else {
        Err(anyhow!(std::io::Error::last_os_error()))
    }
}

fn opt_cstring(s: Option<&str>) -> Result<Option<CString>> {
    s.map(|s| CString::new(s).context("nul byte in mount string"))
        .transpose()
}

fn cstring_path(path: &Path) -> Result<CString> {
    CString::new(path.as_os_str().as_bytes()).context("nul byte in path")
}
