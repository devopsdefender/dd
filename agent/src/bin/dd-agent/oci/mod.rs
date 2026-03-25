mod registry;
mod unpack;

use registry::RegistryClient;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ffi::CString;
use std::fs;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use unpack::{prepare_rootfs_dir, unpack_layers};

const WORKLOAD_DIR: &str = "/var/lib/dd/workload";
const ROOTFS_DIR: &str = "/var/lib/dd/workload/rootfs";
const MOUNT_POINTS: [&str; 3] = ["proc", "sys", "dev"];

/// A port mapping from host to container.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortMapping {
    /// Port on the host.
    pub host_port: u16,
    /// Port inside the container.
    pub container_port: u16,
    /// Protocol (tcp or udp).
    #[serde(default = "default_protocol")]
    pub protocol: String,
}

fn default_protocol() -> String {
    "tcp".into()
}

/// Request to launch a container.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LaunchRequest {
    /// OCI image reference (e.g. `ghcr.io/org/image:tag`).
    pub image: String,
    /// Optional container name.
    pub name: Option<String>,
    /// Environment variables.
    #[serde(default)]
    pub env: Vec<String>,
    /// Port mappings.
    #[serde(default)]
    pub ports: Vec<PortMapping>,
    /// Optional command override.
    #[serde(default)]
    pub cmd: Vec<String>,
}

#[derive(Debug, Clone, Default)]
struct PreparedImage {
    image: String,
    entrypoint: Vec<String>,
    cmd: Vec<String>,
    env: Vec<String>,
    working_dir: Option<String>,
}

#[derive(Debug, Default)]
struct RuntimeState {
    prepared: Option<PreparedImage>,
    child_pid: Option<i32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExitStatus {
    pub success: bool,
    pub exit_code: Option<i32>,
}

/// Native OCI runtime backed by direct registry HTTP access and Linux process primitives.
pub struct NativeOciRuntime {
    registry: RegistryClient,
    state: Arc<Mutex<RuntimeState>>,
    rootfs_dir: PathBuf,
}

impl NativeOciRuntime {
    pub fn new() -> Result<Self, String> {
        fs::create_dir_all(WORKLOAD_DIR)
            .map_err(|e| format!("create workload directory {WORKLOAD_DIR}: {e}"))?;

        Ok(Self {
            registry: RegistryClient::new()?,
            state: Arc::new(Mutex::new(RuntimeState::default())),
            rootfs_dir: PathBuf::from(ROOTFS_DIR),
        })
    }

    pub async fn pull_image(&self, image: &str) -> Result<(), String> {
        self.cleanup_mounts()?;
        prepare_rootfs_dir(&self.rootfs_dir)?;

        let pulled = self.registry.pull_image(image).await?;
        unpack_layers(&self.rootfs_dir, pulled.layers.iter().map(Vec::as_slice))?;

        let prepared = PreparedImage {
            image: image.to_string(),
            entrypoint: pulled.entrypoint,
            cmd: pulled.cmd,
            env: pulled.env,
            working_dir: pulled.working_dir,
        };

        let mut state = self
            .state
            .lock()
            .map_err(|_| "runtime state lock poisoned".to_string())?;
        state.prepared = Some(prepared);
        Ok(())
    }

    pub async fn create_and_start(&self, req: &LaunchRequest) -> Result<i32, String> {
        let prepared = {
            let state = self
                .state
                .lock()
                .map_err(|_| "runtime state lock poisoned".to_string())?;
            state.prepared.clone()
        };

        let prepared = match prepared {
            Some(prepared) if prepared.image == req.image => prepared,
            _ => {
                self.pull_image(&req.image).await?;
                let state = self
                    .state
                    .lock()
                    .map_err(|_| "runtime state lock poisoned".to_string())?;
                state
                    .prepared
                    .clone()
                    .ok_or_else(|| "image pull completed without prepared state".to_string())?
            }
        };

        let argv = build_command_argv(&prepared, req)?;
        let program = argv[0].clone();
        let args = &argv[1..];
        let envs = merge_env(&prepared.env, &req.env);

        self.mount_rootfs_support()?;

        let mut command = Command::new(&program);
        command.args(args);
        command.env_clear();
        command.envs(envs);
        command.stdin(Stdio::null());
        command.stdout(Stdio::inherit());
        command.stderr(Stdio::inherit());
        let rootfs = self.rootfs_dir.clone();
        let chdir_target = prepared
            .working_dir
            .clone()
            .unwrap_or_else(|| "/".to_string());
        unsafe {
            command.pre_exec(move || {
                let rootfs_cstr = path_to_cstring(&rootfs)?;
                if libc::chroot(rootfs_cstr.as_ptr()) != 0 {
                    return Err(std::io::Error::last_os_error());
                }

                let chdir_cstr = CString::new(chdir_target.as_str()).map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("working directory contains NUL byte: {chdir_target:?}"),
                    )
                })?;
                if libc::chdir(chdir_cstr.as_ptr()) != 0 {
                    return Err(std::io::Error::last_os_error());
                }

                Ok(())
            });
        }

        let child = command
            .spawn()
            .map_err(|e| format!("spawn workload {program}: {e}"))?;

        let pid = i32::try_from(child.id())
            .map_err(|_| format!("child PID {} does not fit in i32", child.id()))?;

        let mut state = self
            .state
            .lock()
            .map_err(|_| "runtime state lock poisoned".to_string())?;
        state.child_pid = Some(pid);

        Ok(pid)
    }

    pub fn try_wait(&self) -> Result<Option<ExitStatus>, String> {
        let pid = {
            let state = self
                .state
                .lock()
                .map_err(|_| "runtime state lock poisoned".to_string())?;
            state.child_pid
        };

        let Some(pid) = pid else {
            return Ok(None);
        };

        let mut raw_status = 0;
        let waited = unsafe { libc::waitpid(pid, &mut raw_status, libc::WNOHANG) };
        if waited == 0 {
            return Ok(None);
        }
        if waited < 0 {
            return Err(format!(
                "waitpid({pid}) failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        let exit = if libc::WIFEXITED(raw_status) {
            ExitStatus {
                success: libc::WEXITSTATUS(raw_status) == 0,
                exit_code: Some(libc::WEXITSTATUS(raw_status)),
            }
        } else if libc::WIFSIGNALED(raw_status) {
            ExitStatus {
                success: false,
                exit_code: Some(128 + libc::WTERMSIG(raw_status)),
            }
        } else {
            ExitStatus {
                success: false,
                exit_code: None,
            }
        };

        let mut state = self
            .state
            .lock()
            .map_err(|_| "runtime state lock poisoned".to_string())?;
        state.child_pid = None;
        Ok(Some(exit))
    }

    fn mount_rootfs_support(&self) -> Result<(), String> {
        for mount_name in MOUNT_POINTS {
            let target = self.rootfs_dir.join(mount_name);
            fs::create_dir_all(&target)
                .map_err(|e| format!("create mount point {}: {e}", target.display()))?;

            if is_mountpoint(&target)? {
                continue;
            }

            let status = Command::new("mount")
                .args([
                    "--rbind",
                    &format!("/{mount_name}"),
                    &target.display().to_string(),
                ])
                .status()
                .map_err(|e| format!("bind mount {mount_name} into {}: {e}", target.display()))?;

            if !status.success() {
                return Err(format!(
                    "mount --rbind /{mount_name} {} failed with status {status}",
                    target.display()
                ));
            }
        }

        Ok(())
    }

    fn cleanup_mounts(&self) -> Result<(), String> {
        for mount_name in MOUNT_POINTS.into_iter().rev() {
            let target = self.rootfs_dir.join(mount_name);
            if !target.exists() || !is_mountpoint(&target)? {
                continue;
            }

            let status = Command::new("umount")
                .args(["-l", &target.display().to_string()])
                .status()
                .map_err(|e| format!("unmount {}: {e}", target.display()))?;

            if !status.success() {
                return Err(format!(
                    "umount -l {} failed with status {status}",
                    target.display()
                ));
            }
        }

        Ok(())
    }
}

fn is_mountpoint(path: &Path) -> Result<bool, String> {
    let status = Command::new("mountpoint")
        .args(["-q", &path.display().to_string()])
        .status()
        .map_err(|e| format!("check mountpoint {}: {e}", path.display()))?;
    Ok(status.success())
}

fn path_to_cstring(path: &Path) -> std::io::Result<CString> {
    let bytes = path.as_os_str().as_encoded_bytes();
    CString::new(bytes).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("path contains NUL byte: {}", path.display()),
        )
    })
}

fn build_command_argv(
    prepared: &PreparedImage,
    req: &LaunchRequest,
) -> Result<Vec<String>, String> {
    let mut argv = if prepared.entrypoint.is_empty() {
        Vec::new()
    } else {
        prepared.entrypoint.clone()
    };

    if req.cmd.is_empty() {
        argv.extend(prepared.cmd.clone());
    } else {
        argv.extend(req.cmd.clone());
    }

    if argv.is_empty() {
        return Err("image config did not provide an entrypoint or command".to_string());
    }

    argv[0] = normalize_executable(&argv[0], prepared.working_dir.as_deref());
    Ok(argv)
}

fn normalize_executable(program: &str, working_dir: Option<&str>) -> String {
    if program.starts_with('/') {
        return program.to_string();
    }

    let base = working_dir.unwrap_or("/");
    let prefix = if base.ends_with('/') {
        base.trim_end_matches('/')
    } else {
        base
    };

    if prefix.is_empty() {
        format!("/{program}")
    } else {
        format!("{prefix}/{program}")
    }
}

fn merge_env(image_env: &[String], request_env: &[String]) -> HashMap<String, String> {
    let mut envs = HashMap::new();

    for entry in image_env.iter().chain(request_env.iter()) {
        if let Some((key, value)) = entry.split_once('=') {
            envs.insert(key.to_string(), value.to_string());
        }
    }

    envs
}

#[cfg(test)]
mod tests {
    use super::{
        build_command_argv, merge_env, normalize_executable, LaunchRequest, PreparedImage,
    };

    #[test]
    fn command_override_extends_entrypoint() {
        let prepared = PreparedImage {
            entrypoint: vec!["/bin/server".into()],
            cmd: vec!["--serve".into()],
            ..PreparedImage::default()
        };

        let req = LaunchRequest {
            image: "ghcr.io/example/app:latest".into(),
            name: None,
            env: Vec::new(),
            ports: Vec::new(),
            cmd: vec!["--foreground".into()],
        };

        let argv = build_command_argv(&prepared, &req).unwrap();
        assert_eq!(argv, vec!["/bin/server", "--foreground"]);
    }

    #[test]
    fn merge_env_prefers_request_values() {
        let envs = merge_env(
            &["PATH=/usr/bin".into(), "PORT=8080".into()],
            &["PORT=9090".into()],
        );

        assert_eq!(envs.get("PATH").map(String::as_str), Some("/usr/bin"));
        assert_eq!(envs.get("PORT").map(String::as_str), Some("9090"));
    }

    #[test]
    fn relative_executable_uses_working_directory() {
        assert_eq!(
            normalize_executable("server", Some("/app/bin")),
            "/app/bin/server"
        );
        assert_eq!(normalize_executable("server", None), "/server");
    }
}
