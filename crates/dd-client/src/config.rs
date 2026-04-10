//! Configuration loaded from environment variables.

/// dd-client configuration.
pub struct Config {
    /// DD_REGISTER_URL -- WebSocket URL for registration with dd-register.
    pub register_url: Option<String>,
    /// DD_OWNER -- GitHub user or org that owns this VM.
    pub owner: String,
    /// Hostname or DD_VM_NAME.
    pub vm_name: String,
    /// DD_PASSWORD -- optional shared password for dashboard auth.
    pub password: Option<String>,
    /// EE_SOCKET_PATH -- path to easyenclave unix socket.
    pub ee_socket_path: String,
    /// DD_PORT -- HTTP server port.
    pub port: u16,
    /// DD_HOSTNAME -- tunnel hostname, set after registration.
    pub hostname: Option<String>,
}

impl Config {
    /// Load configuration from environment variables.
    pub fn from_env() -> Self {
        let vm_name = std::env::var("DD_VM_NAME").unwrap_or_else(|_| {
            hostname::get()
                .ok()
                .and_then(|h| h.into_string().ok())
                .unwrap_or_else(|| "unknown".into())
        });

        let register_url = std::env::var("DD_REGISTER_URL")
            .ok()
            .filter(|s| !s.is_empty());

        let owner = std::env::var("DD_OWNER").unwrap_or_default();

        let password = std::env::var("DD_PASSWORD").ok().filter(|s| !s.is_empty());

        let ee_socket_path = std::env::var("EE_SOCKET_PATH")
            .unwrap_or_else(|_| "/var/lib/easyenclave/agent.sock".into());

        let port = std::env::var("DD_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(8080);

        let hostname = std::env::var("DD_HOSTNAME").ok().filter(|s| !s.is_empty());

        Self {
            register_url,
            owner,
            vm_name,
            password,
            ee_socket_path,
            port,
            hostname,
        }
    }
}
