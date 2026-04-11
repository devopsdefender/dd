use dd_common::tunnel::CfConfig;

/// Configuration for the dd-web fleet dashboard.
pub struct Config {
    pub cf: CfConfig,
    pub github_client_id: String,
    pub github_client_secret: String,
    pub github_callback_url: String,
    pub owner: String,
    pub domain: String,
    pub hostname: String,
    pub port: u16,
    pub env_label: String,
    pub peers: Vec<String>,
    pub scrape_interval_secs: u64,
    /// If set, enable GitHub Actions OIDC auth with this audience.
    /// When the workflow mints its ID token it must pass the same
    /// audience: `&audience=<value>`. Unset → OIDC branch disabled.
    pub oidc_audience: Option<String>,
}

impl Config {
    pub fn from_env() -> Self {
        let cf = CfConfig::from_env().unwrap_or_else(|e| {
            eprintln!("dd-web: CF config required: {e}");
            std::process::exit(1);
        });

        let domain = cf.domain.clone();

        let hostname = std::env::var("DD_HOSTNAME").unwrap_or_else(|_| {
            eprintln!("dd-web: DD_HOSTNAME required");
            std::process::exit(1);
        });

        let github_client_id = std::env::var("DD_GITHUB_CLIENT_ID").unwrap_or_else(|_| {
            eprintln!("dd-web: DD_GITHUB_CLIENT_ID required");
            std::process::exit(1);
        });

        let github_client_secret = std::env::var("DD_GITHUB_CLIENT_SECRET").unwrap_or_else(|_| {
            eprintln!("dd-web: DD_GITHUB_CLIENT_SECRET required");
            std::process::exit(1);
        });

        let github_callback_url = std::env::var("DD_GITHUB_CALLBACK_URL")
            .unwrap_or_else(|_| format!("https://{hostname}/auth/github/callback"));

        let owner = std::env::var("DD_OWNER").unwrap_or_default();

        let port: u16 = std::env::var("DD_PORT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(8080);

        let env_label = std::env::var("DD_ENV").unwrap_or_else(|_| "dev".into());

        let peers: Vec<String> = std::env::var("DD_PEERS")
            .ok()
            .map(|s| {
                s.split(',')
                    .map(|p| p.trim().to_string())
                    .filter(|p| !p.is_empty())
                    .collect()
            })
            .unwrap_or_default();

        let scrape_interval_secs: u64 = std::env::var("DD_SCRAPE_INTERVAL")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(30);

        let oidc_audience = std::env::var("DD_OIDC_AUDIENCE")
            .ok()
            .filter(|s| !s.is_empty());

        Self {
            cf,
            github_client_id,
            github_client_secret,
            github_callback_url,
            owner,
            domain,
            hostname,
            port,
            env_label,
            peers,
            scrape_interval_secs,
            oidc_audience,
        }
    }
}
