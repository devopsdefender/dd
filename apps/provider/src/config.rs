use std::env;

pub struct Config {
    pub cp_url: String,
    pub provider_name: String,
    pub bind_addr: String,
    pub skip_attestation: bool,
    pub flush_interval_ms: u64,
}

impl Config {
    pub fn from_env() -> Self {
        Self {
            cp_url: env::var("DD_CP_URL")
                .unwrap_or_else(|_| "https://app.devopsdefender.com".into()),
            provider_name: env::var("DD_PROVIDER_NAME")
                .unwrap_or_else(|_| "default-provider".into()),
            bind_addr: env::var("DD_PROVIDER_BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8081".into()),
            skip_attestation: env::var("DD_PROVIDER_SKIP_ATTESTATION")
                .map(|v| v == "true" || v == "1")
                .unwrap_or(false),
            flush_interval_ms: env::var("DD_PROVIDER_FLUSH_INTERVAL_MS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(10_000),
        }
    }
}
