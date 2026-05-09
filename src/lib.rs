pub mod agent;
pub mod auth;
pub mod cf;
pub mod collector;
pub mod config;
pub mod cp;
pub mod devices;
pub mod ee;
pub mod error;
pub mod gh_oidc;
pub mod html;
pub mod ita;
pub mod metrics;
pub mod noise_gateway;
pub mod oracle;
pub mod shell;
pub mod stonith;
pub mod taint;
pub mod units;

pub(crate) fn system_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .no_hickory_dns()
        .build()
        .expect("build system-resolver HTTP client")
}
