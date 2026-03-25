use crate::common::error::{AppError, AppResult};
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, CONTENT_TYPE};
use serde::{Deserialize, Serialize};

const DEFAULT_ITA_API_URL: &str = "https://api.trustauthority.intel.com";

#[derive(Debug, Serialize)]
struct ItaAttestRequest<'a> {
    quote: &'a str,
}

#[derive(Debug, Deserialize)]
struct ItaTokenResponse {
    token: String,
}

#[derive(Clone)]
pub struct ItaClient {
    api_url: String,
    http: reqwest::Client,
}

impl ItaClient {
    pub fn from_env() -> AppResult<Self> {
        let api_key = std::env::var("DD_INTEL_API_KEY")
            .map_err(|_| AppError::Config("DD_INTEL_API_KEY is required".into()))?;
        let api_url =
            std::env::var("DD_ITA_API_URL").unwrap_or_else(|_| DEFAULT_ITA_API_URL.to_string());
        Self::new(api_url, api_key)
    }

    pub fn new(api_url: impl Into<String>, api_key: impl AsRef<str>) -> AppResult<Self> {
        let mut headers = HeaderMap::new();
        let api_key = HeaderValue::from_str(api_key.as_ref())
            .map_err(|e| AppError::Config(format!("invalid Intel API key header value: {e}")))?;
        headers.insert("x-api-key", api_key);
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));

        let http = reqwest::Client::builder()
            .default_headers(headers)
            .build()
            .map_err(|e| AppError::External(format!("build ITA HTTP client: {e}")))?;

        Ok(Self {
            api_url: api_url.into().trim_end_matches('/').to_string(),
            http,
        })
    }

    pub async fn attest(&self, quote_b64: &str) -> AppResult<String> {
        let url = format!("{}/appraisal/v1/attest", self.api_url);
        let body = ItaAttestRequest { quote: quote_b64 };

        let resp = self
            .http
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| AppError::External(format!("POST {url}: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(AppError::External(format!(
                "POST {url}: status {status}: {body}"
            )));
        }

        let body = resp
            .text()
            .await
            .map_err(|e| AppError::External(format!("read ITA attestation response: {e}")))?;

        parse_token_response(&body)
    }
}

fn parse_token_response(body: &str) -> AppResult<String> {
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return Err(AppError::External("empty ITA attestation response".into()));
    }

    if let Ok(token) = serde_json::from_str::<String>(trimmed) {
        return Ok(token);
    }

    if let Ok(resp) = serde_json::from_str::<ItaTokenResponse>(trimmed) {
        return Ok(resp.token);
    }

    Ok(trimmed.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_token_response_accepts_raw_or_json() {
        assert_eq!(parse_token_response("token-abc").unwrap(), "token-abc");
        assert_eq!(parse_token_response("\"token-abc\"").unwrap(), "token-abc");
        assert_eq!(
            parse_token_response("{\"token\":\"token-abc\"}").unwrap(),
            "token-abc"
        );
    }
}
