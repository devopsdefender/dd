use crate::common::error::{AppError, AppResult};
use base64::Engine;
use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE};
use ring::digest;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ItaNonce {
    pub val: String,
    pub iat: String,
    pub signature: String,
}

#[derive(Debug, Serialize)]
struct ItaAttestRequest<'a> {
    quote: &'a str,
    verifier_nonce: &'a ItaNonce,
    #[serde(skip_serializing_if = "Option::is_none")]
    runtime_data: Option<&'a str>,
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
    pub fn new(api_url: impl Into<String>, api_key: impl AsRef<str>) -> AppResult<Self> {
        let mut headers = HeaderMap::new();
        let api_key = HeaderValue::from_str(api_key.as_ref())
            .map_err(|e| AppError::Config(format!("invalid Intel API key header value: {e}")))?;
        headers.insert("x-api-key", api_key);
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

        let http = reqwest::Client::builder()
            .default_headers(headers)
            .build()
            .map_err(|e| AppError::External(format!("build ITA HTTP client: {e}")))?;

        Ok(Self {
            api_url: api_url.into().trim_end_matches('/').to_string(),
            http,
        })
    }

    pub async fn get_nonce(&self) -> AppResult<ItaNonce> {
        let url = format!("{}/appraisal/v1/nonce", self.api_url);
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| AppError::External(format!("GET {url}: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(AppError::External(format!(
                "GET {url}: status {status}: {body}"
            )));
        }

        resp.json::<ItaNonce>()
            .await
            .map_err(|e| AppError::External(format!("parse ITA nonce response: {e}")))
    }

    pub async fn attest(
        &self,
        quote_b64: &str,
        nonce: &ItaNonce,
        runtime_data_b64: Option<&str>,
    ) -> AppResult<String> {
        let url = format!("{}/appraisal/v1/attest", self.api_url);
        let body = ItaAttestRequest {
            quote: quote_b64,
            verifier_nonce: nonce,
            runtime_data: runtime_data_b64,
        };

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

pub fn build_report_data(ita_nonce: &ItaNonce, runtime_data: &[u8]) -> [u8; 64] {
    let input = [
        ita_nonce.val.as_bytes(),
        b"|",
        ita_nonce.iat.as_bytes(),
        b"|",
        runtime_data,
    ]
    .concat();
    let digest = digest::digest(&digest::SHA512, &input);
    let mut report_data = [0u8; 64];
    report_data.copy_from_slice(digest.as_ref());
    report_data
}

pub fn encode_runtime_data(runtime_data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(runtime_data)
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
    fn build_report_data_hashes_nonce_and_runtime_data() {
        let nonce = ItaNonce {
            val: "nonce-val".into(),
            iat: "2026-03-25T00:00:00Z".into(),
            signature: "sig".into(),
        };

        let report_data = build_report_data(&nonce, b"cp-nonce");

        let expected = digest::digest(&digest::SHA512, b"nonce-val|2026-03-25T00:00:00Z|cp-nonce");
        assert_eq!(report_data.as_slice(), expected.as_ref());
    }

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
