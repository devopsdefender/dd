//! Browser auth for human-facing DD surfaces.
//!
//! Machine APIs stay on ITA / GitHub Actions OIDC. Browser pages use a
//! GitHub App OAuth flow and a DD-signed cookie scoped to the DD apex
//! domain so the production CP can broker auth for PR preview hosts.

use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use base64::Engine as _;
use hmac::{Hmac, Mac};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::error::{Error, Result};
use crate::gh_oidc::{Principal, PrincipalKind};

type HmacSha256 = Hmac<Sha256>;

const SESSION_COOKIE: &str = "dd_session";
const NONCE_COOKIE: &str = "dd_oauth_nonce";
const SESSION_TTL_SECS: i64 = 7 * 24 * 60 * 60;
const STATE_TTL_SECS: i64 = 10 * 60;

#[derive(Clone)]
pub struct AuthConfig {
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub staging_client_id: Option<String>,
    pub staging_client_secret: Option<String>,
    pub production_client_id: Option<String>,
    pub production_client_secret: Option<String>,
    pub cookie_secret: Vec<u8>,
    pub cookie_domain: String,
    pub broker_origin: String,
    pub callback_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub login: String,
    pub user_id: u64,
    pub exp: i64,
    pub owner_name: String,
    pub owner_id: u64,
    pub owner_kind: PrincipalKind,
}

#[derive(Serialize, Deserialize)]
struct StateToken {
    return_to: String,
    nonce: String,
    app: String,
    exp: i64,
}

#[derive(Deserialize)]
struct GithubTokenResponse {
    access_token: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

#[derive(Deserialize)]
struct GithubUser {
    login: String,
    id: u64,
}

impl AuthConfig {
    pub fn from_env(hostname: &str, domain: &str) -> Result<Self> {
        let get = |k: &str| {
            std::env::var(k)
                .ok()
                .filter(|v| !v.trim().is_empty())
                .ok_or_else(|| Error::Internal(format!("{k} required for DD browser auth")))
        };
        let broker_origin = std::env::var("DD_AUTH_BROKER_URL")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| format!("https://{hostname}"));
        let cookie_domain = std::env::var("DD_AUTH_COOKIE_DOMAIN")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| format!(".{domain}"));
        let callback_url = std::env::var("DD_GITHUB_CALLBACK_URL")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| format!("{broker_origin}/auth/github/callback"));
        let cookie_secret_raw = get("DD_AUTH_COOKIE_SECRET")?;
        let cookie_secret = base64::engine::general_purpose::STANDARD
            .decode(cookie_secret_raw.trim())
            .unwrap_or_else(|_| cookie_secret_raw.into_bytes());
        if cookie_secret.len() < 32 {
            return Err(Error::Internal(
                "DD_AUTH_COOKIE_SECRET must contain at least 32 bytes of entropy".into(),
            ));
        }
        Ok(Self {
            client_id: std::env::var("DD_GITHUB_CLIENT_ID")
                .ok()
                .filter(|v| !v.trim().is_empty()),
            client_secret: std::env::var("DD_GITHUB_CLIENT_SECRET")
                .ok()
                .filter(|v| !v.trim().is_empty()),
            staging_client_id: std::env::var("DD_STAGING_GITHUB_CLIENT_ID")
                .ok()
                .filter(|v| !v.trim().is_empty()),
            staging_client_secret: std::env::var("DD_STAGING_GITHUB_CLIENT_SECRET")
                .ok()
                .filter(|v| !v.trim().is_empty()),
            production_client_id: std::env::var("DD_PRODUCTION_GITHUB_CLIENT_ID")
                .ok()
                .filter(|v| !v.trim().is_empty()),
            production_client_secret: std::env::var("DD_PRODUCTION_GITHUB_CLIENT_SECRET")
                .ok()
                .filter(|v| !v.trim().is_empty()),
            cookie_secret,
            cookie_domain,
            broker_origin: broker_origin.trim_end_matches('/').to_string(),
            callback_url,
        })
    }

    pub fn login_redirect(&self, return_to: &str) -> Response {
        Redirect::temporary(&format!(
            "{}/auth/github/start?return_to={}",
            self.broker_origin,
            urlencoding::encode(return_to)
        ))
        .into_response()
    }

    pub fn start_response(&self, return_to: &str, domain: &str) -> Result<Response> {
        validate_return_to(return_to, domain)?;
        let app = app_for_return_to(return_to)?;
        let (client_id, _) = self.client_for(&app)?;
        let nonce = new_nonce();
        let state = StateToken {
            return_to: return_to.to_string(),
            nonce: nonce.clone(),
            app,
            exp: now_ts() + STATE_TTL_SECS,
        };
        let state = sign(&self.cookie_secret, &state)?;
        let url = format!(
            "https://github.com/login/oauth/authorize?client_id={}&redirect_uri={}&state={}",
            urlencoding::encode(client_id),
            urlencoding::encode(&self.callback_url),
            urlencoding::encode(&state)
        );
        let mut resp = Redirect::temporary(&url).into_response();
        append_set_cookie(
            resp.headers_mut(),
            &cookie(
                NONCE_COOKIE,
                &nonce,
                &self.cookie_domain,
                STATE_TTL_SECS,
                true,
            ),
        )?;
        Ok(resp)
    }

    pub async fn callback_response(
        &self,
        http: &Client,
        owner: &Principal,
        code: &str,
        state: &str,
        headers: &HeaderMap,
        domain: &str,
    ) -> Result<Response> {
        let state: StateToken = verify(&self.cookie_secret, state)?;
        if state.exp < now_ts() {
            return Err(Error::Unauthorized);
        }
        validate_return_to(&state.return_to, domain)?;
        let nonce = cookie_value(headers, NONCE_COOKIE).ok_or(Error::Unauthorized)?;
        if nonce != state.nonce {
            return Err(Error::Unauthorized);
        }

        let token = exchange_code(http, self, &state.app, code).await?;
        let user = fetch_user(http, &token).await?;
        authorize_user(http, &token, owner, &user).await?;

        let session = Session {
            login: user.login,
            user_id: user.id,
            exp: now_ts() + SESSION_TTL_SECS,
            owner_name: owner.name.clone(),
            owner_id: owner.id,
            owner_kind: owner.kind,
        };
        let token = sign(&self.cookie_secret, &session)?;
        let mut resp = Redirect::temporary(&state.return_to).into_response();
        append_set_cookie(
            resp.headers_mut(),
            &cookie(
                SESSION_COOKIE,
                &token,
                &self.cookie_domain,
                SESSION_TTL_SECS,
                true,
            ),
        )?;
        append_set_cookie(
            resp.headers_mut(),
            &cookie(NONCE_COOKIE, "", &self.cookie_domain, 0, true),
        )?;
        Ok(resp)
    }

    pub fn verify_session(&self, owner: &Principal, headers: &HeaderMap) -> Option<Session> {
        let token = cookie_value(headers, SESSION_COOKIE)?;
        let session: Session = verify(&self.cookie_secret, token).ok()?;
        if session.exp < now_ts() {
            return None;
        }
        if session.owner_name != owner.name
            || session.owner_id != owner.id
            || session.owner_kind != owner.kind
        {
            return None;
        }
        Some(session)
    }

    fn client_for(&self, app: &str) -> Result<(&str, &str)> {
        let pair = match app {
            "staging" => (
                self.staging_client_id.as_ref().or(self.client_id.as_ref()),
                self.staging_client_secret
                    .as_ref()
                    .or(self.client_secret.as_ref()),
            ),
            "production" => (
                self.production_client_id
                    .as_ref()
                    .or(self.client_id.as_ref()),
                self.production_client_secret
                    .as_ref()
                    .or(self.client_secret.as_ref()),
            ),
            _ => (self.client_id.as_ref(), self.client_secret.as_ref()),
        };
        let id = pair
            .0
            .map(String::as_str)
            .ok_or_else(|| Error::Internal(format!("missing GitHub client id for {app} auth")))?;
        let secret = pair.1.map(String::as_str).ok_or_else(|| {
            Error::Internal(format!("missing GitHub client secret for {app} auth"))
        })?;
        Ok((id, secret))
    }
}

pub fn unauthorized_or_redirect(
    auth: &AuthConfig,
    headers: &HeaderMap,
    return_to: &str,
) -> Response {
    let wants_html = headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.contains("text/html") || v.contains("*/*"))
        .unwrap_or(true);
    if wants_html {
        auth.login_redirect(return_to)
    } else {
        StatusCode::UNAUTHORIZED.into_response()
    }
}

pub fn absolute_url(headers: &HeaderMap, fallback_host: &str, path_and_query: &str) -> String {
    let proto = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("https");
    let host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or(fallback_host);
    format!("{proto}://{host}{path_and_query}")
}

pub fn cookie_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    raw.split(';').find_map(|part| {
        let (k, v) = part.trim().split_once('=')?;
        (k == name).then_some(v)
    })
}

async fn exchange_code(http: &Client, cfg: &AuthConfig, app: &str, code: &str) -> Result<String> {
    let (client_id, client_secret) = cfg.client_for(app)?;
    let resp = http
        .post("https://github.com/login/oauth/access_token")
        .header(header::ACCEPT, "application/json")
        .json(&serde_json::json!({
            "client_id": client_id,
            "client_secret": client_secret,
            "code": code,
            "redirect_uri": cfg.callback_url,
        }))
        .send()
        .await?;
    let status = resp.status();
    let body: GithubTokenResponse = resp.json().await?;
    if !status.is_success() {
        return Err(Error::Upstream(format!(
            "GitHub token exchange returned {status}"
        )));
    }
    if let Some(err) = body.error {
        return Err(Error::Upstream(format!(
            "GitHub token exchange failed: {}",
            body.error_description.unwrap_or(err)
        )));
    }
    body.access_token.ok_or(Error::Unauthorized)
}

async fn fetch_user(http: &Client, token: &str) -> Result<GithubUser> {
    let resp = http
        .get("https://api.github.com/user")
        .bearer_auth(token)
        .header(header::USER_AGENT, "devopsdefender")
        .send()
        .await?;
    if !resp.status().is_success() {
        return Err(Error::Unauthorized);
    }
    Ok(resp.json().await?)
}

async fn authorize_user(
    http: &Client,
    token: &str,
    owner: &Principal,
    user: &GithubUser,
) -> Result<()> {
    match owner.kind {
        PrincipalKind::User => {
            if user.id == owner.id {
                Ok(())
            } else {
                Err(Error::Unauthorized)
            }
        }
        PrincipalKind::Org => {
            let resp = http
                .get(format!(
                    "https://api.github.com/orgs/{}/public_members/{}",
                    owner.name, user.login
                ))
                .bearer_auth(token)
                .header(header::USER_AGENT, "devopsdefender")
                .send()
                .await?;
            if resp.status().is_success() {
                Ok(())
            } else {
                Err(Error::Unauthorized)
            }
        }
        PrincipalKind::Repo => {
            let resp = http
                .get(format!("https://api.github.com/repos/{}", owner.name))
                .bearer_auth(token)
                .header(header::USER_AGENT, "devopsdefender")
                .send()
                .await?;
            if resp.status().is_success() {
                Ok(())
            } else {
                Err(Error::Unauthorized)
            }
        }
    }
}

fn sign<T: Serialize>(secret: &[u8], value: &T) -> Result<String> {
    let json = serde_json::to_vec(value)?;
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json);
    let sig = mac(secret, payload.as_bytes())?;
    Ok(format!("{payload}.{sig}"))
}

fn verify<T: for<'de> Deserialize<'de>>(secret: &[u8], token: &str) -> Result<T> {
    let (payload, sig) = token.split_once('.').ok_or(Error::Unauthorized)?;
    let expected = mac(secret, payload.as_bytes())?;
    if !constant_time_eq(sig.as_bytes(), expected.as_bytes()) {
        return Err(Error::Unauthorized);
    }
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| Error::Unauthorized)?;
    serde_json::from_slice(&bytes).map_err(|_| Error::Unauthorized)
}

fn mac(secret: &[u8], payload: &[u8]) -> Result<String> {
    let mut mac = HmacSha256::new_from_slice(secret)
        .map_err(|e| Error::Internal(format!("auth hmac: {e}")))?;
    mac.update(payload);
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn new_nonce() -> String {
    let mut bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn cookie(name: &str, value: &str, domain: &str, max_age: i64, http_only: bool) -> String {
    let mut c =
        format!("{name}={value}; Path=/; Domain={domain}; Max-Age={max_age}; Secure; SameSite=Lax");
    if http_only {
        c.push_str("; HttpOnly");
    }
    c
}

fn append_set_cookie(headers: &mut HeaderMap, value: &str) -> Result<()> {
    headers.append(
        header::SET_COOKIE,
        HeaderValue::from_str(value)
            .map_err(|e| Error::Internal(format!("invalid Set-Cookie: {e}")))?,
    );
    Ok(())
}

fn validate_return_to(return_to: &str, domain: &str) -> Result<()> {
    let url = reqwest::Url::parse(return_to)
        .map_err(|_| Error::BadRequest("return_to must be an absolute URL".into()))?;
    if url.scheme() != "https" {
        return Err(Error::BadRequest("return_to must be https".into()));
    }
    let Some(host) = url.host_str() else {
        return Err(Error::BadRequest("return_to missing host".into()));
    };
    if host == domain || host.ends_with(&format!(".{domain}")) {
        Ok(())
    } else {
        Err(Error::BadRequest(
            "return_to host is outside DD domain".into(),
        ))
    }
}

fn app_for_return_to(return_to: &str) -> Result<String> {
    let url = reqwest::Url::parse(return_to)
        .map_err(|_| Error::BadRequest("return_to must be an absolute URL".into()))?;
    let host = url
        .host_str()
        .ok_or_else(|| Error::BadRequest("return_to missing host".into()))?;
    if host.starts_with("app.") || host.starts_with("app-") {
        Ok("production".into())
    } else {
        Ok("staging".into())
    }
}

fn now_ts() -> i64 {
    chrono::Utc::now().timestamp()
}
