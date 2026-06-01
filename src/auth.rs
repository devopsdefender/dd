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
    /// GitHub org logins (lowercased) the viewer belongs to — used to
    /// scope deployment visibility by org. `#[serde(default)]` so tokens
    /// minted before this field deserialize as "no orgs".
    #[serde(default)]
    pub orgs: Vec<String>,
    /// True if the viewer is an admin of THIS fleet (the fleet owner, a
    /// member of the fleet-owner org, or a repo collaborator). Admins see
    /// the whole fleet; everyone else is scoped to deployments they own.
    #[serde(default)]
    pub is_fleet_admin: bool,
}

/// What `classify_user` learns about a freshly-authenticated GitHub user
/// relative to this fleet. Unlike the old `authorize_user` (which
/// rejected non-members), this admits any valid GitHub user and records
/// how to scope them — admins see all, others see only what they own.
struct Classification {
    is_fleet_admin: bool,
    orgs: Vec<String>,
}

/// Result of a device-flow poll. `Pending` while the user hasn't approved
/// in the browser yet; `Ready` carries the minted DD bearer for the client.
pub enum DevicePoll {
    Pending,
    Ready {
        token: String,
        exp: i64,
        login: String,
        is_fleet_admin: bool,
    },
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
        let class = classify_user(http, &token, owner, &user).await?;
        let session = self.new_session(owner, &user, class);
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

    fn new_session(&self, owner: &Principal, user: &GithubUser, class: Classification) -> Session {
        Session {
            login: user.login.clone(),
            user_id: user.id,
            exp: now_ts() + SESSION_TTL_SECS,
            owner_name: owner.name.clone(),
            owner_id: owner.id,
            owner_kind: owner.kind,
            orgs: class.orgs,
            is_fleet_admin: class.is_fleet_admin,
        }
    }

    /// Verify a DD-signed session token (used for both the `dd_session`
    /// cookie and native-client bearer — same HMAC, same shape). Checks
    /// signature, expiry, and that the token is bound to THIS fleet.
    fn verify_token(&self, owner: &Principal, token: &str) -> Option<Session> {
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

    pub fn verify_session(&self, owner: &Principal, headers: &HeaderMap) -> Option<Session> {
        let token = cookie_value(headers, SESSION_COOKIE)?;
        self.verify_token(owner, token)
    }

    /// Verify a human caller from either a native-client `Authorization:
    /// Bearer <dd-token>` (checked first) or the browser `dd_session`
    /// cookie. The fleet API accepts both; browser pages use
    /// `verify_session` via `require_browser_auth`.
    pub fn verify_human(&self, owner: &Principal, headers: &HeaderMap) -> Option<Session> {
        if let Some(tok) = bearer_token(headers) {
            if let Some(s) = self.verify_token(owner, tok) {
                return Some(s);
            }
        }
        self.verify_session(owner, headers)
    }

    /// GitHub OAuth **device flow** step 1 (for the native/iOS client):
    /// ask GitHub for a device + user code. Returns the JSON the client
    /// shows the user (`user_code`, `verification_uri`) plus the
    /// `device_code` it polls back with. Requires the GitHub App to have
    /// device flow enabled.
    pub async fn device_start(&self, http: &Client) -> Result<serde_json::Value> {
        let app = app_for_return_to(&self.broker_origin).unwrap_or_else(|_| "production".into());
        let (client_id, _) = self.client_for(&app)?;
        let resp = http
            .post("https://github.com/login/device/code")
            .header(header::ACCEPT, "application/json")
            .header(header::USER_AGENT, "devopsdefender")
            .json(&serde_json::json!({ "client_id": client_id, "scope": "read:org" }))
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(Error::Upstream(format!(
                "GitHub device/code returned {}",
                resp.status()
            )));
        }
        let body: serde_json::Value = resp.json().await?;
        Ok(serde_json::json!({
            "device_code": body.get("device_code").cloned().unwrap_or_default(),
            "user_code": body.get("user_code").cloned().unwrap_or_default(),
            "verification_uri": body.get("verification_uri").cloned().unwrap_or_default(),
            "expires_in": body.get("expires_in").cloned().unwrap_or_default(),
            "interval": body.get("interval").cloned().unwrap_or(serde_json::json!(5)),
        }))
    }

    /// Device flow step 2: poll GitHub with the `device_code`. While the
    /// user hasn't approved yet → `Pending`. On approval, fetch + classify
    /// the user and mint a DD bearer (same signed-`Session` the cookie
    /// uses) the client sends as `Authorization: Bearer`.
    pub async fn device_poll(
        &self,
        http: &Client,
        owner: &Principal,
        device_code: &str,
    ) -> Result<DevicePoll> {
        let app = app_for_return_to(&self.broker_origin).unwrap_or_else(|_| "production".into());
        let (client_id, client_secret) = self.client_for(&app)?;
        let resp = http
            .post("https://github.com/login/oauth/access_token")
            .header(header::ACCEPT, "application/json")
            .header(header::USER_AGENT, "devopsdefender")
            .json(&serde_json::json!({
                "client_id": client_id,
                "client_secret": client_secret,
                "device_code": device_code,
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            }))
            .send()
            .await?;
        let body: GithubTokenResponse = resp.json().await?;
        if let Some(err) = body.error.as_deref() {
            // Device flow signals progress via error codes, not HTTP status.
            return match err {
                "authorization_pending" | "slow_down" => Ok(DevicePoll::Pending),
                other => Err(Error::Upstream(format!("device flow: {other}"))),
            };
        }
        let token = body.access_token.ok_or(Error::Unauthorized)?;
        let user = fetch_user(http, &token).await?;
        let class = classify_user(http, &token, owner, &user).await?;
        let session = self.new_session(owner, &user, class);
        let bearer = sign(&self.cookie_secret, &session)?;
        Ok(DevicePoll::Ready {
            token: bearer,
            exp: session.exp,
            login: session.login,
            is_fleet_admin: session.is_fleet_admin,
        })
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

/// Extract a non-empty `Authorization: Bearer <token>` (native client).
fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let v = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    v.strip_prefix("Bearer ")
        .or_else(|| v.strip_prefix("bearer "))
        .map(str::trim)
        .filter(|t| !t.is_empty())
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

/// Classify a freshly-authenticated GitHub user against this fleet.
/// **Admits any valid GitHub user** (unlike the old reject-on-non-member
/// gate) and records how to scope them: `is_fleet_admin` for the fleet
/// owner / org member / repo collaborator, plus their org memberships for
/// per-org deployment scoping. The admin/orgs lookups fail **closed** (a
/// GitHub hiccup yields non-admin / no-orgs, never a spurious admin).
async fn classify_user(
    http: &Client,
    token: &str,
    owner: &Principal,
    user: &GithubUser,
) -> Result<Classification> {
    let is_fleet_admin = match owner.kind {
        PrincipalKind::User => user.id == owner.id,
        PrincipalKind::Org => {
            gh_ok(
                http,
                token,
                &format!("orgs/{}/public_members/{}", owner.name, user.login),
            )
            .await
        }
        PrincipalKind::Repo => gh_ok(http, token, &format!("repos/{}", owner.name)).await,
    };
    let orgs = fetch_user_orgs(http, token).await.unwrap_or_default();
    Ok(Classification {
        is_fleet_admin,
        orgs,
    })
}

/// `GET https://api.github.com/{path}` with the user token → did it 2xx?
/// Any transport error or non-2xx → `false` (fail closed).
async fn gh_ok(http: &Client, token: &str, path: &str) -> bool {
    http.get(format!("https://api.github.com/{path}"))
        .bearer_auth(token)
        .header(header::USER_AGENT, "devopsdefender")
        .send()
        .await
        .map(|r| r.status().is_success())
        .unwrap_or(false)
}

/// The viewer's GitHub org logins (lowercased), for org-scoped
/// visibility. Best-effort: errors → empty (the viewer just won't match
/// any org-owned deployment).
async fn fetch_user_orgs(http: &Client, token: &str) -> Result<Vec<String>> {
    let resp = http
        .get("https://api.github.com/user/orgs?per_page=100")
        .bearer_auth(token)
        .header(header::USER_AGENT, "devopsdefender")
        .send()
        .await?;
    if !resp.status().is_success() {
        return Ok(Vec::new());
    }
    let orgs: Vec<serde_json::Value> = resp.json().await?;
    Ok(orgs
        .iter()
        .filter_map(|o| o.get("login").and_then(|l| l.as_str()))
        .map(|s| s.to_lowercase())
        .collect())
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
