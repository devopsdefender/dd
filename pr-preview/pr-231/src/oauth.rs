//! CP-hosted GitHub OAuth login.
//!
//! Replaces the old "everything fronted by Cloudflare Access" model.
//! Three routes:
//!
//!   - `GET /login` — redirect to GitHub OAuth authorize URL.
//!   - `GET /oauth/callback` — exchange code → access token, fetch
//!     user + org membership, mint `dd_session` JWT cookie scoped to
//!     `.<fleet_domain>`.
//!   - `GET /logout` — clear cookie, redirect to `/login`.
//!
//! CSRF: a signed `dd_oauth_state` cookie carries the `state` value;
//! we compare it against the GitHub-returned `state` query.
//!
//! Org gate: the user must be a public-or-private member of `DD_OWNER`
//! (when kind=org or kind=user — repo principals fall back to the
//! `DD_ADMIN_EMAIL` allowlist).

use axum::{
    extract::{Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Redirect, Response},
};
use rand::RngCore;
use serde::Deserialize;

use crate::auth;
use crate::config::{Common, GhOauth};
use crate::gh_oidc::PrincipalKind;

const GH_AUTHORIZE: &str = "https://github.com/login/oauth/authorize";
const GH_TOKEN: &str = "https://github.com/login/oauth/access_token";
const GH_API: &str = "https://api.github.com";
const STATE_COOKIE: &str = "dd_oauth_state";

#[derive(Clone)]
pub struct OauthState {
    pub gh: GhOauth,
    pub fleet_jwt_secret: String,
    pub fleet_domain: String,
    pub fleet_owner_name: String,
    pub fleet_owner_kind: PrincipalKind,
    pub admin_email: String,
    /// Public origin of the CP, used to construct the OAuth callback
    /// URL (`{cp_origin}/oauth/callback`). Typically
    /// `https://app.<fleet_domain>`.
    pub cp_origin: String,
    pub http: reqwest::Client,
}

impl OauthState {
    pub fn from_cp(cp: &crate::config::Cp, common: &Common, http: reqwest::Client) -> Self {
        Self {
            gh: cp.gh_oauth.clone(),
            fleet_jwt_secret: common.fleet_jwt_secret.clone(),
            fleet_domain: cp.cf.domain.clone(),
            fleet_owner_name: common.owner.name.clone(),
            fleet_owner_kind: common.owner.kind,
            admin_email: cp.admin_email.clone(),
            cp_origin: format!("https://{}", cp.hostname),
            http,
        }
    }
}

pub fn random_state() -> String {
    let mut bytes = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// `GET /login` — set a `state` cookie and redirect to GitHub.
pub async fn login(State(s): State<OauthState>) -> Response {
    let state = random_state();
    let scope = "read:user read:org user:email";
    let redirect_uri = format!("{}/oauth/callback", s.cp_origin);
    let url = format!(
        "{GH_AUTHORIZE}?client_id={}&redirect_uri={}&scope={}&state={}",
        urlencoding::encode(&s.gh.client_id),
        urlencoding::encode(&redirect_uri),
        urlencoding::encode(scope),
        urlencoding::encode(&state),
    );
    let mut headers = HeaderMap::new();
    headers.insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&state_cookie(&state, &s.fleet_domain)).unwrap(),
    );
    (headers, Redirect::to(&url)).into_response()
}

#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    pub code: String,
    pub state: String,
}

/// `GET /oauth/callback` — exchange the code, verify org membership,
/// mint a session cookie.
pub async fn callback(
    State(s): State<OauthState>,
    headers: HeaderMap,
    Query(q): Query<CallbackQuery>,
) -> Response {
    // CSRF: state cookie must match query.
    let cookie_state = headers
        .get(header::COOKIE)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| {
            auth::parse_cookies(s)
                .find(|(k, _)| *k == STATE_COOKIE)
                .map(|(_, v)| v.to_string())
        });
    if cookie_state.as_deref() != Some(q.state.as_str()) {
        return (StatusCode::BAD_REQUEST, "csrf state mismatch").into_response();
    }

    // Exchange code → access token.
    let access_token = match exchange_code(&s, &q.code).await {
        Ok(t) => t,
        Err(e) => return (StatusCode::BAD_GATEWAY, format!("oauth exchange: {e}")).into_response(),
    };

    // Fetch user + emails.
    let user = match fetch_user(&s.http, &access_token).await {
        Ok(u) => u,
        Err(e) => return (StatusCode::BAD_GATEWAY, format!("user fetch: {e}")).into_response(),
    };
    let emails = fetch_emails(&s.http, &access_token)
        .await
        .unwrap_or_default();

    // Authorize: admin email allowlist OR org/user match.
    let authorized = if emails
        .iter()
        .any(|e| e.eq_ignore_ascii_case(&s.admin_email))
    {
        true
    } else {
        match s.fleet_owner_kind {
            PrincipalKind::User => user.login.eq_ignore_ascii_case(&s.fleet_owner_name),
            PrincipalKind::Org => {
                check_org_membership(&s.http, &access_token, &s.fleet_owner_name, &user.login)
                    .await
                    .unwrap_or(false)
            }
            PrincipalKind::Repo => false, // repo kind = CI only; humans must use admin_email
        }
    };
    if !authorized {
        return (
            StatusCode::FORBIDDEN,
            format!(
                "{} is not a member of {} (or is not the admin)",
                user.login, s.fleet_owner_name
            ),
        )
            .into_response();
    }

    // Mint session cookie.
    let token = match auth::mint(
        &s.fleet_jwt_secret,
        user.login.clone(),
        user.id,
        s.fleet_owner_name.clone(),
    ) {
        Ok(t) => t,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("mint: {e}")).into_response(),
    };
    let mut headers = HeaderMap::new();
    headers.append(
        header::SET_COOKIE,
        HeaderValue::from_str(&auth::set_cookie_header(&token, &s.fleet_domain)).unwrap(),
    );
    headers.append(
        header::SET_COOKIE,
        HeaderValue::from_str(&clear_state_cookie(&s.fleet_domain)).unwrap(),
    );
    (headers, Redirect::to("/")).into_response()
}

/// `GET /logout` — clear the cookie, redirect to /login.
pub async fn logout(State(s): State<OauthState>) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&auth::clear_cookie_header(&s.fleet_domain)).unwrap(),
    );
    (headers, Redirect::to("/login")).into_response()
}

// ─── GitHub API helpers ────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

async fn exchange_code(s: &OauthState, code: &str) -> Result<String, String> {
    let resp = s
        .http
        .post(GH_TOKEN)
        .header(header::ACCEPT, "application/json")
        .form(&[
            ("client_id", s.gh.client_id.as_str()),
            ("client_secret", s.gh.client_secret.as_str()),
            ("code", code),
            ("redirect_uri", &format!("{}/oauth/callback", s.cp_origin)),
        ])
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let body: TokenResponse = resp.json().await.map_err(|e| e.to_string())?;
    if let Some(err) = body.error {
        return Err(format!(
            "{err}: {}",
            body.error_description.unwrap_or_default()
        ));
    }
    body.access_token.ok_or_else(|| "no access_token".into())
}

#[derive(Debug, Deserialize)]
struct GhUser {
    login: String,
    id: u64,
}

async fn fetch_user(http: &reqwest::Client, token: &str) -> Result<GhUser, String> {
    let resp = http
        .get(format!("{GH_API}/user"))
        .bearer_auth(token)
        .header(header::USER_AGENT, "devopsdefender")
        .header(header::ACCEPT, "application/vnd.github+json")
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("user: {}", resp.status()));
    }
    resp.json().await.map_err(|e| e.to_string())
}

#[derive(Debug, Deserialize)]
struct GhEmail {
    email: String,
    verified: bool,
}

async fn fetch_emails(http: &reqwest::Client, token: &str) -> Result<Vec<String>, String> {
    let resp = http
        .get(format!("{GH_API}/user/emails"))
        .bearer_auth(token)
        .header(header::USER_AGENT, "devopsdefender")
        .header(header::ACCEPT, "application/vnd.github+json")
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("emails: {}", resp.status()));
    }
    let list: Vec<GhEmail> = resp.json().await.map_err(|e| e.to_string())?;
    Ok(list
        .into_iter()
        .filter(|e| e.verified)
        .map(|e| e.email)
        .collect())
}

/// Returns true if `login` is a member of `org`. GitHub returns 204
/// for "is member", 404 for "is not". 302 = needs additional scope.
async fn check_org_membership(
    http: &reqwest::Client,
    token: &str,
    org: &str,
    login: &str,
) -> Result<bool, String> {
    let resp = http
        .get(format!("{GH_API}/orgs/{org}/members/{login}"))
        .bearer_auth(token)
        .header(header::USER_AGENT, "devopsdefender")
        .header(header::ACCEPT, "application/vnd.github+json")
        .send()
        .await
        .map_err(|e| e.to_string())?;
    Ok(resp.status() == StatusCode::NO_CONTENT)
}

fn state_cookie(state: &str, fleet_domain: &str) -> String {
    format!(
        "{STATE_COOKIE}={state}; Domain=.{fleet_domain}; Path=/oauth; HttpOnly; Secure; SameSite=Lax; Max-Age=600"
    )
}

fn clear_state_cookie(fleet_domain: &str) -> String {
    format!(
        "{STATE_COOKIE}=; Domain=.{fleet_domain}; Path=/oauth; HttpOnly; Secure; SameSite=Lax; Max-Age=0"
    )
}
