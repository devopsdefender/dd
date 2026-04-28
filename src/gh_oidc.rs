//! GitHub Actions OIDC verifier.
//!
//! GitHub Actions mints an OIDC JWT per job (issuer
//! `https://token.actions.githubusercontent.com`, JWKS at
//! `/.well-known/jwks`). A caller passes the token as
//! `Authorization: Bearer <jwt>`; the agent verifies the signature
//! against the cached JWKS and checks the required claims:
//!
//!   - `iss` matches the GitHub issuer
//!   - `aud` matches the configured audience (default `dd-agent`)
//!   - the principal in `DD_OWNER` / `DD_OWNER_ID` / `DD_OWNER_KIND`
//!     matches via [`Principal::matches`]
//!
//! A "principal" is one of three kinds — a GitHub user, a GitHub
//! organization, or a specific repository. User and org are
//! textually identical at the token layer (both produce the same
//! `repository_owner` claim); the kind is carried alongside only so
//! `cf.rs::human_policy` can decide whether to install a
//! `github-organization` CF Access include rule. A repo principal
//! gates on `repository` instead. All three flavors require the
//! corresponding numeric ID claim (`repository_owner_id` or
//! `repository_id`) to match too — name-only matching would let a
//! re-registered deleted login produce accepted tokens.

use std::collections::HashMap;
use std::sync::Arc;

use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::error::{Error, Result};

const ISSUER: &str = "https://token.actions.githubusercontent.com";
const JWKS_URL: &str = "https://token.actions.githubusercontent.com/.well-known/jwks";
const LEEWAY_SECS: u64 = 60;

const ALLOWED_ALGS: &[Algorithm] = &[
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::PS256,
    Algorithm::PS384,
    Algorithm::PS512,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PrincipalKind {
    User,
    Org,
    Repo,
}

impl PrincipalKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            PrincipalKind::User => "user",
            PrincipalKind::Org => "org",
            PrincipalKind::Repo => "repo",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "user" => Ok(PrincipalKind::User),
            "org" => Ok(PrincipalKind::Org),
            "repo" => Ok(PrincipalKind::Repo),
            other => Err(Error::Internal(format!(
                "invalid principal kind {other:?} (expected user|org|repo)"
            ))),
        }
    }
}

/// One of the three principal kinds the agent's `/deploy` verifier
/// accepts. See module docs for shape.
#[derive(Clone, Debug, Serialize)]
pub struct Principal {
    pub name: String,
    pub id: u64,
    pub kind: PrincipalKind,
}

impl Principal {
    /// Construct a Principal, validating that `name` and `kind`
    /// agree on shape (repo kinds need a slash; user/org kinds must
    /// not have one) and that `id` is non-zero.
    pub fn from_parts(name: String, id: u64, kind: PrincipalKind) -> Result<Self> {
        let has_slash = name.contains('/');
        let shape_ok = matches!(
            (kind, has_slash),
            (PrincipalKind::Repo, true)
                | (PrincipalKind::User, false)
                | (PrincipalKind::Org, false)
        );
        if !shape_ok {
            return Err(Error::Internal(format!(
                "principal shape mismatch: name={name:?} kind={} \
                 (kind=repo requires '/', kind=user|org rejects '/')",
                kind.as_str()
            )));
        }
        if name.is_empty() {
            return Err(Error::Internal("principal name must be non-empty".into()));
        }
        if id == 0 {
            return Err(Error::Internal(
                "principal id must be non-zero (defeats login-squat)".into(),
            ));
        }
        Ok(Self { name, id, kind })
    }

    /// True iff this principal authorizes the bearer of `c`.
    /// `kind=user|org` matches on `repository_owner`+`repository_owner_id`.
    /// `kind=repo` matches on `repository`+`repository_id`.
    /// A token missing the corresponding numeric claim fails — that's
    /// the squat-defense.
    pub fn matches(&self, c: &Claims) -> bool {
        match self.kind {
            PrincipalKind::User | PrincipalKind::Org => {
                c.repository_owner == self.name
                    && c.repository_owner_id != 0
                    && c.repository_owner_id == self.id
            }
            PrincipalKind::Repo => {
                c.repository == self.name && c.repository_id != 0 && c.repository_id == self.id
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Claims {
    pub exp: i64,
    pub iat: i64,
    pub iss: String,
    #[serde(default)]
    pub sub: String,
    #[serde(default)]
    pub repository: String,
    #[serde(default)]
    pub repository_id: u64,
    #[serde(default)]
    pub repository_owner: String,
    #[serde(default)]
    pub repository_owner_id: u64,
    #[serde(default)]
    pub ref_: String,
    #[serde(default)]
    pub workflow: String,
}

pub struct Verifier {
    owner: Principal,
    audience: String,
    http: Client,
    keys: RwLock<HashMap<String, DecodingKey>>,
}

impl Verifier {
    pub fn new(owner: Principal, audience: String) -> Arc<Self> {
        Arc::new(Self {
            owner,
            audience,
            http: Client::new(),
            keys: RwLock::new(HashMap::new()),
        })
    }

    /// Verify a JWT and require it match the fleet `owner`. Use this
    /// for endpoints only the fleet should reach — e.g. `/owner`,
    /// which re-assigns an agent to a tenant.
    pub async fn verify(&self, token: &str) -> Result<Claims> {
        self.verify_allowing(token, None).await
    }

    /// Verify a JWT and accept the caller if it matches EITHER the
    /// fleet `owner` OR the passed `extra` principal (typically the
    /// agent's runtime `agent_owner`, set by the s12e bot via
    /// `POST /owner` when a claim activates). Use this for
    /// workload-control endpoints (`/deploy`, `/exec`, `/logs`) that
    /// should accept either ops or the active tenant.
    pub async fn verify_allowing(
        &self,
        token: &str,
        extra: Option<&Principal>,
    ) -> Result<Claims> {
        let claims = self.decode_and_validate(token).await?;
        let ok = self.owner.matches(&claims) || extra.is_some_and(|p| p.matches(&claims));
        if !ok {
            return Err(Error::Unauthorized);
        }
        Ok(claims)
    }

    /// JWT decode + signature/issuer/audience validation, without
    /// any owner check. Extracted so `verify` and `verify_allowing`
    /// share identical crypto/claim-parsing behaviour and only
    /// differ in the final authorization gate.
    async fn decode_and_validate(&self, token: &str) -> Result<Claims> {
        let header = jsonwebtoken::decode_header(token)
            .map_err(|e| Error::BadRequest(format!("gh oidc header: {e}")))?;
        if !ALLOWED_ALGS.contains(&header.alg) {
            return Err(Error::BadRequest(format!(
                "gh oidc alg {:?} not allowed",
                header.alg
            )));
        }
        let kid = header
            .kid
            .ok_or_else(|| Error::BadRequest("gh oidc token missing kid".into()))?;

        let key = match self.lookup(&kid).await {
            Some(k) => k,
            None => {
                self.refresh().await?;
                self.lookup(&kid)
                    .await
                    .ok_or_else(|| Error::BadRequest(format!("gh oidc kid {kid} not in JWKS")))?
            }
        };

        let mut v = Validation::new(header.alg);
        v.set_issuer(&[ISSUER]);
        v.set_audience(&[self.audience.as_str()]);
        v.leeway = LEEWAY_SECS;
        v.set_required_spec_claims(&["exp", "iat", "iss", "aud"]);

        let data = jsonwebtoken::decode::<serde_json::Value>(token, &key, &v)
            .map_err(|e| Error::BadRequest(format!("gh oidc verify: {e}")))?;

        let raw = data.claims;
        Ok(Claims {
            exp: raw.get("exp").and_then(|x| x.as_i64()).unwrap_or(0),
            iat: raw.get("iat").and_then(|x| x.as_i64()).unwrap_or(0),
            iss: raw.get("iss").and_then(|x| x.as_str()).unwrap_or("").into(),
            sub: raw.get("sub").and_then(|x| x.as_str()).unwrap_or("").into(),
            repository: raw
                .get("repository")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .into(),
            repository_id: raw.get("repository_id").and_then(|x| x.as_u64()).unwrap_or(0),
            repository_owner: raw
                .get("repository_owner")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .into(),
            repository_owner_id: raw
                .get("repository_owner_id")
                .and_then(|x| x.as_u64())
                .unwrap_or(0),
            ref_: raw.get("ref").and_then(|x| x.as_str()).unwrap_or("").into(),
            workflow: raw
                .get("workflow")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .into(),
        })
    }

    async fn lookup(&self, kid: &str) -> Option<DecodingKey> {
        self.keys.read().await.get(kid).cloned()
    }

    async fn refresh(&self) -> Result<()> {
        let resp = self
            .http
            .get(JWKS_URL)
            .send()
            .await
            .map_err(|e| Error::Upstream(format!("GH JWKS fetch: {e}")))?;
        if !resp.status().is_success() {
            return Err(Error::Upstream(format!("GH JWKS: HTTP {}", resp.status())));
        }
        let jwks: jsonwebtoken::jwk::JwkSet = resp
            .json()
            .await
            .map_err(|e| Error::Upstream(format!("GH JWKS parse: {e}")))?;
        let mut map = HashMap::new();
        for jwk in &jwks.keys {
            let kid = match &jwk.common.key_id {
                Some(k) => k.clone(),
                None => continue,
            };
            if let Ok(dk) = DecodingKey::from_jwk(jwk) {
                map.insert(kid, dk);
            }
        }
        *self.keys.write().await = map;
        Ok(())
    }
}

#[cfg(test)]
impl Verifier {
    /// Test-only: pre-seed the JWKS cache with a single (kid, key)
    /// pair and skip the GitHub fetch. Lets unit tests round-trip a
    /// synthetic JWT through the same `verify_allowing` path the
    /// production code uses.
    pub fn for_test(
        owner: Principal,
        audience: String,
        kid: String,
        key: DecodingKey,
    ) -> Arc<Self> {
        let mut keys = HashMap::new();
        keys.insert(kid, key);
        Arc::new(Self {
            owner,
            audience,
            http: Client::new(),
            keys: RwLock::new(keys),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{EncodingKey, Header};
    use serde_json::json;

    // Static test RSA-2048 keypair generated once with
    //   openssl genrsa 2048 | openssl pkcs8 -topk8 -nocrypt
    // and the matching public-key SPKI form. No security implication —
    // used only inside this test module to round-trip JWTs through
    // the verifier without hitting the live GitHub JWKS endpoint.
    const TEST_PRIV_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDHX2vIc1wz+QRm
bB+Sus1FVeam4/XUJ+IiOFDvAQADa4rK/o16DdQUqSzdqDmML4HjTfj7Kz5z4kC5
+uAMvijEtBYcnURN+RC70GtvIRU3qoQLzt1QiNE/Hwm4yB+oh9DTcEdTZbwT19jd
FfQCsz9gmqujkIdnbQTv0bg+xqTts/hQLDL7ki8hrRq+mO17HLxTUWVQm0HEi9S9
Bdm1vpTWazM2FN92j1xy7vhb05c0wNILIvix+aMkoencTId3q7lItFe2VBlur3RY
TOirBmFNlNzpMDU7c8BbSzEEKweqWpiKUzQmzUSTbRZdgsuJnFtmQ7KNqTuzseOK
IT8HQk8XAgMBAAECggEAMqt9qSQoesz+4Uj5fUEcilKanC+zeofoYOoPJ68JYdUj
IRQwwKRjEh0s2ei3N3mbeTmH3c3PwYPvD1VDO/nYQqXCOON/SJHUPudpZoTx74PW
q2mXtbAP/grVXbD+2sYpvJL8jaV9d02UQBwkN8t2gAbPOHKy9wYuCwUx3kJ+CCsR
zjsABQto07Pbcg0t7XUpPyQ7zYwUuGbPzQP0Hm5NvR/PK7WGxOXLZYb2EPXzU5kw
/oUIFIHjoI3njoAxoDACJ4r/OpC6vt2lct0ffQySbfFpaFJmSp5QLIXs+CiZfwgV
+XnbeuykuSq5SRAbPbveyMWXZDAqa1bIDponLlaagQKBgQD3uPnNm5wiLJH++5/D
mOH+d9gkFk/7CPtgYjT41r1bKmzRkglUNk7xsOFmAJpkaP3VS1KI2iKXbL7MMA7F
VTt/cX+t/fnTatkGOdgaVP//CP+qlAVHXmM/rKSsWmfHq4qtcm5Tfb09jJhnD2b7
l/bWN7J9UHAXfDdqc6E5McwSqwKBgQDOCNwbG2uhwEjct0hZbZ39POVKTJ3epAZe
aMaITeBUywRXIp7PdK9SPPm4Wg4Y0+4yu4p+so2jKnYMwoAnclYfaVMNeiLcRtgV
06hpmXeDjRHDhS+fdjNBzoamIykIyuY4SZJrSMi3gY1Uv9L0X3ZbjO6ncL/s9FMS
8w3UByvVRQKBgHjJTawuKrQTDWDJqf3CRrdAEjiOVJMvrvoxCGkos42HIyYQUdIo
5Nc+CrkkpCM/ej0NDAJEckdpM6L1783SID+kxL++rZijaYx6md9FAMmGxrqSj/xb
joMWl/id4Cpgfy7RM/AryCEBs7HUtb8JOsb6w2IM3Yrl+1NBbCQqHrofAoGAF767
p0AcwnKHszBIXU4d1C6tekekNiGPPlgy8UiQXxVatbQeu2gGQKMYYJ+4WjIqlJw6
lOl9G13sZwIPhPxPYqVf1gDKfbqIctOG6Eywkm+yqWbzGxyjQaVMrV8F/qZrq/cG
seicgVGj+S12YYWS/XAbnR6IcAWkgV2TrWj6K0UCgYEArY8dMRksLbzwE8eHT2rQ
95ERpsq0oc84O+GDW/1n0AHiEDNwKn+WPwrLOgss4nR7P7WxdAHGvyc5CP95XWx4
AzloIKJp4ZseC5ai6mcyQLbG6cWPvGAfJdbjWXnyqlhwtl5nWObQ+OKfehuOU8Iy
JQyuinyZVi+WSfcc0EaVlOU=
-----END PRIVATE KEY-----
";
    const TEST_PUB_PEM: &str = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAx19ryHNcM/kEZmwfkrrN
RVXmpuP11CfiIjhQ7wEAA2uKyv6Neg3UFKks3ag5jC+B4034+ys+c+JAufrgDL4o
xLQWHJ1ETfkQu9BrbyEVN6qEC87dUIjRPx8JuMgfqIfQ03BHU2W8E9fY3RX0ArM/
YJqro5CHZ20E79G4Psak7bP4UCwy+5IvIa0avpjtexy8U1FlUJtBxIvUvQXZtb6U
1mszNhTfdo9ccu74W9OXNMDSCyL4sfmjJKHp3EyHd6u5SLRXtlQZbq90WEzoqwZh
TZTc6TA1O3PAW0sxBCsHqlqYilM0Js1Ek20WXYLLiZxbZkOyjak7s7HjiiE/B0JP
FwIDAQAB
-----END PUBLIC KEY-----
";
    const TEST_KID: &str = "test-kid";

    fn enc_key() -> EncodingKey {
        EncodingKey::from_rsa_pem(TEST_PRIV_PEM.as_bytes()).expect("test priv pem")
    }

    fn dec_key() -> DecodingKey {
        DecodingKey::from_rsa_pem(TEST_PUB_PEM.as_bytes()).expect("test pub pem")
    }

    fn now() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    /// Construct a synthetic Actions OIDC JWT signed with the test key.
    /// `extra` is merged into the payload after the standard claims so
    /// individual tests can override or add claims. None values delete.
    fn mint(extra: serde_json::Value) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(TEST_KID.into());
        let mut payload = json!({
            "iss": ISSUER,
            "aud": "dd-agent",
            "exp": now() + 600,
            "iat": now(),
            "sub": "repo:posix4e/dd-hyperliquid-recorder-example:ref:refs/heads/main",
        });
        if let (Some(p), Some(e)) = (payload.as_object_mut(), extra.as_object()) {
            for (k, v) in e {
                if v.is_null() {
                    p.remove(k);
                } else {
                    p.insert(k.clone(), v.clone());
                }
            }
        }
        jsonwebtoken::encode(&header, &payload, &enc_key()).expect("sign")
    }

    fn verifier(owner: Principal) -> Arc<Verifier> {
        Verifier::for_test(owner, "dd-agent".into(), TEST_KID.into(), dec_key())
    }

    fn org() -> Principal {
        Principal::from_parts("devopsdefender".into(), 67890123, PrincipalKind::Org).unwrap()
    }

    fn user() -> Principal {
        Principal::from_parts("posix4e".into(), 12345678, PrincipalKind::User).unwrap()
    }

    fn repo() -> Principal {
        Principal::from_parts(
            "posix4e/dd-hyperliquid-recorder-example".into(),
            884121234,
            PrincipalKind::Repo,
        )
        .unwrap()
    }

    // ── alg-rejection (preserved from before the refactor) ─────────

    #[tokio::test]
    async fn reject_alg_none() {
        let token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.e30.";
        let v = verifier(org());
        let err = v.verify(token).await.unwrap_err();
        assert!(matches!(err, Error::BadRequest(_)));
    }

    #[tokio::test]
    async fn reject_hs256() {
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.sig";
        let v = verifier(org());
        let err = v.verify(token).await.unwrap_err();
        match err {
            Error::BadRequest(m) => assert!(m.contains("alg")),
            e => panic!("expected BadRequest, got {e:?}"),
        }
    }

    #[tokio::test]
    async fn verify_allowing_rejects_bad_alg() {
        let token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.e30.";
        let v = verifier(org());
        let extra = user();
        let err = v.verify_allowing(token, Some(&extra)).await.unwrap_err();
        assert!(matches!(err, Error::BadRequest(_)));
    }

    // ── from_parts shape consistency ──────────────────────────────

    #[test]
    fn from_parts_rejects_repo_without_slash() {
        let err = Principal::from_parts("nopath".into(), 1, PrincipalKind::Repo).unwrap_err();
        assert!(matches!(err, Error::Internal(_)));
    }

    #[test]
    fn from_parts_rejects_user_with_slash() {
        let err = Principal::from_parts("a/b".into(), 1, PrincipalKind::User).unwrap_err();
        assert!(matches!(err, Error::Internal(_)));
    }

    #[test]
    fn from_parts_rejects_org_with_slash() {
        let err = Principal::from_parts("a/b".into(), 1, PrincipalKind::Org).unwrap_err();
        assert!(matches!(err, Error::Internal(_)));
    }

    #[test]
    fn from_parts_rejects_zero_id() {
        let err = Principal::from_parts("name".into(), 0, PrincipalKind::User).unwrap_err();
        assert!(matches!(err, Error::Internal(_)));
    }

    #[test]
    fn from_parts_rejects_empty_name() {
        let err = Principal::from_parts("".into(), 1, PrincipalKind::User).unwrap_err();
        assert!(matches!(err, Error::Internal(_)));
    }

    // ── positive paths ────────────────────────────────────────────

    #[tokio::test]
    async fn org_kind_accepts_matching_token() {
        let token = mint(json!({
            "repository": "devopsdefender/anything",
            "repository_id": 999_001u64,
            "repository_owner": "devopsdefender",
            "repository_owner_id": 67890123u64,
        }));
        let claims = verifier(org()).verify(&token).await.unwrap();
        assert_eq!(claims.repository_owner, "devopsdefender");
    }

    #[tokio::test]
    async fn user_kind_accepts_matching_token() {
        let token = mint(json!({
            "repository": "posix4e/dd-hyperliquid-recorder-example",
            "repository_id": 884121234u64,
            "repository_owner": "posix4e",
            "repository_owner_id": 12345678u64,
        }));
        let claims = verifier(user()).verify(&token).await.unwrap();
        assert_eq!(claims.repository_owner, "posix4e");
    }

    #[tokio::test]
    async fn repo_kind_accepts_matching_token() {
        let token = mint(json!({
            "repository": "posix4e/dd-hyperliquid-recorder-example",
            "repository_id": 884121234u64,
            "repository_owner": "posix4e",
            "repository_owner_id": 12345678u64,
        }));
        let claims = verifier(repo()).verify(&token).await.unwrap();
        assert_eq!(claims.repository, "posix4e/dd-hyperliquid-recorder-example");
    }

    // ── squat-defense / shape-mismatch rejections ─────────────────

    #[tokio::test]
    async fn org_kind_rejects_wrong_owner_id() {
        // Right name, wrong ID — exactly the squat-attack shape.
        let token = mint(json!({
            "repository_owner": "devopsdefender",
            "repository_owner_id": 99999999u64,
        }));
        let err = verifier(org()).verify(&token).await.unwrap_err();
        assert!(matches!(err, Error::Unauthorized));
    }

    #[tokio::test]
    async fn org_kind_rejects_missing_owner_id() {
        let token = mint(json!({
            "repository_owner": "devopsdefender",
            "repository_owner_id": null,
        }));
        let err = verifier(org()).verify(&token).await.unwrap_err();
        assert!(matches!(err, Error::Unauthorized));
    }

    #[tokio::test]
    async fn org_kind_rejects_wrong_owner_name() {
        let token = mint(json!({
            "repository_owner": "someone-else",
            "repository_owner_id": 67890123u64,
        }));
        let err = verifier(org()).verify(&token).await.unwrap_err();
        assert!(matches!(err, Error::Unauthorized));
    }

    #[tokio::test]
    async fn repo_kind_rejects_owner_only_token() {
        // Verifier wants repository_id; token has a matching owner
        // but a different repository_id (= a different repo under
        // the same owner). Strictness is the point.
        let token = mint(json!({
            "repository": "posix4e/some-other-repo",
            "repository_id": 222222u64,
            "repository_owner": "posix4e",
            "repository_owner_id": 12345678u64,
        }));
        let err = verifier(repo()).verify(&token).await.unwrap_err();
        assert!(matches!(err, Error::Unauthorized));
    }

    // ── extra principal ───────────────────────────────────────────

    #[tokio::test]
    async fn extra_principal_accepts_when_fleet_rejects() {
        let token = mint(json!({
            "repository_owner": "posix4e",
            "repository_owner_id": 12345678u64,
        }));
        // Fleet is an org; token is a user — but extra=user matches.
        let v = verifier(org());
        let claims = v.verify_allowing(&token, Some(&user())).await.unwrap();
        assert_eq!(claims.repository_owner, "posix4e");
    }

    #[tokio::test]
    async fn extra_principal_does_not_relax_squat_defense() {
        let token = mint(json!({
            "repository_owner": "posix4e",
            "repository_owner_id": 99999999u64,
        }));
        let v = verifier(org());
        let err = v
            .verify_allowing(&token, Some(&user()))
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Unauthorized));
    }
}
