use reqwest::header::{ACCEPT, AUTHORIZATION, WWW_AUTHENTICATE};
use reqwest::{Client, Response, StatusCode};
use serde::Deserialize;
use std::collections::HashMap;

const OCI_MANIFEST_MEDIA_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";
const DOCKER_MANIFEST_MEDIA_TYPE: &str = "application/vnd.docker.distribution.manifest.v2+json";

#[derive(Debug, Clone)]
pub struct RegistryClient {
    http: Client,
}

#[derive(Debug, Clone)]
pub struct PulledImage {
    pub layers: Vec<Vec<u8>>,
    pub entrypoint: Vec<String>,
    pub cmd: Vec<String>,
    pub env: Vec<String>,
    pub working_dir: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ImageReference {
    scheme: String,
    registry: String,
    repository: String,
    reference: String,
}

#[derive(Debug, Deserialize)]
struct Manifest {
    #[serde(rename = "schemaVersion")]
    _schema_version: u32,
    config: Descriptor,
    layers: Vec<Descriptor>,
}

#[derive(Debug, Deserialize)]
struct Descriptor {
    digest: String,
}

#[derive(Debug, Deserialize)]
struct ImageConfig {
    config: Option<ConfigSection>,
    #[serde(default)]
    working_dir: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ConfigSection {
    #[serde(default)]
    #[serde(rename = "Entrypoint")]
    entrypoint: Option<Vec<String>>,
    #[serde(default)]
    #[serde(rename = "Cmd")]
    cmd: Option<Vec<String>>,
    #[serde(default)]
    #[serde(rename = "Env")]
    env: Option<Vec<String>>,
    #[serde(default)]
    #[serde(rename = "WorkingDir")]
    working_dir: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    token: Option<String>,
    access_token: Option<String>,
}

#[derive(Debug)]
struct WwwAuthenticate {
    realm: String,
    params: HashMap<String, String>,
}

impl RegistryClient {
    pub fn new() -> Result<Self, String> {
        let http = Client::builder()
            .build()
            .map_err(|e| format!("build registry client: {e}"))?;
        Ok(Self { http })
    }

    pub async fn pull_image(&self, image: &str) -> Result<PulledImage, String> {
        let image = ImageReference::parse(image)?;
        let manifest_url = format!(
            "{}://{}/v2/{}/manifests/{}",
            image.scheme, image.registry, image.repository, image.reference
        );

        let accept = manifest_accept_header();
        let manifest_bytes = self.get_with_auth(&manifest_url, Some(&accept)).await?;
        let manifest: Manifest = serde_json::from_slice(&manifest_bytes)
            .map_err(|e| format!("parse manifest for {image:?}: {e}"))?;

        let config_url = format!(
            "{}://{}/v2/{}/blobs/{}",
            image.scheme, image.registry, image.repository, manifest.config.digest
        );
        let config_bytes = self.get_with_auth(&config_url, None).await?;
        let config: ImageConfig = serde_json::from_slice(&config_bytes)
            .map_err(|e| format!("parse image config for {image:?}: {e}"))?;

        let mut layers = Vec::with_capacity(manifest.layers.len());
        for layer in manifest.layers {
            let blob_url = format!(
                "{}://{}/v2/{}/blobs/{}",
                image.scheme, image.registry, image.repository, layer.digest
            );
            layers.push(self.get_with_auth(&blob_url, None).await?);
        }

        let (entrypoint, cmd, env, working_dir) = match config.config {
            Some(config_section) => (
                config_section.entrypoint.unwrap_or_default(),
                config_section.cmd.unwrap_or_default(),
                config_section.env.unwrap_or_default(),
                config_section.working_dir.or(config.working_dir),
            ),
            None => (Vec::new(), Vec::new(), Vec::new(), config.working_dir),
        };

        Ok(PulledImage {
            layers,
            entrypoint,
            cmd,
            env,
            working_dir,
        })
    }

    async fn get_with_auth(&self, url: &str, accept: Option<&str>) -> Result<Vec<u8>, String> {
        let initial = self.send(url, accept, None).await?;

        let response = if initial.status() == StatusCode::UNAUTHORIZED {
            let challenge = initial
                .headers()
                .get(WWW_AUTHENTICATE)
                .ok_or_else(|| format!("401 from {url} without WWW-Authenticate header"))?
                .to_str()
                .map_err(|e| format!("parse WWW-Authenticate header for {url}: {e}"))?
                .to_string();

            let token = self.fetch_bearer_token(&challenge).await?;
            self.send(url, accept, Some(&token)).await?
        } else {
            initial
        };

        if !response.status().is_success() {
            return Err(format!(
                "GET {url} failed with status {}",
                response.status()
            ));
        }

        response
            .bytes()
            .await
            .map(|bytes| bytes.to_vec())
            .map_err(|e| format!("read response body for {url}: {e}"))
    }

    async fn send(
        &self,
        url: &str,
        accept: Option<&str>,
        bearer_token: Option<&str>,
    ) -> Result<Response, String> {
        let mut request = self.http.get(url);

        if let Some(value) = accept {
            request = request.header(ACCEPT, value);
        }
        if let Some(token) = bearer_token {
            request = request.header(AUTHORIZATION, format!("Bearer {token}"));
        }

        request.send().await.map_err(|e| format!("GET {url}: {e}"))
    }

    async fn fetch_bearer_token(&self, header_value: &str) -> Result<String, String> {
        let challenge = parse_www_authenticate(header_value)?;
        let mut request = self.http.get(&challenge.realm);

        for (key, value) in &challenge.params {
            request = request.query(&[(key, value)]);
        }

        let response = request
            .send()
            .await
            .map_err(|e| format!("GET token endpoint {}: {e}", challenge.realm))?;

        if !response.status().is_success() {
            return Err(format!(
                "token endpoint {} failed with status {}",
                challenge.realm,
                response.status()
            ));
        }

        let token: TokenResponse = response
            .json()
            .await
            .map_err(|e| format!("parse token response from {}: {e}", challenge.realm))?;

        token
            .token
            .or(token.access_token)
            .ok_or_else(|| format!("token endpoint {} returned no token", challenge.realm))
    }
}

fn manifest_accept_header() -> String {
    format!("{OCI_MANIFEST_MEDIA_TYPE}, {DOCKER_MANIFEST_MEDIA_TYPE}, application/json")
}

fn parse_www_authenticate(header: &str) -> Result<WwwAuthenticate, String> {
    let (scheme, rest) = header
        .split_once(' ')
        .ok_or_else(|| format!("unsupported WWW-Authenticate header: {header}"))?;

    if !scheme.eq_ignore_ascii_case("Bearer") {
        return Err(format!("unsupported auth scheme {scheme}"));
    }

    let mut realm = None;
    let mut params = HashMap::new();

    for field in rest.split(',') {
        let (raw_key, raw_value) = field
            .trim()
            .split_once('=')
            .ok_or_else(|| format!("invalid auth challenge component: {field}"))?;
        let value = raw_value.trim().trim_matches('"').to_string();

        if raw_key == "realm" {
            realm = Some(value);
        } else {
            params.insert(raw_key.to_string(), value);
        }
    }

    let realm = realm.ok_or_else(|| "auth challenge missing realm".to_string())?;
    Ok(WwwAuthenticate { realm, params })
}

impl ImageReference {
    fn parse(input: &str) -> Result<Self, String> {
        let (scheme, remainder) = if let Some(value) = input.strip_prefix("https://") {
            ("https".to_string(), value)
        } else if let Some(value) = input.strip_prefix("http://") {
            ("http".to_string(), value)
        } else {
            ("https".to_string(), input)
        };

        let (registry, repository_and_reference) = match remainder.split_once('/') {
            Some((first, rest))
                if first.contains('.') || first.contains(':') || first == "localhost" =>
            {
                (first.to_string(), rest.to_string())
            }
            _ => {
                let repository = if remainder.contains('/') {
                    remainder.to_string()
                } else {
                    format!("library/{remainder}")
                };
                ("registry-1.docker.io".to_string(), repository)
            }
        };

        let (repository, reference) =
            if let Some((repo, digest)) = repository_and_reference.rsplit_once('@') {
                (repo.to_string(), digest.to_string())
            } else if let Some((repo, tag)) = split_tag(&repository_and_reference) {
                (repo.to_string(), tag.to_string())
            } else {
                (repository_and_reference, "latest".to_string())
            };

        Ok(Self {
            scheme,
            registry,
            repository,
            reference,
        })
    }
}

fn split_tag(value: &str) -> Option<(&str, &str)> {
    let slash = value.rfind('/')?;
    let colon = value[slash + 1..].rfind(':')?;
    let offset = slash + 1 + colon;
    Some((&value[..offset], &value[offset + 1..]))
}

#[cfg(test)]
mod tests {
    use super::{parse_www_authenticate, ImageReference};

    #[test]
    fn parses_ghcr_reference() {
        let image = ImageReference::parse("ghcr.io/acme/app:1.2.3").unwrap();
        assert_eq!(image.scheme, "https");
        assert_eq!(image.registry, "ghcr.io");
        assert_eq!(image.repository, "acme/app");
        assert_eq!(image.reference, "1.2.3");
    }

    #[test]
    fn defaults_to_docker_hub_and_latest() {
        let image = ImageReference::parse("busybox").unwrap();
        assert_eq!(image.registry, "registry-1.docker.io");
        assert_eq!(image.repository, "library/busybox");
        assert_eq!(image.reference, "latest");
    }

    #[test]
    fn parses_bearer_challenge() {
        let challenge = parse_www_authenticate(
            "Bearer realm=\"https://ghcr.io/token\",service=\"ghcr.io\",scope=\"repository:acme/app:pull\"",
        )
        .unwrap();

        assert_eq!(challenge.realm, "https://ghcr.io/token");
        assert_eq!(
            challenge.params.get("service").map(String::as_str),
            Some("ghcr.io")
        );
        assert_eq!(
            challenge.params.get("scope").map(String::as_str),
            Some("repository:acme/app:pull")
        );
    }
}
