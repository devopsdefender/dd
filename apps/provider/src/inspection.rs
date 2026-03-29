use bollard::Docker;
use futures_util::TryStreamExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::info;

/// Result of inspecting a container image.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageReport {
    pub image: String,
    pub digest: Option<String>,
    pub layer_digests: Vec<String>,
    pub entrypoint: Vec<String>,
    pub cmd: Vec<String>,
    pub env: Vec<String>,
    pub exposed_ports: Vec<String>,
    pub labels: std::collections::HashMap<String, String>,
    pub measurement_hash: String,
}

/// Pull and inspect a container image, producing a measurement report.
pub async fn inspect_image(image: &str) -> Result<ImageReport, String> {
    let docker =
        Docker::connect_with_local_defaults().map_err(|e| format!("docker connect: {e}"))?;

    // Pull the image
    use bollard::image::CreateImageOptions;

    let opts = CreateImageOptions {
        from_image: image,
        ..Default::default()
    };
    docker
        .create_image(Some(opts), None, None)
        .try_collect::<Vec<_>>()
        .await
        .map_err(|e| format!("pull {image}: {e}"))?;
    info!(image, "pulled image");

    // Inspect
    let inspect = docker
        .inspect_image(image)
        .await
        .map_err(|e| format!("inspect {image}: {e}"))?;

    let digest = inspect
        .repo_digests
        .as_ref()
        .and_then(|d| d.first().cloned());

    let config = inspect.config.unwrap_or_default();

    let layer_digests: Vec<String> = inspect.root_fs.and_then(|fs| fs.layers).unwrap_or_default();

    let entrypoint = config.entrypoint.unwrap_or_default();
    let cmd = config.cmd.unwrap_or_default();
    let env = config.env.unwrap_or_default();

    let exposed_ports: Vec<String> = config
        .exposed_ports
        .map(|p| p.keys().cloned().collect())
        .unwrap_or_default();

    let labels = config.labels.unwrap_or_default();

    // Compute measurement hash: sorted layer digests + config hash
    let measurement_hash = compute_measurement_hash(&layer_digests, &entrypoint, &cmd, &env);

    Ok(ImageReport {
        image: image.to_string(),
        digest,
        layer_digests,
        entrypoint,
        cmd,
        env,
        exposed_ports,
        labels,
        measurement_hash,
    })
}

fn compute_measurement_hash(
    layers: &[String],
    entrypoint: &[String],
    cmd: &[String],
    env: &[String],
) -> String {
    let mut hasher = Sha256::new();

    // Hash layers in order
    for layer in layers {
        hasher.update(layer.as_bytes());
        hasher.update(b"\n");
    }

    // Hash config
    hasher.update(b"entrypoint:");
    for e in entrypoint {
        hasher.update(e.as_bytes());
        hasher.update(b"\0");
    }
    hasher.update(b"cmd:");
    for c in cmd {
        hasher.update(c.as_bytes());
        hasher.update(b"\0");
    }
    hasher.update(b"env:");
    let mut sorted_env: Vec<&String> = env.iter().collect();
    sorted_env.sort();
    for e in sorted_env {
        hasher.update(e.as_bytes());
        hasher.update(b"\0");
    }

    format!("sha256:{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn measurement_hash_is_deterministic() {
        let layers = vec!["sha256:aaa".into(), "sha256:bbb".into()];
        let ep = vec!["/bin/sh".into()];
        let cmd = vec!["-c".into(), "echo hi".into()];
        let env = vec!["PATH=/usr/bin".into(), "HOME=/root".into()];

        let h1 = compute_measurement_hash(&layers, &ep, &cmd, &env);
        let h2 = compute_measurement_hash(&layers, &ep, &cmd, &env);
        assert_eq!(h1, h2);
        assert!(h1.starts_with("sha256:"));
    }

    #[test]
    fn different_layers_different_hash() {
        let ep = vec![];
        let cmd = vec![];
        let env = vec![];

        let h1 = compute_measurement_hash(&["sha256:aaa".into()], &ep, &cmd, &env);
        let h2 = compute_measurement_hash(&["sha256:bbb".into()], &ep, &cmd, &env);
        assert_ne!(h1, h2);
    }
}
