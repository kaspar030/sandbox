//! OCI Distribution client for pulling images from registries.
//!
//! Supports Docker Hub and any OCI-compliant registry with anonymous access.
//! Handles token-based authentication, multi-arch manifest resolution, and
//! parallel layer downloads.

use crate::error::{Error, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::sync::Arc;

/// A parsed OCI image reference.
#[derive(Debug, Clone)]
pub struct Reference {
    pub registry: String,
    pub repository: String,
    pub tag: String,
}

impl Reference {
    /// Parse an image reference string.
    ///
    /// Examples:
    /// - `alpine:latest` → `docker.io/library/alpine:latest`
    /// - `ubuntu:22.04` → `docker.io/library/ubuntu:22.04`
    /// - `ghcr.io/foo/bar:v1` → `ghcr.io/foo/bar:v1`
    /// - `myregistry.io/org/image` → `myregistry.io/org/image:latest`
    pub fn parse(reference: &str) -> Result<Self> {
        let reference = reference.trim();
        if reference.is_empty() {
            return Err(Error::Other("empty image reference".to_string()));
        }

        let (name, tag) = if let Some((n, t)) = reference.rsplit_once(':') {
            // Make sure the colon isn't part of a port (e.g., localhost:5000/image)
            if t.contains('/') {
                (reference, "latest")
            } else {
                (n, t)
            }
        } else {
            (reference, "latest")
        };

        let (registry, repository) =
            if name.contains('.') || name.contains(':') || name.starts_with("localhost") {
                // Has a dot or port or is localhost — treat first segment as registry
                if let Some((reg, repo)) = name.split_once('/') {
                    (reg.to_string(), repo.to_string())
                } else {
                    return Err(Error::Other(format!("invalid reference: {reference}")));
                }
            } else if name.contains('/') {
                // No dots but has slash — Docker Hub with explicit org
                ("docker.io".to_string(), name.to_string())
            } else {
                // Simple name — Docker Hub official image
                ("docker.io".to_string(), format!("library/{name}"))
            };

        Ok(Self {
            registry,
            repository,
            tag: tag.to_string(),
        })
    }

    /// The base name for local storage (e.g., "alpine" from "docker.io/library/alpine:latest").
    pub fn base_name(&self) -> String {
        self.repository
            .rsplit('/')
            .next()
            .unwrap_or(&self.repository)
            .to_string()
    }

    /// Registry URL base.
    fn api_base(&self) -> String {
        if self.registry == "docker.io" {
            "https://registry-1.docker.io".to_string()
        } else {
            format!("https://{}", self.registry)
        }
    }
}

impl std::fmt::Display for Reference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}:{}", self.registry, self.repository, self.tag)
    }
}

// --- OCI/Docker manifest types ---

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum ManifestResponse {
    Index(ManifestIndex),
    Single(ImageManifest),
}

#[derive(Debug, Deserialize)]
struct ManifestIndex {
    #[serde(default)]
    manifests: Vec<ManifestDescriptor>,
}

#[derive(Debug, Deserialize)]
struct ManifestDescriptor {
    #[serde(rename = "mediaType")]
    #[serde(default)]
    media_type: String,
    digest: String,
    #[serde(default)]
    platform: Option<Platform>,
}

#[derive(Debug, Deserialize)]
struct Platform {
    architecture: String,
    os: String,
}

#[derive(Debug, Deserialize)]
pub struct ImageManifest {
    pub config: Descriptor,
    pub layers: Vec<Descriptor>,
}

#[derive(Debug, Deserialize)]
pub struct Descriptor {
    #[serde(rename = "mediaType")]
    #[serde(default)]
    pub media_type: String,
    pub digest: String,
    #[serde(default)]
    pub size: u64,
}

/// OCI image config (subset of fields we care about).
#[derive(Debug, Clone, Deserialize)]
pub struct ImageConfig {
    #[serde(default)]
    pub config: Option<ContainerConfig>,
    #[serde(default)]
    pub rootfs: Option<RootFs>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ContainerConfig {
    #[serde(rename = "Entrypoint")]
    #[serde(default)]
    pub entrypoint: Option<Vec<String>>,
    #[serde(rename = "Cmd")]
    #[serde(default)]
    pub cmd: Option<Vec<String>>,
    #[serde(rename = "Env")]
    #[serde(default)]
    pub env: Option<Vec<String>>,
    #[serde(rename = "WorkingDir")]
    #[serde(default)]
    pub working_dir: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RootFs {
    #[serde(rename = "type")]
    #[serde(default)]
    pub fs_type: String,
    #[serde(default)]
    pub diff_ids: Vec<String>,
}

// --- Token auth ---

#[derive(Deserialize)]
struct TokenResponse {
    token: String,
}

/// Obtain a bearer token for anonymous access to a registry repository.
fn authenticate(reference: &Reference) -> Result<String> {
    let api_base = reference.api_base();

    // First, try GET /v2/ to see if we get a 401 with WWW-Authenticate
    let resp = match ureq::get(&format!("{api_base}/v2/")).call() {
        Ok(_resp) => return Ok(String::new()), // No auth needed
        Err(ureq::Error::Status(401, resp)) => resp,
        Err(ureq::Error::Status(code, _)) => {
            return Err(Error::Other(format!("registry returned HTTP {code}")));
        }
        Err(e) => {
            return Err(Error::Other(format!("HTTP error: {e}")));
        }
    };

    // Parse WWW-Authenticate header
    let www_auth = resp
        .header("www-authenticate")
        .ok_or_else(|| Error::Other("no WWW-Authenticate header in 401 response".to_string()))?
        .to_string();

    let realm = extract_auth_param(&www_auth, "realm")
        .ok_or_else(|| Error::Other("no realm in WWW-Authenticate".to_string()))?;
    let service = extract_auth_param(&www_auth, "service").unwrap_or_default();
    let scope = format!("repository:{}:pull", reference.repository);

    let mut url = format!("{realm}?scope={scope}");
    if !service.is_empty() {
        url = format!("{url}&service={service}");
    }

    let token_resp: TokenResponse = ureq::get(&url)
        .call()
        .map_err(|e| Error::Other(format!("token request failed: {e}")))?
        .into_json()
        .map_err(|e| Error::Other(format!("token parse error: {e}")))?;

    Ok(token_resp.token)
}

fn extract_auth_param(header: &str, key: &str) -> Option<String> {
    let pattern = format!("{key}=\"");
    let start = header.find(&pattern)? + pattern.len();
    let end = header[start..].find('"')? + start;
    Some(header[start..end].to_string())
}

// --- Manifest fetching ---

const ACCEPT_MANIFEST: &str = "application/vnd.oci.image.index.v1+json, \
    application/vnd.docker.distribution.manifest.list.v2+json, \
    application/vnd.oci.image.manifest.v1+json, \
    application/vnd.docker.distribution.manifest.v2+json";

/// Fetch and resolve the image manifest (handles fat manifests / OCI indexes).
pub fn fetch_manifest(reference: &Reference, token: &str) -> Result<ImageManifest> {
    let api_base = reference.api_base();
    let url = format!(
        "{api_base}/v2/{}/manifests/{}",
        reference.repository, reference.tag
    );

    let body = authed_get(&url, token)?;
    let response: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|e| Error::Other(format!("manifest parse error: {e}")))?;

    // Check if this is a manifest list / OCI index
    let schema_version = response.get("schemaVersion").and_then(|v| v.as_i64());
    let media_type = response
        .get("mediaType")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let is_index = media_type.contains("manifest.list")
        || media_type.contains("image.index")
        || (response.get("manifests").is_some() && schema_version == Some(2));

    if is_index {
        // Fat manifest — resolve to platform-specific manifest
        let index: ManifestIndex = serde_json::from_value(response)
            .map_err(|e| Error::Other(format!("manifest index parse error: {e}")))?;

        let target_arch = current_arch();
        let platform_manifest = index
            .manifests
            .iter()
            .find(|m| {
                m.platform
                    .as_ref()
                    .is_some_and(|p| p.architecture == target_arch && p.os == "linux")
            })
            .ok_or_else(|| {
                Error::Other(format!(
                    "no manifest for linux/{target_arch} in multi-arch image"
                ))
            })?;

        // Fetch the platform-specific manifest
        let platform_url = format!(
            "{api_base}/v2/{}/manifests/{}",
            reference.repository, platform_manifest.digest
        );
        let platform_body = authed_get(&platform_url, token)?;
        serde_json::from_slice(&platform_body)
            .map_err(|e| Error::Other(format!("platform manifest parse error: {e}")))
    } else {
        // Single-arch manifest
        serde_json::from_value(response)
            .map_err(|e| Error::Other(format!("manifest parse error: {e}")))
    }
}

/// Fetch the image config blob.
pub fn fetch_config(reference: &Reference, token: &str, digest: &str) -> Result<ImageConfig> {
    let api_base = reference.api_base();
    let url = format!("{api_base}/v2/{}/blobs/{digest}", reference.repository);
    let body = authed_get(&url, token)?;
    serde_json::from_slice(&body).map_err(|e| Error::Other(format!("config parse error: {e}")))
}

/// Download a single blob and verify its digest.
pub fn fetch_blob(reference: &Reference, token: &str, digest: &str) -> Result<Vec<u8>> {
    let api_base = reference.api_base();
    let url = format!("{api_base}/v2/{}/blobs/{digest}", reference.repository);
    let body = authed_get(&url, token)?;

    // Verify digest
    if let Some(expected) = digest.strip_prefix("sha256:") {
        let mut hasher = Sha256::new();
        hasher.update(&body);
        let actual = hex::encode(hasher.finalize());
        if actual != expected {
            return Err(Error::Other(format!(
                "digest mismatch: expected sha256:{expected}, got sha256:{actual}"
            )));
        }
    }

    Ok(body)
}

/// Download multiple blobs in parallel. Returns (index, blob) pairs.
///
/// `layers` is a list of (index, digest) pairs. `skip` contains indices to skip
/// (already cached). Downloads happen on a thread pool.
pub fn fetch_blobs_parallel(
    reference: &Reference,
    token: &str,
    layers: &[(usize, String)],
    skip: &std::collections::HashSet<usize>,
) -> Result<Vec<(usize, Vec<u8>)>> {
    let reference = Arc::new(reference.clone());
    let token = Arc::new(token.to_string());

    let to_download: Vec<_> = layers
        .iter()
        .filter(|(idx, _)| !skip.contains(idx))
        .cloned()
        .collect();

    if to_download.is_empty() {
        return Ok(Vec::new());
    }

    tracing::info!("downloading {} layer(s)", to_download.len());

    let handles: Vec<_> = to_download
        .into_iter()
        .map(|(idx, digest)| {
            let reference = Arc::clone(&reference);
            let token = Arc::clone(&token);
            std::thread::spawn(move || {
                tracing::debug!("downloading layer {idx}: {digest}");
                let blob = fetch_blob(&reference, &token, &digest)?;
                tracing::debug!("downloaded layer {idx}: {} bytes", blob.len());
                Ok((idx, blob))
            })
        })
        .collect();

    let mut results: Vec<(usize, Vec<u8>)> = Vec::new();
    for handle in handles {
        let result: Result<(usize, Vec<u8>)> = handle
            .join()
            .map_err(|_| Error::Other("download thread panicked".to_string()))?;
        results.push(result?);
    }

    // Sort by index so extraction can proceed in order
    results.sort_by_key(|(idx, _)| *idx);
    Ok(results)
}

/// Full pull: authenticate, fetch manifest, download layers.
pub struct PullResult {
    pub reference: Reference,
    pub manifest: ImageManifest,
    pub config: ImageConfig,
    /// (layer_index, blob_data) — only layers that weren't cached
    pub layers: Vec<(usize, Vec<u8>)>,
    /// Which layer indices were skipped (already cached)
    pub cached: std::collections::HashSet<usize>,
}

/// Pull an image: authenticate, fetch manifest + config, download uncached layers.
pub fn pull_image(
    reference: &Reference,
    cached_chain_ids: &std::collections::HashSet<usize>,
) -> Result<PullResult> {
    tracing::info!("pulling {reference}");

    // Step 1: Authenticate
    let token = authenticate(reference)?;
    tracing::debug!("authenticated with {}", reference.registry);

    // Step 2: Fetch manifest
    let manifest = fetch_manifest(reference, &token)?;
    tracing::info!(
        "manifest: {} layer(s), config: {}",
        manifest.layers.len(),
        manifest.config.digest
    );

    // Step 3: Fetch image config
    let config = fetch_config(reference, &token, &manifest.config.digest)?;

    // Step 4: Download uncached layers in parallel
    let layer_refs: Vec<(usize, String)> = manifest
        .layers
        .iter()
        .enumerate()
        .map(|(i, l)| (i, l.digest.clone()))
        .collect();

    let layers = fetch_blobs_parallel(reference, &token, &layer_refs, cached_chain_ids)?;

    Ok(PullResult {
        reference: reference.clone(),
        manifest,
        config,
        layers,
        cached: cached_chain_ids.clone(),
    })
}

// --- Helpers ---

fn authed_get(url: &str, token: &str) -> Result<Vec<u8>> {
    let mut req = ureq::get(url).set("Accept", ACCEPT_MANIFEST);

    if !token.is_empty() {
        req = req.set("Authorization", &format!("Bearer {token}"));
    }

    let resp = req
        .call()
        .map_err(|e| Error::Other(format!("HTTP GET {url} failed: {e}")))?;

    let mut body = Vec::new();
    resp.into_reader()
        .read_to_end(&mut body)
        .map_err(|e| Error::Other(format!("read body error: {e}")))?;
    Ok(body)
}

fn current_arch() -> String {
    match std::env::consts::ARCH {
        "x86_64" => "amd64".to_string(),
        "aarch64" => "arm64".to_string(),
        "arm" => "arm".to_string(),
        "riscv64" => "riscv64".to_string(),
        other => other.to_string(),
    }
}
