//! Rust-native software update service.
//!
//! The update endpoint is deliberately kept outside the proxy/data-plane
//! builder.  It only deals with release metadata, bounded downloads and an
//! atomic hand-off to the platform helper. The HTTP client uses Hyper with
//! rustls and its ring provider; no system TLS library such as OpenSSL is
//! required.

use bytes::Bytes;
use futures_util::StreamExt;
use http::{Method, Request, Uri, header};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use hyper_util::rt::TokioExecutor;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::env;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
#[cfg(target_os = "macos")]
use std::time::Instant;
use tokio::io::AsyncWriteExt;

const DEFAULT_RELEASES_URL: &str = "https://api.github.com/repos/yuhaiin/yuhaiin/releases";
const MAX_RELEASES_PAGE: usize = 100;
const MAX_RELEASE_BODY: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckResult {
    pub supported: bool,
    pub channel: String,
    pub current_version: String,
    pub target_version: String,
    pub target_tag: String,
    pub prerelease: bool,
    pub release_url: String,
    pub release_notes: String,
    pub published_at: String,
    pub asset_name: String,
    pub asset_sha256: String,
    pub update_available: bool,
    pub reason: String,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    pub running: bool,
    pub stage: String,
    pub progress: u8,
    pub bytes_downloaded: u64,
    pub total_bytes: u64,
    pub error: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    Stable,
    Beta,
    Main,
}

impl Channel {
    pub fn parse(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "beta" => Self::Beta,
            "main" => Self::Main,
            _ => Self::Stable,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::Beta => "beta",
            Self::Main => "main",
        }
    }
}

#[derive(Debug, Deserialize)]
struct Release {
    #[serde(default, rename = "tag_name")]
    tag: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    prerelease: bool,
    #[serde(default)]
    draft: bool,
    #[serde(default, rename = "html_url")]
    html_url: String,
    #[serde(default)]
    body: String,
    #[serde(default, rename = "published_at")]
    published_at: String,
    #[serde(default)]
    assets: Vec<ReleaseAsset>,
}

#[derive(Debug, Deserialize)]
struct ReleaseAsset {
    name: String,
    #[serde(rename = "browser_download_url")]
    url: String,
    #[serde(default)]
    size: u64,
}

#[derive(Debug, Clone)]
struct SelectedRelease {
    tag: String,
    version: String,
    prerelease: bool,
    release_url: String,
    notes: String,
    published_at: String,
    asset_name: String,
    asset_url: String,
    checksum_url: String,
    asset_size: u64,
}

type UpdateHttpClient = Client<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>>;

#[derive(Debug, Clone)]
pub struct UpdateService {
    client: UpdateHttpClient,
    timeout: Duration,
    releases_url: String,
    current_version: String,
    target_os: String,
    target_arch: String,
    status: Arc<Mutex<Status>>,
}

impl UpdateService {
    pub fn new() -> Self {
        Self::with_releases_url(
            env::var("YUHAIIN_UPDATE_RELEASES_URL")
                .unwrap_or_else(|_| DEFAULT_RELEASES_URL.to_owned()),
            Duration::from_secs(30 * 60),
        )
    }

    /// Construct a short-timeout client for API contract tests. The API crate
    /// is a separate package, so a dependency cannot see this method through
    /// its own `cfg(test)` build unless the constructor is part of the public
    /// runtime surface.
    #[doc(hidden)]
    pub fn test_stub() -> Self {
        Self::with_releases_url("http://127.0.0.1:9".to_owned(), Duration::from_millis(100))
    }

    fn with_releases_url(releases_url: String, timeout: Duration) -> Self {
        // Install the ring provider once for this process; an already
        // installed provider is harmless when another runtime component
        // initialized it.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let https = HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .build();
        let client = Client::builder(TokioExecutor::new()).build(https);
        Self {
            client,
            timeout,
            releases_url,
            current_version: env::var("YUHAIIN_VERSION")
                .unwrap_or_else(|_| env!("CARGO_PKG_VERSION").to_owned()),
            target_os: release_os(),
            target_arch: release_arch(),
            status: Arc::new(Mutex::new(Status {
                // Go's zero-value update.Status has an empty stage before the
                // first check/apply operation.
                stage: String::new(),
                ..Status::default()
            })),
        }
    }

    pub fn status(&self) -> Status {
        self.status
            .lock()
            .expect("update status mutex poisoned")
            .clone()
    }

    fn request(
        &self,
        method: Method,
        url: &str,
        headers: &[(&str, &str)],
        body: Bytes,
    ) -> Result<Request<Full<Bytes>>, String> {
        let uri = url
            .parse::<Uri>()
            .map_err(|error| format!("invalid update URL: {error}"))?;
        let mut builder = Request::builder().method(method).uri(uri).header(
            header::USER_AGENT,
            format!("yuhaiin-rust/{}", env!("CARGO_PKG_VERSION")),
        );
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        builder
            .body(Full::new(body))
            .map_err(|error| format!("build update request: {error}"))
    }

    async fn send(
        &self,
        request: Request<Full<Bytes>>,
        label: &str,
    ) -> Result<hyper::Response<Incoming>, String> {
        tokio::time::timeout(self.timeout, self.client.request(request))
            .await
            .map_err(|_| format!("{label}: request timed out"))?
            .map_err(|error| format!("{label}: {error}"))
    }

    fn ensure_success(
        response: hyper::Response<Incoming>,
        label: &str,
    ) -> Result<hyper::Response<Incoming>, String> {
        if response.status().is_success() {
            Ok(response)
        } else {
            Err(format!("{label}: HTTP {}", response.status()))
        }
    }

    pub async fn check(&self, channel: &str) -> Result<CheckResult, String> {
        let channel = Channel::parse(channel);
        let mut result = CheckResult {
            supported: true,
            channel: channel.as_str().to_owned(),
            current_version: self.current_version.clone(),
            target_version: String::new(),
            target_tag: String::new(),
            prerelease: false,
            release_url: String::new(),
            release_notes: String::new(),
            published_at: String::new(),
            asset_name: String::new(),
            asset_sha256: String::new(),
            update_available: false,
            reason: String::new(),
        };
        let releases = self.releases().await?;
        let Some(selected) = select_release(
            &releases,
            &self.current_version,
            channel,
            &self.target_os,
            &self.target_arch,
        ) else {
            result.reason = "no newer release found for this platform".to_owned();
            return Ok(result);
        };
        let checksum = self
            .download_checksum(&selected.checksum_url, &selected.asset_name)
            .await?;
        result.target_version = selected.version;
        result.target_tag = selected.tag;
        result.prerelease = selected.prerelease;
        result.release_url = selected.release_url;
        result.release_notes = selected.notes;
        result.published_at = selected.published_at;
        result.asset_name = selected.asset_name;
        result.asset_sha256 = checksum;
        result.update_available = true;
        Ok(result)
    }

    pub async fn apply(&self, channel: &str, target_tag: &str) -> Result<(), String> {
        if target_tag.trim().is_empty() {
            return Err("target tag is required".to_owned());
        }
        {
            let mut status = self.status.lock().expect("update status mutex poisoned");
            if status.running {
                return Err("an update is already running".to_owned());
            }
            *status = Status {
                running: true,
                stage: "preparing".to_owned(),
                ..Status::default()
            };
        }

        let result = self.apply_inner(channel, target_tag).await;
        let mut status = self.status.lock().expect("update status mutex poisoned");
        status.running = false;
        match &result {
            Ok(()) => {
                status.stage = "completed".to_owned();
                status.progress = 100;
            }
            Err(error) => {
                status.stage = "error".to_owned();
                status.error = error.clone();
            }
        }
        result
    }

    async fn apply_inner(&self, channel: &str, target_tag: &str) -> Result<(), String> {
        let channel = Channel::parse(channel);
        let releases = self.releases().await?;
        let selected = select_release(
            &releases,
            &self.current_version,
            channel,
            &self.target_os,
            &self.target_arch,
        )
        .filter(|release| release.tag == target_tag)
        .ok_or_else(|| "requested release is no longer available".to_owned())?;
        let checksum = self
            .download_checksum(&selected.checksum_url, &selected.asset_name)
            .await?;
        let staging_dir = update_staging_dir();
        tokio::fs::create_dir_all(&staging_dir)
            .await
            .map_err(|error| format!("create update staging directory: {error}"))?;
        let staged = staging_dir.join(format!("{}-{}", env!("CARGO_PKG_NAME"), selected.tag));
        let _ = tokio::fs::remove_file(&staged).await;
        self.set_progress("downloading", 0, selected.asset_size);
        let request = self.request(Method::GET, &selected.asset_url, &[], Bytes::new())?;
        let response = Self::ensure_success(
            self.send(request, "download update asset").await?,
            "download update asset",
        )?;
        let total = response
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(selected.asset_size);
        let mut stream = response.into_body().into_data_stream();
        let mut file = tokio::fs::File::create(&staged)
            .await
            .map_err(|error| format!("create staged update: {error}"))?;
        let mut hasher = Sha256::new();
        let mut downloaded = 0_u64;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|error| format!("read update asset: {error}"))?;
            file.write_all(&chunk)
                .await
                .map_err(|error| format!("write staged update: {error}"))?;
            hasher.update(&chunk);
            downloaded = downloaded.saturating_add(chunk.len() as u64);
            self.set_progress("downloading", downloaded, total);
        }
        file.flush()
            .await
            .map_err(|error| format!("flush staged update: {error}"))?;
        drop(file);
        self.set_progress("verifying", downloaded, total);
        let actual = hex_lower(&hasher.finalize());
        if actual != checksum {
            let _ = tokio::fs::remove_file(&staged).await;
            return Err(format!("checksum mismatch: got {actual} want {checksum}"));
        }
        self.set_progress("installing", downloaded, total);
        spawn_update_helper(staged).map_err(|error| error.to_string())
    }

    fn set_progress(&self, stage: &str, downloaded: u64, total: u64) {
        let mut status = self.status.lock().expect("update status mutex poisoned");
        status.stage = stage.to_owned();
        status.bytes_downloaded = downloaded;
        status.total_bytes = total;
        status.progress = if total == 0 {
            0
        } else {
            downloaded
                .saturating_mul(100)
                .checked_div(total)
                .unwrap_or(0)
                .min(100) as u8
        };
    }

    async fn releases(&self) -> Result<Vec<Release>, String> {
        let mut all = Vec::new();
        for page in 1.. {
            let mut url = url::Url::parse(&self.releases_url)
                .map_err(|error| format!("invalid releases URL: {error}"))?;
            url.query_pairs_mut()
                .append_pair("per_page", &MAX_RELEASES_PAGE.to_string())
                .append_pair("page", &page.to_string());
            let request = self.request(
                Method::GET,
                url.as_str(),
                &[
                    ("accept", "application/vnd.github+json"),
                    ("cache-control", "no-cache"),
                ],
                Bytes::new(),
            )?;
            let response = Self::ensure_success(
                self.send(request, "request releases").await?,
                "request releases",
            )?;
            let body = response
                .into_body()
                .collect()
                .await
                .map_err(|error| format!("read releases: {error}"))?
                .to_bytes();
            if body.len() > MAX_RELEASE_BODY {
                return Err("release metadata is too large".to_owned());
            }
            let page_releases: Vec<Release> = serde_json::from_slice(&body)
                .map_err(|error| format!("decode releases: {error}"))?;
            let count = page_releases.len();
            all.extend(page_releases);
            if count < MAX_RELEASES_PAGE {
                return Ok(all);
            }
        }
        unreachable!("release page loop always returns")
    }

    async fn download_checksum(&self, url: &str, asset_name: &str) -> Result<String, String> {
        let request = self.request(Method::GET, url, &[], Bytes::new())?;
        let response = Self::ensure_success(
            self.send(request, "download checksums").await?,
            "download checksums",
        )?;
        let body = response
            .into_body()
            .collect()
            .await
            .map_err(|error| format!("read checksums: {error}"))?
            .to_bytes();
        let body =
            std::str::from_utf8(&body).map_err(|error| format!("decode checksums: {error}"))?;
        parse_checksum(body, asset_name)
    }
}

impl Default for UpdateService {
    fn default() -> Self {
        Self::new()
    }
}

#[path = "update_platform.rs"]
mod update_platform;
#[path = "update_release.rs"]
mod update_release;

use update_platform::spawn_update_helper;
use update_release::{
    hex_lower, parse_checksum, release_arch, release_os, select_release, update_staging_dir,
};

pub use update_platform::run_update_helper;

#[cfg(test)]
use update_platform::{parse_macos_launchd_pid, run_update_helper_with_hooks};
#[cfg(test)]
use update_release::{compare_versions, normalized_version};

#[cfg(test)]
#[path = "update_tests.rs"]
mod tests;
