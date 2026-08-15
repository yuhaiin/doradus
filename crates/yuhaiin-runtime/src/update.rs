//! Rust-native software update service.
//!
//! The update endpoint is deliberately kept outside the proxy/data-plane
//! builder.  It only deals with release metadata, bounded downloads and an
//! atomic hand-off to the platform helper.  The HTTP client uses reqwest with
//! rustls and the RustCrypto provider; no native TLS library is required.

use futures_util::StreamExt;
use reqwest::Client;
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

#[derive(Debug, Clone)]
pub struct UpdateService {
    client: Client,
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
        // reqwest is built with rustls' no-provider feature.  Install the
        // RustCrypto provider once for this process; an already installed
        // provider is harmless when another runtime component initialized it.
        let _ = rustls_rustcrypto::provider().install_default();
        let client = Client::builder()
            .timeout(timeout)
            .user_agent(format!("yuhaiin-rust/{}", env!("CARGO_PKG_VERSION")))
            .build()
            .unwrap_or_else(|_| Client::new());
        Self {
            client,
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
        let response = self
            .client
            .get(&selected.asset_url)
            .send()
            .await
            .map_err(|error| format!("download update asset: {error}"))?
            .error_for_status()
            .map_err(|error| format!("download update asset: {error}"))?;
        let total = response.content_length().unwrap_or(selected.asset_size);
        let mut stream = response.bytes_stream();
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
            let response = self
                .client
                .get(&self.releases_url)
                .query(&[("per_page", MAX_RELEASES_PAGE), ("page", page)])
                .header("accept", "application/vnd.github+json")
                .header("cache-control", "no-cache")
                .send()
                .await
                .map_err(|error| format!("request releases: {error}"))?
                .error_for_status()
                .map_err(|error| format!("request releases: {error}"))?;
            let body = response
                .bytes()
                .await
                .map_err(|error| format!("read releases: {error}"))?;
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
        let body = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|error| format!("download checksums: {error}"))?
            .error_for_status()
            .map_err(|error| format!("download checksums: {error}"))?
            .text()
            .await
            .map_err(|error| format!("read checksums: {error}"))?;
        parse_checksum(&body, asset_name)
    }
}

impl Default for UpdateService {
    fn default() -> Self {
        Self::new()
    }
}

fn select_release(
    releases: &[Release],
    current: &str,
    channel: Channel,
    target_os: &str,
    target_arch: &str,
) -> Option<SelectedRelease> {
    let asset_name = format!(
        "yuhaiin-{}-{}{}",
        target_os,
        target_arch,
        if target_os == "windows" { ".exe" } else { "" }
    );
    let mut candidates = releases
        .iter()
        .filter_map(|release| {
            if release.draft || (channel == Channel::Stable && release.prerelease) {
                return None;
            }
            if channel == Channel::Beta && !release.prerelease {
                return None;
            }
            let version = match channel {
                Channel::Main => main_version(release),
                Channel::Stable | Channel::Beta => normalized_version(&release.tag),
            }?;
            if channel != Channel::Main
                && compare_versions(&version, &normalized_version(current)?) != Ordering::Greater
            {
                return None;
            }
            let asset = release
                .assets
                .iter()
                .find(|asset| asset.name == asset_name)?;
            let checksum = release
                .assets
                .iter()
                .find(|asset| asset.name == "checksums.txt")?;
            Some(SelectedRelease {
                tag: release.tag.clone(),
                version,
                prerelease: release.prerelease,
                release_url: release.html_url.clone(),
                notes: release.body.clone(),
                published_at: release.published_at.clone(),
                asset_name: asset.name.clone(),
                asset_url: asset.url.clone(),
                checksum_url: checksum.url.clone(),
                asset_size: asset.size,
            })
        })
        .collect::<Vec<_>>();
    if candidates.is_empty() {
        return None;
    }
    if channel == Channel::Main {
        candidates.sort_by(|a, b| b.published_at.cmp(&a.published_at));
    } else {
        candidates.sort_by(|a, b| compare_versions(&b.version, &a.version));
    }
    candidates.into_iter().next()
}

fn normalized_version(value: &str) -> Option<String> {
    let value = value.trim().trim_start_matches('v');
    let value = value.split_once('+').map_or(value, |(version, _)| version);
    let value = value.split_once('-').map_or(value, |(version, _)| version);
    (!value.is_empty() && value.split('.').all(|part| part.parse::<u64>().is_ok()))
        .then(|| value.to_owned())
}

fn compare_versions(left: &str, right: &str) -> Ordering {
    let mut left = left.split('.').map(|part| part.parse::<u64>().unwrap_or(0));
    let mut right = right
        .split('.')
        .map(|part| part.parse::<u64>().unwrap_or(0));
    for _ in 0..3 {
        match left.next().unwrap_or(0).cmp(&right.next().unwrap_or(0)) {
            Ordering::Equal => continue,
            ordering => return ordering,
        }
    }
    Ordering::Equal
}

fn main_version(release: &Release) -> Option<String> {
    release
        .name
        .strip_prefix("main-")
        .or_else(|| release.tag.strip_prefix("main-"))
        .map(ToOwned::to_owned)
}

fn parse_checksum(body: &str, asset_name: &str) -> Result<String, String> {
    for line in body.lines() {
        let mut fields = line.split_whitespace();
        let Some(hash) = fields.next() else { continue };
        let Some(name) = fields.next() else { continue };
        let name = name.trim_start_matches('*');
        if name == asset_name
            && hash.len() == 64
            && hash.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Ok(hash.to_ascii_lowercase());
        }
    }
    Err(format!("checksum for {asset_name:?} is missing"))
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn release_os() -> String {
    match env::consts::OS {
        "macos" => "darwin".to_owned(),
        other => other.to_owned(),
    }
}

fn release_arch() -> String {
    match env::consts::ARCH {
        "aarch64" => "arm64".to_owned(),
        "x86_64" => "amd64".to_owned(),
        other => other.to_owned(),
    }
}

fn update_staging_dir() -> PathBuf {
    if let Some(path) = env::var_os("YUHAIIN_UPDATE_DIR") {
        return PathBuf::from(path);
    }
    let cache = env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache")))
        .unwrap_or_else(|| PathBuf::from("."));
    cache.join("yuhaiin-rust/updates")
}

fn spawn_update_helper(staged: PathBuf) -> Result<(), std::io::Error> {
    #[cfg(windows)]
    {
        let target = env::current_exe()?;
        // The service executable stays open for its whole lifetime on
        // Windows. Copying it first gives the helper an image that can
        // survive stopping the service and replacing the installed binary.
        let helper = target.with_extension("update-helper.exe");
        let _ = std::fs::remove_file(&helper);
        std::fs::copy(&target, &helper)?;
        let mut command = std::process::Command::new(&helper);
        command.arg("update-helper").arg(&target).arg(staged);
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
        return command.spawn().map(|_| ());
    }

    #[cfg(not(windows))]
    {
        let target = env::current_exe()?;
        let mut command = std::process::Command::new(&target);
        command.arg("update-helper").arg(&target).arg(staged);
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
        command.spawn().map(|_| ())
    }
}

/// Replace an installed executable after the service has handed control to a
/// detached helper.  The old binary remains as a rollback file until the
/// service manager successfully restarts the service.
pub fn run_update_helper(target: &Path, staged: &Path) -> Result<(), String> {
    run_update_helper_with_hooks(
        target,
        staged,
        stop_platform_service,
        restart_platform_service,
    )
}

fn run_update_helper_with_hooks<FStop, FRestart>(
    target: &Path,
    staged: &Path,
    stop_service: FStop,
    restart_service: FRestart,
) -> Result<(), String>
where
    FStop: Fn() -> Result<(), String>,
    FRestart: Fn() -> Result<(), String>,
{
    let target = target
        .canonicalize()
        .map_err(|error| format!("resolve update target: {error}"))?;
    let staged = staged
        .canonicalize()
        .map_err(|error| format!("resolve staged update: {error}"))?;
    let replacement = target.with_extension("update-stage");
    let _ = std::fs::remove_file(&replacement);
    std::fs::copy(&staged, &replacement)
        .map_err(|error| format!("copy staged update beside executable: {error}"))?;
    #[cfg(unix)]
    if let Err(error) = set_executable(&replacement) {
        let _ = std::fs::remove_file(&replacement);
        return Err(format!("set staged executable permissions: {error}"));
    }
    if let Err(error) = stop_service() {
        // The replacement is only a temporary copy until the service has
        // stopped. Do not leave it beside the executable when the service
        // manager rejects the stop request; a later retry should start from
        // the original target/staged pair.
        let _ = std::fs::remove_file(&replacement);
        return Err(format!("stop updated service: {error}"));
    }
    let backup = target.with_extension("update-backup");
    let _ = std::fs::remove_file(&backup);
    std::fs::rename(&target, &backup).map_err(|error| {
        let _ = std::fs::remove_file(&replacement);
        let _ = restart_service();
        format!("backup current executable: {error}")
    })?;
    if let Err(error) = std::fs::rename(&replacement, &target) {
        let _ = std::fs::remove_file(&replacement);
        let _ = std::fs::rename(&backup, &target);
        let _ = restart_service();
        return Err(format!("install updated executable: {error}"));
    }
    #[cfg(unix)]
    if let Err(error) = set_executable(&target) {
        let _ = std::fs::remove_file(&target);
        let _ = std::fs::rename(&backup, &target);
        let _ = restart_service();
        return Err(format!("set executable permissions: {error}"));
    }
    if let Err(error) = restart_service() {
        let _ = std::fs::remove_file(&target);
        let _ = std::fs::rename(&backup, &target);
        let recovery = restart_service();
        return Err(match recovery {
            Ok(()) => format!("restart updated service: {error}"),
            Err(recovery) => {
                format!("restart updated service: {error}; recovery restart failed: {recovery}")
            }
        });
    }
    let _ = std::fs::remove_file(staged);
    // Keep the previous image so the native service rollback action can
    // restore the last successfully installed release. The next update
    // replaces this single backup atomically.
    #[cfg(windows)]
    {
        let helper = target.with_extension("update-helper.exe");
        let _ = std::fs::remove_file(helper);
    }
    Ok(())
}

fn stop_platform_service() -> Result<(), String> {
    if let Ok(command) = env::var("YUHAIIN_UPDATE_STOP_COMMAND") {
        return run_shell_command(&command, "stop updated service");
    }
    #[cfg(target_os = "windows")]
    {
        return windows_service_stop();
    }
    #[cfg(target_os = "macos")]
    {
        // The helper is detached from the service process. A failed bootout
        // therefore means the old image may still be running; fail closed
        // instead of replacing the executable under an active launchd job.
        let pid = macos_launchd_pid()?;
        run_command(
            "launchctl",
            &[
                "bootout",
                "system",
                "/Library/LaunchDaemons/com.asutorufa.yuhaiin.plist",
            ],
            "stop updated launchd service",
        )?;
        if let Some(pid) = pid {
            wait_for_macos_process_exit(pid)?;
        }
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    {
        return Ok(());
    }
    #[allow(unreachable_code)]
    Ok(())
}

#[cfg(any(target_os = "macos", test))]
fn parse_macos_launchd_pid(data: &[u8]) -> Option<i32> {
    for field in String::from_utf8_lossy(data).split(';') {
        let Some((key, value)) = field.split_once('=') else {
            continue;
        };
        if !key.trim().trim_matches('"').eq_ignore_ascii_case("pid") {
            continue;
        }
        let value = value.trim().trim_matches('"');
        if let Ok(pid) = value.parse::<i32>() {
            return Some(pid);
        }
    }
    None
}

#[cfg(target_os = "macos")]
fn macos_launchd_pid() -> Result<Option<i32>, String> {
    let output = std::process::Command::new("launchctl")
        .args(["list", "com.asutorufa.yuhaiin"])
        .output()
        .map_err(|error| format!("query updated launchd service: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "query updated launchd service exited with {}; {}{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(parse_macos_launchd_pid(&output.stdout))
}

#[cfg(target_os = "macos")]
fn wait_for_macos_process_exit(pid: i32) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let probe = std::process::Command::new("kill")
            .args(["-0", &pid.to_string()])
            .output()
            .map_err(|error| format!("check stopped launchd process {pid}: {error}"))?;
        if !probe.status.success() {
            let details = format!(
                "{}{}",
                String::from_utf8_lossy(&probe.stdout),
                String::from_utf8_lossy(&probe.stderr)
            );
            if details.to_ascii_lowercase().contains("no such process") {
                return Ok(());
            }
            return Err(format!(
                "check stopped launchd process {pid} exited with {}: {}",
                probe.status,
                details.trim()
            ));
        }
        if Instant::now() >= deadline {
            return Err(format!("timeout waiting for launchd process {pid} to stop"));
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

fn restart_platform_service() -> Result<(), String> {
    if let Ok(command) = env::var("YUHAIIN_UPDATE_RESTART_COMMAND") {
        return run_shell_command(&command, "restart updated service");
    }
    #[cfg(target_os = "windows")]
    {
        return windows_service_start();
    }
    #[cfg(target_os = "macos")]
    {
        run_command(
            "launchctl",
            &[
                "bootstrap",
                "system",
                "/Library/LaunchDaemons/com.asutorufa.yuhaiin.plist",
            ],
            "bootstrap updated launchd service",
        )?;
        return run_command(
            "launchctl",
            &["kickstart", "-kp", "system/com.asutorufa.yuhaiin"],
            "start updated launchd service",
        );
    }
    #[cfg(target_os = "linux")]
    {
        return run_command(
            "systemctl",
            &["restart", "yuhaiin.service"],
            "restart updated systemd service",
        );
    }
    #[allow(unreachable_code)]
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn run_command(program: &str, args: &[&str], action: &str) -> Result<(), String> {
    let status = std::process::Command::new(program)
        .args(args)
        .status()
        .map_err(|error| format!("{action}: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{action} exited with {status}"))
    }
}

fn run_shell_command(command: &str, action: &str) -> Result<(), String> {
    #[cfg(windows)]
    let mut process = {
        let mut process = std::process::Command::new("cmd.exe");
        process.args(["/D", "/C", command]);
        process
    };
    #[cfg(not(windows))]
    let mut process = {
        let mut process = std::process::Command::new("sh");
        process.args(["-c", command]);
        process
    };
    let status = process
        .status()
        .map_err(|error| format!("{action}: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{action} exited with {status}"))
    }
}

#[cfg(windows)]
fn windows_service() -> Result<windows_service::service::Service, String> {
    use windows_service::service::ServiceAccess;
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|error| format!("open Windows Service Control Manager: {error}"))?;
    manager
        .open_service(
            "yuhaiin",
            ServiceAccess::QUERY_STATUS | ServiceAccess::START | ServiceAccess::STOP,
        )
        .map_err(|error| format!("open Windows service yuhaiin: {error}"))
}

#[cfg(windows)]
fn windows_service_stop() -> Result<(), String> {
    use windows_service::service::ServiceState;
    let service = windows_service()?;
    let status = service
        .query_status()
        .map_err(|error| format!("query Windows service: {error}"))?;
    if status.current_state == ServiceState::Stopped {
        return Ok(());
    }
    if status.current_state != ServiceState::StopPending {
        service
            .stop()
            .map_err(|error| format!("stop Windows service: {error}"))?;
    }
    windows_wait_service_state(&service, ServiceState::Stopped)
}

#[cfg(windows)]
fn windows_service_start() -> Result<(), String> {
    use std::ffi::OsStr;
    use windows_service::service::ServiceState;
    let service = windows_service()?;
    let status = service
        .query_status()
        .map_err(|error| format!("query Windows service: {error}"))?;
    if status.current_state == ServiceState::Running {
        return Ok(());
    }
    if status.current_state != ServiceState::StartPending {
        service
            .start::<&OsStr>(&[])
            .map_err(|error| format!("start Windows service: {error}"))?;
    }
    windows_wait_service_state(&service, ServiceState::Running)
}

#[cfg(windows)]
fn windows_wait_service_state(
    service: &windows_service::service::Service,
    expected: windows_service::service::ServiceState,
) -> Result<(), String> {
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let status = service
            .query_status()
            .map_err(|error| format!("query Windows service state: {error}"))?;
        if status.current_state == expected {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err(format!(
                "timed out waiting for Windows service state {expected:?}; current={:?}",
                status.current_state
            ));
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

#[cfg(unix)]
fn set_executable(path: &Path) -> Result<(), std::io::Error> {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = std::fs::metadata(path)?.permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(path, permissions)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn update_test_dir(name: &str) -> PathBuf {
        let cache = env::var_os("XDG_CACHE_HOME")
            .map(PathBuf::from)
            .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache")))
            .unwrap_or_else(|| PathBuf::from("."));
        cache
            .join("yuhaiin-rust/update-tests")
            .join(format!("{name}-{}", std::process::id()))
    }

    fn write_update_fixture(name: &str) -> (PathBuf, PathBuf, PathBuf) {
        let root = update_test_dir(name);
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let target = root.join("yuhaiin");
        let staged = root.join("download");
        std::fs::write(&target, b"old executable\n").unwrap();
        std::fs::write(&staged, b"new executable\n").unwrap();
        (root, target, staged)
    }

    fn asset(name: &str) -> ReleaseAsset {
        ReleaseAsset {
            name: name.to_owned(),
            url: format!("https://example.invalid/{name}"),
            size: 7,
        }
    }

    fn release(tag: &str, prerelease: bool, published_at: &str) -> Release {
        Release {
            tag: tag.to_owned(),
            name: tag.to_owned(),
            prerelease,
            draft: false,
            html_url: format!("https://example.invalid/{tag}"),
            body: String::new(),
            published_at: published_at.to_owned(),
            assets: vec![asset("yuhaiin-linux-amd64"), asset("checksums.txt")],
        }
    }

    #[test]
    fn selects_highest_stable_release_with_matching_asset() {
        let releases = vec![
            release("v1.4.0", false, "2026-01-02"),
            release("v1.3.0", false, "2026-01-01"),
            release("v2.0.0-beta.1", true, "2026-01-03"),
        ];
        let selected =
            select_release(&releases, "v1.0.0", Channel::Stable, "linux", "amd64").unwrap();
        assert_eq!(selected.tag, "v1.4.0");
        assert!(!selected.prerelease);
    }

    #[test]
    fn beta_channel_does_not_select_stable_release() {
        let releases = vec![release("v1.4.0", false, "2026-01-02")];
        assert!(select_release(&releases, "v1.0.0", Channel::Beta, "linux", "amd64").is_none());
    }

    #[test]
    fn checksum_parser_accepts_gnu_and_bsd_style_filenames() {
        let body = "deadbeef\n";
        assert!(parse_checksum(body, "yuhaiin-linux-amd64").is_err());
        let hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert_eq!(
            parse_checksum(
                &format!("{hash}  yuhaiin-linux-amd64\n"),
                "yuhaiin-linux-amd64"
            )
            .unwrap(),
            hash
        );
        assert!(
            parse_checksum(
                &format!("SHA256 (yuhaiin-linux-amd64) = {hash}\n"),
                "yuhaiin-linux-amd64"
            )
            .is_err()
        );
    }

    #[test]
    fn version_comparison_ignores_v_prefix_and_build_metadata() {
        assert_eq!(normalized_version("v1.2.3+build"), Some("1.2.3".to_owned()));
        assert_eq!(compare_versions("1.2.4", "1.2.3"), Ordering::Greater);
        assert_eq!(compare_versions("1.2", "1.2.0"), Ordering::Equal);
    }

    #[test]
    fn parses_macos_launchd_pid_without_trusting_field_order_or_case() {
        assert_eq!(
            parse_macos_launchd_pid(br#""LastExitStatus" = 0; "PID" = 10287;"#),
            Some(10287)
        );
        assert_eq!(parse_macos_launchd_pid(br#""PID" = "not-a-pid";"#), None);
    }

    #[test]
    fn update_helper_installs_release_and_keeps_rollback_image() {
        let (root, target, staged) = write_update_fixture("success");
        let stop_calls = AtomicUsize::new(0);
        let restart_calls = AtomicUsize::new(0);

        run_update_helper_with_hooks(
            &target,
            &staged,
            || {
                stop_calls.fetch_add(1, AtomicOrdering::Relaxed);
                Ok(())
            },
            || {
                restart_calls.fetch_add(1, AtomicOrdering::Relaxed);
                Ok(())
            },
        )
        .unwrap();

        assert_eq!(std::fs::read(&target).unwrap(), b"new executable\n");
        assert_eq!(
            std::fs::read(target.with_extension("update-backup")).unwrap(),
            b"old executable\n"
        );
        assert!(!staged.exists());
        assert_eq!(stop_calls.load(AtomicOrdering::Relaxed), 1);
        assert_eq!(restart_calls.load(AtomicOrdering::Relaxed), 1);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn update_helper_restores_previous_release_when_restart_fails() {
        let (root, target, staged) = write_update_fixture("restart-failure");
        let restart_calls = AtomicUsize::new(0);

        let error = run_update_helper_with_hooks(
            &target,
            &staged,
            || Ok(()),
            || {
                if restart_calls.fetch_add(1, AtomicOrdering::Relaxed) == 0 {
                    Err("fixture restart failure".to_owned())
                } else {
                    Ok(())
                }
            },
        )
        .unwrap_err();

        assert!(error.contains("restart updated service: fixture restart failure"));
        assert_eq!(std::fs::read(&target).unwrap(), b"old executable\n");
        assert!(!target.with_extension("update-backup").exists());
        assert!(staged.exists(), "failed update remains staged for retry");
        assert_eq!(restart_calls.load(AtomicOrdering::Relaxed), 2);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn update_helper_cleans_replacement_when_service_stop_fails() {
        let (root, target, staged) = write_update_fixture("stop-failure");

        let error = run_update_helper_with_hooks(
            &target,
            &staged,
            || Err("fixture stop failure".to_owned()),
            || panic!("restart must not run when stop fails"),
        )
        .unwrap_err();

        assert_eq!(error, "stop updated service: fixture stop failure");
        assert_eq!(std::fs::read(&target).unwrap(), b"old executable\n");
        assert_eq!(std::fs::read(&staged).unwrap(), b"new executable\n");
        assert!(!target.with_extension("update-stage").exists());
        assert!(!target.with_extension("update-backup").exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn check_fetches_release_metadata_and_checksum_from_http_fixture() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let asset_name = format!("yuhaiin-{}-{}", release_os(), release_arch());
        let releases = serde_json::json!([{
            "tag_name": "v9.9.9",
            "name": "v9.9.9",
            "prerelease": false,
            "draft": false,
            "html_url": "https://example.invalid/v9.9.9",
            "body": "fixture release",
            "published_at": "2026-08-09T00:00:00Z",
            "assets": [
                {"name": asset_name, "browser_download_url": format!("http://{address}/asset"), "size": 1},
                {"name": "checksums.txt", "browser_download_url": format!("http://{address}/checksums.txt"), "size": hash.len() + 2}
            ]
        }]).to_string();
        let checksum = format!("{hash}  {asset_name}\n");
        let releases_for_server = releases.clone();
        let checksum_for_server = checksum.clone();
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                let mut buffer = [0_u8; 1024];
                loop {
                    let count = stream.read(&mut buffer).await.unwrap();
                    if count == 0 {
                        break;
                    }
                    request.extend_from_slice(&buffer[..count]);
                    if request.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                let body = if request
                    .windows(b"/checksums.txt".len())
                    .any(|window| window == b"/checksums.txt")
                {
                    checksum_for_server.as_bytes()
                } else {
                    releases_for_server.as_bytes()
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                stream.write_all(response.as_bytes()).await.unwrap();
                stream.write_all(body).await.unwrap();
            }
        });

        let mut service = UpdateService::with_releases_url(
            format!("http://{address}/releases"),
            Duration::from_secs(5),
        );
        service.current_version = "0.1.0".to_owned();
        let result = service.check("stable").await.unwrap();
        assert!(result.update_available);
        assert_eq!(result.target_tag, "v9.9.9");
        assert_eq!(result.asset_name, asset_name);
        assert_eq!(result.asset_sha256, hash);
        server.await.unwrap();
    }
}
