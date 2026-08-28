//! Release metadata selection and update staging paths.

use super::*;
use std::env;

pub(super) fn select_release(
    releases: &[Release],
    current: &str,
    channel: Channel,
    target_os: &str,
    target_arch: &str,
) -> Option<SelectedRelease> {
    let asset_name = format!(
        "doradus-{}-{}{}",
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

pub(super) fn normalized_version(value: &str) -> Option<String> {
    let value = value.trim().trim_start_matches('v');
    let value = value.split_once('+').map_or(value, |(version, _)| version);
    let value = value.split_once('-').map_or(value, |(version, _)| version);
    (!value.is_empty() && value.split('.').all(|part| part.parse::<u64>().is_ok()))
        .then(|| value.to_owned())
}

pub(super) fn compare_versions(left: &str, right: &str) -> Ordering {
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

pub(super) fn parse_checksum(body: &str, asset_name: &str) -> Result<String, String> {
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

pub(super) fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub(super) fn release_os() -> String {
    match env::consts::OS {
        "macos" => "darwin".to_owned(),
        other => other.to_owned(),
    }
}

pub(super) fn release_arch() -> String {
    match env::consts::ARCH {
        "aarch64" => "arm64".to_owned(),
        "x86_64" => "amd64".to_owned(),
        other => other.to_owned(),
    }
}

pub(super) fn update_staging_dir() -> PathBuf {
    if let Some(path) = env::var_os("DORADUS_UPDATE_DIR") {
        return PathBuf::from(path);
    }
    let cache = env::var_os("DORADUS_CACHE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    cache.join("doradus/updates")
}
