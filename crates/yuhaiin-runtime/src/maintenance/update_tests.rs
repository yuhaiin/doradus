//! Runtime update service tests.

use super::*;
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn update_test_dir(name: &str) -> PathBuf {
    let cache = env::var_os("YUHAIIN_CACHE_DIR")
        .map(PathBuf::from)
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
    let selected = select_release(&releases, "v1.0.0", Channel::Stable, "linux", "amd64").unwrap();
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
