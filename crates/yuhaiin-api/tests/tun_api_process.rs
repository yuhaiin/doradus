#![cfg(target_os = "linux")]
#![allow(dead_code)]

mod support;

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use serde_json::{Value, json};
use tokio::time::sleep;

use support::{api_json, integration_dir, reserve_loopback, seed_empty_database};

struct RuntimeChild {
    child: Option<Child>,
}

impl RuntimeChild {
    fn spawn(database: &std::path::Path, address: &str, diagnostics: &Arc<Mutex<String>>) -> Self {
        let binary = std::env::var_os("YUHAIIN_RUNTIME_BIN")
            .unwrap_or_else(|| env!("CARGO_BIN_EXE_yuhaiin").into());
        let mut child = Command::new(binary)
            .env("YUHAIIN_DB", database)
            .env("YUHAIIN_HTTP", address)
            .env("YUHAIIN_QUIET", "0")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stderr = child.stderr.take().unwrap();
        let diagnostics = Arc::clone(diagnostics);
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                diagnostics
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .push_str(&format!("{line}\n"));
            }
        });
        Self { child: Some(child) }
    }

    fn id(&self) -> u32 {
        self.child.as_ref().unwrap().id()
    }

    fn stop(mut self) {
        let mut child = self.child.take().unwrap();
        kill(Pid::from_raw(child.id() as i32), Signal::SIGTERM).unwrap();
        let status = child.wait().unwrap();
        assert!(status.success(), "runtime exited with {status}");
    }
}

impl Drop for RuntimeChild {
    fn drop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        let _ = kill(Pid::from_raw(child.id() as i32), Signal::SIGKILL);
        let _ = child.wait();
    }
}

fn device_is_present(name: &str) -> bool {
    std::fs::read_to_string("/proc/net/dev")
        .ok()
        .is_some_and(|contents| {
            contents.lines().any(|line| {
                line.split_once(':')
                    .is_some_and(|(interface, _)| interface.trim() == name)
            })
        })
}

async fn wait_for_health(
    client: &reqwest::Client,
    base_url: &str,
    diagnostics: &Arc<Mutex<String>>,
) {
    for _ in 0..160 {
        if client
            .get(format!("{base_url}/health"))
            .send()
            .await
            .is_ok_and(|response| response.status().is_success())
        {
            return;
        }
        sleep(Duration::from_millis(25)).await;
    }
    panic!(
        "runtime API did not become healthy; stderr={}",
        diagnostics
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    );
}

async fn wait_for_device(name: &str, expected: bool, diagnostics: &Arc<Mutex<String>>) {
    for _ in 0..240 {
        if device_is_present(name) == expected {
            return;
        }
        sleep(Duration::from_millis(25)).await;
    }
    panic!(
        "TUN device {name} did not reach present={expected}; stderr={}",
        diagnostics
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    );
}

async fn put_inbound(client: &reqwest::Client, base_url: &str, id: &str, config: &Value) -> Value {
    api_json(
        client,
        base_url,
        reqwest::Method::PUT,
        &format!("/api/v2/inbounds/{id}"),
        Some(config),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Podman /dev/net/tun and CAP_NET_ADMIN; run scripts/integration/tun-api-process.sh"]
async fn foreground_binary_api_toggle_changes_real_tun_device() {
    yuhaiin_platform::enable_loopback().unwrap();

    let root = integration_dir("tun-api-process");
    std::fs::create_dir_all(&root).unwrap();
    let database = root.join("state.sqlite");
    seed_empty_database(&database).await;
    let address = reserve_loopback().await;
    let base_url = format!("http://{address}");
    let _ = rustls_rustcrypto::provider().install_default();
    let client = reqwest::Client::new();
    let diagnostics = Arc::new(Mutex::new(String::new()));
    let runtime = RuntimeChild::spawn(&database, &address.to_string(), &diagnostics);
    let tun_id = "tun-api-process";
    // Linux IFNAMSIZ is 16 including the trailing NUL, so keep the test
    // interface name below the 15-byte kernel limit.
    let tun_name = format!("yrtun-ap-{}", runtime.id());
    let mut config = json!({
        "name": "TUN API process toggle",
        "enabled": false,
        "network": {"type": "empty", "empty": {}},
        "transports": [],
        "protocol": {
            "type": "tun",
            "tun": {
                "name": tun_name,
                "mtu": 1500,
                "portal": "10.42.0.1/24",
                "portalV6": "",
                "routes": [],
                "excludes": []
            }
        }
    });

    wait_for_health(&client, &base_url, &diagnostics).await;
    let saved = put_inbound(&client, &base_url, tun_id, &config).await;
    assert_eq!(saved["id"], tun_id);
    assert_eq!(saved["enabled"], false);
    wait_for_device(&tun_name, false, &diagnostics).await;

    config["enabled"] = json!(true);
    let enabled = put_inbound(&client, &base_url, tun_id, &config).await;
    assert_eq!(enabled["enabled"], true);
    wait_for_device(&tun_name, true, &diagnostics).await;

    let second_id = "tun-api-process-second";
    let second_name = format!("yrtun-b-{}", runtime.id());
    let mut second_config = config.clone();
    second_config["name"] = json!("TUN API process second toggle");
    second_config["protocol"]["tun"]["name"] = json!(second_name);
    second_config["enabled"] = json!(false);
    let saved_second = put_inbound(&client, &base_url, second_id, &second_config).await;
    assert_eq!(saved_second["enabled"], false);
    wait_for_device(&second_name, false, &diagnostics).await;

    second_config["enabled"] = json!(true);
    let enabled_second = put_inbound(&client, &base_url, second_id, &second_config).await;
    assert_eq!(enabled_second["enabled"], true);
    wait_for_device(&tun_name, true, &diagnostics).await;
    wait_for_device(&second_name, true, &diagnostics).await;

    second_config["enabled"] = json!(false);
    let disabled_second = put_inbound(&client, &base_url, second_id, &second_config).await;
    assert_eq!(disabled_second["enabled"], false);
    wait_for_device(&second_name, false, &diagnostics).await;
    wait_for_device(&tun_name, true, &diagnostics).await;

    config["enabled"] = json!(false);
    let disabled = put_inbound(&client, &base_url, tun_id, &config).await;
    assert_eq!(disabled["enabled"], false);
    wait_for_device(&tun_name, false, &diagnostics).await;

    config["enabled"] = json!(true);
    put_inbound(&client, &base_url, tun_id, &config).await;
    wait_for_device(&tun_name, true, &diagnostics).await;

    config["enabled"] = json!(false);
    put_inbound(&client, &base_url, tun_id, &config).await;
    wait_for_device(&tun_name, false, &diagnostics).await;

    runtime.stop();
}
