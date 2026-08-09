//! Shared process-level fixtures for runtime integration tests.
//!
//! The fixtures deliberately use loopback sockets and a cache-owned state
//! directory. `YUHAIIN_INTEGRATION_DIR` can point at a persistent directory
//! when a developer or Podman job wants to inspect/reuse the SQLite state.

use std::io::Read;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use yuhaiin_store::ConfigStore;

pub fn integration_dir(name: &str) -> PathBuf {
    if let Some(path) = std::env::var_os("YUHAIIN_INTEGRATION_DIR") {
        return PathBuf::from(path).join(name);
    }
    let cache = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache")))
        .unwrap_or_else(|| PathBuf::from(".cache"));
    cache
        .join("yuhaiin-rust")
        .join("integration")
        .join(name)
        .join(std::process::id().to_string())
}

pub async fn reserve_loopback() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    address
}

/// A small HTTP CONNECT proxy and target server used to prove that the Rust
/// service sends a flow through a configured outbound, rather than merely
/// connecting directly from the inbound listener.
pub struct ConnectFixture {
    pub target: SocketAddr,
    pub outbound: SocketAddr,
    pub connect_authorities: Arc<Mutex<Vec<String>>>,
    shutdown: watch::Sender<bool>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl ConnectFixture {
    pub async fn start() -> Self {
        let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = target_listener.local_addr().unwrap();
        let outbound_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let outbound = outbound_listener.local_addr().unwrap();
        let connect_authorities = Arc::new(Mutex::new(Vec::new()));
        let (shutdown, _) = watch::channel(false);

        let target_shutdown = shutdown.subscribe();
        let target_task = tokio::spawn(serve_target(target_listener, target_shutdown));
        let proxy_shutdown = shutdown.subscribe();
        let proxy_authorities = connect_authorities.clone();
        let proxy_task = tokio::spawn(serve_connect_proxy(
            outbound_listener,
            target_shutdown_for(proxy_shutdown),
            proxy_authorities,
        ));

        Self {
            target,
            outbound,
            connect_authorities,
            shutdown,
            tasks: vec![target_task, proxy_task],
        }
    }

    pub async fn shutdown(self) {
        let _ = self.shutdown.send(true);
        for task in self.tasks {
            let _ = task.await;
        }
    }
}

// Keep the proxy fixture's receiver independent from the target receiver. The
// helper makes the ownership at the two spawned task boundaries explicit.
fn target_shutdown_for(receiver: watch::Receiver<bool>) -> watch::Receiver<bool> {
    receiver
}

async fn serve_target(listener: TcpListener, mut shutdown: watch::Receiver<bool>) {
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let Ok((stream, _)) = accepted else { break };
                tokio::spawn(handle_target(stream));
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() { break; }
            }
        }
    }
}

async fn handle_target(mut stream: TcpStream) {
    let mut buffer = vec![0u8; 16 * 1024];
    let Ok(length) = stream.read(&mut buffer).await else {
        return;
    };
    if length == 0 {
        return;
    }
    if buffer[..length].starts_with(b"GET ") || buffer[..length].starts_with(b"HEAD ") {
        let _ = stream
            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await;
    } else {
        let _ = stream.write_all(&buffer[..length]).await;
    }
}

async fn serve_connect_proxy(
    listener: TcpListener,
    mut shutdown: watch::Receiver<bool>,
    authorities: Arc<Mutex<Vec<String>>>,
) {
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let Ok((stream, _)) = accepted else { break };
                let authorities = authorities.clone();
                tokio::spawn(async move { handle_connect(stream, authorities).await; });
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() { break; }
            }
        }
    }
}

async fn handle_connect(mut client: TcpStream, authorities: Arc<Mutex<Vec<String>>>) {
    let mut request = Vec::with_capacity(1024);
    let mut buffer = [0u8; 1024];
    loop {
        let Ok(length) = client.read(&mut buffer).await else {
            return;
        };
        if length == 0 {
            return;
        }
        request.extend_from_slice(&buffer[..length]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
        if request.len() > 16 * 1024 {
            return;
        }
    }
    let request = String::from_utf8_lossy(&request);
    let Some(authority) = request
        .lines()
        .next()
        .and_then(|line| line.strip_prefix("CONNECT "))
        .and_then(|line| line.split_whitespace().next())
    else {
        return;
    };
    authorities
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .push(authority.to_owned());
    let Ok(target) = authority.parse::<SocketAddr>() else {
        let Some(port) = authority
            .rsplit_once(':')
            .and_then(|(_, port)| port.parse().ok())
        else {
            return;
        };
        let Ok(target) = "127.0.0.1:0".parse::<SocketAddr>() else {
            return;
        };
        let target = SocketAddr::new(target.ip(), port);
        let Ok(mut upstream) = TcpStream::connect(target).await else {
            return;
        };
        if client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .is_err()
        {
            return;
        }
        let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
        return;
    };
    let Ok(mut upstream) = TcpStream::connect(target).await else {
        return;
    };
    if client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
        .is_err()
    {
        return;
    }
    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
}

pub async fn seed_empty_database(path: &Path) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    let store = ConfigStore::open(path).await.unwrap();
    drop(store);
}

pub async fn api_json(
    client: &reqwest::Client,
    base_url: &str,
    method: reqwest::Method,
    path: &str,
    body: Option<&Value>,
) -> Value {
    let request = client.request(method, format!("{base_url}{path}"));
    let response = match body {
        Some(body) => request.json(body).send().await.unwrap(),
        None => request.send().await.unwrap(),
    };
    let status = response.status();
    let text = response.text().await.unwrap();
    assert!(status.is_success(), "{path} returned {status}: {text}");
    serde_json::from_str(&text)
        .unwrap_or_else(|error| panic!("{path} returned invalid JSON: {error}: {text}"))
}

pub struct ServiceProcess {
    child: Child,
    pub client: reqwest::Client,
    pub base_url: String,
    diagnostics: Arc<Mutex<String>>,
}

impl ServiceProcess {
    pub async fn start(db: &Path) -> Self {
        let api_address = reserve_loopback().await;
        let diagnostics = Arc::new(Mutex::new(String::new()));
        let mut child = Command::new(env!("CARGO_BIN_EXE_yuhaiin"))
            .env("YUHAIIN_DB", db)
            .env("YUHAIIN_HTTP", api_address.to_string())
            .env("YUHAIIN_QUIET", "1")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        if let Some(mut stderr) = child.stderr.take() {
            let diagnostics_writer = diagnostics.clone();
            std::thread::spawn(move || {
                let mut output = String::new();
                let _ = stderr.read_to_string(&mut output);
                *diagnostics_writer
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()) = output;
            });
        }
        let _ = rustls_rustcrypto::provider().install_default();
        let client = reqwest::Client::builder().build().unwrap();
        let base_url = format!("http://{api_address}");
        let mut service = Self {
            child,
            client,
            base_url,
            diagnostics,
        };
        for _ in 0..120 {
            if let Some(status) = service.child.try_wait().unwrap() {
                panic!(
                    "yuhaiin exited before ready ({status}): {}",
                    service.diagnostics()
                );
            }
            if let Ok(response) = service
                .client
                .get(format!("{}/api/v2/info", service.base_url))
                .send()
                .await
            {
                if response.status().is_success() {
                    return service;
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("yuhaiin did not become ready: {}", service.diagnostics());
    }

    pub fn diagnostics(&self) -> String {
        self.diagnostics
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    pub async fn shutdown(mut self) {
        if self.child.try_wait().unwrap().is_none() {
            #[cfg(unix)]
            {
                let _ = Command::new("kill")
                    .args(["-TERM", &self.child.id().to_string()])
                    .status();
            }
            #[cfg(not(unix))]
            {
                let _ = self.child.kill();
            }
            for _ in 0..100 {
                if self.child.try_wait().unwrap().is_some() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}

impl Drop for ServiceProcess {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
        }
    }
}

pub async fn wait_for_connection(client: &reqwest::Client, base_url: &str) -> Value {
    for _ in 0..100 {
        let value = api_json(
            client,
            base_url,
            reqwest::Method::GET,
            "/api/v2/connections",
            None,
        )
        .await;
        if value["connections"]
            .as_array()
            .is_some_and(|items| !items.is_empty())
        {
            return value;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("connection did not become visible");
}

pub async fn configure_http_chain(
    service: &ServiceProcess,
    inbound: SocketAddr,
    outbound: SocketAddr,
) {
    let node = json!({
        "id":"http-out",
        "name":"HTTP test outbound",
        "group":"integration",
        "enabled":true,
        "chain":[
            {"type":"fixed","fixed":{"host":"127.0.0.1","port":outbound.port()}},
            {"type":"http","http":{"user":"","password":""}}
        ]
    });
    api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::POST,
        "/api/v2/nodes",
        Some(&node),
    )
    .await;
    api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::POST,
        "/api/v2/nodes/http-out/use",
        None,
    )
    .await;

    let inbound = json!({
        "id":"http-chain-in",
        "name":"HTTP chain inbound",
        "enabled":true,
        "network":{"type":"tcp_udp","tcp_udp":{"host":inbound.to_string(),"udp":"disabled"}},
        "transports":[{"type":"normal","normal":{}}],
        "protocol":{"type":"http","http":{"username":"","password":""}}
    });
    api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::POST,
        "/api/v2/inbounds",
        Some(&inbound),
    )
    .await;

    let rule = json!({
        "name":"proxy-example-test",
        "mode":"proxy",
        "match":{"domain":"example.test"},
        "tag":"integration"
    });
    api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::POST,
        "/api/v2/route/rules",
        Some(&rule),
    )
    .await;
}
