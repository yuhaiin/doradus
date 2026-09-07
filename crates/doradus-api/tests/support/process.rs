use super::*;

pub async fn seed_empty_database(path: &Path) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    // The reusable Podman smoke scripts deliberately keep their cache mount
    // so logs and fixture directories survive a run. Their explicit reset
    // gate makes the database itself disposable and prevents a prior test's
    // selected node/inbound from changing a later scenario.
    if std::env::var("DORADUS_RESET_INTEGRATION_STATE").as_deref() == Ok("1") {
        for suffix in ["", "-wal", "-shm"] {
            let candidate = if suffix.is_empty() {
                path.to_owned()
            } else {
                PathBuf::from(format!("{}{}", path.display(), suffix))
            };
            let _ = std::fs::remove_file(candidate);
        }
    }
    let store = ConfigStore::open(path).await.unwrap();
    drop(store);
}

pub async fn api_json(
    client: &HttpClient,
    base_url: &str,
    method: Method,
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

/// Management mutations publish the snapshot before the inbound owner has
/// finished rebinding its listener set. Process-level flow fixtures wait for
/// that short latest-wins reload window before opening a protocol connection,
/// so a test does not connect to a socket that is about to be retired by an
/// already-acknowledged mutation.
pub(super) async fn settle_runtime_reload() {
    tokio::time::sleep(Duration::from_millis(100)).await;
}

pub struct ServiceProcess {
    child: Child,
    pub client: HttpClient,
    pub base_url: String,
    diagnostics: Arc<Mutex<String>>,
}

impl ServiceProcess {
    pub async fn start(db: &Path) -> Self {
        let diagnostics = Arc::new(Mutex::new(String::new()));
        let runtime_binary = std::env::var_os("DORADUS_RUNTIME_BIN")
            .unwrap_or_else(|| env!("CARGO_BIN_EXE_doradus").into());
        let mut child = Command::new(runtime_binary)
            .arg("-path")
            .arg(db.parent().unwrap_or_else(|| Path::new(".")))
            // Let the child own an ephemeral API port.  Reserving a port in
            // the test process and then dropping the listener before spawn
            // races with every other integration process that also allocates
            // loopback ports.  The startup notice below is the authoritative
            // hand-off for the port actually bound by the child.
            .args(["-host", "127.0.0.1:0"])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        if let Some(mut stderr) = child.stderr.take() {
            let diagnostics_writer = diagnostics.clone();
            std::thread::spawn(move || {
                let mut reader = BufReader::new(&mut stderr);
                let mut output = String::new();
                let mut line = String::new();
                while reader.read_line(&mut line).unwrap_or(0) != 0 {
                    output.push_str(&line);
                    // Keep diagnostics useful while bounding the memory held
                    // by a long-running child. The tail contains the latest
                    // startup/reload failure, which is what a timed-out
                    // integration test needs.
                    if output.len() > 64 * 1024 {
                        let trim_at = output.len() - 64 * 1024;
                        let trim_at = output
                            .char_indices()
                            .find(|(index, _)| *index >= trim_at)
                            .map(|(index, _)| index)
                            .unwrap_or(0);
                        output.drain(..trim_at);
                    }
                    *diagnostics_writer
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner()) = output.clone();
                    line.clear();
                }
            });
        }
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client = HttpClient::new();
        let mut service = Self {
            child,
            client,
            base_url: String::new(),
            diagnostics,
        };
        for _ in 0..120 {
            if let Some(status) = service.child.try_wait().unwrap() {
                panic!(
                    "doradus exited before ready ({status}): {}",
                    service.diagnostics()
                );
            }
            if service.base_url.is_empty()
                && let Some(address) = api_address_from_diagnostics(&service.diagnostics())
            {
                service.base_url = format!("http://{address}");
            }
            if service.base_url.is_empty() {
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
            if let Ok(response) = service
                .client
                .get(format!("{}/api/v2/info", service.base_url))
                .send()
                .await
                && response.status().is_success()
            {
                return service;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("doradus did not become ready: {}", service.diagnostics());
    }

    pub fn diagnostics(&self) -> String {
        self.diagnostics
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    pub fn pid(&self) -> u32 {
        self.child.id()
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

    /// Terminate the runtime without giving the persistence worker a
    /// shutdown opportunity. This deliberately models SIGKILL/force-stop so
    /// callers can verify SQLite WAL recovery and the next process restart.
    pub async fn force_stop(mut self) {
        self.force_stop_inner().await;
    }

    pub async fn force_stop_with_diagnostics(mut self) -> String {
        self.force_stop_inner().await;
        self.diagnostics()
    }

    async fn force_stop_inner(&mut self) {
        if self.child.try_wait().unwrap().is_none() {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}

fn api_address_from_diagnostics(diagnostics: &str) -> Option<SocketAddr> {
    diagnostics.lines().find_map(|line| {
        line.strip_prefix("doradus: HTTP API listening on http://")
            .and_then(|address| address.trim().parse().ok())
    })
}

impl Drop for ServiceProcess {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
        }
    }
}

pub async fn wait_for_connection(client: &HttpClient, base_url: &str) -> Value {
    // The reusable Podman smoke runs many real service processes in parallel;
    // under load the flow can be established before the monitor checkpoint
    // is visible, so keep the observation window independent of the normal
    // listener startup retry budget.
    let mut last = Value::Null;
    for _ in 0..500 {
        let value = api_json(client, base_url, Method::GET, "/api/v2/connections", None).await;
        last = value.clone();
        if value["connections"]
            .as_array()
            .is_some_and(|items| !items.is_empty())
        {
            return value;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("connection did not become visible; last response={last}");
}

/// Open a real HTTP CONNECT tunnel against an HTTP inbound. Keeping this
/// helper in the shared process fixture makes API/event tests exercise the
/// same inbound -> router -> outbound path as reload and protocol tests.
pub async fn open_http_tunnel(inbound: SocketAddr, authority: &str) -> TcpStream {
    let mut client = connect_loopback(inbound).await;
    client
        .write_all(format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes())
        .await
        .unwrap();

    let mut headers = Vec::new();
    let mut buffer = [0u8; 1024];
    while !headers.windows(4).any(|window| window == b"\r\n\r\n") {
        let length = client.read(&mut buffer).await.unwrap();
        assert!(length > 0, "HTTP inbound closed before CONNECT response");
        headers.extend_from_slice(&buffer[..length]);
    }
    assert!(String::from_utf8_lossy(&headers).starts_with("HTTP/1.1 200"));
    client
}

pub async fn echo_on_tunnel(client: &mut TcpStream, payload: &[u8]) {
    client.write_all(payload).await.unwrap();
    let mut echoed = vec![0u8; payload.len()];
    client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(echoed, payload);
}
