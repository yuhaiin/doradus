use super::*;

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

/// A minimal no-auth SOCKS5 proxy fixture. It records the address form sent by
/// the runtime and maps domain destinations to the loopback echo target so
/// the integration test proves proxy-side DNS framing without host DNS.
pub struct Socks5Fixture {
    pub target: SocketAddr,
    pub outbound: SocketAddr,
    pub destinations: Arc<Mutex<Vec<String>>>,
    shutdown: watch::Sender<bool>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

#[derive(Clone, Copy)]
pub enum H2FinalProtocol {
    Http,
    Socks5,
}

/// A prior-knowledge HTTP/2 server with an HTTP CONNECT or SOCKS5 protocol
/// endpoint behind each CONNECT stream. It exercises the same composition
/// that a configured Rust chain uses: fixed -> HTTP/2 -> final protocol.
pub struct H2ProtocolFixture {
    pub outbound: SocketAddr,
    shutdown: watch::Sender<bool>,
    server_task: tokio::task::JoinHandle<()>,
}

impl H2ProtocolFixture {
    pub async fn start(protocol: H2FinalProtocol) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let outbound = listener.local_addr().unwrap();
        let (shutdown, receiver) = watch::channel(false);
        let server_task = tokio::spawn(serve_h2_protocol_listener(listener, receiver, protocol));
        Self {
            outbound,
            shutdown,
            server_task,
        }
    }

    pub async fn shutdown(self) {
        let _ = self.shutdown.send(true);
        let _ = self.server_task.await;
    }
}

impl Socks5Fixture {
    pub async fn start() -> Self {
        let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = target_listener.local_addr().unwrap();
        let outbound_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let outbound = outbound_listener.local_addr().unwrap();
        let destinations = Arc::new(Mutex::new(Vec::new()));
        let (shutdown, _) = watch::channel(false);

        let target_task = tokio::spawn(serve_target(target_listener, shutdown.subscribe()));
        let proxy_task = tokio::spawn(serve_socks5_proxy(
            outbound_listener,
            shutdown.subscribe(),
            target,
            destinations.clone(),
        ));
        Self {
            target,
            outbound,
            destinations,
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

struct DomainMappingProxy {
    direct: DirectAsyncProxy,
    tcp_target: SocketAddr,
    udp_target: SocketAddr,
}

impl DomainMappingProxy {
    fn mapped_context(&self, context: &FlowContext) -> FlowContext {
        let mut mapped = context.clone();
        let target = if context.network == doradus_core::Network::Udp {
            self.udp_target
        } else {
            self.tcp_target
        };
        mapped.resolved_destination = Some(vec![target]);
        mapped
    }
}

struct DomainMappingDatagram {
    inner: Box<dyn AsyncDatagram>,
    target: SocketAddr,
}

impl DomainMappingDatagram {
    fn map_target(&self, target: Endpoint) -> Endpoint {
        let port = target.port().unwrap_or(self.target.port());
        Endpoint::ip(
            doradus_core::Network::Udp,
            SocketAddr::new(self.target.ip(), port),
        )
    }
}

impl AsyncDatagram for DomainMappingDatagram {
    fn send_to<'a>(&'a self, payload: &'a [u8], target: Endpoint) -> BoxFuture<'a, Result<usize>> {
        let target = self.map_target(target);
        Box::pin(async move { self.inner.send_to(payload, target).await })
    }

    fn recv_from<'a>(&'a self, buffer: &'a mut [u8]) -> BoxFuture<'a, Result<(usize, Endpoint)>> {
        self.inner.recv_from(buffer)
    }

    fn local_addr(&self) -> Result<Endpoint> {
        self.inner.local_addr()
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        self.inner.close()
    }
}

impl AsyncProxy for DomainMappingProxy {
    fn connect<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>> {
        let mapped = self.mapped_context(context);
        Box::pin(async move { self.direct.connect(&mapped).await })
    }

    fn open_datagram<'a>(
        &'a self,
        context: &'a FlowContext,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
        let mapped = self.mapped_context(context);
        let target = self.udp_target;
        Box::pin(async move {
            let datagram = self.direct.open_datagram(&mapped).await?;
            Ok(Box::new(DomainMappingDatagram {
                inner: datagram,
                target,
            }) as Box<dyn AsyncDatagram>)
        })
    }

    fn ping<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<Duration>> {
        let mapped = self.mapped_context(context);
        Box::pin(async move { self.direct.ping(&mapped).await })
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        self.direct.close()
    }
}

/// A real TLS + HTTP/2 + Yuubinsya server used by the service-level chain
/// test. The target mapping is deliberately kept in the fixture so the
/// client can send a domain destination while the loopback target remains
/// deterministic and does not depend on the host resolver.
pub struct H2YuubinsyaFixture {
    pub target: SocketAddr,
    pub udp_target: SocketAddr,
    pub outbound: SocketAddr,
    shutdown: Option<oneshot::Sender<()>>,
    target_shutdown: watch::Sender<bool>,
    server_task: tokio::task::JoinHandle<()>,
    target_task: tokio::task::JoinHandle<()>,
    udp_target_task: tokio::task::JoinHandle<()>,
}

impl H2YuubinsyaFixture {
    pub async fn start() -> Self {
        let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = target_listener.local_addr().unwrap();
        let (target_shutdown, target_receiver) = watch::channel(false);
        let target_task = tokio::spawn(serve_target(target_listener, target_receiver));
        let udp_target_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_target = udp_target_socket.local_addr().unwrap();
        let udp_target_task = tokio::spawn(serve_udp_echo(
            udp_target_socket,
            target_shutdown.subscribe(),
        ));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let outbound = listener.local_addr().unwrap();
        let upstream: Arc<dyn AsyncProxy> = Arc::new(DomainMappingProxy {
            direct: DirectAsyncProxy {
                timeout: Duration::from_secs(3),
            },
            tcp_target: target,
            udp_target,
        });
        let proxy = Arc::new(YuubinsyaServerProxy::new(
            derive_salt(YUUBINSYA_PASSWORD.as_bytes()),
            upstream,
        ));
        let server = Arc::new(YuubinsyaH2Server::new(yuubinsya_server_config(), proxy).unwrap());
        let (shutdown, receiver) = oneshot::channel();
        let server_task = tokio::spawn(async move {
            server
                .serve_listener_until(listener, async move {
                    let _ = receiver.await;
                })
                .await
                .unwrap();
        });

        Self {
            target,
            udp_target,
            outbound,
            shutdown: Some(shutdown),
            target_shutdown,
            server_task,
            target_task,
            udp_target_task,
        }
    }

    pub async fn shutdown(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let _ = self.server_task.await;
        let _ = self.target_shutdown.send(true);
        let _ = self.target_task.await;
        let _ = self.udp_target_task.await;
    }
}

fn build_tls_server_config(alpn_protocols: Vec<Vec<u8>>) -> Arc<ServerConfig> {
    let certificate = rustls_pemfile::certs(&mut Cursor::new(LEAF_CERTIFICATE_PEM))
        .next()
        .unwrap()
        .unwrap();
    let key = rustls_pemfile::private_key(&mut Cursor::new(PRIVATE_KEY_PEM))
        .unwrap()
        .unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls::pki_types::CertificateDer::from(
                certificate.to_vec(),
            )],
            key,
        )
        .unwrap();
    config.alpn_protocols = alpn_protocols;
    Arc::new(config)
}

pub fn tls_server_acceptor() -> TlsAcceptor {
    TlsAcceptor::from(build_tls_server_config(Vec::new()))
}

/// Return the Go-shaped certificate object used by a `tls_termination`
/// contract point. Keeping this in the shared fixture avoids duplicating
/// private test key material in every process-level chain test.
pub fn tls_termination_certificate() -> Value {
    json!({
        "certBase64": base64::engine::general_purpose::STANDARD.encode(LEAF_CERTIFICATE_PEM),
        "keyBase64": base64::engine::general_purpose::STANDARD.encode(PRIVATE_KEY_PEM),
    })
}

/// Build a fresh Go-shaped TLS-auto transport using a P-256 root fixture.
/// The generated certificate is only used to sign the ephemeral SNI leaf in
/// this process test; the client deliberately skips chain validation just as
/// the other local TLS fixtures do.
pub fn tls_auto_transport() -> Value {
    let signer = SigningKey::random(&mut OsRng);
    let subject = Name::from_str("CN=TLS-auto integration CA").unwrap();
    let builder = CertificateBuilder::new(
        Profile::Root,
        SerialNumber::from(1u64),
        Validity::from_now(Duration::from_secs(86400)).unwrap(),
        subject,
        SubjectPublicKeyInfoOwned::from_key(PublicKey::from(signer.verifying_key())).unwrap(),
        &signer,
    )
    .unwrap();
    let certificate = builder
        .build_with_rng::<DerSignature>(&mut OsRng)
        .unwrap()
        .to_der()
        .unwrap();
    let key = SecretKey::from(&signer).to_pkcs8_der().unwrap();
    json!({
        "type":"tls_auto",
        "tls_auto":{
            "ca_cert":base64::engine::general_purpose::STANDARD.encode(certificate),
            "ca_key":base64::engine::general_purpose::STANDARD.encode(key.as_bytes()),
            "servernames":["localhost"],
            "next_protos":[]
        }
    })
}

fn yuubinsya_server_config() -> Arc<ServerConfig> {
    build_tls_server_config(vec![b"h2".to_vec()])
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

async fn serve_udp_echo(socket: tokio::net::UdpSocket, mut shutdown: watch::Receiver<bool>) {
    let mut packet = [0u8; 65_535];
    loop {
        tokio::select! {
            received = socket.recv_from(&mut packet) => {
                let Ok((length, peer)) = received else { break };
                if socket.send_to(&packet[..length], peer).await.is_err() {
                    break;
                }
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() { break; }
            }
        }
    }
}

async fn handle_target(mut stream: TcpStream) {
    let mut buffer = vec![0u8; 16 * 1024];
    let Ok(mut length) = stream.read(&mut buffer).await else {
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
        loop {
            if stream.write_all(&buffer[..length]).await.is_err() {
                return;
            }
            let Ok(next_length) = stream.read(&mut buffer).await else {
                return;
            };
            if next_length == 0 {
                return;
            }
            length = next_length;
        }
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

async fn serve_socks5_proxy(
    listener: TcpListener,
    mut shutdown: watch::Receiver<bool>,
    fallback_target: SocketAddr,
    destinations: Arc<Mutex<Vec<String>>>,
) {
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let Ok((stream, _)) = accepted else { break };
                let destinations = destinations.clone();
                tokio::spawn(async move {
                    handle_socks5_proxy(stream, fallback_target, destinations).await;
                });
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() { break; }
            }
        }
    }
}

async fn handle_socks5_proxy(
    mut client: TcpStream,
    fallback_target: SocketAddr,
    destinations: Arc<Mutex<Vec<String>>>,
) {
    let mut greeting = [0u8; 2];
    if client.read_exact(&mut greeting).await.is_err() || greeting[0] != 5 {
        return;
    }
    let mut methods = vec![0u8; usize::from(greeting[1])];
    if client.read_exact(&mut methods).await.is_err() {
        return;
    }
    if !methods.contains(&0) {
        let _ = client.write_all(&[5, 255]).await;
        return;
    }
    if client.write_all(&[5, 0]).await.is_err() {
        return;
    }

    let mut request = [0u8; 4];
    if client.read_exact(&mut request).await.is_err()
        || request[0] != 5
        || request[1] != 1
        || request[2] != 0
    {
        return;
    }
    let (authority, target) = match request[3] {
        1 => {
            let mut ip = [0u8; 4];
            if client.read_exact(&mut ip).await.is_err() {
                return;
            }
            let mut port = [0u8; 2];
            if client.read_exact(&mut port).await.is_err() {
                return;
            }
            let address =
                SocketAddr::new(std::net::IpAddr::V4(ip.into()), u16::from_be_bytes(port));
            (address.to_string(), address)
        }
        3 => {
            let mut length = [0u8; 1];
            if client.read_exact(&mut length).await.is_err() {
                return;
            }
            let mut host = vec![0u8; usize::from(length[0])];
            if client.read_exact(&mut host).await.is_err() {
                return;
            }
            let host = String::from_utf8_lossy(&host);
            let mut port = [0u8; 2];
            if client.read_exact(&mut port).await.is_err() {
                return;
            }
            let port = u16::from_be_bytes(port);
            (
                format!("{host}:{port}"),
                SocketAddr::new(fallback_target.ip(), port),
            )
        }
        4 => {
            let mut ip = [0u8; 16];
            if client.read_exact(&mut ip).await.is_err() {
                return;
            }
            let mut port = [0u8; 2];
            if client.read_exact(&mut port).await.is_err() {
                return;
            }
            let address =
                SocketAddr::new(std::net::IpAddr::V6(ip.into()), u16::from_be_bytes(port));
            (address.to_string(), address)
        }
        _ => return,
    };
    destinations
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .push(authority);
    let Ok(mut upstream) = TcpStream::connect(target).await else {
        let _ = client.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await;
        return;
    };
    if client
        .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .is_err()
    {
        return;
    }
    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
}

async fn serve_h2_protocol_listener(
    listener: TcpListener,
    mut shutdown: watch::Receiver<bool>,
    protocol: H2FinalProtocol,
) {
    let mut tasks = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let Ok((stream, _)) = accepted else { break };
                tasks.spawn(serve_h2_protocol_connection(stream, shutdown.clone(), protocol));
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() { break; }
            }
            joined = tasks.join_next(), if !tasks.is_empty() => {
                let _ = joined;
            }
        }
    }
    while let Some(result) = tasks.join_next().await {
        let _ = result;
    }
}

async fn serve_h2_protocol_connection(
    socket: TcpStream,
    mut shutdown: watch::Receiver<bool>,
    protocol: H2FinalProtocol,
) {
    let Ok(mut connection) = h2::server::handshake(socket).await else {
        return;
    };
    let request = tokio::select! {
        request = connection.accept() => request,
        changed = shutdown.changed() => {
            if changed.is_ok() { connection.abrupt_shutdown(h2::Reason::NO_ERROR); }
            return;
        }
    };
    let Some(Ok((request, mut respond))) = request else {
        return;
    };
    if request.method() != http::Method::CONNECT || request.uri().host() != Some("localhost") {
        let _ = respond.send_response(
            Response::builder()
                .status(http::StatusCode::BAD_REQUEST)
                .body(())
                .unwrap(),
            true,
        );
        return;
    }

    let mut body = request.into_body();
    let Ok(mut send) = respond.send_response(Response::new(()), false) else {
        return;
    };
    let (application, relay) = tokio::io::duplex(64 * 1024);
    let (mut relay_read, mut relay_write) = tokio::io::split(relay);
    let body_to_application = tokio::spawn(async move {
        while let Some(data) = body.data().await {
            let Ok(data) = data else { break };
            if body.flow_control().release_capacity(data.len()).is_err() {
                break;
            }
            if relay_write.write_all(&data).await.is_err() {
                break;
            }
        }
        let _ = relay_write.shutdown().await;
    });
    let application_to_body = tokio::spawn(async move {
        let mut buffer = [0u8; 16 * 1024];
        loop {
            let length = match relay_read.read(&mut buffer).await {
                Ok(0) | Err(_) => break,
                Ok(length) => length,
            };
            if send
                .send_data(Bytes::copy_from_slice(&buffer[..length]), false)
                .is_err()
            {
                break;
            }
        }
        let _ = send.send_data(Bytes::new(), true);
    });
    let protocol_task = tokio::spawn(serve_h2_destination(application, protocol));

    while let Some(result) = tokio::select! {
        result = connection.accept() => result,
        changed = shutdown.changed() => {
            if changed.is_ok() { connection.abrupt_shutdown(h2::Reason::NO_ERROR); }
            None
        }
    } {
        if result.is_err() {
            break;
        }
    }

    protocol_task.abort();
    body_to_application.abort();
    application_to_body.abort();
    let _ = protocol_task.await;
    let _ = body_to_application.await;
    let _ = application_to_body.await;
}

async fn serve_h2_destination(mut stream: tokio::io::DuplexStream, protocol: H2FinalProtocol) {
    match protocol {
        H2FinalProtocol::Http => {
            let request = read_fixture_headers(&mut stream).await;
            if !request.starts_with("CONNECT example.test:")
                || !request.contains(" HTTP/1.1\r\n")
                || !request.contains("Host: ")
                || !request.contains("Proxy-Authorization: Basic dXNlcjpwYXNz\r\n")
            {
                return;
            }
            if stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .is_err()
            {
                return;
            }
        }
        H2FinalProtocol::Socks5 => {
            let mut greeting = [0u8; 4];
            if stream.read_exact(&mut greeting).await.is_err() || greeting != [5, 2, 0, 2] {
                return;
            }
            if stream.write_all(&[5, 2]).await.is_err() {
                return;
            }
            let mut auth_head = [0u8; 2];
            if stream.read_exact(&mut auth_head).await.is_err() || auth_head[0] != 1 {
                return;
            }
            let mut username = vec![0u8; usize::from(auth_head[1])];
            if stream.read_exact(&mut username).await.is_err() {
                return;
            }
            let mut password_length = [0u8; 1];
            if stream.read_exact(&mut password_length).await.is_err() {
                return;
            }
            let mut password = vec![0u8; usize::from(password_length[0])];
            if stream.read_exact(&mut password).await.is_err()
                || username != b"user"
                || password != b"pass"
            {
                return;
            }
            if stream.write_all(&[1, 0]).await.is_err() {
                return;
            }
            let mut request = [0u8; 4];
            if stream.read_exact(&mut request).await.is_err() || request != [5, 1, 0, 3] {
                return;
            }
            let mut host_length = [0u8; 1];
            if stream.read_exact(&mut host_length).await.is_err() {
                return;
            }
            let mut host = vec![0u8; usize::from(host_length[0])];
            if stream.read_exact(&mut host).await.is_err() {
                return;
            }
            let mut port = [0u8; 2];
            if stream.read_exact(&mut port).await.is_err() || host != b"example.test" {
                return;
            }
            if stream
                .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 80])
                .await
                .is_err()
            {
                return;
            }
        }
    }

    let mut buffer = [0u8; 16 * 1024];
    let length = match stream.read(&mut buffer).await {
        Ok(0) | Err(_) => return,
        Ok(length) => length,
    };
    if buffer[..length].starts_with(b"GET ") {
        let _ = stream
            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await;
        return;
    }
    if stream.write_all(&buffer[..length]).await.is_err() {
        return;
    }
    loop {
        let length = match stream.read(&mut buffer).await {
            Ok(0) | Err(_) => break,
            Ok(length) => length,
        };
        if stream.write_all(&buffer[..length]).await.is_err() {
            break;
        }
    }
}

async fn read_fixture_headers(stream: &mut tokio::io::DuplexStream) -> String {
    let mut headers = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    while !headers.ends_with(b"\r\n\r\n") && headers.len() <= 64 * 1024 {
        if stream.read_exact(&mut byte).await.is_err() {
            return String::new();
        }
        headers.push(byte[0]);
    }
    String::from_utf8(headers).unwrap_or_default()
}
