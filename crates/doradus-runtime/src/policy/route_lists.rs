use super::*;

/// original JSON for compatibility; this normalized view is what the route
/// original JSON for compatibility; this normalized view is what the route
/// compiler consumes. Remote lists use an atomic cache file when one exists,
/// while a missing remote cache is reported without making a valid local
/// configuration unusable.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RouteListSnapshot {
    values: BTreeMap<String, Vec<String>>,
    kinds: BTreeMap<String, String>,
    host_indexes: BTreeMap<String, Arc<HostTrie>>,
    errors: BTreeMap<String, String>,
}

fn process_path_matches(actual: &str, expected: &str) -> bool {
    fn without_deleted_suffix(path: &str) -> &str {
        path.strip_suffix(" (deleted)").unwrap_or(path)
    }

    without_deleted_suffix(actual) == without_deleted_suffix(expected)
}

impl RouteListSnapshot {
    pub fn values(&self, name: &str) -> Option<&[String]> {
        self.values.get(name).map(Vec::as_slice)
    }

    pub fn host_index(&self, name: &str) -> Option<Arc<HostTrie>> {
        self.host_indexes.get(name).cloned()
    }

    pub fn error(&self, name: &str) -> Option<&str> {
        self.errors.get(name).map(String::as_str)
    }

    pub fn list_names(&self) -> impl Iterator<Item = &str> {
        self.values.keys().map(String::as_str)
    }

    pub fn error_names(&self) -> impl Iterator<Item = &str> {
        self.errors.keys().map(String::as_str)
    }

    /// Return the route lists that the Go host/process tries would report for
    /// this flow before rule evaluation.  A rule may be selected from a list,
    /// but Go's connection metadata still includes every independently
    /// matched list, including lists used only by a later rule.
    pub fn matching_names(&self, context: &FlowContext) -> Vec<String> {
        let mut names = Vec::new();
        // Go's FakeDNS wrapper reverse-resolves a known synthetic address
        // before it calls HostTrie.Search.  `effective_destination` is the
        // equivalent view here: keep `destination` for packet/telemetry
        // metadata, but never let the FakeIP range itself make a flow match
        // the default LAN list.
        let destination = context.effective_destination();
        for (name, values) in &self.values {
            let kind = self.kinds.get(name).map(String::as_str).unwrap_or_default();
            let matched = if kind == "process" || kind == "processes" {
                context.process.as_deref().is_some_and(|process| {
                    values
                        .iter()
                        .any(|value| process_path_matches(process, value))
                })
            } else {
                self.host_indexes
                    .get(name)
                    .is_some_and(|index| index.search_parent(&destination).is_some())
            };
            if matched {
                names.push(name.clone());
            }
        }
        names
    }
}

/// Load local route-list contents and any already downloaded remote cache.
/// The cache location deliberately follows the user's persistent cache
/// policy and never falls back to `/tmp`.
pub fn load_route_lists(records: &[GoRouteListRecord]) -> RouteListSnapshot {
    let mut snapshot = RouteListSnapshot::default();
    for record in records {
        let root = match serde_json::from_slice::<Value>(&record.data_json) {
            Ok(value) => value,
            Err(error) => {
                snapshot
                    .errors
                    .insert(record.name.clone(), format!("invalid list JSON: {error}"));
                continue;
            }
        };
        let kind = string_field(&root, &["type", "kind"])
            .unwrap_or_else(|| record.list_type.clone())
            .to_ascii_lowercase();
        let source = root.get("source").unwrap_or(&Value::Null);
        let source_type = string_field(source, &["type"])
            .unwrap_or_else(|| record.source_type.clone())
            .to_ascii_lowercase();
        let raw_values = if source_type.is_empty() || source_type == "local" {
            local_list_values(&root, source)
        } else if source_type == "remote" {
            remote_list_values(&root, source)
        } else {
            Err(format!("unsupported route list source {source_type:?}"))
        };
        match raw_values {
            Ok(raw_values) => {
                let values = normalize_list_values(&kind, raw_values);
                if values.is_empty() {
                    snapshot.errors.insert(
                        record.name.clone(),
                        "route list has no usable entries".to_owned(),
                    );
                } else {
                    let normalized_kind = kind.replace('-', "_");
                    if normalized_kind == "process" || normalized_kind == "processes" {
                        snapshot.kinds.insert(record.name.clone(), normalized_kind);
                    } else {
                        let index = match HostTrie::from_patterns(values.iter()) {
                            Ok(index) => index,
                            Err(error) => {
                                snapshot.errors.insert(
                                    record.name.clone(),
                                    format!("failed to build on-disk route list index: {error}"),
                                );
                                continue;
                            }
                        };
                        snapshot.kinds.insert(record.name.clone(), normalized_kind);
                        snapshot
                            .host_indexes
                            .insert(record.name.clone(), Arc::new(index));
                    }
                    snapshot.values.insert(record.name.clone(), values);
                }
            }
            Err(error) => {
                snapshot.errors.insert(record.name.clone(), error);
            }
        }
    }
    snapshot
}

pub fn route_list_cache_dir() -> PathBuf {
    let root = std::env::var_os("DORADUS_CACHE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(".cache"));
    root.join("doradus").join("rules")
}

pub fn route_list_cache_path(url: &str) -> PathBuf {
    route_list_cache_dir().join(format!("{:016x}.list", stable_hash(url)))
}

fn stable_hash(value: &str) -> u64 {
    value.bytes().fold(0xcbf29ce484222325, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x100000001b3)
    })
}

fn local_list_values(root: &Value, source: &Value) -> std::result::Result<Vec<String>, String> {
    array_strings(
        source
            .get("local")
            .and_then(|value| value.get("lists"))
            .or_else(|| source.get("lists"))
            .or_else(|| root.get("lists"))
            .or_else(|| root.get("values"))
            .or_else(|| root.get("items")),
    )
}

fn remote_list_values(root: &Value, source: &Value) -> std::result::Result<Vec<String>, String> {
    let mut urls = remote_urls(root, source)?;
    if let Some(path) = root.get("path").and_then(Value::as_str) {
        urls.push(format!("file://{path}"));
    }
    if urls.is_empty() {
        return Err("remote route list has no URL".to_owned());
    }
    let mut values = Vec::new();
    let mut missing = Vec::new();
    for url in urls {
        let path = if let Some(path) = url.strip_prefix("file://") {
            PathBuf::from(path)
        } else {
            route_list_cache_path(&url)
        };
        match fs::read(&path) {
            Ok(bytes) => values.extend(String::from_utf8_lossy(&bytes).lines().map(str::to_owned)),
            Err(error) => missing.push(format!("{url}: {error}")),
        }
    }
    if values.is_empty() {
        return Err(format!(
            "remote route list cache unavailable: {}",
            missing.join("; ")
        ));
    }
    Ok(values)
}

fn remote_urls(root: &Value, source: &Value) -> std::result::Result<Vec<String>, String> {
    let urls = array_strings(
        source
            .get("remote")
            .and_then(|value| value.get("urls"))
            .or_else(|| source.get("urls"))
            .or_else(|| root.get("urls")),
    )?;
    let mut urls = urls;
    if let Some(url) = source
        .get("remote")
        .and_then(|value| value.get("url"))
        .or_else(|| source.get("url"))
        .or_else(|| root.get("url"))
        .and_then(Value::as_str)
    {
        urls.push(url.to_owned());
    }
    Ok(urls)
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RouteListRefreshReport {
    pub refreshed: usize,
    pub errors: BTreeMap<String, Vec<String>>,
}

/// Connection boundary for route-list downloads.
///
/// The default compatibility entry point remains direct TCP, while the
/// runtime API can inject the currently selected outbound proxy. Keeping this
/// boundary here avoids coupling route parsing to a concrete proxy protocol
/// and leaves room for a future downloader with redirect or cache policy.
pub trait RouteListTransport: Send + Sync {
    fn connect<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>>;
}

/// Adapts the shared async proxy and resolver abstractions to the route-list
/// downloader. Resolving before `connect` makes the adapter work with direct,
/// fixed, HTTP, SOCKS5, and chained proxies whose current implementations all
/// accept an IP endpoint; the original URL host is still used for HTTP Host
/// and TLS SNI.
pub struct ProxyRouteListTransport {
    proxy: Arc<dyn AsyncProxy>,
    resolver: Arc<dyn AsyncIpResolver>,
}

impl ProxyRouteListTransport {
    pub fn new(proxy: Arc<dyn AsyncProxy>, resolver: Arc<dyn AsyncIpResolver>) -> Self {
        Self { proxy, resolver }
    }
}

impl RouteListTransport for ProxyRouteListTransport {
    fn connect<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>> {
        let proxy = self.proxy.clone();
        let resolver = self.resolver.clone();
        let mut context = context.clone();
        Box::pin(async move {
            if let Endpoint::Domain {
                network,
                host,
                port,
            } = context.destination.clone()
            {
                let addresses = resolver.resolve(&host, ResolveStrategy::Default).await?;
                let address = addresses
                    .v4
                    .first()
                    .copied()
                    .map(IpAddr::V4)
                    .or_else(|| addresses.v6.first().copied().map(IpAddr::V6))
                    .ok_or_else(|| {
                        Error::invalid(format!(
                            "route-list host {} resolved to no address",
                            host.as_str()
                        ))
                    })?;
                context.destination = Endpoint::ip(network, SocketAddr::new(address, port));
                context.network = network;
            }
            proxy.connect(&context).await
        })
    }
}

/// Download all configured HTTP(S) route-list sources into the persistent
/// cache. Each successful response is written to a sibling `.part` file and
/// atomically renamed, so a force-stop cannot leave a partially readable
/// list. The caller can then publish a normal runtime snapshot.
pub async fn refresh_route_list_caches(
    records: &[GoRouteListRecord],
    timeout: Duration,
) -> RouteListRefreshReport {
    refresh_route_list_caches_inner(records, timeout, None).await
}

/// Refresh route-list caches through an injected outbound transport.
///
/// This is the runtime equivalent of Go's `Lists.SetProxy`: management-plane
/// downloads follow the selected node instead of silently bypassing it.
pub async fn refresh_route_list_caches_with_transport(
    records: &[GoRouteListRecord],
    timeout: Duration,
    transport: Arc<dyn RouteListTransport>,
) -> RouteListRefreshReport {
    refresh_route_list_caches_inner(records, timeout, Some(transport.as_ref())).await
}

async fn refresh_route_list_caches_inner(
    records: &[GoRouteListRecord],
    timeout: Duration,
    transport: Option<&dyn RouteListTransport>,
) -> RouteListRefreshReport {
    let mut report = RouteListRefreshReport::default();
    for record in records {
        let Ok(root) = serde_json::from_slice::<Value>(&record.data_json) else {
            report
                .errors
                .entry(record.name.clone())
                .or_default()
                .push("route list data_json is invalid".to_owned());
            continue;
        };
        let source = root.get("source").unwrap_or(&Value::Null);
        let source_type = string_field(source, &["type"])
            .unwrap_or_else(|| record.source_type.clone())
            .to_ascii_lowercase();
        if source_type != "remote" {
            continue;
        }
        let urls = match remote_urls(&root, source) {
            Ok(urls) => urls,
            Err(error) => {
                report
                    .errors
                    .entry(record.name.clone())
                    .or_default()
                    .push(error);
                continue;
            }
        };
        for url in urls {
            if url.starts_with("file://") {
                continue;
            }
            let download = match transport {
                Some(transport) => {
                    download_route_url_with_transport(&url, timeout, Some(transport)).await
                }
                None => download_route_url(&url, timeout).await,
            };
            match download {
                Ok(bytes) => match write_route_list_cache(&url, &bytes) {
                    Ok(()) => report.refreshed += 1,
                    Err(error) => report
                        .errors
                        .entry(record.name.clone())
                        .or_default()
                        .push(format!("{url}: {error}")),
                },
                Err(error) => report
                    .errors
                    .entry(record.name.clone())
                    .or_default()
                    .push(format!("{url}: {error}")),
            }
        }
    }
    report
}

fn write_route_list_cache(url: &str, bytes: &[u8]) -> std::io::Result<()> {
    let directory = route_list_cache_dir();
    fs::create_dir_all(&directory)?;
    let target = route_list_cache_path(url);
    let part = directory.join(format!(
        "{:016x}.part.{}",
        stable_hash(url),
        std::process::id()
    ));
    fs::write(&part, bytes)?;
    if let Err(error) = fs::rename(&part, &target) {
        let _ = fs::remove_file(&part);
        return Err(error);
    }
    Ok(())
}

trait RouteDownloadStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T> RouteDownloadStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

pub(super) async fn download_route_url(url: &str, timeout: Duration) -> Result<Vec<u8>> {
    download_route_url_with_transport(url, timeout, None).await
}

pub async fn download_route_url_with_transport(
    url: &str,
    timeout: Duration,
    transport: Option<&dyn RouteListTransport>,
) -> Result<Vec<u8>> {
    let (secure, host, port, path) = parse_http_url(url)?;
    let mut stream: Box<dyn RouteDownloadStream> = if let Some(transport) = transport {
        let context = FlowContext::new(Endpoint::domain(
            Network::Tcp,
            DomainName::new(&host)?,
            port,
        ));
        let stream = transport.connect(&context).await?;
        if secure {
            #[cfg(feature = "doh-tls")]
            {
                let mut roots = rustls::RootCertStore::empty();
                roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
                let dialer = crate::RustlsTlsDialer::from_root_store(roots, timeout)?;
                Box::new(dialer.connect_boxed_stream(&host, stream).await?)
            }
            #[cfg(not(feature = "doh-tls"))]
            {
                let _ = stream;
                return Err(Error::new(
                    ErrorKind::Unsupported,
                    "https route-list refresh requires the doh-tls feature",
                ));
            }
        } else {
            Box::new(stream)
        }
    } else if secure {
        #[cfg(feature = "doh-tls")]
        {
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let dialer = crate::RustlsTlsDialer::from_root_store(roots, timeout)?;
            Box::new(dialer.connect(&host, port, &host).await?)
        }
        #[cfg(not(feature = "doh-tls"))]
        {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "https route-list refresh requires the doh-tls feature",
            ));
        }
    } else {
        Box::new(
            tokio::time::timeout(timeout, TcpStream::connect((host.as_str(), port)))
                .await
                .map_err(|_| Error::new(ErrorKind::Timeout, "route-list TCP connect timed out"))?
                .map_err(|error| {
                    Error::new(ErrorKind::Io, format!("route-list TCP connect: {error}"))
                })?,
        )
    };
    let host_header = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.clone()
    };
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host_header}\r\nAccept: text/plain, */*\r\nConnection: close\r\n\r\n"
    );
    tokio::time::timeout(timeout, async {
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|error| Error::new(ErrorKind::Io, format!("route-list request: {error}")))?;
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .await
            .map_err(|error| Error::new(ErrorKind::Io, format!("route-list response: {error}")))?;
        parse_http_response(&response)
    })
    .await
    .map_err(|_| Error::new(ErrorKind::Timeout, "route-list request timed out"))?
}

pub(super) fn parse_http_url(url: &str) -> Result<(bool, String, u16, String)> {
    let (secure, rest) = if let Some(rest) = url.strip_prefix("https://") {
        (true, rest)
    } else if let Some(rest) = url.strip_prefix("http://") {
        (false, rest)
    } else {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!("route-list URL must use http or https: {url:?}"),
        ));
    };
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (host, suffix) = rest
            .split_once(']')
            .ok_or_else(|| Error::invalid("route-list URL has invalid IPv6 authority"))?;
        let port = suffix
            .strip_prefix(':')
            .map(|value| value.parse::<u16>())
            .transpose()
            .map_err(|error| Error::invalid(format!("route-list URL port: {error}")))?
            .unwrap_or(if secure { 443 } else { 80 });
        (host.to_owned(), port)
    } else if let Some((host, port)) = authority.rsplit_once(':') {
        if host.contains(':') {
            (authority.to_owned(), if secure { 443 } else { 80 })
        } else {
            (
                host.to_owned(),
                port.parse::<u16>()
                    .map_err(|error| Error::invalid(format!("route-list URL port: {error}")))?,
            )
        }
    } else {
        (authority.to_owned(), if secure { 443 } else { 80 })
    };
    if host.is_empty() {
        return Err(Error::invalid("route-list URL host is empty"));
    }
    let path = if path.is_empty() {
        "/".to_owned()
    } else {
        format!("/{path}")
    };
    Ok((secure, host, port, path))
}

pub(super) fn parse_http_response(response: &[u8]) -> Result<Vec<u8>> {
    const MAX_ROUTE_LIST_BYTES: usize = 64 * 1024 * 1024;
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| Error::new(ErrorKind::Protocol, "route-list response has no headers"))?;
    let headers = &response[..header_end];
    let body = &response[header_end + 4..];
    let status = headers
        .split(|byte| *byte == b'\n')
        .next()
        .and_then(|line| line.split(|byte| *byte == b' ').nth(1))
        .and_then(|code| std::str::from_utf8(code).ok())
        .and_then(|code| code.trim().parse::<u16>().ok())
        .ok_or_else(|| {
            Error::new(
                ErrorKind::Protocol,
                "route-list response has invalid status",
            )
        })?;
    if !(200..300).contains(&status) {
        return Err(Error::new(
            ErrorKind::Protocol,
            format!("route-list response status {status}"),
        ));
    }
    let chunked = String::from_utf8_lossy(headers).lines().any(|line| {
        line.split_once(':').is_some_and(|(key, value)| {
            key.eq_ignore_ascii_case("transfer-encoding")
                && value.to_ascii_lowercase().contains("chunked")
        })
    });
    let body = if chunked {
        decode_chunked_body(body)?
    } else {
        body.to_vec()
    };
    if body.len() > MAX_ROUTE_LIST_BYTES {
        return Err(Error::new(
            ErrorKind::Protocol,
            "route-list response is too large",
        ));
    }
    Ok(body)
}

fn decode_chunked_body(mut body: &[u8]) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    loop {
        let end = body
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or_else(|| Error::new(ErrorKind::Protocol, "invalid chunk header"))?;
        let size = usize::from_str_radix(
            std::str::from_utf8(&body[..end])
                .map_err(|_| Error::new(ErrorKind::Protocol, "invalid chunk size"))?
                .split(';')
                .next()
                .unwrap_or_default()
                .trim(),
            16,
        )
        .map_err(|_| Error::new(ErrorKind::Protocol, "invalid chunk size"))?;
        body = &body[end + 2..];
        if size == 0 {
            return Ok(output);
        }
        if body.len() < size + 2 || &body[size..size + 2] != b"\r\n" {
            return Err(Error::new(ErrorKind::Protocol, "invalid chunk body"));
        }
        output.extend_from_slice(&body[..size]);
        body = &body[size + 2..];
    }
}

fn array_strings(value: Option<&Value>) -> std::result::Result<Vec<String>, String> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let Some(items) = value.as_array() else {
        return Err("route list values must be an array".to_owned());
    };
    Ok(items
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect())
}

fn normalize_list_values(kind: &str, raw_values: Vec<String>) -> Vec<String> {
    let kind = kind.replace('-', "_");
    let hosts_file = kind == "hosts_as_host";
    let process_only = kind == "process" || kind == "processes";
    let cidr_only = matches!(kind.as_str(), "cidr" | "ip" | "ip_cidr");
    let mut values = BTreeSet::new();
    for raw in raw_values {
        let line = raw
            .split_once('#')
            .map_or(raw.as_str(), |(line, _)| line)
            .trim();
        if line.is_empty() {
            continue;
        }
        let fields = line.split_whitespace().collect::<Vec<_>>();
        let fields = if hosts_file {
            if fields.len() < 2 {
                continue;
            }
            &fields[1..]
        } else {
            fields.as_slice()
        };
        for field in fields {
            let mut value = field
                .trim()
                .trim_start_matches("||")
                .trim_start_matches('.');
            if value.is_empty() {
                continue;
            }
            if process_only {
                values.insert(value.to_owned());
                continue;
            }
            if cidr_only && !value.contains('/') {
                continue;
            }
            if value.contains('/') {
                if !valid_cidr(value) {
                    continue;
                }
            } else if !valid_domain_pattern(value) {
                continue;
            }
            value = value.trim_end_matches('.');
            values.insert(value.to_ascii_lowercase());
        }
    }
    values.into_iter().collect()
}

fn valid_cidr(value: &str) -> bool {
    let Some((address, prefix)) = value.split_once('/') else {
        return false;
    };
    let Ok(address) = address.parse::<std::net::IpAddr>() else {
        return false;
    };
    let Ok(prefix) = prefix.parse::<u8>() else {
        return false;
    };
    prefix
        <= match address {
            std::net::IpAddr::V4(_) => 32,
            std::net::IpAddr::V6(_) => 128,
        }
}

fn valid_domain_pattern(value: &str) -> bool {
    let value = value.trim().trim_end_matches('.');
    !value.is_empty()
        && value
            .split('.')
            .all(|label| label == "*" || doradus_core::DomainName::new(label).is_ok())
}
