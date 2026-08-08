//! Conversion from the persisted Go route-rule shape to the trie runtime.
//!
//! The store keeps the original JSON payload for forward compatibility.  This
//! module is deliberately strict at the runtime boundary: a rule that cannot
//! be represented by the current domain/CIDR router is reported instead of
//! silently becoming a different rule.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use yuhaiin_core::GeoLookup;
use yuhaiin_core::{Error, ErrorKind, Network, ResolveStrategy, ResolverPolicy, Result};
use yuhaiin_store::{GoRouteListRecord, GoRouteRuleRecord};
use yuhaiin_trie::router::{RouteDecision, RouteRule, Router, RouterRuntime, RuleAction};

/// Runtime contents of Go route lists. The persisted record keeps the
/// original JSON for compatibility; this normalized view is what the route
/// compiler consumes. Remote lists use an atomic cache file when one exists,
/// while a missing remote cache is reported without making a valid local
/// configuration unusable.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RouteListSnapshot {
    values: BTreeMap<String, Vec<String>>,
    errors: BTreeMap<String, String>,
}

impl RouteListSnapshot {
    pub fn values(&self, name: &str) -> Option<&[String]> {
        self.values.get(name).map(Vec::as_slice)
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
    let root = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache")))
        .unwrap_or_else(|| PathBuf::from(".cache"));
    root.join("yuhaiin-rust").join("rules")
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

/// Download all configured HTTP(S) route-list sources into the persistent
/// cache. Each successful response is written to a sibling `.part` file and
/// atomically renamed, so a force-stop cannot leave a partially readable
/// list. The caller can then publish a normal runtime snapshot.
pub async fn refresh_route_list_caches(
    records: &[GoRouteListRecord],
    timeout: Duration,
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
            match download_route_url(&url, timeout).await {
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

async fn download_route_url(url: &str, timeout: Duration) -> Result<Vec<u8>> {
    let (secure, host, port, path) = parse_http_url(url)?;
    let mut stream: Box<dyn RouteDownloadStream> = if secure {
        #[cfg(feature = "doh-tls")]
        {
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let dialer = crate::RustCryptoTlsDialer::from_root_store(roots, timeout)?;
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

fn parse_http_url(url: &str) -> Result<(bool, String, u16, String)> {
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

fn parse_http_response(response: &[u8]) -> Result<Vec<u8>> {
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
            .all(|label| label == "*" || yuhaiin_core::DomainName::new(label).is_ok())
}

pub fn compile_go_route_rules(
    records: &[GoRouteRuleRecord],
    fallback: RouteDecision,
) -> Result<RouterRuntime> {
    compile_go_route_rules_with_lists(records, &RouteListSnapshot::default(), fallback, None)
}

pub fn compile_go_route_rules_with_geo(
    records: &[GoRouteRuleRecord],
    fallback: RouteDecision,
    geo: Option<Arc<dyn GeoLookup>>,
) -> Result<RouterRuntime> {
    compile_go_route_rules_with_lists(records, &RouteListSnapshot::default(), fallback, geo)
}

pub fn compile_go_route_rules_with_lists(
    records: &[GoRouteRuleRecord],
    lists: &RouteListSnapshot,
    fallback: RouteDecision,
    geo: Option<Arc<dyn GeoLookup>>,
) -> Result<RouterRuntime> {
    let mut rules = Vec::with_capacity(records.len());
    for record in records {
        rules.extend(expand_go_route_rule(record, lists)?);
    }
    let router = Router::compile(rules, fallback)?;
    let router = match geo {
        Some(geo) => router.with_geo_lookup(geo),
        None => router,
    };
    Ok(RouterRuntime::new(router))
}

pub fn expand_go_route_rule(
    record: &GoRouteRuleRecord,
    lists: &RouteListSnapshot,
) -> Result<Vec<RouteRule>> {
    if record.disabled {
        return Ok(Vec::new());
    }
    let root: Value = serde_json::from_slice(&record.data_json).map_err(|error| {
        Error::new(
            ErrorKind::InvalidInput,
            format!("route rule {} has invalid data_json: {error}", record.id),
        )
    })?;
    let Some(expressions) = root.get("rules").and_then(Value::as_array) else {
        return Ok(route_rule_from_root(record, &root)?.into_iter().collect());
    };
    let action = parse_action(&record.action_mode, &root, record.id.as_str())?;
    let resolver_policy = parse_resolver_policy(&root, &root, action, record.id.as_str())?;
    let priority = i32::try_from(record.priority).map_err(|_| {
        Error::new(
            ErrorKind::InvalidInput,
            format!("route rule {} priority is outside i32", record.id),
        )
    })?;
    let variants = if expressions.is_empty() {
        vec![RuleVariant::default()]
    } else {
        let mut variants = Vec::new();
        for expression in expressions {
            variants.extend(parse_rule_expression(
                expression,
                lists,
                record.id.as_str(),
            )?);
        }
        variants
    };
    if variants.is_empty() {
        // Go keeps a rule whose referenced list is unavailable and simply
        // makes that matcher return false until the list is refreshed.
        return Ok(Vec::new());
    }
    Ok(variants
        .into_iter()
        .map(|variant| RouteRule {
            pattern: variant.pattern.unwrap_or_default(),
            action,
            network: variant.network,
            port: variant.port,
            geo_country: variant.geo_country,
            resolver_policy,
            priority,
        })
        .collect())
}

fn route_rule_from_root(record: &GoRouteRuleRecord, root: &Value) -> Result<Option<RouteRule>> {
    let matcher = root
        .get("match")
        .or_else(|| root.get("matcher"))
        .unwrap_or(root);
    let match_type = record.match_type.trim().to_ascii_lowercase();
    let pattern = match match_type.as_str() {
        "domain" | "host" => string_field(matcher, &["domain", "host", "pattern"]),
        "cidr" | "ip" | "network" => string_field(matcher, &["cidr", "ip", "network", "pattern"]),
        _ => string_field(
            matcher,
            &["domain", "host", "cidr", "ip", "network", "pattern"],
        ),
    }
    .ok_or_else(|| {
        Error::new(
            ErrorKind::Unsupported,
            format!(
                "route rule {} has unsupported matcher type {:?}",
                record.id, record.match_type
            ),
        )
    })?;

    let action = parse_action(&record.action_mode, root, record.id.as_str())?;
    let network = parse_network(
        field(root, matcher, &["network", "protocol"]),
        record.id.as_str(),
    )?;
    let port = parse_port(field(root, matcher, &["port", "ports"]), record.id.as_str())?;
    let geo_country = string_field(root, &["geo_country", "geoCountry", "country"])
        .or_else(|| string_field(matcher, &["geo_country", "geoCountry", "country"]));
    let resolver_policy = parse_resolver_policy(root, matcher, action, record.id.as_str())?;
    let priority = i32::try_from(record.priority).map_err(|_| {
        Error::new(
            ErrorKind::InvalidInput,
            format!("route rule {} priority is outside i32", record.id),
        )
    })?;

    Ok(Some(RouteRule {
        pattern,
        action,
        network,
        port,
        geo_country,
        resolver_policy,
        priority,
    }))
}

pub fn route_rule_from_go_record(record: &GoRouteRuleRecord) -> Result<Option<RouteRule>> {
    if record.disabled {
        return Ok(None);
    }
    let root: Value = serde_json::from_slice(&record.data_json).map_err(|error| {
        Error::new(
            ErrorKind::InvalidInput,
            format!("route rule {} has invalid data_json: {error}", record.id),
        )
    })?;
    route_rule_from_root(record, &root)
}

#[derive(Debug, Clone, Default)]
struct RuleVariant {
    /// `None` means the expression has no host/CIDR constraint and is a
    /// global rule whose remaining network/port/geo predicates still apply.
    pattern: Option<String>,
    network: Option<Network>,
    port: Option<(u16, u16)>,
    geo_country: Option<String>,
}

fn parse_rule_expression(
    value: &Value,
    lists: &RouteListSnapshot,
    id: &str,
) -> Result<Vec<RuleVariant>> {
    let kind = value
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_ascii_lowercase();
    if kind == "all" || value.get("all").is_some() {
        let children = value
            .get("all")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        return combine_all(&children, lists, id);
    }
    if kind == "any" || value.get("any").is_some() {
        let children = value
            .get("any")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let mut variants = Vec::new();
        for child in children {
            variants.extend(parse_rule_expression(&child, lists, id)?);
        }
        return Ok(variants);
    }
    if kind == "not" || value.get("not").is_some() {
        return Err(Error::new(
            ErrorKind::Unsupported,
            format!("route rule {id} has unsupported `not` expression"),
        ));
    }

    match kind.as_str() {
        "host" => {
            let host = value.get("host").unwrap_or(value);
            let name = string_field(host, &["list", "name"])
                .ok_or_else(|| unsupported_expression(id, "host list name"))?;
            let patterns = lists.values(&name).unwrap_or_default();
            Ok(patterns
                .iter()
                .map(|pattern| RuleVariant {
                    pattern: Some(pattern.clone()),
                    ..RuleVariant::default()
                })
                .collect())
        }
        "network" => {
            let nested = value.get("network").unwrap_or(value);
            let network = parse_network_text(
                string_field(nested, &["network", "protocol"]).as_deref(),
                id,
            )?;
            Ok(vec![RuleVariant {
                network,
                ..Default::default()
            }])
        }
        "port" => {
            let nested = value.get("port").unwrap_or(value);
            let value = nested
                .get("ports")
                .or_else(|| nested.get("port"))
                .unwrap_or(nested);
            parse_port_variants(value, id)
        }
        "geoip" => {
            let nested = value.get("geoip").unwrap_or(value);
            let countries = nested
                .get("countries")
                .and_then(Value::as_array)
                .map(|values| {
                    values
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect::<Vec<_>>()
                })
                .or_else(|| string_field(nested, &["country"]).map(|value| vec![value]))
                .unwrap_or_default();
            if countries.is_empty() {
                return Err(unsupported_expression(id, "geoip countries"));
            }
            Ok(countries
                .into_iter()
                .map(|country| RuleVariant {
                    geo_country: Some(country),
                    ..Default::default()
                })
                .collect())
        }
        "domain" | "cidr" | "ip" => {
            let pattern = string_field(value, &["domain", "host", "cidr", "ip", "pattern"])
                .ok_or_else(|| unsupported_expression(id, "matcher pattern"))?;
            Ok(vec![RuleVariant {
                pattern: Some(pattern),
                ..Default::default()
            }])
        }
        other => Err(unsupported_expression(
            id,
            format!("expression type {other:?}"),
        )),
    }
}

fn combine_all(
    children: &[Value],
    lists: &RouteListSnapshot,
    id: &str,
) -> Result<Vec<RuleVariant>> {
    let mut variants = vec![RuleVariant::default()];
    for child in children {
        let child_variants = parse_rule_expression(child, lists, id)?;
        let mut combined = Vec::new();
        for left in &variants {
            for right in &child_variants {
                if left.pattern.is_some() && right.pattern.is_some() {
                    return Err(unsupported_expression(
                        id,
                        "all expression with two host/CIDR predicates",
                    ));
                }
                let network = match (left.network, right.network) {
                    (Some(left), Some(right)) if left != right => {
                        return Ok(Vec::new());
                    }
                    (Some(network), _) | (_, Some(network)) => Some(network),
                    (None, None) => None,
                };
                let port = intersect_ports(left.port, right.port);
                if left.port.is_some() && right.port.is_some() && port.is_none() {
                    continue;
                }
                let geo_country = match (&left.geo_country, &right.geo_country) {
                    (Some(left), Some(right)) if !left.eq_ignore_ascii_case(right) => continue,
                    (Some(country), _) | (_, Some(country)) => Some(country.clone()),
                    (None, None) => None,
                };
                combined.push(RuleVariant {
                    pattern: left.pattern.clone().or_else(|| right.pattern.clone()),
                    network,
                    port,
                    geo_country,
                });
            }
        }
        variants = combined;
    }
    Ok(variants)
}

fn intersect_ports(left: Option<(u16, u16)>, right: Option<(u16, u16)>) -> Option<(u16, u16)> {
    match (left, right) {
        (Some((left_start, left_end)), Some((right_start, right_end))) => {
            let start = left_start.max(right_start);
            let end = left_end.min(right_end);
            (start <= end).then_some((start, end))
        }
        (Some(port), None) | (None, Some(port)) => Some(port),
        (None, None) => None,
    }
}

fn parse_port_variants(value: &Value, id: &str) -> Result<Vec<RuleVariant>> {
    if let Some(values) = value.as_array() {
        let mut variants = Vec::new();
        for value in values {
            let port = parse_port(Some(value), id)?;
            variants.push(RuleVariant {
                port,
                ..Default::default()
            });
        }
        return Ok(variants);
    }
    Ok(vec![RuleVariant {
        port: parse_port(Some(value), id)?,
        ..Default::default()
    }])
}

fn parse_network_text(value: Option<&str>, id: &str) -> Result<Option<Network>> {
    let Some(value) = value else { return Ok(None) };
    match value.trim().to_ascii_lowercase().as_str() {
        "" | "any" | "all" => Ok(None),
        "tcp" => Ok(Some(Network::Tcp)),
        "udp" => Ok(Some(Network::Udp)),
        "icmp" => Ok(Some(Network::Icmp)),
        other => Err(Error::new(
            ErrorKind::Unsupported,
            format!("route rule {id} has unsupported network {other:?}"),
        )),
    }
}

fn unsupported_expression(id: &str, detail: impl std::fmt::Display) -> Error {
    Error::new(
        ErrorKind::Unsupported,
        format!("route rule {id} has unsupported {detail}"),
    )
}

fn parse_action(mode: &str, root: &Value, id: &str) -> Result<RuleAction> {
    let mode = string_field(root, &["mode", "action"]).unwrap_or_else(|| mode.to_owned());
    match mode.trim().to_ascii_lowercase().as_str() {
        "direct" => Ok(RuleAction::Direct),
        "proxy" => Ok(RuleAction::Proxy),
        "bypass" => Ok(RuleAction::Bypass),
        "drop" | "block" => Ok(RuleAction::Drop),
        other => Err(Error::new(
            ErrorKind::Unsupported,
            format!("route rule {id} has unsupported action {other:?}"),
        )),
    }
}

fn parse_network(value: Option<&Value>, id: &str) -> Result<Option<Network>> {
    let Some(value) = value else { return Ok(None) };
    let Some(value) = value.as_str() else {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!("route rule {id} network must be a string"),
        ));
    };
    match value.trim().to_ascii_lowercase().as_str() {
        "" | "any" | "all" => Ok(None),
        "tcp" => Ok(Some(Network::Tcp)),
        "udp" => Ok(Some(Network::Udp)),
        "icmp" => Ok(Some(Network::Icmp)),
        other => Err(Error::new(
            ErrorKind::Unsupported,
            format!("route rule {id} has unsupported network {other:?}"),
        )),
    }
}

fn parse_port(value: Option<&Value>, id: &str) -> Result<Option<(u16, u16)>> {
    let Some(value) = value else { return Ok(None) };
    let (start, end) = if let Some(port) = value.as_u64() {
        let port = u16::try_from(port).map_err(|_| invalid_port(id))?;
        (port, port)
    } else if let Some(range) = value.as_str() {
        let mut values = range.split('-');
        let start = values.next().and_then(|value| value.trim().parse().ok());
        let end = values.next().and_then(|value| value.trim().parse().ok());
        if values.next().is_some() || start.is_none() || end.is_none() {
            return Err(invalid_port(id));
        }
        (start.unwrap(), end.unwrap())
    } else if let Some(object) = value.as_object() {
        let start = object
            .get("start")
            .or_else(|| object.get("from"))
            .and_then(Value::as_u64)
            .and_then(|port| u16::try_from(port).ok());
        let end = object
            .get("end")
            .or_else(|| object.get("to"))
            .and_then(Value::as_u64)
            .and_then(|port| u16::try_from(port).ok());
        match (start, end) {
            (Some(start), Some(end)) => (start, end),
            _ => return Err(invalid_port(id)),
        }
    } else {
        return Err(invalid_port(id));
    };
    if start > end {
        return Err(invalid_port(id));
    }
    Ok(Some((start, end)))
}

fn parse_resolver_policy(
    root: &Value,
    matcher: &Value,
    action: RuleAction,
    id: &str,
) -> Result<ResolverPolicy> {
    let policy = root
        .get("resolverPolicy")
        .or_else(|| root.get("resolver_policy"))
        .unwrap_or(&Value::Null);
    let strategy_value = field(root, policy, &["resolve_strategy", "resolveStrategy"])
        .or_else(|| field(matcher, policy, &["resolve_strategy", "resolveStrategy"]));
    let strategy = match strategy_value {
        None => ResolveStrategy::Default,
        Some(value) => {
            let Some(value) = value.as_str() else {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!("route rule {id} resolve strategy must be a string"),
                ));
            };
            match value.trim().to_ascii_lowercase().as_str() {
                "" | "default" => ResolveStrategy::Default,
                "only_ipv4" | "onlyipv4" | "ipv4" => ResolveStrategy::OnlyIpv4,
                "prefer_ipv4" | "preferipv4" => ResolveStrategy::PreferIpv4,
                "only_ipv6" | "onlyipv6" | "ipv6" => ResolveStrategy::OnlyIpv6,
                "prefer_ipv6" | "preferipv6" => ResolveStrategy::PreferIpv6,
                other => {
                    return Err(Error::new(
                        ErrorKind::Unsupported,
                        format!("route rule {id} has unsupported resolve strategy {other:?}"),
                    ));
                }
            }
        }
    };
    let use_fake_ip = bool_field(root, policy, &["use_fake_ip", "useFakeIp"])
        .unwrap_or(action == RuleAction::Proxy);
    let fake_ip_skip_check_upstream = bool_field(
        root,
        policy,
        &[
            "fake_ip_skip_check_upstream",
            "fakeIpSkipCheckUpstream",
            "skip_check_upstream",
        ],
    )
    .unwrap_or(false);
    let udp_skip_resolve_target = bool_field(
        root,
        policy,
        &["udp_skip_resolve_target", "udpSkipResolveTarget"],
    )
    .unwrap_or(false);
    Ok(ResolverPolicy {
        strategy,
        use_fake_ip,
        fake_ip_skip_check_upstream,
        udp_skip_resolve_target,
    })
}

fn field<'a>(root: &'a Value, nested: &'a Value, keys: &[&str]) -> Option<&'a Value> {
    keys.iter()
        .find_map(|key| root.get(*key).or_else(|| nested.get(*key)))
}

fn bool_field(root: &Value, nested: &Value, keys: &[&str]) -> Option<bool> {
    field(root, nested, keys).and_then(Value::as_bool)
}

fn string_field(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        value
            .get(*key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
    })
}

fn invalid_port(id: &str) -> Error {
    Error::new(
        ErrorKind::InvalidInput,
        format!("route rule {id} has an invalid port range"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use yuhaiin_core::{Endpoint, Network};

    fn record(json: &str, mode: &str, match_type: &str) -> GoRouteRuleRecord {
        GoRouteRuleRecord {
            id: "rule-1".to_owned(),
            name: "rule-1".to_owned(),
            priority: 10,
            disabled: false,
            action_mode: mode.to_owned(),
            match_type: match_type.to_owned(),
            tag: String::new(),
            updated_at: 0,
            data_json: json.as_bytes().to_vec(),
        }
    }

    #[test]
    fn production_domain_shape_compiles_to_router() {
        let rule = route_rule_from_go_record(&record(
            r#"{"name":"production-domain","match":{"domain":"example.com"},"mode":"proxy"}"#,
            "proxy",
            "domain",
        ))
        .unwrap()
        .unwrap();
        assert_eq!(rule.pattern, "example.com");
        assert_eq!(rule.action, RuleAction::Proxy);
        assert!(rule.resolver_policy.use_fake_ip);
        let router = Router::compile(
            vec![rule],
            RouteDecision {
                mode: yuhaiin_core::RouteMode::Direct,
                resolver_policy: ResolverPolicy::default(),
                priority: 0,
            },
        )
        .unwrap();
        let endpoint = Endpoint::domain(
            Network::Tcp,
            yuhaiin_core::DomainName::new("www.example.com").unwrap(),
            443,
        );
        assert_eq!(
            router.decide(&endpoint).mode,
            yuhaiin_core::RouteMode::Proxy
        );
    }

    #[test]
    fn disabled_and_cidr_policy_are_supported() {
        let mut disabled = record(
            r#"{"match":{"domain":"disabled.example"}}"#,
            "direct",
            "domain",
        );
        disabled.disabled = true;
        assert!(route_rule_from_go_record(&disabled).unwrap().is_none());

        let rule = route_rule_from_go_record(&record(
            r#"{"match":{"cidr":"192.0.2.0/24","network":"udp","port":"53-853"},"resolveStrategy":"only_ipv4","useFakeIp":false}"#,
            "direct",
            "cidr",
        ))
        .unwrap()
        .unwrap();
        assert_eq!(rule.pattern, "192.0.2.0/24");
        assert_eq!(rule.network, Some(Network::Udp));
        assert_eq!(rule.port, Some((53, 853)));
        assert_eq!(rule.resolver_policy.strategy, ResolveStrategy::OnlyIpv4);
        assert!(!rule.resolver_policy.use_fake_ip);
    }

    #[test]
    fn unsupported_matcher_is_not_silently_dropped() {
        let error = route_rule_from_go_record(&record(
            r#"{"rules":[{"host":{"list":"domains"}}]}"#,
            "proxy",
            "all",
        ))
        .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Unsupported);
    }

    #[test]
    fn local_host_list_expands_go_nested_rule_into_router_patterns() {
        let list = GoRouteListRecord {
            name: "domains".to_owned(),
            list_type: "host".to_owned(),
            source_type: "local".to_owned(),
            updated_at: 1,
            data_json: br#"{
                "name":"domains",
                "type":"host",
                "source":{"type":"local","local":{"lists":["example.com","*.blocked.test"]}}
            }"#
            .to_vec(),
        };
        let lists = load_route_lists(&[list]);
        let router = compile_go_route_rules_with_lists(
            &[record(
                r#"{"mode":"proxy","rules":[{"type":"host","host":{"list":"domains"}}]}"#,
                "proxy",
                "all",
            )],
            &lists,
            RouteDecision {
                mode: yuhaiin_core::RouteMode::Direct,
                resolver_policy: ResolverPolicy::default(),
                priority: 100,
            },
            None,
        )
        .unwrap();
        let endpoint = Endpoint::domain(
            Network::Tcp,
            yuhaiin_core::DomainName::new("www.example.com").unwrap(),
            443,
        );
        assert_eq!(
            router.decide(&endpoint).mode,
            yuhaiin_core::RouteMode::Proxy
        );
        let wildcard = Endpoint::domain(
            Network::Tcp,
            yuhaiin_core::DomainName::new("api.blocked.test").unwrap(),
            443,
        );
        assert_eq!(
            router.decide(&wildcard).mode,
            yuhaiin_core::RouteMode::Proxy
        );
        assert!(
            lists
                .values("domains")
                .unwrap()
                .contains(&"example.com".to_owned())
        );
    }

    #[test]
    fn hosts_as_host_and_global_network_rules_match_go_shapes() {
        let list = GoRouteListRecord {
            name: "hosts".to_owned(),
            list_type: "hosts_as_host".to_owned(),
            source_type: "local".to_owned(),
            updated_at: 1,
            data_json: br#"{
                "type":"hosts_as_host",
                "source":{"type":"local","local":{"lists":["0.0.0.0 local.example alias.example"]}}
            }"#
            .to_vec(),
        };
        let lists = load_route_lists(&[list]);
        assert_eq!(
            lists.values("hosts").unwrap(),
            ["alias.example".to_owned(), "local.example".to_owned()]
        );

        let router = compile_go_route_rules_with_lists(
            &[record(
                r#"{"mode":"drop","rules":[{"type":"all","all":[{"type":"network","network":{"network":"udp"}},{"type":"port","port":{"ports":[53]}}]}]}"#,
                "drop",
                "all",
            )],
            &lists,
            RouteDecision {
                mode: yuhaiin_core::RouteMode::Direct,
                resolver_policy: ResolverPolicy::default(),
                priority: 100,
            },
            None,
        )
        .unwrap();
        let udp = Endpoint::ip(Network::Udp, "192.0.2.1:53".parse().unwrap());
        assert_eq!(router.decide(&udp).mode, yuhaiin_core::RouteMode::Block);
        let tcp = Endpoint::ip(Network::Tcp, "192.0.2.1:53".parse().unwrap());
        assert_eq!(router.decide(&tcp).mode, yuhaiin_core::RouteMode::Direct);
    }

    #[test]
    fn http_route_list_response_parser_handles_chunked_body() {
        let response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nalpha\r\n4\r\nbeta\r\n0\r\n\r\n";
        assert_eq!(parse_http_response(response).unwrap(), b"alphabeta");
        assert_eq!(
            parse_http_url("http://127.0.0.1:8080/rules?x=1").unwrap(),
            (false, "127.0.0.1".to_owned(), 8080, "/rules?x=1".to_owned())
        );
    }

    #[test]
    fn http_route_list_downloader_reads_a_local_http_server() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = [0u8; 1024];
                let _ = stream.read(&mut request).await.unwrap();
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
                    )
                    .await
                    .unwrap();
                stream.write_all(b"b\r\nexample.com\r\n0\r\n\r\n").await.unwrap();
            });
            let body = download_route_url(
                &format!("http://{address}/rules"),
                Duration::from_secs(2),
            )
            .await
            .unwrap();
            assert_eq!(body, b"example.com");
            server.await.unwrap();
        });
    }

    #[test]
    fn remote_route_list_refresh_writes_atomic_cache_used_by_snapshot_loader() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = [0u8; 1024];
                let _ = stream.read(&mut request).await.unwrap();
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\nConnection: close\r\n\r\nremote.test\n"
                    )
                    .await
                    .unwrap();
            });
            let url = format!("http://{address}/rules");
            let record = GoRouteListRecord {
                name: "remote".to_owned(),
                list_type: "host".to_owned(),
                source_type: "remote".to_owned(),
                updated_at: 1,
                data_json: serde_json::json!({
                    "name":"remote",
                    "type":"host",
                    "source":{"type":"remote","remote":{"urls":[url.clone()]}}
                })
                .to_string()
                .into_bytes(),
            };
            let cache = route_list_cache_path(&url);
            let report = refresh_route_list_caches(&[record], Duration::from_secs(2)).await;
            assert_eq!(report.refreshed, 1);
            assert!(report.errors.is_empty());
            let loaded = load_route_lists(&[GoRouteListRecord {
                name: "remote".to_owned(),
                list_type: "host".to_owned(),
                source_type: "remote".to_owned(),
                updated_at: 1,
                data_json: serde_json::json!({
                    "name":"remote",
                    "type":"host",
                    "source":{"type":"remote","remote":{"urls":[url]}}
                })
                .to_string()
                .into_bytes(),
            }]);
            assert_eq!(loaded.values("remote").unwrap(), ["remote.test"]);
            server.await.unwrap();
            let _ = fs::remove_file(cache);
        });
    }
}
