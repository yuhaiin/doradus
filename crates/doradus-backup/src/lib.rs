//! S3-compatible backup transport used by the management API.
//!
//! The Go service uses AWS Signature Version 4 through its S3 client.  This
//! crate keeps the same wire contract without pulling a C-backed SDK into the
//! desktop binary.  It intentionally exposes only the operations needed by
//! doradus: uploading and downloading one opaque SQLite object.

use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use hmac::{Hmac, Mac};
use http::header::{HeaderMap, HeaderName, HeaderValue};
use http::{Method, Request, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use hyper_util::rt::TokioExecutor;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sha2_10::Sha256 as Sha256V10;
use time::{OffsetDateTime, macros::format_description};
use url::Url;

type HmacSha256 = Hmac<Sha256V10>;

const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// Go-compatible backup S3 settings.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
#[serde(rename_all = "camelCase")]
pub struct S3Config {
    pub enabled: bool,
    pub access_key: String,
    pub secret_key: String,
    pub bucket: String,
    pub region: String,
    pub endpoint_url: String,
    pub use_path_style: bool,
    pub storage_class: String,
}

#[derive(Debug)]
pub enum Error {
    Invalid(String),
    Url(url::ParseError),
    Request(String),
    Transport(String),
    Response { status: StatusCode, body: String },
    Header(String),
    Time(time::error::Format),
}

impl Display for Error {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(message) => formatter.write_str(message),
            Self::Url(error) => write!(formatter, "S3 endpoint URL: {error}"),
            Self::Request(error) => write!(formatter, "S3 request: {error}"),
            Self::Transport(message) => write!(formatter, "S3 transport: {message}"),
            Self::Response { status, body } => {
                write!(formatter, "S3 response {status}: {body}")
            }
            Self::Header(message) => write!(formatter, "S3 request header: {message}"),
            Self::Time(error) => write!(formatter, "S3 request timestamp: {error}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<url::ParseError> for Error {
    fn from(error: url::ParseError) -> Self {
        Self::Url(error)
    }
}

impl From<time::error::Format> for Error {
    fn from(error: time::error::Format) -> Self {
        Self::Time(error)
    }
}

/// A signed request handed to a runtime-specific network transport.
///
/// The backup crate deliberately does not depend on the runtime proxy graph.
/// A desktop runtime can therefore route this request through its selected
/// HTTP/SOCKS5/TLS/HTTP2/Yuubinsya outbound while tests can provide a tiny
/// in-process transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S3Request {
    pub method: String,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub path_and_query: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S3Response {
    pub status: u16,
    pub body: Vec<u8>,
}

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub trait S3Transport: Send + Sync {
    fn execute<'a>(&'a self, request: S3Request) -> BoxFuture<'a, Result<S3Response, Error>>;
}

struct SignedRequest {
    method: Method,
    url: Url,
    headers: HeaderMap,
    transport: S3Request,
    body: Vec<u8>,
}

type S3HttpClient = Client<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>>;

#[derive(Clone)]
pub struct S3Client {
    client: S3HttpClient,
    config: S3Config,
    endpoint: Url,
    transport: Option<Arc<dyn S3Transport>>,
}

impl S3Client {
    pub fn new(config: S3Config) -> Result<Self, Error> {
        Self::build(config, None)
    }

    pub fn with_transport(
        config: S3Config,
        transport: Arc<dyn S3Transport>,
    ) -> Result<Self, Error> {
        Self::build(config, Some(transport))
    }

    fn build(config: S3Config, transport: Option<Arc<dyn S3Transport>>) -> Result<Self, Error> {
        if !config.enabled {
            return Err(Error::Invalid("S3 backup is disabled".to_owned()));
        }
        if config.access_key.trim().is_empty() || config.secret_key.is_empty() {
            return Err(Error::Invalid(
                "S3 backup requires accessKey and secretKey".to_owned(),
            ));
        }
        if config.bucket.trim().is_empty() {
            return Err(Error::Invalid("S3 backup requires bucket".to_owned()));
        }
        let region = if config.region.trim().is_empty() {
            "us-east-1"
        } else {
            config.region.trim()
        };
        let endpoint = if config.endpoint_url.trim().is_empty() {
            Url::parse(&format!("https://s3.{region}.amazonaws.com"))?
        } else {
            Url::parse(config.endpoint_url.trim())?
        };
        let _ = rustls::crypto::ring::default_provider().install_default();
        let https = HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .build();
        let client = Client::builder(TokioExecutor::new()).build(https);
        Ok(Self {
            client,
            config,
            endpoint,
            transport,
        })
    }

    fn http_request(&self, signed: SignedRequest) -> Result<Request<Full<Bytes>>, Error> {
        let mut builder = Request::builder()
            .method(signed.method)
            .uri(signed.url.as_str());
        for (name, value) in &signed.headers {
            builder = builder.header(name, value);
        }
        builder
            .header("user-agent", "doradus-backup")
            .body(Full::new(Bytes::from(signed.body)))
            .map_err(|error| Error::Request(format!("build S3 request: {error}")))
    }

    async fn send(
        &self,
        request: Request<Full<Bytes>>,
    ) -> Result<hyper::Response<Incoming>, Error> {
        tokio::time::timeout(Duration::from_secs(30), self.client.request(request))
            .await
            .map_err(|_| Error::Request("S3 request timed out".to_owned()))?
            .map_err(|error| Error::Request(error.to_string()))
    }

    pub async fn put(&self, object: &str, body: &[u8]) -> Result<(), Error> {
        let signed = self.signed_request(Method::PUT, object, body)?;
        if let Some(transport) = &self.transport {
            let response = transport.execute(signed.transport).await?;
            return ensure_transport_success(response).map(|_| ());
        }
        let response = self.send(self.http_request(signed)?).await?;
        ensure_success(response).await
    }

    pub async fn get(&self, object: &str) -> Result<Vec<u8>, Error> {
        let signed = self.signed_request(Method::GET, object, &[])?;
        if let Some(transport) = &self.transport {
            let response = transport.execute(signed.transport).await?;
            return ensure_transport_success(response).map(|response| response.body);
        }
        let response = self.send(self.http_request(signed)?).await?;
        let response = ensure_success_response(response).await?;
        Ok(response
            .into_body()
            .collect()
            .await
            .map_err(|error| Error::Request(format!("read S3 response: {error}")))?
            .to_bytes()
            .to_vec())
    }

    fn signed_request(
        &self,
        method: Method,
        object: &str,
        body: &[u8],
    ) -> Result<SignedRequest, Error> {
        if object.is_empty() || object.starts_with('/') {
            return Err(Error::Invalid("S3 object key is invalid".to_owned()));
        }
        let region = if self.config.region.trim().is_empty() {
            "us-east-1"
        } else {
            self.config.region.trim()
        };
        let (url, canonical_uri) = self.object_url(object)?;
        let now = OffsetDateTime::now_utc();
        let amz_date = now.format(&format_description!(
            "[year][month][day]T[hour][minute][second]Z"
        ))?;
        let short_date = now.format(&format_description!("[year][month][day]"))?;
        let payload_hash = if body.is_empty() {
            EMPTY_SHA256.to_owned()
        } else {
            sha256_hex(body)
        };
        let host = host_header(&url)?;
        let mut headers = BTreeMap::new();
        headers.insert("host".to_owned(), host.clone());
        headers.insert("x-amz-content-sha256".to_owned(), payload_hash.clone());
        headers.insert("x-amz-date".to_owned(), amz_date.clone());
        if method == Method::PUT {
            headers.insert(
                "content-type".to_owned(),
                "application/octet-stream".to_owned(),
            );
        }
        if !self.config.storage_class.trim().is_empty() && method == Method::PUT {
            headers.insert(
                "x-amz-storage-class".to_owned(),
                self.config.storage_class.trim().to_owned(),
            );
        }
        let signed_headers = headers.keys().cloned().collect::<Vec<_>>().join(";");
        let canonical_headers = headers
            .iter()
            .map(|(name, value)| format!("{name}:{}\n", normalize_header(value)))
            .collect::<String>();
        let canonical_request = format!(
            "{}\n{}\n\n{}\n{}\n{}",
            method, canonical_uri, canonical_headers, signed_headers, payload_hash
        );
        let scope = format!("{short_date}/{region}/s3/aws4_request");
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
            sha256_hex(canonical_request.as_bytes())
        );
        let signing_key = signing_key(&self.config.secret_key, &short_date, region);
        let signature = hex_lower(&hmac_sha256(&signing_key, string_to_sign.as_bytes()));
        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",
            self.config.access_key
        );

        let mut request_headers = HeaderMap::new();
        insert_header(&mut request_headers, "host", &host)?;
        insert_header(&mut request_headers, "x-amz-content-sha256", &payload_hash)?;
        insert_header(&mut request_headers, "x-amz-date", &amz_date)?;
        insert_header(&mut request_headers, "authorization", &authorization)?;
        if let Some(content_type) = headers.get("content-type") {
            insert_header(&mut request_headers, "content-type", content_type)?;
        }
        if let Some(storage_class) = headers.get("x-amz-storage-class") {
            insert_header(&mut request_headers, "x-amz-storage-class", storage_class)?;
        }
        let port = url
            .port_or_known_default()
            .ok_or_else(|| Error::Invalid("S3 endpoint port is missing".to_owned()))?;
        let path_and_query = match url.query() {
            Some(query) => format!("{}?{query}", url.path()),
            None => url.path().to_owned(),
        };
        let transport_headers = request_headers
            .iter()
            .map(|(name, value)| {
                Ok::<_, Error>((
                    name.as_str().to_owned(),
                    value
                        .to_str()
                        .map_err(|error| Error::Header(error.to_string()))?
                        .to_owned(),
                ))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let transport = S3Request {
            method: method.as_str().to_owned(),
            scheme: url.scheme().to_owned(),
            host: url
                .host_str()
                .ok_or_else(|| Error::Invalid("S3 endpoint host is missing".to_owned()))?
                .to_owned(),
            port,
            path_and_query,
            headers: transport_headers,
            body: body.to_vec(),
        };
        Ok(SignedRequest {
            method,
            url,
            headers: request_headers,
            transport,
            body: body.to_vec(),
        })
    }

    fn object_url(&self, object: &str) -> Result<(Url, String), Error> {
        let bucket = encode_path_component(self.config.bucket.trim());
        let object_path = encode_object_key(object);
        let base_path = self.endpoint.path().trim_end_matches('/');
        let (path, mut url) = if self.config.use_path_style {
            let path = format!("{base_path}/{bucket}/{object_path}");
            (path, self.endpoint.clone())
        } else {
            let mut url = self.endpoint.clone();
            let host = url
                .host_str()
                .ok_or_else(|| Error::Invalid("S3 endpoint host is missing".to_owned()))?;
            let bucket_host = format!("{bucket}.{host}");
            url.set_host(Some(&bucket_host))
                .map_err(|_| Error::Invalid("S3 bucket host is invalid".to_owned()))?;
            let path = format!("{base_path}/{object_path}");
            (path, url)
        };
        if path.is_empty() {
            return Err(Error::Invalid("S3 object path is empty".to_owned()));
        }
        url.set_path(&path);
        Ok((url, path))
    }
}

async fn ensure_success(response: hyper::Response<Incoming>) -> Result<(), Error> {
    ensure_success_response(response).await.map(|_| ())
}

fn ensure_transport_success(response: S3Response) -> Result<S3Response, Error> {
    if (200..300).contains(&response.status) {
        return Ok(response);
    }
    Err(Error::Response {
        status: StatusCode::from_u16(response.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        body: String::from_utf8_lossy(&response.body)
            .chars()
            .take(1024)
            .collect(),
    })
}

async fn ensure_success_response(
    response: hyper::Response<Incoming>,
) -> Result<hyper::Response<Incoming>, Error> {
    if response.status().is_success() {
        return Ok(response);
    }
    let status = response.status();
    let body = response
        .into_body()
        .collect()
        .await
        .map(|body| String::from_utf8_lossy(&body.to_bytes()).into_owned())
        .unwrap_or_else(|_| "<unreadable response>".to_owned());
    Err(Error::Response {
        status,
        body: body.chars().take(1024).collect(),
    })
}

fn insert_header(headers: &mut HeaderMap, name: &str, value: &str) -> Result<(), Error> {
    let name = HeaderName::from_bytes(name.as_bytes())
        .map_err(|error| Error::Header(error.to_string()))?;
    let value = HeaderValue::from_str(value).map_err(|error| Error::Header(error.to_string()))?;
    headers.insert(name, value);
    Ok(())
}

fn host_header(url: &Url) -> Result<String, Error> {
    let host = url
        .host_str()
        .ok_or_else(|| Error::Invalid("S3 endpoint host is missing".to_owned()))?;
    match url.port() {
        Some(port) => Ok(format!("{host}:{port}")),
        None => Ok(host.to_owned()),
    }
}

fn normalize_header(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn signing_key(secret: &str, date: &str, region: &str) -> Vec<u8> {
    let date_key = hmac_sha256(format!("AWS4{secret}").as_bytes(), date.as_bytes());
    let region_key = hmac_sha256(&date_key, region.as_bytes());
    let service_key = hmac_sha256(&region_key, b"s3");
    hmac_sha256(&service_key, b"aws4_request")
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut hmac = HmacSha256::new_from_slice(key).expect("HMAC accepts arbitrary keys");
    hmac.update(data);
    hmac.finalize().into_bytes().to_vec()
}

fn sha256_hex(data: &[u8]) -> String {
    hex_lower(&Sha256::digest(data))
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn encode_object_key(object: &str) -> String {
    object
        .split('/')
        .map(encode_path_component)
        .collect::<Vec<_>>()
        .join("/")
}

fn encode_path_component(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut output = String::new();
    for byte in value.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            output.push(*byte as char);
        } else {
            output.push('%');
            output.push(HEX[(byte >> 4) as usize] as char);
            output.push(HEX[(byte & 0x0f) as usize] as char);
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::{Arc, Mutex};
    use std::thread;

    #[derive(Debug)]
    struct CapturedRequest {
        method: String,
        path: String,
        headers: BTreeMap<String, String>,
        body: Vec<u8>,
    }

    fn read_request(stream: &mut TcpStream) -> CapturedRequest {
        let mut bytes = Vec::new();
        let header_end = loop {
            let mut chunk = [0_u8; 4096];
            let count = stream.read(&mut chunk).unwrap();
            assert!(count > 0, "client closed before sending request headers");
            bytes.extend_from_slice(&chunk[..count]);
            if let Some(index) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
                break index;
            }
        };
        let header_text = std::str::from_utf8(&bytes[..header_end]).unwrap();
        let mut lines = header_text.split("\r\n");
        let mut request_line = lines.next().unwrap().split_whitespace();
        let method = request_line.next().unwrap().to_owned();
        let path = request_line.next().unwrap().to_owned();
        let headers = lines
            .filter_map(|line| {
                let (name, value) = line.split_once(':')?;
                Some((name.to_ascii_lowercase(), value.trim().to_owned()))
            })
            .collect::<BTreeMap<_, _>>();
        let content_length = headers
            .get("content-length")
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(0);
        let body_start = header_end + 4;
        while bytes.len() < body_start + content_length {
            let mut chunk = [0_u8; 4096];
            let count = stream.read(&mut chunk).unwrap();
            assert!(count > 0, "client closed before sending request body");
            bytes.extend_from_slice(&chunk[..count]);
        }
        CapturedRequest {
            method,
            path,
            headers,
            body: bytes[body_start..body_start + content_length].to_vec(),
        }
    }

    fn write_response(stream: &mut TcpStream, body: &[u8]) {
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .unwrap();
        stream.write_all(body).unwrap();
        stream.flush().unwrap();
    }

    #[test]
    fn aws_example_signing_key_matches_known_vector() {
        let key = signing_key(
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "20150830",
            "us-east-1",
        );
        assert_eq!(
            hex_lower(&key),
            "32f78051dcde24c552811d654f4a769112bb834b03975cdd6b1fd7d16248c269"
        );
    }

    #[test]
    fn object_paths_encode_key_segments_and_support_path_style() {
        let config = S3Config {
            enabled: true,
            access_key: "a".to_owned(),
            secret_key: "b".to_owned(),
            bucket: "my.bucket".to_owned(),
            region: "us-east-1".to_owned(),
            endpoint_url: "http://127.0.0.1:9000/base".to_owned(),
            use_path_style: true,
            storage_class: String::new(),
        };
        let client = S3Client::new(config).unwrap();
        let (url, canonical) = client.object_url("instance/state file.db").unwrap();
        assert_eq!(canonical, "/base/my.bucket/instance/state%20file.db");
        assert_eq!(url.path(), canonical);
    }

    #[test]
    fn s3_config_round_trips_go_camel_case_fields() {
        let config = S3Config {
            enabled: true,
            access_key: "key".to_owned(),
            secret_key: "secret".to_owned(),
            bucket: "bucket".to_owned(),
            region: "eu-west-1".to_owned(),
            endpoint_url: "https://s3.example".to_owned(),
            use_path_style: true,
            storage_class: "STANDARD_IA".to_owned(),
        };
        let json = serde_json::to_value(&config).unwrap();
        assert_eq!(json["accessKey"], "key");
        assert_eq!(json["endpointUrl"], "https://s3.example");
        assert_eq!(serde_json::from_value::<S3Config>(json).unwrap(), config);
    }

    #[test]
    fn rejects_disabled_or_incomplete_s3_config_before_network_use() {
        let mut config = S3Config::default();
        assert!(matches!(
            S3Client::new(config.clone()),
            Err(Error::Invalid(message)) if message == "S3 backup is disabled"
        ));

        config.enabled = true;
        assert!(matches!(
            S3Client::new(config.clone()),
            Err(Error::Invalid(message)) if message == "S3 backup requires accessKey and secretKey"
        ));

        config.access_key = "access".to_owned();
        config.secret_key = "secret".to_owned();
        assert!(matches!(
            S3Client::new(config.clone()),
            Err(Error::Invalid(message)) if message == "S3 backup requires bucket"
        ));

        config.bucket = "bucket".to_owned();
        config.endpoint_url = "not a URL".to_owned();
        assert!(matches!(S3Client::new(config), Err(Error::Url(_))));
    }

    #[test]
    fn rejects_empty_or_absolute_object_keys_before_signing() {
        let client = S3Client::new(S3Config {
            enabled: true,
            access_key: "access".to_owned(),
            secret_key: "secret".to_owned(),
            bucket: "bucket".to_owned(),
            region: "us-east-1".to_owned(),
            endpoint_url: "http://s3.example".to_owned(),
            use_path_style: true,
            storage_class: String::new(),
        })
        .unwrap();
        for object in ["", "/absolute.db"] {
            assert!(matches!(
                client.signed_request(Method::GET, object, &[]),
                Err(Error::Invalid(message)) if message == "S3 object key is invalid"
            ));
        }
    }

    #[derive(Clone)]
    struct CaptureTransport {
        requests: Arc<Mutex<Vec<S3Request>>>,
    }

    impl S3Transport for CaptureTransport {
        fn execute<'a>(&'a self, request: S3Request) -> BoxFuture<'a, Result<S3Response, Error>> {
            let requests = Arc::clone(&self.requests);
            Box::pin(async move {
                let is_get = request.method == "GET";
                requests.lock().unwrap().push(request);
                Ok(S3Response {
                    status: 200,
                    body: if is_get {
                        b"transport-body".to_vec()
                    } else {
                        Vec::new()
                    },
                })
            })
        }
    }

    #[tokio::test]
    async fn injected_transport_receives_signed_request_and_returns_body() {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let client = S3Client::with_transport(
            S3Config {
                enabled: true,
                access_key: "access".to_owned(),
                secret_key: "secret".to_owned(),
                bucket: "bucket".to_owned(),
                region: "us-east-1".to_owned(),
                endpoint_url: "http://s3.example/base".to_owned(),
                use_path_style: true,
                storage_class: "STANDARD".to_owned(),
            },
            Arc::new(CaptureTransport {
                requests: Arc::clone(&requests),
            }),
        )
        .unwrap();

        client.put("instance-state.db", b"snapshot").await.unwrap();
        assert_eq!(
            client.get("instance-state.db").await.unwrap(),
            b"transport-body"
        );

        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].method, "PUT");
        assert_eq!(requests[0].path_and_query, "/base/bucket/instance-state.db");
        assert_eq!(requests[0].host, "s3.example");
        assert_eq!(requests[0].body, b"snapshot");
        assert!(
            requests[0]
                .headers
                .iter()
                .any(|(name, value)| name == "authorization"
                    && value.starts_with("AWS4-HMAC-SHA256 "))
        );
        assert_eq!(requests[1].method, "GET");
        assert!(requests[1].body.is_empty());
    }

    #[test]
    fn injected_transport_errors_keep_s3_status_and_body() {
        let error = ensure_transport_success(S3Response {
            status: 503,
            body: b"temporarily unavailable".to_vec(),
        })
        .unwrap_err();
        assert!(
            matches!(error, Error::Response { status, body } if status == StatusCode::SERVICE_UNAVAILABLE && body == "temporarily unavailable")
        );

        let error = ensure_transport_success(S3Response {
            status: 500,
            body: vec![b'x'; 2048],
        })
        .unwrap_err();
        assert!(
            matches!(error, Error::Response { body, .. } if body.len() == 1024 && body.chars().all(|value| value == 'x'))
        );
    }

    #[tokio::test]
    async fn put_and_get_use_s3_signature_and_opaque_sqlite_body() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let mut requests = Vec::new();
            let mut uploaded = Vec::new();
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                let request = read_request(&mut stream);
                if request.method == "PUT" {
                    uploaded = request.body.clone();
                    write_response(&mut stream, &[]);
                } else {
                    write_response(&mut stream, &uploaded);
                }
                requests.push(request);
            }
            requests
        });

        let body = b"SQLite format 3\0opaque state snapshot";
        let client = S3Client::new(S3Config {
            enabled: true,
            access_key: "access".to_owned(),
            secret_key: "secret".to_owned(),
            bucket: "bucket".to_owned(),
            region: "us-east-1".to_owned(),
            endpoint_url: format!("http://{address}/base"),
            use_path_style: true,
            storage_class: "STANDARD".to_owned(),
        })
        .unwrap();
        client.put("instance/state.db", body).await.unwrap();
        assert_eq!(client.get("instance/state.db").await.unwrap(), body);

        let requests = server.join().unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].method, "PUT");
        assert_eq!(requests[0].path, "/base/bucket/instance/state.db");
        assert_eq!(requests[0].body, body);
        assert_eq!(
            requests[0].headers.get("x-amz-content-sha256"),
            Some(&sha256_hex(body))
        );
        assert_eq!(
            requests[0].headers.get("content-type"),
            Some(&"application/octet-stream".to_owned())
        );
        assert_eq!(
            requests[0].headers.get("x-amz-storage-class"),
            Some(&"STANDARD".to_owned())
        );
        assert!(
            requests[0]
                .headers
                .get("authorization")
                .is_some_and(|value| value.starts_with("AWS4-HMAC-SHA256 "))
        );
        assert_eq!(requests[1].method, "GET");
        assert_eq!(requests[1].path, "/base/bucket/instance/state.db");
        assert!(requests[1].body.is_empty());
    }
}
