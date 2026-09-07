use super::*;

type HyperTestClient = Client<HttpConnector, Full<Bytes>>;

#[derive(Clone)]
pub struct HttpClient {
    inner: HyperTestClient,
}

pub struct HttpRequestBuilder {
    client: HyperTestClient,
    method: Method,
    url: String,
    headers: HeaderMap,
    body: Option<std::result::Result<Bytes, String>>,
}

pub struct HttpResponse {
    inner: Response<Incoming>,
}

impl HttpClient {
    pub fn new() -> Self {
        Self {
            inner: Client::builder(TokioExecutor::new()).build_http(),
        }
    }

    pub fn request(&self, method: Method, url: impl Into<String>) -> HttpRequestBuilder {
        HttpRequestBuilder {
            client: self.inner.clone(),
            method,
            url: url.into(),
            headers: HeaderMap::new(),
            body: None,
        }
    }

    pub fn get(&self, url: impl Into<String>) -> HttpRequestBuilder {
        self.request(Method::GET, url)
    }
}

impl HttpRequestBuilder {
    pub fn header(mut self, name: impl http::header::IntoHeaderName, value: &str) -> Self {
        if let Ok(value) = http::HeaderValue::try_from(value) {
            self.headers.insert(name, value);
        }
        self
    }

    pub fn json<T: serde::Serialize>(mut self, value: &T) -> Self {
        self.headers.insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/json"),
        );
        self.body = Some(
            serde_json::to_vec(value)
                .map(Bytes::from)
                .map_err(|error| error.to_string()),
        );
        self
    }

    pub async fn send(self) -> std::result::Result<HttpResponse, String> {
        let uri = self
            .url
            .parse::<http::Uri>()
            .map_err(|error| format!("invalid HTTP URL: {error}"))?;
        let mut request = Request::builder().method(self.method).uri(uri);
        for (name, value) in &self.headers {
            request = request.header(name, value);
        }
        let body = self
            .body
            .unwrap_or_else(|| Ok(Bytes::new()))
            .map_err(|error| format!("encode HTTP request body: {error}"))?;
        let request = request
            .body(Full::new(body))
            .map_err(|error| format!("build HTTP request: {error}"))?;
        let response = self
            .client
            .request(request)
            .await
            .map_err(|error| format!("HTTP request: {error}"))?;
        Ok(HttpResponse { inner: response })
    }
}

impl HttpResponse {
    pub fn status(&self) -> StatusCode {
        self.inner.status()
    }

    pub fn headers(&self) -> &HeaderMap {
        self.inner.headers()
    }

    pub async fn text(self) -> std::result::Result<String, String> {
        let body = self
            .inner
            .into_body()
            .collect()
            .await
            .map_err(|error| format!("read HTTP response: {error}"))?;
        String::from_utf8(body.to_bytes().to_vec())
            .map_err(|error| format!("decode HTTP response: {error}"))
    }

    pub async fn chunk(&mut self) -> std::result::Result<Option<Bytes>, String> {
        loop {
            let Some(frame) = self.inner.body_mut().frame().await else {
                return Ok(None);
            };
            let frame = frame.map_err(|error| format!("read HTTP response: {error}"))?;
            if let Ok(data) = frame.into_data() {
                return Ok(Some(data));
            }
        }
    }
}
