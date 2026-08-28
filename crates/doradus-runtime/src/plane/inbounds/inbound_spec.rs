use super::*;

impl InboundSpec {
    pub(crate) fn from_record(record: GoInboundRecord) -> Result<Self> {
        let value: serde_json::Value = serde_json::from_slice(&record.data_json)
            .map_err(|error| Error::new(ErrorKind::Protocol, format!("inbound JSON: {error}")))?;
        let protocol = value
            .pointer("/protocol/type")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(record.protocol_type.as_str())
            .to_owned();
        let protocol = normalize_inbound_protocol(&protocol);
        let network_type = value
            .pointer("/network/type")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(record.network_type.as_str());
        let protocol_value = value.pointer("/protocol").cloned().unwrap_or_default();
        let section = protocol_value
            .get(&protocol)
            .or_else(|| match protocol.as_str() {
                "mixed" => protocol_value.get("mix"),
                "reverse_http" => protocol_value.get("reverseHttp"),
                "reverse_tcp" => protocol_value.get("reverseTcp"),
                _ => None,
            })
            .cloned()
            .unwrap_or_default();
        if !network_type.eq_ignore_ascii_case("tcp_udp")
            && !network_type.eq_ignore_ascii_case("empty")
        {
            return Err(Error::new(
                ErrorKind::Unsupported,
                format!("inbound network {network_type:?} is not a TCP listener"),
            ));
        }
        let listen_text = if network_type.eq_ignore_ascii_case("empty") {
            section
                .get("host")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("")
        } else {
            value
                .pointer("/network/tcp_udp/host")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("")
        };
        let listen = parse_listen_addr(listen_text)?;
        let udp_mode = if network_type.eq_ignore_ascii_case("empty") {
            if protocol.eq_ignore_ascii_case("tproxy") {
                UdpMode::Enabled
            } else {
                UdpMode::Disabled
            }
        } else {
            UdpMode::from_value(value.pointer("/network/tcp_udp/udp"))
        };
        let username = section
            .get("username")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let password = section
            .get("password")
            .or_else(|| section.get("uuid"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let protocol_udp = section
            .get("udp")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let transports: Vec<String> =
            serde_json::from_slice::<Vec<serde_json::Value>>(&record.transport_types_json)
                .unwrap_or_default()
                .into_iter()
                .filter_map(|transport| {
                    transport
                        .get("type")
                        .and_then(serde_json::Value::as_str)
                        .or_else(|| transport.as_str())
                        .map(ToOwned::to_owned)
                })
                .collect();
        let (aead_password, aead_method) = parse_aead_transport(&value, &transports)?;
        let reverse_target = if protocol.eq_ignore_ascii_case("reverse_tcp") {
            let target = section
                .get("host")
                .or_else(|| section.get("target"))
                .and_then(serde_json::Value::as_str)
                .filter(|target| !target.trim().is_empty())
                .ok_or_else(|| {
                    Error::new(
                        ErrorKind::InvalidInput,
                        "reverse_tcp inbound target is missing",
                    )
                })?;
            Some(doradus_protocol::http_server::parse_authority(
                target,
                doradus_core::Network::Tcp,
            )?)
        } else {
            None
        };
        let reverse_http = if protocol.eq_ignore_ascii_case("reverse_http") {
            let url = section
                .get("url")
                .or_else(|| section.get("URL"))
                .and_then(serde_json::Value::as_str)
                .filter(|url| !url.trim().is_empty())
                .ok_or_else(|| {
                    Error::new(
                        ErrorKind::InvalidInput,
                        "reverse_http inbound URL is missing",
                    )
                })?;
            Some(parse_reverse_http_config(url)?)
        } else {
            None
        };
        Ok(Self {
            id: record.id,
            name: record.name,
            protocol,
            listen,
            username,
            password,
            auth: None,
            udp_mode,
            protocol_udp,
            transports,
            aead_password,
            aead_method,
            outbound_id: String::new(),
            reverse_target,
            reverse_http,
        })
    }

    pub(crate) fn annotate_context(&self, context: &mut FlowContext) {
        self.annotate_context_with_process_resolver(context, inbound_process_resolver());
    }

    pub(crate) fn annotate_context_with_process_resolver(
        &self,
        context: &mut FlowContext,
        resolver: Option<&dyn ProcessResolver>,
    ) {
        let inbound = if context.network == doradus_core::Network::Tcp
            && self.listen.ip().is_unspecified()
            && self.listen.ip().is_ipv4()
        {
            // Go's dual-stack net.Listen canonicalizes an IPv4 wildcard to
            // the IPv6 wildcard in Listener.Addr(). Keep the public contract
            // stable while local_addr remains the actual endpoint used by
            // loopback protection.
            format!("[::]:{}", self.listen.port())
        } else {
            self.listen.to_string()
        };
        context.inbound = Some(inbound);
        context.inbound_name = Some(if self.name.trim().is_empty() {
            self.id.clone()
        } else {
            self.name.clone()
        });
        if context.local_addr.is_none() {
            context.local_addr = Some(Endpoint::ip(context.network, self.listen));
        }
        if self.transports.iter().any(|transport| {
            transport.eq_ignore_ascii_case("tls") || transport.eq_ignore_ascii_case("tls_auto")
        }) {
            // Go's inbound sniffer observes the raw connection before the
            // TLS listener unwraps it, so TLS has precedence over the
            // application protocol carried inside the encrypted stream.
            context.protocol = Some("tls".to_owned());
        }
        if !self.outbound_id.is_empty() {
            context.outbound = Some(self.outbound_id.clone());
        }
        let Some(resolver) = resolver else {
            return;
        };
        let Some(source) = context.source.as_ref().and_then(Endpoint::addr) else {
            return;
        };
        if context.process.is_some() && context.process_id.is_some() && context.user_id.is_some() {
            return;
        }
        if let Ok(Some(process)) = resolver.resolve(context.network, source, self.listen) {
            if context.process.is_none() {
                context.process = Some(process.path);
            }
            if context.process_id.is_none() {
                context.process_id = Some(process.pid);
            }
            if context.user_id.is_none() {
                context.user_id = Some(process.uid);
            }
        }
    }
}

pub(crate) fn parse_aead_transport(
    value: &serde_json::Value,
    transports: &[String],
) -> Result<(Option<String>, doradus_protocol::aead::CryptoMethod)> {
    if !has_transport(transports, "aead") {
        return Ok((None, doradus_protocol::aead::CryptoMethod::Chacha20Poly1305));
    }
    let transport = value
        .get("transports")
        .or_else(|| value.get("transport"))
        .and_then(serde_json::Value::as_array)
        .and_then(|items| {
            items.iter().find(|item| {
                item.get("type")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|kind| kind.eq_ignore_ascii_case("aead"))
            })
        })
        .ok_or_else(|| Error::invalid("AEAD transport configuration is missing"))?;
    let config = transport
        .get("aead")
        .or_else(|| transport.get("config"))
        .unwrap_or(transport);
    let password = config
        .get("password")
        .and_then(serde_json::Value::as_str)
        .filter(|password| !password.is_empty())
        .ok_or_else(|| Error::invalid("AEAD transport password is empty"))?
        .to_owned();
    let method = config
        .get("cryptoMethod")
        .or_else(|| config.get("crypto_method"))
        .and_then(serde_json::Value::as_str)
        .map(doradus_protocol::aead::CryptoMethod::parse)
        .unwrap_or(doradus_protocol::aead::CryptoMethod::Chacha20Poly1305);
    Ok((Some(password), method))
}

/// Apply the stream transports which precede an application listener.
///
/// Go composes contract transports in declaration order. In the supported
/// desktop combinations TLS and AEAD are stream wrappers, while HTTP/2 and
/// WebSocket consume the resulting stream as their application transport.
/// Keeping this boundary shared is important: AEAD must be removed before
/// both the HTTP/2 and WebSocket handshakes, not only before the plain TCP
/// protocol path.
pub(crate) fn transport_index(transports: &[String], kind: &str) -> Option<usize> {
    transports
        .iter()
        .position(|transport| transport.eq_ignore_ascii_case(kind))
}

pub(crate) fn aead_before_tls(transports: &[String]) -> bool {
    transport_index(transports, "aead")
        .zip(transports.iter().position(|transport| {
            transport.eq_ignore_ascii_case("tls") || transport.eq_ignore_ascii_case("tls_auto")
        }))
        .is_some_and(|(aead, tls)| aead < tls)
}

pub(crate) async fn apply_inbound_aead(
    stream: BoxAsyncStream,
    spec: &InboundSpec,
) -> Result<BoxAsyncStream> {
    let Some(password) = spec.aead_password.as_deref() else {
        return Ok(stream);
    };
    if let Some(auth) = spec.auth.as_ref() {
        let passwords = auth.inbound_passwords();
        if passwords.is_empty() {
            doradus_protocol::aead::server(stream, password.as_bytes(), spec.aead_method).await
        } else {
            doradus_protocol::aead::server_with_passwords(stream, &passwords, spec.aead_method)
                .await
        }
    } else {
        doradus_protocol::aead::server(stream, password.as_bytes(), spec.aead_method).await
    }
}

pub(crate) async fn prepare_inbound_stream<S>(
    stream: S,
    spec: &InboundSpec,
    tls_acceptor: Option<InboundTlsAcceptor>,
    require_h2_alpn: bool,
) -> Result<BoxAsyncStream>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let aead_is_before_tls = aead_before_tls(&spec.transports);
    let mut stream: BoxAsyncStream = Box::new(stream);

    // Go wraps the listener in declaration order, so Accept unwraps the
    // outermost transport first. Usually TLS is declared before AEAD, but
    // preserve the inverse order too for configs that intentionally put TLS
    // outside AEAD.
    if aead_is_before_tls {
        stream = apply_inbound_aead(stream, spec).await?;
    }

    #[cfg(feature = "doh-tls")]
    if let Some(acceptor) = tls_acceptor {
        let tls_stream = acceptor.accept(stream).await.map_err(|error| {
            Error::new(
                ErrorKind::Protocol,
                format!("inbound TLS handshake: {error}"),
            )
        })?;
        if require_h2_alpn && tls_stream.get_ref().1.alpn_protocol() != Some(b"h2") {
            return Err(Error::new(
                ErrorKind::Protocol,
                "inbound HTTP/2 TLS did not negotiate ALPN h2",
            ));
        }
        stream = Box::new(tls_stream);
    }
    #[cfg(not(feature = "doh-tls"))]
    {
        let _ = (tls_acceptor, require_h2_alpn);
    }

    if !aead_is_before_tls {
        stream = apply_inbound_aead(stream, spec).await?;
    }
    Ok(stream)
}

pub(crate) fn parse_listen_addr(value: &str) -> Result<SocketAddr> {
    let value = value.trim();
    let value = if value.starts_with(':') {
        format!("0.0.0.0{value}")
    } else {
        value.to_owned()
    };
    value.parse().map_err(|error| {
        Error::new(
            ErrorKind::InvalidInput,
            format!("inbound listen address: {error}"),
        )
    })
}

pub(crate) fn parse_reverse_http_config(value: &str) -> Result<ReverseHttpConfig> {
    let value = value.trim();
    let (https, rest) = if let Some(rest) = value.strip_prefix("http://") {
        (false, rest)
    } else if let Some(rest) = value.strip_prefix("https://") {
        (true, rest)
    } else {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "reverse_http URL must use http:// or https://",
        ));
    };
    let (authority, path) = rest.split_once('/').unwrap_or((rest, "/"));
    if authority.is_empty() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "reverse_http URL has no target authority",
        ));
    }
    let default_port = if https { 443 } else { 80 };
    let target = doradus_protocol::http_server::parse_authority_with_default(
        authority,
        doradus_core::Network::Tcp,
        Some(default_port),
    )?;
    let path = format!("/{}", path.trim_start_matches('/'));
    Ok(ReverseHttpConfig {
        target,
        path,
        authority: authority.to_owned(),
        https,
    })
}

pub(crate) fn build_inbound_tls_acceptor(
    data_json: &[u8],
    transports: &[String],
) -> Result<Option<InboundTlsAcceptor>> {
    #[cfg(not(feature = "doh-tls"))]
    {
        let _ = data_json;
        if has_transport(transports, "tls") || has_transport(transports, "tls_auto") {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "inbound TLS transport requires the doh-tls feature",
            ));
        }
        return Ok(None);
    }

    #[cfg(feature = "doh-tls")]
    {
        doradus_protocol::tls_server::build(data_json, transports)
    }
}
