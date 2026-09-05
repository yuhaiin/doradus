use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum InboundProtocolKind {
    Socks4a,
    Socks5,
    Http,
    ReverseTcp,
    ReverseHttp,
    Mixed,
    Trojan,
    Vless,
    Yuubinsya,
    Tproxy,
    Redir,
    None,
    Other(String),
}

impl InboundProtocolKind {
    pub(crate) fn compile(value: &str) -> Self {
        match normalize_inbound_protocol(value).as_str() {
            "socks4a" => Self::Socks4a,
            "socks5" => Self::Socks5,
            "http" => Self::Http,
            "reverse_tcp" => Self::ReverseTcp,
            "reverse_http" => Self::ReverseHttp,
            "mixed" => Self::Mixed,
            "trojan" => Self::Trojan,
            "vless" => Self::Vless,
            "yuubinsya" => Self::Yuubinsya,
            "tproxy" => Self::Tproxy,
            "redir" => Self::Redir,
            "none" => Self::None,
            other => Self::Other(other.to_owned()),
        }
    }

    pub(crate) fn is_transparent(&self) -> bool {
        matches!(self, Self::Tproxy | Self::Redir)
    }

    pub(crate) fn is_tproxy(&self) -> bool {
        matches!(self, Self::Tproxy)
    }

    pub(crate) fn is_password_hash_protocol(&self) -> bool {
        matches!(self, Self::Yuubinsya | Self::Trojan)
    }

    #[cfg(test)]
    pub(crate) fn supports_socks5_udp(&self, protocol_udp: bool) -> bool {
        matches!(self, Self::Mixed) || matches!(self, Self::Socks5) && protocol_udp
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct InboundTransportPlan {
    pub(crate) websocket: bool,
    pub(crate) http2: bool,
    pub(crate) tls: bool,
    pub(crate) aead: Option<InboundAeadPlan>,
    pub(crate) unsupported: bool,
    pub(crate) transparent_unsupported: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct InboundAeadPlan {
    pub(crate) password: String,
    pub(crate) method: doradus_protocol::aead::CryptoMethod,
}

#[derive(Debug, Clone)]
pub(crate) enum InboundProtocolPlan {
    Socks5 { udp: bool },
    Mixed,
    Trojan { password: String },
    Vless { uuid: String },
    Yuubinsya { password: String },
    ReverseTcp { target: Endpoint },
    ReverseHttp { config: ReverseHttpConfig },
    Other,
}

impl InboundProtocolPlan {
    pub(crate) fn compile(kind: &InboundProtocolKind, spec: &InboundSpec) -> Self {
        match kind {
            InboundProtocolKind::Socks5 => Self::Socks5 {
                udp: spec.protocol_udp,
            },
            InboundProtocolKind::Mixed => Self::Mixed,
            InboundProtocolKind::Trojan => Self::Trojan {
                password: spec.password.clone(),
            },
            InboundProtocolKind::Vless => Self::Vless {
                uuid: spec.password.clone(),
            },
            InboundProtocolKind::Yuubinsya => Self::Yuubinsya {
                password: spec.password.clone(),
            },
            InboundProtocolKind::ReverseTcp => spec
                .reverse_target
                .clone()
                .map(|target| Self::ReverseTcp { target })
                .unwrap_or(Self::Other),
            InboundProtocolKind::ReverseHttp => spec
                .reverse_http
                .clone()
                .map(|config| Self::ReverseHttp { config })
                .unwrap_or(Self::Other),
            _ => Self::Other,
        }
    }

    pub(crate) fn supports_socks5_udp(&self) -> bool {
        matches!(self, Self::Mixed | Self::Socks5 { udp: true })
    }

    pub(crate) fn password(&self) -> Option<&str> {
        match self {
            Self::Trojan { password } | Self::Yuubinsya { password } => Some(password),
            _ => None,
        }
    }

    pub(crate) fn vless_uuid(&self) -> Option<&str> {
        match self {
            Self::Vless { uuid } => Some(uuid),
            _ => None,
        }
    }

    pub(crate) fn reverse_target(&self) -> Option<&Endpoint> {
        match self {
            Self::ReverseTcp { target } => Some(target),
            _ => None,
        }
    }

    pub(crate) fn reverse_http(&self) -> Option<&ReverseHttpConfig> {
        match self {
            Self::ReverseHttp { config } => Some(config),
            _ => None,
        }
    }
}

impl InboundTransportPlan {
    fn compile(transports: &[String]) -> Self {
        Self {
            websocket: has_transport(transports, "websocket"),
            http2: has_transport(transports, "http2"),
            tls: has_transport(transports, "tls") || has_transport(transports, "tls_auto"),
            aead: None,
            unsupported: transports
                .iter()
                .any(|transport| !is_supported_inbound_transport(transport)),
            transparent_unsupported: transports
                .iter()
                .any(|transport| !is_supported_transparent_transport(transport)),
        }
    }
}

pub(crate) struct InboundPlan {
    pub(crate) spec: InboundSpec,
    pub(crate) protocol: InboundProtocolKind,
    pub(crate) protocol_config: InboundProtocolPlan,
    pub(crate) transports: InboundTransportPlan,
    pub(crate) tls_acceptor: Option<InboundTlsAcceptor>,
}

impl InboundPlan {
    pub(crate) fn compile(record: GoInboundRecord) -> Result<Self> {
        let spec = InboundSpec::from_record(record.clone())?;
        let protocol = InboundProtocolKind::compile(&spec.protocol);
        let protocol_config = InboundProtocolPlan::compile(&protocol, &spec);
        let mut transports = InboundTransportPlan::compile(&spec.transports);
        transports.aead = spec.aead_password.as_ref().map(|password| InboundAeadPlan {
            password: password.clone(),
            method: spec.aead_method,
        });
        let tls_acceptor = build_inbound_tls_acceptor(&record.data_json, &spec.transports)?;
        Ok(Self {
            spec,
            protocol,
            protocol_config,
            transports,
            tls_acceptor,
        })
    }

    fn refresh_protocol_config(&mut self) {
        self.protocol_config = InboundProtocolPlan::compile(&self.protocol, &self.spec);
    }

    pub(crate) fn prepare_runtime(&mut self, outbound_id: &str, auth: &Arc<InboundAuth>) {
        self.spec.outbound_id = outbound_id.to_owned();
        if auth.has_basic_users() || !auth.inbound_passwords().is_empty() {
            self.spec.username.clear();
            if auth.has_basic_users() {
                self.spec.password.clear();
            }
            self.spec.auth = Some(Arc::clone(auth));
        }
        self.refresh_protocol_config();
    }
}
