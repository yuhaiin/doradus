use std::net::{SocketAddr, ToSocketAddrs};

use serde_json::Value;
use yuhaiin_core::dns_resolver::AsyncIpResolver;
use yuhaiin_core::{DomainName, Error, ErrorKind, Result};

use super::{GoProxyLayer, network_interface_field};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ProxyEndpoint {
    pub(super) host: String,
    pub(super) port: u16,
    pub(super) bind_interface: Option<String>,
}

impl ProxyEndpoint {
    pub(super) fn text(&self) -> String {
        if self.host.contains(':') && !self.host.starts_with('[') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

pub(super) fn fixed_endpoints(layers: &[GoProxyLayer]) -> Result<Vec<ProxyEndpoint>> {
    let config = layers
        .iter()
        .find(|layer| matches!(layer.kind.as_str(), "fixed" | "simple" | "fixedv2"))
        .map(|layer| &layer.config)
        .ok_or_else(|| Error::invalid("Go proxy chain has no fixed endpoint layer"))?;
    let default_interface = network_interface_field(config);
    if let Some(addresses) = config.get("addresses").and_then(Value::as_array) {
        if addresses.is_empty() {
            return Err(Error::invalid("Go fixed endpoint addresses is empty"));
        }
        return addresses
            .iter()
            .map(|value| {
                let mut endpoint = proxy_endpoint_value(value)?;
                if endpoint.bind_interface.is_none() {
                    endpoint.bind_interface =
                        network_interface_field(value).or_else(|| default_interface.clone());
                }
                Ok(endpoint)
            })
            .collect();
    }
    let mut endpoints = Vec::new();
    if config.get("host").is_some() {
        endpoints.push(proxy_endpoint_value(config)?);
    }
    if let Some(alternates) = config.get("alternate_host").and_then(Value::as_array) {
        endpoints.extend(
            alternates
                .iter()
                .map(proxy_endpoint_value)
                .collect::<Result<Vec<_>>>()?,
        );
    }
    if endpoints.is_empty() {
        return Err(Error::invalid(
            "Go fixed node requires addresses or host/port",
        ));
    }
    for endpoint in &mut endpoints {
        if endpoint.bind_interface.is_none() {
            endpoint.bind_interface = default_interface.clone();
        }
    }
    Ok(endpoints)
}

pub(super) fn proxy_endpoint_value(value: &Value) -> Result<ProxyEndpoint> {
    if let Some(value) = value.as_str() {
        if let Ok(address) = value.parse::<SocketAddr>() {
            return Ok(ProxyEndpoint {
                host: address.ip().to_string(),
                port: address.port(),
                bind_interface: None,
            });
        }
        let (host, port) = split_endpoint_text(value)?;
        return Ok(ProxyEndpoint {
            host,
            port,
            bind_interface: None,
        });
    }
    let host = value
        .get("host")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::invalid("Go proxy endpoint requires host"))?;
    let port = value
        .get("port")
        .and_then(Value::as_u64)
        .ok_or_else(|| Error::invalid("Go proxy endpoint requires port"))?;
    if port == 0 || port > u64::from(u16::MAX) {
        return Err(Error::invalid("Go proxy endpoint port is out of range"));
    }
    Ok(ProxyEndpoint {
        host: host.to_owned(),
        port: u16::try_from(port)
            .map_err(|_| Error::invalid("Go proxy endpoint port is out of range"))?,
        bind_interface: network_interface_field(value),
    })
}

fn split_endpoint_text(value: &str) -> Result<(String, u16)> {
    let (host, port) = if let Some(value) = value.strip_prefix('[') {
        value.split_once("]:").ok_or_else(|| {
            Error::invalid(format!("Go proxy endpoint {value:?} requires host:port"))
        })?
    } else {
        value.rsplit_once(':').ok_or_else(|| {
            Error::invalid(format!("Go proxy endpoint {value:?} requires host:port"))
        })?
    };
    let port = port.parse::<u16>().map_err(|error| {
        Error::new(
            ErrorKind::InvalidInput,
            format!("invalid proxy port: {error}"),
        )
    })?;
    if host.is_empty() {
        return Err(Error::invalid("Go proxy endpoint host cannot be empty"));
    }
    if host.parse::<std::net::IpAddr>().is_err() {
        DomainName::new(host)?;
    }
    Ok((host.to_owned(), port))
}

pub(super) fn resolve_socket_addr(value: &str) -> Result<SocketAddr> {
    if let Ok(address) = value.parse() {
        return Ok(address);
    }
    value
        .to_socket_addrs()
        .map_err(|error| {
            Error::new(
                ErrorKind::InvalidInput,
                format!("Go proxy endpoint {value:?} cannot be resolved: {error}"),
            )
        })?
        .next()
        .ok_or_else(|| {
            Error::invalid(format!(
                "Go proxy endpoint {value:?} resolved to no address"
            ))
        })
}

pub(super) async fn resolve_endpoints(
    endpoint: &ProxyEndpoint,
    resolver: &dyn AsyncIpResolver,
) -> Result<Vec<SocketAddr>> {
    if let Ok(address) = endpoint.text().parse() {
        return Ok(vec![address]);
    }
    let domain = DomainName::new(&endpoint.host)?;
    let addresses = resolver
        .resolve(&domain, yuhaiin_core::ResolveStrategy::Default)
        .await?;
    let addresses = addresses
        .iter()
        .map(|address| SocketAddr::new(address, endpoint.port))
        .collect::<Vec<_>>();
    if addresses.is_empty() {
        return Err(Error::invalid(format!(
            "proxy endpoint {} resolved to no address",
            domain
        )));
    }
    Ok(addresses)
}
