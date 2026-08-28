//! Construction of the reusable base async proxies.
//!
//! This keeps application configuration from reaching into protocol structs.
//! Yuubinsya/TLS/HTTP2 chains are built by `doradus-chain`; this module owns
//! the direct/drop/fixed/HTTP CONNECT/SOCKS5 base proxy selection.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::YuubinsyaUdpProxy;
use crate::http::HttpProxy;
use crate::proxy::{
    BindInterfaceProxy, DelayedDropAsyncProxy, DirectAsyncProxy, DropAsyncProxy,
    FallbackAsyncProxy, FixedAsyncProxy, Socks5AsyncProxy,
};
#[cfg(feature = "quic")]
use crate::quic::{QuicConfig, QuicProxy};
use doradus_core::proxy::AsyncProxy;
use doradus_core::{Error, ErrorKind, Result};
use doradus_metrics::RuntimeMetrics;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaseProxyEndpoint {
    pub address: SocketAddr,
    pub bind_interface: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BaseProxyKind {
    Direct,
    /// Immediate reject used by Go's `reject` node and route `block` policy.
    Reject,
    /// Delayed, write-accepting sink used by Go's `drop` node.
    Drop,
    Fixed {
        address: SocketAddr,
    },
    FixedMany {
        endpoints: Vec<BaseProxyEndpoint>,
    },
    Http {
        proxy: SocketAddr,
        username: Option<String>,
        password: Option<String>,
    },
    HttpMany {
        endpoints: Vec<BaseProxyEndpoint>,
        username: Option<String>,
        password: Option<String>,
    },
    Socks5 {
        proxy: SocketAddr,
        username: Option<String>,
        password: Option<String>,
    },
    Socks5Many {
        endpoints: Vec<BaseProxyEndpoint>,
        username: Option<String>,
        password: Option<String>,
    },
    YuubinsyaUdp {
        server: SocketAddr,
        password_hash: [u8; 32],
        socks5_prefix: bool,
    },
    YuubinsyaUdpMany {
        endpoints: Vec<BaseProxyEndpoint>,
        password_hash: [u8; 32],
        socks5_prefix: bool,
    },
    #[cfg(feature = "quic")]
    Quic {
        server: SocketAddr,
        server_name: String,
        ca_certificates: Vec<Vec<u8>>,
        insecure_skip_verify: bool,
    },
    #[cfg(feature = "quic")]
    QuicMany {
        endpoints: Vec<BaseProxyEndpoint>,
        server_name: String,
        ca_certificates: Vec<Vec<u8>>,
        insecure_skip_verify: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaseProxyConfig {
    pub kind: BaseProxyKind,
    pub timeout: Duration,
}

impl BaseProxyConfig {
    pub fn build(&self) -> Result<Arc<dyn AsyncProxy>> {
        self.build_inner(None)
    }

    /// Build the base proxy and attach the owning runtime metrics collector
    /// to transports that expose protocol-level telemetry.
    pub fn build_with_metrics(&self, metrics: Arc<RuntimeMetrics>) -> Result<Arc<dyn AsyncProxy>> {
        self.build_inner(Some(metrics))
    }

    fn build_inner(&self, metrics: Option<Arc<RuntimeMetrics>>) -> Result<Arc<dyn AsyncProxy>> {
        #[cfg(not(feature = "quic"))]
        let _ = &metrics;

        if self.timeout.is_zero() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "base proxy timeout must be greater than zero",
            ));
        }
        let proxy: Arc<dyn AsyncProxy> = match &self.kind {
            BaseProxyKind::Direct => Arc::new(DirectAsyncProxy {
                timeout: self.timeout,
            }),
            BaseProxyKind::Reject => Arc::new(DropAsyncProxy),
            BaseProxyKind::Drop => Arc::new(DelayedDropAsyncProxy::new()),
            BaseProxyKind::Fixed { address } => Arc::new(FixedAsyncProxy {
                address: *address,
                timeout: self.timeout,
            }),
            BaseProxyKind::FixedMany { endpoints } => fallback_fixed(endpoints, self.timeout)?,
            BaseProxyKind::Http {
                proxy,
                username,
                password,
            } => http_proxy(*proxy, self.timeout, username.clone(), password.clone()),
            BaseProxyKind::HttpMany {
                endpoints,
                username,
                password,
            } => fallback_http(endpoints, self.timeout, username.clone(), password.clone())?,
            BaseProxyKind::Socks5 {
                proxy,
                username,
                password,
            } => Arc::new(Socks5AsyncProxy {
                proxy: *proxy,
                timeout: self.timeout,
                username: username.clone(),
                password: password.clone(),
            }),
            BaseProxyKind::Socks5Many {
                endpoints,
                username,
                password,
            } => fallback_socks5(endpoints, self.timeout, username.clone(), password.clone())?,
            BaseProxyKind::YuubinsyaUdp {
                server,
                password_hash,
                socks5_prefix,
            } => Arc::new(YuubinsyaUdpProxy {
                server: *server,
                password_hash: *password_hash,
                socks5_prefix: *socks5_prefix,
            }),
            BaseProxyKind::YuubinsyaUdpMany {
                endpoints,
                password_hash,
                socks5_prefix,
            } => fallback_yuubinsya(endpoints, *password_hash, *socks5_prefix)?,
            #[cfg(feature = "quic")]
            BaseProxyKind::Quic {
                server,
                server_name,
                ca_certificates,
                insecure_skip_verify,
            } => Arc::new(match metrics.as_ref() {
                Some(metrics) => QuicProxy::new_with_metrics(
                    QuicConfig {
                        server: *server,
                        server_name: server_name.clone(),
                        ca_certificates: ca_certificates.clone(),
                        insecure_skip_verify: *insecure_skip_verify,
                        timeout: self.timeout,
                        idle_timeout: crate::quic::DEFAULT_IDLE_TIMEOUT,
                        association_idle_timeout: crate::quic::DEFAULT_ASSOCIATION_IDLE_TIMEOUT,
                        max_associations: crate::quic::DEFAULT_MAX_ASSOCIATIONS,
                        rx_queue_capacity: crate::quic::DEFAULT_RX_QUEUE_CAPACITY,
                        rx_memory_budget: crate::quic::DEFAULT_RX_MEMORY_BUDGET,
                    },
                    Arc::clone(metrics),
                )?,
                None => QuicProxy::new(QuicConfig {
                    server: *server,
                    server_name: server_name.clone(),
                    ca_certificates: ca_certificates.clone(),
                    insecure_skip_verify: *insecure_skip_verify,
                    timeout: self.timeout,
                    idle_timeout: crate::quic::DEFAULT_IDLE_TIMEOUT,
                    association_idle_timeout: crate::quic::DEFAULT_ASSOCIATION_IDLE_TIMEOUT,
                    max_associations: crate::quic::DEFAULT_MAX_ASSOCIATIONS,
                    rx_queue_capacity: crate::quic::DEFAULT_RX_QUEUE_CAPACITY,
                    rx_memory_budget: crate::quic::DEFAULT_RX_MEMORY_BUDGET,
                })?,
            }),
            #[cfg(feature = "quic")]
            BaseProxyKind::QuicMany {
                endpoints,
                server_name,
                ca_certificates,
                insecure_skip_verify,
            } => fallback_quic(
                endpoints,
                self.timeout,
                server_name.clone(),
                ca_certificates.clone(),
                *insecure_skip_verify,
                metrics.clone(),
            )?,
        };
        Ok(proxy)
    }
}

fn bind_endpoint(proxy: Arc<dyn AsyncProxy>, endpoint: &BaseProxyEndpoint) -> Arc<dyn AsyncProxy> {
    Arc::new(BindInterfaceProxy::new(
        proxy,
        endpoint.bind_interface.clone(),
    ))
}

fn fallback_fixed(
    endpoints: &[BaseProxyEndpoint],
    timeout: Duration,
) -> Result<Arc<dyn AsyncProxy>> {
    let proxies = endpoints
        .iter()
        .map(|endpoint| {
            bind_endpoint(
                Arc::new(FixedAsyncProxy {
                    address: endpoint.address,
                    timeout,
                }),
                endpoint,
            )
        })
        .collect();
    Ok(Arc::new(FallbackAsyncProxy::new(proxies)?))
}

fn fallback_http(
    endpoints: &[BaseProxyEndpoint],
    timeout: Duration,
    username: Option<String>,
    password: Option<String>,
) -> Result<Arc<dyn AsyncProxy>> {
    let proxies = endpoints
        .iter()
        .map(|endpoint| {
            bind_endpoint(
                http_proxy(
                    endpoint.address,
                    timeout,
                    username.clone(),
                    password.clone(),
                ),
                endpoint,
            )
        })
        .collect();
    Ok(Arc::new(FallbackAsyncProxy::new(proxies)?))
}

fn fallback_socks5(
    endpoints: &[BaseProxyEndpoint],
    timeout: Duration,
    username: Option<String>,
    password: Option<String>,
) -> Result<Arc<dyn AsyncProxy>> {
    let proxies = endpoints
        .iter()
        .map(|endpoint| {
            bind_endpoint(
                Arc::new(Socks5AsyncProxy {
                    proxy: endpoint.address,
                    timeout,
                    username: username.clone(),
                    password: password.clone(),
                }),
                endpoint,
            )
        })
        .collect();
    Ok(Arc::new(FallbackAsyncProxy::new(proxies)?))
}

fn fallback_yuubinsya(
    endpoints: &[BaseProxyEndpoint],
    password_hash: [u8; 32],
    socks5_prefix: bool,
) -> Result<Arc<dyn AsyncProxy>> {
    let proxies = endpoints
        .iter()
        .map(|endpoint| {
            bind_endpoint(
                Arc::new(YuubinsyaUdpProxy {
                    server: endpoint.address,
                    password_hash,
                    socks5_prefix,
                }),
                endpoint,
            )
        })
        .collect();
    Ok(Arc::new(FallbackAsyncProxy::new(proxies)?))
}

#[cfg(feature = "quic")]
fn fallback_quic(
    endpoints: &[BaseProxyEndpoint],
    timeout: Duration,
    server_name: String,
    ca_certificates: Vec<Vec<u8>>,
    insecure_skip_verify: bool,
    metrics: Option<Arc<RuntimeMetrics>>,
) -> Result<Arc<dyn AsyncProxy>> {
    let proxies = endpoints
        .iter()
        .map(|endpoint| {
            let config = QuicConfig {
                server: endpoint.address,
                server_name: server_name.clone(),
                ca_certificates: ca_certificates.clone(),
                insecure_skip_verify,
                timeout,
                idle_timeout: crate::quic::DEFAULT_IDLE_TIMEOUT,
                association_idle_timeout: crate::quic::DEFAULT_ASSOCIATION_IDLE_TIMEOUT,
                max_associations: crate::quic::DEFAULT_MAX_ASSOCIATIONS,
                rx_queue_capacity: crate::quic::DEFAULT_RX_QUEUE_CAPACITY,
                rx_memory_budget: crate::quic::DEFAULT_RX_MEMORY_BUDGET,
            };
            let proxy = match metrics.as_ref() {
                Some(metrics) => QuicProxy::new_with_metrics(config, Arc::clone(metrics))?,
                None => QuicProxy::new(config)?,
            };
            Ok(bind_endpoint(Arc::new(proxy), endpoint))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(Arc::new(FallbackAsyncProxy::new(proxies)?))
}

fn http_proxy(
    proxy: SocketAddr,
    timeout: Duration,
    username: Option<String>,
    password: Option<String>,
) -> Arc<dyn AsyncProxy> {
    let (username, password) = match (username, password) {
        (Some(username), Some(password)) => (username, password),
        _ => (String::new(), String::new()),
    };
    Arc::new(HttpProxy::new(
        Arc::new(FixedAsyncProxy {
            address: proxy,
            timeout,
        }),
        username,
        password,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use doradus_core::{Endpoint, FlowContext, Network};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn timeout() -> Duration {
        Duration::from_secs(3)
    }

    #[test]
    fn builds_all_base_proxy_kinds() {
        let address = "127.0.0.1:1080".parse().unwrap();
        let configs = [
            BaseProxyConfig {
                kind: BaseProxyKind::Direct,
                timeout: timeout(),
            },
            BaseProxyConfig {
                kind: BaseProxyKind::Drop,
                timeout: timeout(),
            },
            BaseProxyConfig {
                kind: BaseProxyKind::Reject,
                timeout: timeout(),
            },
            BaseProxyConfig {
                kind: BaseProxyKind::Fixed { address },
                timeout: timeout(),
            },
            BaseProxyConfig {
                kind: BaseProxyKind::Http {
                    proxy: address,
                    username: Some("user".to_owned()),
                    password: Some("pass".to_owned()),
                },
                timeout: timeout(),
            },
            BaseProxyConfig {
                kind: BaseProxyKind::Socks5 {
                    proxy: address,
                    username: None,
                    password: None,
                },
                timeout: timeout(),
            },
            BaseProxyConfig {
                kind: BaseProxyKind::YuubinsyaUdp {
                    server: address,
                    password_hash: [7; 32],
                    socks5_prefix: false,
                },
                timeout: timeout(),
            },
            #[cfg(feature = "quic")]
            BaseProxyConfig {
                kind: BaseProxyKind::Quic {
                    server: address,
                    server_name: "localhost".to_owned(),
                    ca_certificates: Vec::new(),
                    insecure_skip_verify: true,
                },
                timeout: timeout(),
            },
        ];
        for config in configs {
            assert!(config.build().is_ok());
        }
    }

    #[test]
    fn rejects_zero_timeout_before_building_a_proxy() {
        let result = BaseProxyConfig {
            kind: BaseProxyKind::Direct,
            timeout: Duration::ZERO,
        }
        .build();
        let error = match result {
            Ok(_) => panic!("zero timeout must be rejected"),
            Err(error) => error,
        };
        assert_eq!(error.kind, ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn fixed_many_falls_back_after_a_failed_upstream() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let working = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut payload = [0; 8];
            stream.read_exact(&mut payload).await.unwrap();
            payload
        });
        let proxy = BaseProxyConfig {
            kind: BaseProxyKind::FixedMany {
                endpoints: vec![
                    BaseProxyEndpoint {
                        address: "127.0.0.1:1".parse().unwrap(),
                        bind_interface: None,
                    },
                    BaseProxyEndpoint {
                        address: working,
                        bind_interface: None,
                    },
                ],
            },
            timeout: timeout(),
        }
        .build()
        .unwrap();
        let context = FlowContext::new(Endpoint::ip(Network::Tcp, working));
        let mut stream = proxy.connect(&context).await.unwrap();
        stream.write_all(b"fallback").await.unwrap();
        assert_eq!(&accept.await.unwrap(), b"fallback");
    }

    #[test]
    fn built_reject_proxy_fails_closed_for_stream_and_datagram() {
        let proxy = BaseProxyConfig {
            kind: BaseProxyKind::Reject,
            timeout: timeout(),
        }
        .build()
        .unwrap();
        let context =
            FlowContext::new(Endpoint::ip(Network::Tcp, "127.0.0.1:443".parse().unwrap()));
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let error = match runtime.block_on(proxy.connect(&context)) {
            Ok(_) => panic!("reject proxy must reject stream"),
            Err(error) => error,
        };
        assert_eq!(error.kind, ErrorKind::Closed);
        let error = match runtime.block_on(proxy.open_datagram(&context)) {
            Ok(_) => panic!("reject proxy must reject datagram"),
            Err(error) => error,
        };
        assert_eq!(error.kind, ErrorKind::Closed);
    }

    #[tokio::test]
    async fn built_drop_proxy_accepts_writes_and_ends_reads() {
        let proxy = BaseProxyConfig {
            kind: BaseProxyKind::Drop,
            timeout: timeout(),
        }
        .build()
        .unwrap();
        let context =
            FlowContext::new(Endpoint::ip(Network::Tcp, "127.0.0.1:443".parse().unwrap()));
        let mut stream = proxy.connect(&context).await.unwrap();
        assert_eq!(stream.write(b"discarded").await.unwrap(), 9);
        let mut buffer = [0u8; 1];
        assert_eq!(stream.read(&mut buffer).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn built_drop_proxy_accepts_udp_writes_and_closes_reads() {
        let proxy = BaseProxyConfig {
            kind: BaseProxyKind::Drop,
            timeout: timeout(),
        }
        .build()
        .unwrap();
        let target = Endpoint::domain(
            Network::Udp,
            doradus_core::DomainName::new("udp-blocked.example").unwrap(),
            53,
        );
        let context = FlowContext::new(target.clone());
        let datagram = proxy.open_datagram(&context).await.unwrap();
        assert_eq!(datagram.local_addr().unwrap().port(), Some(0));
        assert_eq!(datagram.send_to(b"discarded", target).await.unwrap(), 9);
        let mut buffer = [0u8; 1];
        let error = datagram.recv_from(&mut buffer).await.unwrap_err();
        assert_eq!(error.kind, ErrorKind::Closed);
        datagram.close().await.unwrap();
    }

    #[test]
    fn built_yuubinsya_udp_proxy_round_trips_through_native_server() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let password_hash = crate::yuubinsya::derive_salt(b"password");
            let server = crate::YuubinsyaUdpServer::bind(
                "127.0.0.1:0".parse().unwrap(),
                password_hash,
                false,
            )
            .await
            .unwrap();
            let proxy = BaseProxyConfig {
                kind: BaseProxyKind::YuubinsyaUdp {
                    server: server.local_addr().unwrap().addr().unwrap(),
                    password_hash,
                    socks5_prefix: false,
                },
                timeout: timeout(),
            }
            .build()
            .unwrap();
            let target = Endpoint::domain(
                Network::Udp,
                doradus_core::DomainName::new("example.com").unwrap(),
                53,
            );
            let context = FlowContext::new(target.clone());
            let datagram = proxy.open_datagram(&context).await.unwrap();
            datagram.send_to(b"query", target.clone()).await.unwrap();
            let mut buffer = [0; 64];
            let (length, decoded_target, peer) = server.recv_from(&mut buffer).await.unwrap();
            assert_eq!(&buffer[..length], b"query");
            assert_eq!(decoded_target, target);
            server
                .send_to(b"answer", decoded_target.clone(), peer)
                .await
                .unwrap();
            let (length, target) = datagram.recv_from(&mut buffer).await.unwrap();
            assert_eq!(&buffer[..length], b"answer");
            assert_eq!(target, decoded_target);
        });
    }
}
