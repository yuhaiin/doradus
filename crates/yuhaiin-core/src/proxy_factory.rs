//! Construction of the reusable base async proxies.
//!
//! This keeps application configuration from reaching into protocol structs.
//! Yuubinsya/TLS/HTTP2 chains are built by `yuhaiin-chain`; this module owns
//! the direct/drop/fixed/HTTP CONNECT/SOCKS5 base proxy selection.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::proxy::{
    AsyncProxy, BlockingStreamProxy, DirectAsyncProxy, DropAsyncProxy, FixedAsyncProxy,
    HttpProxyConnector, Socks5Connector, StreamConnector, YuubinsyaUdpProxy,
};
use crate::{Error, ErrorKind, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BaseProxyKind {
    Direct,
    Drop,
    Fixed {
        address: SocketAddr,
    },
    Http {
        proxy: SocketAddr,
        username: Option<String>,
        password: Option<String>,
    },
    Socks5 {
        proxy: SocketAddr,
        username: Option<String>,
        password: Option<String>,
    },
    YuubinsyaUdp {
        server: SocketAddr,
        password_hash: [u8; 32],
        socks5_prefix: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaseProxyConfig {
    pub kind: BaseProxyKind,
    pub timeout: Duration,
}

impl BaseProxyConfig {
    pub fn build(&self) -> Result<Arc<dyn AsyncProxy>> {
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
            BaseProxyKind::Drop => Arc::new(DropAsyncProxy),
            BaseProxyKind::Fixed { address } => Arc::new(FixedAsyncProxy {
                address: *address,
                timeout: self.timeout,
            }),
            BaseProxyKind::Http {
                proxy,
                username,
                password,
            } => Arc::new(blocking_connector(HttpProxyConnector {
                proxy: *proxy,
                timeout: self.timeout,
                username: username.clone(),
                password: password.clone(),
            })),
            BaseProxyKind::Socks5 {
                proxy,
                username,
                password,
            } => Arc::new(blocking_connector(Socks5Connector {
                proxy: *proxy,
                timeout: self.timeout,
                username: username.clone(),
                password: password.clone(),
            })),
            BaseProxyKind::YuubinsyaUdp {
                server,
                password_hash,
                socks5_prefix,
            } => Arc::new(YuubinsyaUdpProxy {
                server: *server,
                password_hash: *password_hash,
                socks5_prefix: *socks5_prefix,
            }),
        };
        Ok(proxy)
    }
}

fn blocking_connector(connector: impl StreamConnector + 'static) -> BlockingStreamProxy {
    BlockingStreamProxy {
        connector: Arc::new(connector),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Endpoint, FlowContext, Network};

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

    #[test]
    fn built_drop_proxy_fails_closed_for_stream_and_datagram() {
        let proxy = BaseProxyConfig {
            kind: BaseProxyKind::Drop,
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
            Ok(_) => panic!("drop proxy must reject stream"),
            Err(error) => error,
        };
        assert_eq!(error.kind, ErrorKind::Closed);
        let error = match runtime.block_on(proxy.open_datagram(&context)) {
            Ok(_) => panic!("drop proxy must reject datagram"),
            Err(error) => error,
        };
        assert_eq!(error.kind, ErrorKind::Closed);
    }

    #[test]
    fn built_yuubinsya_udp_proxy_round_trips_through_native_server() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let password_hash = crate::yuubinsya::derive_salt(b"password");
            let server = crate::proxy::YuubinsyaUdpServer::bind(
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
                crate::DomainName::new("example.com").unwrap(),
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
