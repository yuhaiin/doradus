//! Outbound SOCKS5 CONNECT protocol wrapper.
//!
//! This is deliberately stream-only.  A SOCKS5 UDP association needs a
//! datagram path to the relay returned by the server; a raw HTTP/2 CONNECT
//! stream does not provide that path.  The wrapper therefore fails UDP
//! explicitly instead of silently sending a TCP-shaped packet.

use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use yuhaiin_core::proxy::{AsyncDatagram, AsyncProxy, BoxAsyncStream};
use yuhaiin_core::{BoxFuture, Endpoint, Error, ErrorKind, FlowContext, Network, Result};

pub struct Socks5Proxy {
    upstream: Arc<dyn AsyncProxy>,
    username: String,
    password: String,
    /// Preserved from Go's contract. It is used by UDP associate in Go; TCP
    /// CONNECT intentionally uses the original destination unchanged.
    hostname: String,
    override_port: Option<u16>,
}

impl Socks5Proxy {
    pub fn new(
        upstream: Arc<dyn AsyncProxy>,
        username: impl Into<String>,
        password: impl Into<String>,
        hostname: impl Into<String>,
        override_port: i32,
    ) -> Result<Self> {
        let override_port = match override_port {
            0 => None,
            value if (1..=i32::from(u16::MAX)).contains(&value) => Some(value as u16),
            _ => return Err(Error::invalid("SOCKS5 override_port is out of range")),
        };
        Ok(Self {
            upstream,
            username: username.into(),
            password: password.into(),
            hostname: hostname.into(),
            override_port,
        })
    }

    async fn connect_stream(&self, context: &FlowContext) -> Result<BoxAsyncStream> {
        if context.network != Network::Tcp {
            return Err(Error::invalid("SOCKS5 CONNECT requires a TCP flow"));
        }
        let destination = context.effective_destination();
        let mut stream = self.upstream.connect(context).await?;
        self.handshake(&mut stream, &destination).await?;
        Ok(stream)
    }

    async fn handshake<S>(&self, stream: &mut S, destination: &Endpoint) -> Result<()>
    where
        S: AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        if destination.network() != Network::Tcp {
            return Err(Error::invalid(
                "SOCKS5 CONNECT target must be a TCP endpoint",
            ));
        }
        if self.username.len() > 255 || self.password.len() > 255 {
            return Err(Error::invalid("SOCKS5 credentials are too long"));
        }

        // Go always advertises both methods, even when credentials are empty.
        stream.write_all(&[5, 2, 0, 2]).await.map_err(io_error)?;
        let mut selected = [0u8; 2];
        stream.read_exact(&mut selected).await.map_err(io_error)?;
        if selected[0] != 5 {
            return Err(Error::new(
                ErrorKind::Protocol,
                "SOCKS5 server returned an invalid version",
            ));
        }
        match selected[1] {
            0 => {}
            2 => {
                let mut auth = Vec::with_capacity(3 + self.username.len() + self.password.len());
                auth.push(1);
                auth.push(self.username.len() as u8);
                auth.extend_from_slice(self.username.as_bytes());
                auth.push(self.password.len() as u8);
                auth.extend_from_slice(self.password.as_bytes());
                stream.write_all(&auth).await.map_err(io_error)?;
                let mut response = [0u8; 2];
                stream.read_exact(&mut response).await.map_err(io_error)?;
                if response != [1, 0] {
                    return Err(Error::new(
                        ErrorKind::Protocol,
                        "SOCKS5 authentication failed",
                    ));
                }
            }
            0xff => {
                return Err(Error::new(
                    ErrorKind::Protocol,
                    "SOCKS5 no acceptable authentication method",
                ));
            }
            method => {
                return Err(Error::new(
                    ErrorKind::Protocol,
                    format!("SOCKS5 authentication method {method} is unsupported"),
                ));
            }
        }

        let mut request = vec![5, 1, 0];
        encode_address(destination, &mut request)?;
        stream.write_all(&request).await.map_err(io_error)?;

        let mut response = [0u8; 4];
        stream.read_exact(&mut response).await.map_err(io_error)?;
        if response[0] != 5 {
            return Err(Error::new(
                ErrorKind::Protocol,
                "SOCKS5 CONNECT response has an invalid version",
            ));
        }
        if response[1] != 0 {
            return Err(Error::new(
                ErrorKind::Protocol,
                format!("SOCKS5 CONNECT failed with code {}", response[1]),
            ));
        }
        discard_address(stream, response[3]).await
    }
}

impl AsyncProxy for Socks5Proxy {
    fn connect<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>> {
        Box::pin(async move { self.connect_stream(context).await })
    }

    fn open_datagram<'a>(
        &'a self,
        _context: &'a FlowContext,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
        let _ = (&self.hostname, self.override_port);
        Box::pin(async {
            Err(Error::new(
                ErrorKind::Unsupported,
                "SOCKS5 UDP associate requires a datagram parent; raw HTTP/2 transport is stream-only",
            ))
        })
    }

    fn ping<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<std::time::Duration>> {
        Box::pin(async move {
            let started = std::time::Instant::now();
            let mut stream = self.connect_stream(context).await?;
            stream.shutdown().await.map_err(io_error)?;
            Ok(started.elapsed())
        })
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        self.upstream.close()
    }
}

fn encode_address(endpoint: &Endpoint, output: &mut Vec<u8>) -> Result<()> {
    match endpoint {
        Endpoint::Ip { network, addr } if *network == Network::Tcp => {
            match addr.ip() {
                std::net::IpAddr::V4(address) => {
                    output.push(1);
                    output.extend_from_slice(&address.octets());
                }
                std::net::IpAddr::V6(address) => {
                    output.push(4);
                    output.extend_from_slice(&address.octets());
                }
            }
            output.extend_from_slice(&addr.port().to_be_bytes());
        }
        Endpoint::Domain {
            network,
            host,
            port,
        } if *network == Network::Tcp => {
            if host.as_str().len() > 255 {
                return Err(Error::invalid("SOCKS5 domain is too long"));
            }
            output.push(3);
            output.push(host.as_str().len() as u8);
            output.extend_from_slice(host.as_str().as_bytes());
            output.extend_from_slice(&port.to_be_bytes());
        }
        _ => return Err(Error::invalid("SOCKS5 target must be a TCP endpoint")),
    }
    Ok(())
}

async fn discard_address<S>(stream: &mut S, atyp: u8) -> Result<()>
where
    S: AsyncRead + Unpin,
{
    let length = match atyp {
        1 => 4,
        4 => 16,
        3 => {
            let mut length = [0u8; 1];
            stream.read_exact(&mut length).await.map_err(io_error)?;
            usize::from(length[0])
        }
        _ => {
            return Err(Error::new(
                ErrorKind::Protocol,
                "SOCKS5 CONNECT response has an invalid address type",
            ));
        }
    };
    let mut address = vec![0u8; length + 2];
    stream
        .read_exact(&mut address)
        .await
        .map(|_| ())
        .map_err(io_error)
}

fn io_error(error: std::io::Error) -> Error {
    Error::new(ErrorKind::Io, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use yuhaiin_core::proxy::FixedAsyncProxy;
    use yuhaiin_core::{DomainName, Network};

    #[tokio::test]
    async fn authenticated_connect_preserves_domain_and_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut greeting = [0u8; 4];
            stream.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 2, 0, 2]);
            stream.write_all(&[5, 2]).await.unwrap();

            let mut auth_head = [0u8; 2];
            stream.read_exact(&mut auth_head).await.unwrap();
            assert_eq!(auth_head[0], 1);
            let mut username = vec![0u8; usize::from(auth_head[1])];
            stream.read_exact(&mut username).await.unwrap();
            let mut password_length = [0u8; 1];
            stream.read_exact(&mut password_length).await.unwrap();
            let mut password = vec![0u8; usize::from(password_length[0])];
            stream.read_exact(&mut password).await.unwrap();
            assert_eq!(username, b"user");
            assert_eq!(password, b"pass");
            stream.write_all(&[1, 0]).await.unwrap();

            let mut request_head = [0u8; 5];
            stream.read_exact(&mut request_head).await.unwrap();
            assert_eq!(&request_head[..4], &[5, 1, 0, 3]);
            let mut host = vec![0u8; usize::from(request_head[4])];
            stream.read_exact(&mut host).await.unwrap();
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await.unwrap();
            assert_eq!(host, b"example.com");
            assert_eq!(u16::from_be_bytes(port), 443);
            stream
                .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 80])
                .await
                .unwrap();
            let mut payload = [0u8; 7];
            stream.read_exact(&mut payload).await.unwrap();
            stream.write_all(&payload).await.unwrap();
        });
        let parent: Arc<dyn AsyncProxy> = Arc::new(FixedAsyncProxy {
            address,
            timeout: std::time::Duration::from_secs(1),
        });
        let proxy = Socks5Proxy::new(parent, "user", "pass", "", 0).unwrap();
        let context = FlowContext::new(Endpoint::domain(
            Network::Tcp,
            DomainName::new("example.com").unwrap(),
            443,
        ));
        let mut stream = proxy.connect(&context).await.unwrap();
        stream.write_all(b"payload").await.unwrap();
        let mut response = [0u8; 7];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"payload");
        server.await.unwrap();
    }

    #[test]
    fn validates_override_port_like_go_int32_contract() {
        let parent: Arc<dyn AsyncProxy> = Arc::new(yuhaiin_core::proxy::DropAsyncProxy);
        assert!(Socks5Proxy::new(parent.clone(), "", "", "", -1).is_err());
        assert!(Socks5Proxy::new(parent.clone(), "", "", "", 65_536).is_err());
        assert!(Socks5Proxy::new(parent, "", "", "", 443).is_ok());
    }
}
