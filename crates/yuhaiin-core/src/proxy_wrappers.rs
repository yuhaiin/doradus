//! Proxy wrappers.

use super::*;

use super::datagrams::FixedDatagram;

#[derive(Debug, Clone, Copy)]
pub struct FixedAsyncProxy {
    pub address: SocketAddr,
    pub timeout: Duration,
}

/// Apply one node's per-endpoint interface policy before entering the actual
/// proxy implementation.  Go's fixedv2 model allows alternate addresses to
/// carry their own interface, while the common `FlowContext` keeps the
/// policy at the flow boundary; this adapter bridges those two shapes.
pub struct BindInterfaceProxy {
    pub inner: Arc<dyn AsyncProxy>,
    pub interface: Option<String>,
}

impl BindInterfaceProxy {
    pub fn new(inner: Arc<dyn AsyncProxy>, interface: Option<String>) -> Self {
        Self { inner, interface }
    }

    fn context(&self, context: &FlowContext) -> FlowContext {
        let mut context = context.clone();
        context.bind_interface = self.interface.clone();
        context
    }
}

impl AsyncProxy for BindInterfaceProxy {
    fn connect<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>> {
        let context = self.context(context);
        Box::pin(async move { self.inner.connect(&context).await })
    }

    fn open_datagram<'a>(
        &'a self,
        context: &'a FlowContext,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
        let context = self.context(context);
        Box::pin(async move { self.inner.open_datagram(&context).await })
    }

    fn ping<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<Duration>> {
        let context = self.context(context);
        Box::pin(async move { self.inner.ping(&context).await })
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        self.inner.close()
    }
}

/// Try the endpoints of one Go fixedv2 node in order.  The first successful
/// endpoint is enough for a flow; failures during a protocol handshake (not
/// just the TCP connect) are deliberately included in the fallback boundary.
pub struct FallbackAsyncProxy {
    pub proxies: Vec<Arc<dyn AsyncProxy>>,
}

impl FallbackAsyncProxy {
    pub fn new(proxies: Vec<Arc<dyn AsyncProxy>>) -> Result<Self> {
        if proxies.is_empty() {
            return Err(Error::invalid("proxy endpoint fallback has no endpoints"));
        }
        Ok(Self { proxies })
    }
}

impl AsyncProxy for FallbackAsyncProxy {
    fn connect<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>> {
        let proxies = self.proxies.clone();
        let context = context.clone();
        Box::pin(async move {
            let mut last_error = None;
            for proxy in proxies {
                match proxy.connect(&context).await {
                    Ok(stream) => return Ok(stream),
                    Err(error) => last_error = Some(error),
                }
            }
            Err(last_error.unwrap_or_else(|| Error::invalid("proxy endpoint fallback failed")))
        })
    }

    fn open_datagram<'a>(
        &'a self,
        context: &'a FlowContext,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
        let proxies = self.proxies.clone();
        let context = context.clone();
        Box::pin(async move {
            let mut last_error = None;
            for proxy in proxies {
                match proxy.open_datagram(&context).await {
                    Ok(datagram) => return Ok(datagram),
                    Err(error) => last_error = Some(error),
                }
            }
            Err(last_error.unwrap_or_else(|| Error::invalid("proxy endpoint fallback failed")))
        })
    }

    fn ping<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<Duration>> {
        let proxies = self.proxies.clone();
        let context = context.clone();
        Box::pin(async move {
            let mut last_error = None;
            for proxy in proxies {
                match proxy.ping(&context).await {
                    Ok(duration) => return Ok(duration),
                    Err(error) => last_error = Some(error),
                }
            }
            Err(last_error.unwrap_or_else(|| Error::invalid("proxy endpoint fallback failed")))
        })
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            let mut last_error = None;
            for proxy in &self.proxies {
                if let Err(error) = proxy.close().await {
                    last_error = Some(error);
                }
            }
            last_error.map_or(Ok(()), Err)
        })
    }
}

impl AsyncProxy for FixedAsyncProxy {
    fn connect<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>> {
        let local_bind = context.local_bind_for(self.address);
        let bind_interface = context.bind_interface.clone();
        Box::pin(async move {
            let stream = connect_tokio_tcp_with_interface(
                self.address,
                local_bind,
                bind_interface.as_deref(),
                self.timeout,
            )
            .await?;
            let local_addr = stream.local_addr().ok();
            Ok(with_stream_socket_addrs(
                Box::new(stream) as BoxAsyncStream,
                local_addr,
                Some(self.address),
            ))
        })
    }

    fn open_datagram<'a>(
        &'a self,
        context: &'a FlowContext,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
        let target = self.address;
        let fallback = if target.is_ipv4() {
            "0.0.0.0:0".parse().expect("valid IPv4 wildcard")
        } else {
            "[::]:0".parse().expect("valid IPv6 wildcard")
        };
        let bind_address = context.local_bind_for(target).unwrap_or(fallback);
        let bind_interface = context.bind_interface.clone();
        Box::pin(async move {
            let socket = bind_tokio_udp_socket_for_target(
                bind_address,
                target,
                bind_interface.as_deref(),
                "fixed",
            )
            .await?;
            Ok(Box::new(FixedDatagram { socket, target }) as Box<dyn AsyncDatagram>)
        })
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async { Ok(()) })
    }
}
