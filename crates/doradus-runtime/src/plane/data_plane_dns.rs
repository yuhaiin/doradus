//! Runtime DNS handler.

use super::*;

/// DNS packet handler backed by the resolver in the current immutable
/// runtime snapshot. TUN DNS hijacking and both DNS listener transports use
/// the same handler, so a reload cannot make them disagree about resolver
/// policy.
#[derive(Clone)]
pub struct RuntimeDnsHandler {
    pub resolver: Arc<dyn AsyncIpResolver>,
    pub fakeip: Option<doradus_store::FakeIpPools>,
}

/// A live DNS handler slot for long-lived TUN runtimes.
///
/// Ordinary resolver reloads must update DNS policy without rebuilding the
/// TUN device or interrupting existing flows. The slot snapshots the current
/// handler for each query, so an in-flight query can finish on the old
/// immutable snapshot while the next query observes the new one.
#[derive(Clone, Default)]
pub(crate) struct ReloadableAsyncDnsHandler {
    current: Arc<RwLock<Option<RuntimeDnsHandler>>>,
}

#[derive(Clone)]
pub(super) struct LoggedDnsHandler<H> {
    pub(super) inner: H,
    pub(super) monitor: Arc<crate::ConnectionMonitor>,
}

impl<H> AsyncDnsHandler for LoggedDnsHandler<H>
where
    H: AsyncDnsHandler + Clone + Send + Sync + 'static,
{
    fn answer<'a>(&'a self, packet: &'a [u8]) -> BoxFuture<'a, Result<Vec<u8>>> {
        let inner = self.inner.clone();
        let monitor = Arc::clone(&self.monitor);
        Box::pin(async move {
            let result = inner.answer(packet).await;
            if let Err(error) = &result {
                let target = decode_query(packet)
                    .map(|query| format!("{} {:?}", query.domain, query.record_type))
                    .unwrap_or_else(|_| format!("packet_len={}", packet.len()));
                monitor.error(format!(
                    "DNS listener query failed target={target}: {error}"
                ));
            }
            result
        })
    }
}

impl ReloadableAsyncDnsHandler {
    pub(crate) fn new(handler: Option<RuntimeDnsHandler>) -> Self {
        Self {
            current: Arc::new(RwLock::new(handler)),
        }
    }

    pub(crate) fn replace(&self, handler: Option<RuntimeDnsHandler>) {
        *self
            .current
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = handler;
    }
}

impl AsyncDnsHandler for ReloadableAsyncDnsHandler {
    fn answer<'a>(&'a self, packet: &'a [u8]) -> BoxFuture<'a, Result<Vec<u8>>> {
        let handler = self
            .current
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        Box::pin(async move {
            match handler {
                Some(handler) => handler.answer(packet).await,
                None => Err(doradus_core::Error::new(
                    doradus_core::ErrorKind::Closed,
                    "TUN DNS hijacking is disabled",
                )),
            }
        })
    }
}

impl AsyncDnsHandler for RuntimeDnsHandler {
    fn answer<'a>(&'a self, packet: &'a [u8]) -> BoxFuture<'a, Result<Vec<u8>>> {
        Box::pin(self.answer_impl(packet))
    }
}

impl RuntimeDnsHandler {
    async fn answer_impl(&self, packet: &[u8]) -> Result<Vec<u8>> {
        let question = match decode_query(packet) {
            Ok(question) => question,
            Err(error) if error.kind == doradus_core::ErrorKind::Unsupported => {
                return self.resolver.query_packet(packet).await;
            }
            Err(error) => return Err(error),
        };
        if question.record_type == DnsRecordType::Ptr
            && let Some(fakeip) = &self.fakeip
            && let Some(domain) = fakeip.lookup_ptr_domain(&question.domain).await
        {
            return encode_response(
                packet,
                &DnsResponse {
                    addresses: doradus_core::IpSet::default(),
                    ptr_names: vec![domain],
                    service_bindings: Vec::new(),
                    minimum_ttl: Some(60),
                },
            );
        }
        let response = self
            .resolver
            .query(&question.domain, question.record_type)
            .await?;
        encode_response(packet, &response)
    }
}

impl crate::monitor::SocketDnsHandler for RuntimeDnsHandler {
    fn answer<'a>(&'a self, packet: &'a [u8]) -> BoxFuture<'a, Result<Vec<u8>>> {
        Box::pin(self.answer_impl(packet))
    }
}

/// Build the one DNS handler used by all inbound owners. Keeping this at the
/// snapshot boundary makes reloads choose the same resolver/FakeIP policy for
/// socket DNS and TUN DNS instead of letting each protocol invent its own.
pub(crate) fn inbound_dns_handler(
    snapshot: &RuntimeSnapshot,
) -> Result<Option<Arc<RuntimeDnsHandler>>> {
    if !snapshot.inbound_settings.hijack_dns {
        return Ok(None);
    }
    let resolver = if snapshot.inbound_settings.hijack_dns_fakeip {
        snapshot.inbound_resolver_for_route_mode(RouteMode::Proxy)?
    } else {
        snapshot.dns_resolver_for_route_mode(RouteMode::Proxy)?
    };
    Ok(Some(Arc::new(RuntimeDnsHandler {
        resolver,
        fakeip: snapshot.inbound_fakeip.clone(),
    })))
}
