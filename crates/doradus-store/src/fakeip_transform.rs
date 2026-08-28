//! FakeIP DNS answer transforms.

use super::*;

/// Applies the IPv4 FakeIP answer policy while keeping the store on its
/// owner/future boundary. This intentionally does not implement the
/// synchronous `DnsHandler`: the current store SQLite connection is owned by
/// the synchronous repository boundary and must not be moved into a `Send +
/// Sync` task.
pub struct FakeIpAnswerTransform {
    pub pool: Arc<FakeIpPool>,
}

/// IPv6 counterpart to [`FakeIpAnswerTransform`].  It is kept as a separate
/// type so existing IPv4 callers keep their source-compatible struct literal
/// while a future dual-stack resolver can choose both pools explicitly.
pub struct FakeIpV6AnswerTransform {
    pub pool: Arc<FakeIpV6Pool>,
}

/// Dual-stack transform for callers that answer HTTPS/SVCB in one resolver
/// request.  The family-specific transforms remain public for resolvers that
/// issue separate A/AAAA requests; this wrapper composes the same semantics
/// without duplicating allocation or hint-rewrite logic.
pub struct FakeIpDualStackAnswerTransform {
    pub ipv4: Arc<FakeIpPool>,
    pub ipv6: Arc<FakeIpV6Pool>,
}

impl FakeIpDualStackAnswerTransform {
    pub async fn apply(
        &self,
        domain: &DomainName,
        record_type: DnsRecordType,
        response: DnsResponse,
    ) -> Result<DnsResponse> {
        let response = FakeIpAnswerTransform {
            pool: Arc::clone(&self.ipv4),
        }
        .apply(domain, record_type, response)
        .await?;
        FakeIpV6AnswerTransform {
            pool: Arc::clone(&self.ipv6),
        }
        .apply(domain, record_type, response)
        .await
    }
}

impl FakeIpV6AnswerTransform {
    pub async fn apply(
        &self,
        domain: &DomainName,
        record_type: DnsRecordType,
        response: DnsResponse,
    ) -> Result<DnsResponse> {
        if record_type == DnsRecordType::Aaaa && !response.addresses.v6.is_empty() {
            let address = self.pool.allocate(domain.clone()).await?;
            return Ok(DnsResponse {
                addresses: IpSet {
                    v4: Vec::new(),
                    v6: vec![address],
                },
                ptr_names: response.ptr_names,
                service_bindings: response.service_bindings,
                minimum_ttl: response.minimum_ttl,
            });
        }
        if !matches!(record_type, DnsRecordType::Https | DnsRecordType::Svcb)
            || !response.service_bindings.iter().any(|binding| {
                binding.params.iter().any(|param| {
                    matches!(param, DnsServiceParam::Ipv6Hint(values) if !values.is_empty())
                })
            })
        {
            return Ok(response);
        }
        let address = self.pool.allocate(domain.clone()).await?;
        let mut service_bindings = response.service_bindings;
        for binding in &mut service_bindings {
            for param in &mut binding.params {
                if let DnsServiceParam::Ipv6Hint(values) = param {
                    *values = vec![address];
                }
            }
        }
        Ok(DnsResponse {
            addresses: response.addresses,
            ptr_names: response.ptr_names,
            service_bindings,
            minimum_ttl: response.minimum_ttl,
        })
    }
}

/// Resolves PTR queries for addresses currently owned by either FakeIP pool.
/// A local hit is answered before the upstream resolver is called; an unknown
/// reverse name returns `None` so the caller can preserve the upstream path.
pub struct FakeIpPtrTransform {
    pub ipv4: Arc<FakeIpPool>,
    pub ipv6: Arc<FakeIpV6Pool>,
}

impl FakeIpPtrTransform {
    async fn local_response(
        &self,
        domain: &DomainName,
        record_type: DnsRecordType,
    ) -> Result<Option<DnsResponse>> {
        if record_type != DnsRecordType::Ptr {
            return Ok(None);
        }
        let Some(address) = reverse_name_to_ip(domain) else {
            return Ok(None);
        };
        let mapped = match address {
            IpAddr::V4(address) => self.ipv4.lookup_domain(address).await,
            IpAddr::V6(address) => self.ipv6.lookup_domain(address).await,
        };
        Ok(mapped.map(|domain| DnsResponse {
            addresses: IpSet::default(),
            ptr_names: vec![domain],
            service_bindings: Vec::new(),
            minimum_ttl: Some(60),
        }))
    }

    pub async fn apply(
        &self,
        _domain: &DomainName,
        _record_type: DnsRecordType,
        response: DnsResponse,
    ) -> Result<DnsResponse> {
        Ok(response)
    }
}

impl FakeIpAnswerTransform {
    pub async fn apply(
        &self,
        domain: &DomainName,
        record_type: DnsRecordType,
        response: DnsResponse,
    ) -> Result<DnsResponse> {
        if record_type == DnsRecordType::A && !response.addresses.v4.is_empty() {
            let address = self.pool.allocate(domain.clone()).await?;
            return Ok(DnsResponse {
                addresses: IpSet {
                    v4: vec![address],
                    v6: Vec::new(),
                },
                ptr_names: response.ptr_names,
                service_bindings: response.service_bindings,
                minimum_ttl: response.minimum_ttl,
            });
        }
        if !matches!(record_type, DnsRecordType::Https | DnsRecordType::Svcb)
            || !response.service_bindings.iter().any(|binding| {
                binding.params.iter().any(|param| {
                    matches!(param, DnsServiceParam::Ipv4Hint(values) if !values.is_empty())
                })
            })
        {
            return Ok(response);
        }
        let address = self.pool.allocate(domain.clone()).await?;
        let mut service_bindings = response.service_bindings;
        for binding in &mut service_bindings {
            for param in &mut binding.params {
                if let DnsServiceParam::Ipv4Hint(values) = param {
                    *values = vec![address];
                }
            }
        }
        Ok(DnsResponse {
            addresses: response.addresses,
            ptr_names: response.ptr_names,
            service_bindings,
            minimum_ttl: response.minimum_ttl,
        })
    }
}

pub trait AsyncDomainResolver {
    fn resolve<'a>(
        &'a self,
        domain: &'a DomainName,
        record_type: DnsRecordType,
    ) -> BoxFuture<'a, Result<DnsResponse>>;
}

pub trait FakeIpResponseTransform {
    fn local_response<'a>(
        &'a self,
        _domain: &'a DomainName,
        _record_type: DnsRecordType,
    ) -> BoxFuture<'a, Result<Option<DnsResponse>>> {
        Box::pin(async { Ok(None) })
    }

    fn apply<'a>(
        &'a self,
        domain: &'a DomainName,
        record_type: DnsRecordType,
        response: DnsResponse,
    ) -> BoxFuture<'a, Result<DnsResponse>>;
}

impl FakeIpResponseTransform for FakeIpAnswerTransform {
    fn apply<'a>(
        &'a self,
        domain: &'a DomainName,
        record_type: DnsRecordType,
        response: DnsResponse,
    ) -> BoxFuture<'a, Result<DnsResponse>> {
        Box::pin(
            async move { FakeIpAnswerTransform::apply(self, domain, record_type, response).await },
        )
    }
}

impl FakeIpResponseTransform for FakeIpV6AnswerTransform {
    fn apply<'a>(
        &'a self,
        domain: &'a DomainName,
        record_type: DnsRecordType,
        response: DnsResponse,
    ) -> BoxFuture<'a, Result<DnsResponse>> {
        Box::pin(async move {
            FakeIpV6AnswerTransform::apply(self, domain, record_type, response).await
        })
    }
}

impl FakeIpResponseTransform for FakeIpDualStackAnswerTransform {
    fn apply<'a>(
        &'a self,
        domain: &'a DomainName,
        record_type: DnsRecordType,
        response: DnsResponse,
    ) -> BoxFuture<'a, Result<DnsResponse>> {
        Box::pin(async move { self.apply(domain, record_type, response).await })
    }
}

impl FakeIpResponseTransform for FakeIpPtrTransform {
    fn local_response<'a>(
        &'a self,
        domain: &'a DomainName,
        record_type: DnsRecordType,
    ) -> BoxFuture<'a, Result<Option<DnsResponse>>> {
        Box::pin(async move { FakeIpPtrTransform::local_response(self, domain, record_type).await })
    }

    fn apply<'a>(
        &'a self,
        domain: &'a DomainName,
        record_type: DnsRecordType,
        response: DnsResponse,
    ) -> BoxFuture<'a, Result<DnsResponse>> {
        Box::pin(
            async move { FakeIpPtrTransform::apply(self, domain, record_type, response).await },
        )
    }
}

pub struct FakeIpAsyncDnsHandler<R, T = FakeIpAnswerTransform> {
    pub upstream: R,
    pub transform: T,
}

impl<R, T> AsyncDnsHandler for FakeIpAsyncDnsHandler<R, T>
where
    R: AsyncDomainResolver + Send + Sync,
    T: FakeIpResponseTransform + Send + Sync,
{
    fn answer<'a>(&'a self, packet: &'a [u8]) -> BoxFuture<'a, Result<Vec<u8>>> {
        Box::pin(async move {
            let question = decode_query(packet)?;
            let response = if let Some(response) = self
                .transform
                .local_response(&question.domain, question.record_type)
                .await?
            {
                response
            } else {
                self.upstream
                    .resolve(&question.domain, question.record_type)
                    .await?
            };
            let response = self
                .transform
                .apply(&question.domain, question.record_type, response)
                .await?;
            encode_response(packet, &response)
        })
    }
}
