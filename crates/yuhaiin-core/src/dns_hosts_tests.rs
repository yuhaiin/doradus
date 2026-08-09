use super::*;
use crate::dns::{DnsQuestion, decode_query, decode_response, encode_query};

struct StaticUpstream;

impl DnsHandler for StaticUpstream {
    fn resolve(&self, _domain: &DomainName, _record_type: DnsRecordType) -> Result<DnsResponse> {
        Ok(DnsResponse {
            addresses: IpSet {
                v4: vec!["203.0.113.99".parse().unwrap()],
                v6: Vec::new(),
            },
            ptr_names: Vec::new(),
            service_bindings: Vec::new(),
            minimum_ttl: Some(30),
        })
    }
}

fn hosts() -> (HostsTable, DomainName) {
    let hosts = HostsTable::new();
    let domain = DomainName::new("local.example").unwrap();
    hosts
        .insert_ip(domain.clone(), "192.0.2.10".parse().unwrap())
        .unwrap();
    hosts
        .insert_ip(domain.clone(), "2001:db8::10".parse().unwrap())
        .unwrap();
    (hosts, domain)
}

#[test]
fn hosts_table_deduplicates_dual_stack_addresses_and_supports_reload() {
    let (hosts, domain) = hosts();
    hosts
        .insert_ip(domain.clone(), "192.0.2.10".parse().unwrap())
        .unwrap();
    let entry = hosts.lookup(&domain).unwrap().unwrap();
    assert_eq!(
        entry.v4,
        vec!["192.0.2.10".parse::<std::net::Ipv4Addr>().unwrap()]
    );
    assert_eq!(
        entry.v6,
        vec!["2001:db8::10".parse::<std::net::Ipv6Addr>().unwrap()]
    );
    assert_eq!(hosts.len().unwrap(), 1);
    assert!(hosts.remove(&domain).unwrap());
    assert!(hosts.lookup(&domain).unwrap().is_none());
}

#[test]
fn hosts_handler_overrides_a_and_aaaa_but_delegates_unknown_queries() {
    let (hosts, domain) = hosts();
    let handler = HostsDnsHandler {
        hosts,
        upstream: StaticUpstream,
    };
    let a = handler.resolve(&domain, DnsRecordType::A).unwrap();
    assert_eq!(
        a.addresses.v4,
        vec!["192.0.2.10".parse::<std::net::Ipv4Addr>().unwrap()]
    );
    assert!(a.addresses.v6.is_empty());
    let aaaa = handler.resolve(&domain, DnsRecordType::Aaaa).unwrap();
    assert_eq!(
        aaaa.addresses.v6,
        vec!["2001:db8::10".parse::<std::net::Ipv6Addr>().unwrap()]
    );
    let unknown = handler
        .resolve(
            &DomainName::new("remote.example").unwrap(),
            DnsRecordType::A,
        )
        .unwrap();
    assert_eq!(
        unknown.addresses.v4,
        vec!["203.0.113.99".parse::<std::net::Ipv4Addr>().unwrap()]
    );
}

#[test]
fn hosts_handler_does_not_hide_non_address_records_from_upstream() {
    let (hosts, domain) = hosts();
    let handler = HostsDnsHandler {
        hosts,
        upstream: StaticUpstream,
    };
    let response = handler.resolve(&domain, DnsRecordType::Https).unwrap();
    assert_eq!(
        response.addresses.v4,
        vec!["203.0.113.99".parse::<std::net::Ipv4Addr>().unwrap()]
    );
}

#[test]
fn hosts_aliases_follow_chains_and_unresolved_aliases_use_upstream() {
    let (hosts, target) = hosts();
    let alias = DomainName::new("alias.example").unwrap();
    let alias2 = DomainName::new("alias2.example").unwrap();
    hosts.insert_alias(alias2.clone(), target).unwrap();
    hosts.insert_alias(alias, alias2).unwrap();
    let handler = HostsDnsHandler {
        hosts: hosts.clone(),
        upstream: StaticUpstream,
    };
    assert_eq!(
        handler
            .resolve(&DomainName::new("alias.example").unwrap(), DnsRecordType::A)
            .unwrap()
            .addresses
            .v4,
        vec!["192.0.2.10".parse::<std::net::Ipv4Addr>().unwrap()]
    );

    hosts
        .insert_alias(
            DomainName::new("unresolved.example").unwrap(),
            DomainName::new("missing.example").unwrap(),
        )
        .unwrap();
    assert_eq!(
        handler
            .resolve(
                &DomainName::new("unresolved.example").unwrap(),
                DnsRecordType::A,
            )
            .unwrap()
            .addresses
            .v4,
        vec!["203.0.113.99".parse::<std::net::Ipv4Addr>().unwrap()]
    );
}

#[test]
fn hosts_alias_cycles_are_rejected_and_target_loading_accepts_ip_or_domain() {
    let hosts = HostsTable::new();
    hosts
        .insert_target(DomainName::new("example.com").unwrap(), "example.com")
        .unwrap();
    assert_eq!(
        hosts
            .resolve(&DomainName::new("example.com").unwrap())
            .unwrap(),
        None
    );
    hosts
        .insert_target(DomainName::new("ip.example").unwrap(), "192.0.2.20")
        .unwrap();
    hosts
        .insert_target(DomainName::new("alias.example").unwrap(), "ip.example")
        .unwrap();
    assert_eq!(
        hosts
            .resolve(&DomainName::new("alias.example").unwrap())
            .unwrap()
            .unwrap()
            .v4,
        vec!["192.0.2.20".parse::<std::net::Ipv4Addr>().unwrap()]
    );
    hosts
        .insert_alias(
            DomainName::new("cycle-a.example").unwrap(),
            DomainName::new("cycle-b.example").unwrap(),
        )
        .unwrap();
    hosts
        .insert_alias(
            DomainName::new("cycle-b.example").unwrap(),
            DomainName::new("cycle-a.example").unwrap(),
        )
        .unwrap();
    assert!(
        hosts
            .resolve(&DomainName::new("cycle-a.example").unwrap())
            .is_err()
    );
}

#[test]
fn host_overrides_accept_go_address_forms_with_optional_ports() {
    assert_eq!(host_without_port("example.com"), "example.com");
    assert_eq!(host_without_port("example.com:443"), "example.com");
    assert_eq!(host_without_port("[2001:db8::1]:443"), "2001:db8::1");
    assert_eq!(host_without_port("2001:db8::1"), "2001:db8::1");

    let hosts = HostsTable::new();
    hosts
        .insert_target(DomainName::new("example.com").unwrap(), "127.0.0.1:8022")
        .unwrap();
    assert_eq!(
        hosts
            .lookup(&DomainName::new("example.com").unwrap())
            .unwrap()
            .unwrap()
            .v4,
        vec!["127.0.0.1".parse::<std::net::Ipv4Addr>().unwrap()]
    );
}

#[cfg(feature = "async-proxy")]
struct AsyncStaticUpstream;

#[cfg(feature = "async-proxy")]
impl AsyncDnsHandler for AsyncStaticUpstream {
    fn answer<'a>(&'a self, packet: &'a [u8]) -> LocalBoxFuture<'a, Result<Vec<u8>>> {
        Box::pin(async move {
            let DnsQuestion { .. } = decode_query(packet)?;
            crate::dns::encode_response(
                packet,
                &DnsResponse {
                    addresses: IpSet {
                        v4: vec!["203.0.113.99".parse().unwrap()],
                        v6: Vec::new(),
                    },
                    ptr_names: Vec::new(),
                    service_bindings: Vec::new(),
                    minimum_ttl: Some(30),
                },
            )
        })
    }
}

#[cfg(feature = "async-proxy")]
#[tokio::test(flavor = "current_thread")]
async fn async_hosts_handler_answers_hosts_before_upstream() {
    let (hosts, domain) = hosts();
    let handler = AsyncHostsDnsHandler {
        hosts,
        upstream: AsyncStaticUpstream,
    };
    let packet = encode_query(7, &domain, DnsRecordType::A).unwrap();
    let response = handler.answer(&packet).await.unwrap();
    let decoded = decode_response(&response, 7, DnsRecordType::A).unwrap();
    assert_eq!(
        decoded.addresses.v4,
        vec!["192.0.2.10".parse::<std::net::Ipv4Addr>().unwrap()]
    );
    assert_eq!(decoded.minimum_ttl, Some(60));
}
