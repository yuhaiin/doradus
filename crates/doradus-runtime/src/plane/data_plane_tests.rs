//! Runtime data-plane tests.

use super::*;
use crate::RuntimeBuilder;
use doradus_core::dns::{
    AsyncDnsHandler, DnsRecordType, DnsResponse, DnsServiceBinding, DnsServiceParam, decode_query,
    decode_response, encode_query, encode_raw_query,
};
use doradus_core::dns::{AsyncUdpDnsClient, AsyncUdpDnsServer};
use doradus_core::dns_resolver::{AsyncIpResolver, SystemAsyncIpResolver};
use doradus_core::dns_tcp::{AsyncTcpDnsClient, AsyncTcpDnsServer};
use doradus_core::{BoxFuture, DomainName, ErrorKind, IpSet, ResolveStrategy};
use doradus_store::fakeip::{FakeIpConfig, FakeIpPool, FakeIpV6Config, FakeIpV6Pool};
use doradus_store::{ConfigStore, FakeIpPools, FakeIpResolver};
use std::sync::Arc;

fn platform_tun_config(enabled: bool) -> TunRuntimeConfig {
    TunRuntimeConfig {
        inbound_id: None,
        enabled,
        tun: doradus_tun::TunConfig {
            name: Some("platform-vpn".to_owned()),
            ipv4: Some((Ipv4Addr::new(10, 42, 0, 1), 24)),
            ..Default::default()
        },
        network_service: None,
        routes: Vec::new(),
        direct_id: "direct".to_owned(),
        proxy_id: Some("proxy".to_owned()),
        bypass_id: String::new(),
        drop_id: String::new(),
        channel_capacity: 256,
        socket_rx_buffer_size: DEFAULT_TUN_SOCKET_RX_BUFFER_SIZE,
        socket_tx_buffer_size: DEFAULT_TUN_SOCKET_TX_BUFFER_SIZE,
        udp_packet_capacity: DEFAULT_TUN_UDP_PACKET_CAPACITY,
    }
}

#[test]
fn tun_socket_defaults_use_bounded_per_flow_buffers() {
    let config = platform_tun_config(true);
    assert_eq!(config.socket_rx_buffer_size, 8 * 1024);
    assert_eq!(config.socket_tx_buffer_size, 8 * 1024);
}

fn go_tun_record(id: &str, enabled: bool, updated_at: i64) -> GoInboundRecord {
    let data = serde_json::json!({
        "id": id,
        "name": id,
        "enabled": enabled,
        "network": {"type": "empty", "empty": {}},
        "transports": [],
        "protocol": {
            "type": "tun",
            "tun": {
                "name": format!("tun://{id}"),
                "portal": "10.42.0.1/24"
            }
        }
    });
    GoInboundRecord {
        id: id.to_owned(),
        name: id.to_owned(),
        enabled,
        network_type: "empty".to_owned(),
        protocol_type: "tun".to_owned(),
        transport_types_json: br"[]".to_vec(),
        updated_at,
        data_json: serde_json::to_vec(&data).unwrap(),
    }
}

#[test]
fn go_tun_selection_ignores_disabled_default_when_custom_tun_is_enabled() {
    let selected = select_go_tun_record(vec![
        go_tun_record("tun", false, 0),
        go_tun_record("custom", true, 1),
    ])
    .unwrap()
    .unwrap();
    assert_eq!(selected.id, "custom");
}

#[test]
fn go_tun_selection_rejects_multiple_enabled_devices() {
    let error = select_go_tun_record(vec![
        go_tun_record("first", true, 1),
        go_tun_record("second", true, 2),
    ])
    .unwrap_err();
    assert!(error.to_string().contains("multiple enabled TUN"));
}

#[test]
fn go_tun_selection_keeps_newest_disabled_definition() {
    let selected = select_go_tun_record(vec![
        go_tun_record("older", false, 1),
        go_tun_record("newer", false, 2),
    ])
    .unwrap()
    .unwrap();
    assert_eq!(selected.id, "newer");
}

#[tokio::test]
async fn desktop_tun_loader_keeps_all_enabled_go_inbounds() {
    let store = ConfigStore::open_memory().await.unwrap();
    for (id, enabled) in [("default", false), ("alpha", true), ("beta", true)] {
        store
            .repository()
            .put_go_inbound(&go_tun_record(id, enabled, 1))
            .await
            .unwrap();
    }

    let configs = load_tun_configs_for_desktop(&store).await.unwrap();
    assert_eq!(configs.len(), 3);
    assert_eq!(
        configs
            .iter()
            .map(|config| config.tun.name.as_deref())
            .collect::<Vec<_>>(),
        vec![Some("alpha"), Some("beta"), Some("default")]
    );
    assert_eq!(configs.iter().filter(|config| config.enabled).count(), 2);
}

#[tokio::test]
async fn desktop_tun_loader_rejects_duplicate_enabled_device_names() {
    let store = ConfigStore::open_memory().await.unwrap();
    let mut first = go_tun_record("first", true, 1);
    let mut second = go_tun_record("second", true, 2);
    for record in [&mut first, &mut second] {
        let mut value: Value = serde_json::from_slice(&record.data_json).unwrap();
        value["protocol"]["tun"]["name"] = Value::String("tun://shared".to_owned());
        record.data_json = serde_json::to_vec(&value).unwrap();
        store.repository().put_go_inbound(record).await.unwrap();
    }

    let error = load_tun_configs_for_desktop(&store).await.unwrap_err();
    assert!(error.to_string().contains("same device name"));
}

#[tokio::test]
async fn inbound_dns_handler_uses_the_route_resolver_for_hijacked_queries() {
    let store = ConfigStore::open_memory().await.unwrap();
    let mut snapshot = RuntimeBuilder::new(store, Arc::new(SystemAsyncIpResolver))
        .build()
        .await
        .unwrap();
    snapshot.resolver = Arc::new(FixedAddressResolver {
        address: Ipv4Addr::new(192, 0, 2, 1),
    });
    snapshot.dns_resolver = Arc::new(FixedAddressResolver {
        address: Ipv4Addr::new(192, 0, 2, 2),
    });
    snapshot.inbound_resolver = Arc::new(FixedAddressResolver {
        address: Ipv4Addr::new(192, 0, 2, 3),
    });
    snapshot.resolver_by_id.insert(
        "bootstrap".to_owned(),
        Arc::new(FixedAddressResolver {
            address: Ipv4Addr::new(192, 0, 2, 53),
        }),
    );
    snapshot.dns_resolver_by_id.insert(
        "bootstrap".to_owned(),
        Arc::new(FixedAddressResolver {
            address: Ipv4Addr::new(192, 0, 2, 54),
        }),
    );
    snapshot.inbound_resolver_by_id.insert(
        "bootstrap".to_owned(),
        Arc::new(FixedAddressResolver {
            address: Ipv4Addr::new(192, 0, 2, 53),
        }),
    );
    snapshot.resolver_registry_enabled = true;
    snapshot.route.as_mut().unwrap().proxy_resolver = "bootstrap".to_owned();
    snapshot.inbound_settings.hijack_dns = true;

    let domain = DomainName::new("route-selected.example.test").unwrap();
    let packet = encode_query(0x5353, &domain, DnsRecordType::A).unwrap();

    snapshot.inbound_settings.hijack_dns_fakeip = true;
    let handler = inbound_dns_handler(&snapshot).unwrap().unwrap();
    let response = handler.answer(&packet).await.unwrap();
    assert_eq!(
        decode_response(&response, 0x5353, DnsRecordType::A)
            .unwrap()
            .addresses
            .v4,
        vec![Ipv4Addr::new(192, 0, 2, 53)]
    );

    snapshot.inbound_settings.hijack_dns_fakeip = false;
    let handler = inbound_dns_handler(&snapshot).unwrap().unwrap();
    let response = handler.answer(&packet).await.unwrap();
    assert_eq!(
        decode_response(&response, 0x5353, DnsRecordType::A)
            .unwrap()
            .addresses
            .v4,
        vec![Ipv4Addr::new(192, 0, 2, 54)]
    );
}

#[tokio::test]
async fn inbound_dns_handler_reports_a_missing_route_resolver() {
    let store = ConfigStore::open_memory().await.unwrap();
    let mut snapshot = RuntimeBuilder::new(store, Arc::new(SystemAsyncIpResolver))
        .build()
        .await
        .unwrap();
    snapshot.inbound_settings.hijack_dns = true;
    snapshot.resolver_registry_enabled = true;
    snapshot.route.as_mut().unwrap().proxy_resolver = "missing".to_owned();

    let error = match inbound_dns_handler(&snapshot) {
        Ok(_) => panic!("missing route resolver unexpectedly produced a DNS handler"),
        Err(error) => error,
    };
    assert_eq!(error.kind, ErrorKind::NotFound);
    assert!(error.message.contains("missing"));
}

#[tokio::test]
async fn inbound_fakeip_is_available_when_global_fakedns_is_disabled() {
    let store = ConfigStore::open_memory().await.unwrap();
    let mut snapshot = RuntimeBuilder::new(store, Arc::new(SystemAsyncIpResolver))
        .build()
        .await
        .unwrap();
    assert!(snapshot.fakeip.is_none());
    let pools = snapshot
        .inbound_fakeip
        .clone()
        .expect("inbound FakeIP should not depend on global FakeDNS");
    snapshot.inbound_settings.hijack_dns = true;
    snapshot.inbound_settings.hijack_dns_fakeip = true;
    snapshot.inbound_resolver = Arc::new(FakeIpResolver::new(
        Arc::new(FixedAddressResolver {
            address: Ipv4Addr::new(192, 0, 2, 7),
        }),
        pools.clone(),
        false,
    ));

    let domain = DomainName::new("inbound-only-fakeip.example.test").unwrap();
    let packet = encode_query(0x5454, &domain, DnsRecordType::A).unwrap();
    let handler = inbound_dns_handler(&snapshot).unwrap().unwrap();
    let response = handler.answer(&packet).await.unwrap();
    let address = decode_response(&response, 0x5454, DnsRecordType::A)
        .unwrap()
        .addresses
        .v4[0];
    assert_eq!(address.octets()[0], 10);
    assert_eq!(
        pools.view_store().lookup_domain_ip(address.into()),
        Some(domain)
    );
}

struct ServiceBindingResolver;

struct FixedAddressResolver {
    address: Ipv4Addr,
}

struct RawPacketResolver;

impl AsyncIpResolver for RawPacketResolver {
    fn resolve<'a>(
        &'a self,
        _domain: &'a DomainName,
        _strategy: ResolveStrategy,
    ) -> BoxFuture<'a, Result<IpSet>> {
        Box::pin(async { Ok(IpSet::default()) })
    }

    fn query_packet<'a>(&'a self, packet: &'a [u8]) -> BoxFuture<'a, Result<Vec<u8>>> {
        Box::pin(async move {
            assert_eq!(
                decode_query(packet).unwrap_err().kind,
                ErrorKind::Unsupported
            );
            let mut response = packet.to_vec();
            response[2] |= 0x80;
            Ok(response)
        })
    }
}

impl AsyncIpResolver for FixedAddressResolver {
    fn resolve<'a>(
        &'a self,
        _domain: &'a DomainName,
        _strategy: ResolveStrategy,
    ) -> BoxFuture<'a, Result<IpSet>> {
        Box::pin(async move {
            Ok(IpSet {
                v4: vec![self.address],
                v6: Vec::new(),
            })
        })
    }
}

impl AsyncIpResolver for ServiceBindingResolver {
    fn resolve<'a>(
        &'a self,
        _domain: &'a DomainName,
        _strategy: ResolveStrategy,
    ) -> BoxFuture<'a, Result<IpSet>> {
        Box::pin(async { Ok(IpSet::default()) })
    }

    fn query<'a>(
        &'a self,
        _domain: &'a DomainName,
        _record_type: DnsRecordType,
    ) -> BoxFuture<'a, Result<DnsResponse>> {
        Box::pin(async {
            Ok(DnsResponse {
                addresses: IpSet::default(),
                ptr_names: Vec::new(),
                service_bindings: vec![DnsServiceBinding {
                    priority: 1,
                    target: Some(DomainName::new("origin.example.test").unwrap()),
                    params: vec![
                        DnsServiceParam::Alpn(vec!["h2".to_owned()]),
                        DnsServiceParam::Port(8443),
                    ],
                }],
                minimum_ttl: Some(42),
            })
        })
    }
}

#[tokio::test]
async fn injected_tun_host_can_load_shared_persisted_config_without_opening_device() {
    let store = ConfigStore::open_memory().await.unwrap();
    let value = serde_json::json!({
        "enabled": true,
        "name": "vpn0",
        "ipv4": "10.23.0.1/24",
        "ipv6": ["fd23::1/64", {"address": "fd23::2", "prefix": 128}],
        "mtu": 1400,
        "queueCapacity": 64,
        "directId": "direct",
        "proxyId": "proxy",
        "bypassId": "bypass",
        "dropId": "drop",
        "channelCapacity": 32,
        "socketRxBufferSize": 8192,
        "socketTxBufferSize": 12288,
        "udpPacketCapacity": 32
    });
    store
        .put_config("tun.runtime", &serde_json::to_vec(&value).unwrap())
        .await
        .unwrap();
    store
        .put_config("settings", br#"{"ipv6":true}"#)
        .await
        .unwrap();

    let config = load_tun_config(&store).await.unwrap();
    assert!(config.enabled);
    assert_eq!(config.tun.name.as_deref(), Some("vpn0"));
    assert_eq!(config.tun.ipv4, Some((Ipv4Addr::new(10, 23, 0, 1), 24)));
    assert_eq!(config.tun.ipv6.len(), 2);
    assert_eq!(config.tun.mtu, 1400);
    assert_eq!(config.tun.queue_capacity, 64);
    assert_eq!(config.channel_capacity, 32);
    assert_eq!(config.proxy_id.as_deref(), Some("proxy"));
    assert_eq!(config.socket_rx_buffer_size, 8192);
    assert_eq!(config.socket_tx_buffer_size, 12288);
    assert_eq!(config.udp_packet_capacity, 32);
}

#[tokio::test]
async fn go_tun_inbound_is_the_primary_config_source() {
    let store = ConfigStore::open_memory().await.unwrap();
    let value = serde_json::json!({
        "id": "tun",
        "name": "tun",
        "enabled": true,
        "network": {"type": "empty", "empty": {}},
        "transports": [],
        "protocol": {
            "type": "tun",
            "tun": {
                "name": "tun://doradus0",
                "mtu": 1400,
                "portal": "10.24.0.1/24",
                "portalV6": "fd24::1/64",
                "platform": {"darwin": {"network_service": "Wi-Fi"}},
                "skipMulticast": true,
                "routes": ["198.18.0.0/15"],
                "excludes": ["10.0.0.0/8"]
            }
        }
    });
    store
        .repository()
        .put_go_inbound(&GoInboundRecord {
            id: "tun".to_owned(),
            name: "tun".to_owned(),
            enabled: true,
            network_type: "empty".to_owned(),
            protocol_type: "tun".to_owned(),
            transport_types_json: br"[]".to_vec(),
            updated_at: 1,
            data_json: serde_json::to_vec(&value).unwrap(),
        })
        .await
        .unwrap();
    store
        .put_config("settings", br#"{"ipv6":true}"#)
        .await
        .unwrap();

    let config = load_tun_config(&store).await.unwrap();
    assert!(config.enabled);
    assert_eq!(config.tun.name.as_deref(), Some("doradus0"));
    assert_eq!(config.tun.ipv4, Some((Ipv4Addr::new(10, 24, 0, 1), 24)));
    assert_eq!(config.tun.ipv6, vec![("fd24::1".parse().unwrap(), 64)]);
    assert_eq!(config.network_service.as_deref(), Some("Wi-Fi"));
    assert!(config.tun.skip_multicast);
    assert_eq!(config.tun.mtu, 1400);
    assert_eq!(config.routes, ["198.18.0.0/15", "10.0.0.0/8"]);
}

#[test]
fn macos_tun_dns_servers_follow_go_gateway_next_addresses() {
    let config = doradus_tun::TunConfig {
        ipv4: Some((Ipv4Addr::new(10, 24, 0, 1), 24)),
        ipv6: vec![("fd24::1".parse().unwrap(), 64)],
        ..Default::default()
    };
    assert_eq!(
        tun_dns_servers(&config),
        vec![
            "10.24.0.2".parse::<std::net::IpAddr>().unwrap(),
            "fd24::2".parse::<std::net::IpAddr>().unwrap(),
        ]
    );
}

#[tokio::test]
async fn injected_tun_host_keeps_device_creation_disabled_by_default() {
    let store = ConfigStore::open_memory().await.unwrap();
    let config = load_tun_config(&store).await.unwrap();
    assert!(!config.enabled);
    assert!(config.tun.ipv4.is_none());
    assert!(config.tun.ipv6.is_empty());
}

#[tokio::test]
async fn injected_tun_supervisor_keeps_platform_config_without_persisted_tun() {
    let store = ConfigStore::open_memory().await.unwrap();
    let fallback = platform_tun_config(true);
    let config = load_tun_config_for_supervisor(&store, fallback.clone())
        .await
        .unwrap();
    assert_eq!(config.enabled, fallback.enabled);
    assert_eq!(config.tun.name, fallback.tun.name);
}

#[tokio::test]
async fn injected_tun_supervisor_honors_persisted_disable_after_reload() {
    let store = ConfigStore::open_memory().await.unwrap();
    store
        .put_config(
            "tun.runtime",
            br#"{"enabled":false,"name":"platform-vpn","ipv4":"10.42.0.1/24"}"#,
        )
        .await
        .unwrap();
    let config = load_tun_config_for_supervisor(&store, platform_tun_config(true))
        .await
        .unwrap();
    assert!(!config.enabled);
    assert_eq!(config.tun.name.as_deref(), Some("platform-vpn"));
}

#[tokio::test]
async fn dns_server_overlay_is_used_before_legacy_database_fallback() {
    let store = ConfigStore::open_memory().await.unwrap();
    store
        .put_config("resolver.server", br#"{"server":"127.0.0.1:5353"}"#)
        .await
        .unwrap();
    assert_eq!(
        configured_dns_server(&store).await.unwrap().as_deref(),
        Some("127.0.0.1:5353")
    );
}

#[tokio::test]
async fn empty_store_uses_go_default_dns_server() {
    let store = ConfigStore::open_memory().await.unwrap();
    assert_eq!(
        configured_dns_server(&store).await.unwrap().as_deref(),
        Some(DEFAULT_DNS_SERVER)
    );
}

#[tokio::test]
async fn dns_server_binds_udp_and_tcp_on_the_same_configured_address() {
    let probe = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = probe.local_addr().unwrap();
    drop(probe);
    let handler = RuntimeDnsHandler {
        resolver: Arc::new(SystemAsyncIpResolver),
        fakeip: None,
    };
    let udp = doradus_core::dns::AsyncUdpDnsServer::bind(address, handler.clone(), 4096)
        .await
        .unwrap();
    let tcp = AsyncTcpDnsServer::bind(address, handler, 65535, Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(udp.local_addr().unwrap(), address);
    assert_eq!(tcp.local_addr().unwrap(), address);
}

#[tokio::test]
async fn runtime_dns_preserves_https_service_bindings() {
    let domain = DomainName::new("service.example.test").unwrap();
    let packet = encode_query(0x5151, &domain, DnsRecordType::Https).unwrap();
    let handler = RuntimeDnsHandler {
        resolver: Arc::new(ServiceBindingResolver),
        fakeip: None,
    };

    let response = handler.answer(&packet).await.unwrap();
    let decoded = decode_response(&response, 0x5151, DnsRecordType::Https).unwrap();
    assert_eq!(decoded.minimum_ttl, Some(42));
    assert_eq!(decoded.service_bindings.len(), 1);
    assert_eq!(
        decoded.service_bindings[0].target,
        Some(DomainName::new("origin.example.test").unwrap())
    );
    assert!(
        decoded.service_bindings[0]
            .params
            .contains(&DnsServiceParam::Alpn(vec!["h2".to_owned()]))
    );
    assert!(
        decoded.service_bindings[0]
            .params
            .contains(&DnsServiceParam::Port(8443))
    );
}

#[tokio::test]
async fn runtime_dns_forwards_unmodeled_qtypes_to_the_resolver() {
    use doradus_core::dns::{decode_query, encode_raw_query};

    struct RawResolver;

    impl AsyncIpResolver for RawResolver {
        fn resolve<'a>(
            &'a self,
            _domain: &'a DomainName,
            _strategy: ResolveStrategy,
        ) -> BoxFuture<'a, Result<IpSet>> {
            Box::pin(async { Ok(IpSet::default()) })
        }

        fn query_packet<'a>(&'a self, packet: &'a [u8]) -> BoxFuture<'a, Result<Vec<u8>>> {
            Box::pin(async move {
                assert_eq!(
                    decode_query(packet).unwrap_err().kind,
                    ErrorKind::Unsupported
                );
                let mut response = packet.to_vec();
                response[2] |= 0x80;
                Ok(response)
            })
        }
    }

    let query = encode_raw_query(0x6161, &DomainName::new("example.test").unwrap(), 16).unwrap();
    let handler = RuntimeDnsHandler {
        resolver: Arc::new(RawResolver),
        fakeip: None,
    };
    let response = handler.answer(&query).await.unwrap();
    assert_eq!(response, {
        let mut expected = query.clone();
        expected[2] |= 0x80;
        expected
    });
}

#[tokio::test]
async fn runtime_dns_servers_forward_unmodeled_qtypes_over_udp_and_tcp() {
    let query = encode_raw_query(0x7171, &DomainName::new("example.test").unwrap(), 16).unwrap();
    let handler = RuntimeDnsHandler {
        resolver: Arc::new(RawPacketResolver),
        fakeip: None,
    };

    let udp_server = AsyncUdpDnsServer::bind("127.0.0.1:0".parse().unwrap(), handler.clone(), 2048)
        .await
        .unwrap();
    let udp_client = AsyncUdpDnsClient::new(
        udp_server.local_addr().unwrap(),
        Duration::from_secs(1),
        2048,
        Arc::from(Vec::new().into_boxed_slice()),
        None,
    );
    let (udp_server_result, udp_response) =
        tokio::join!(udp_server.serve_once(), udp_client.query_packet(&query));
    assert!(udp_server_result.unwrap() > 0);
    let mut expected = query.clone();
    expected[2] |= 0x80;
    assert_eq!(udp_response.unwrap(), expected);

    let tcp_server = AsyncTcpDnsServer::bind(
        "127.0.0.1:0".parse().unwrap(),
        handler,
        2048,
        Duration::from_secs(1),
    )
    .await
    .unwrap();
    let tcp_client = AsyncTcpDnsClient {
        server: tcp_server.local_addr().unwrap(),
        timeout: Duration::from_secs(1),
        max_packet_size: 2048,
        local_bind_addresses: Arc::from(Vec::new().into_boxed_slice()),
        bind_interface: None,
    };
    let (tcp_server_result, tcp_response) =
        tokio::join!(tcp_server.serve_once(), tcp_client.query_packet(&query));
    assert!(tcp_server_result.unwrap() > 2);
    assert_eq!(tcp_response.unwrap(), expected);
}

#[tokio::test]
async fn runtime_dns_returns_preloaded_fakeip_ptr_mapping() {
    let store = ConfigStore::open_memory().await.unwrap();
    let pool = Arc::new(
        FakeIpPool::open(
            store.clone(),
            FakeIpConfig::new("198.18.0.1".parse().unwrap(), "198.18.0.8".parse().unwrap())
                .unwrap(),
        )
        .await
        .unwrap(),
    );
    let ipv6 = Arc::new(
        FakeIpV6Pool::open(
            store,
            FakeIpV6Config::new("fc00::1".parse().unwrap(), "fc00::8".parse().unwrap()).unwrap(),
        )
        .await
        .unwrap(),
    );
    let pools = FakeIpPools::new(pool, ipv6);
    let original = DomainName::new("ptr.example.test").unwrap();
    let address = pools.ipv4.allocate(original.clone()).await.unwrap();
    let octets = address.octets();
    let reverse_name = format!(
        "{}.{}.{}.{}.in-addr.arpa",
        octets[3], octets[2], octets[1], octets[0]
    );
    let reverse = DomainName::new(&reverse_name).unwrap();
    let packet = encode_query(0x4242, &reverse, DnsRecordType::Ptr).unwrap();
    let handler = RuntimeDnsHandler {
        resolver: Arc::new(SystemAsyncIpResolver),
        fakeip: Some(pools),
    };

    let response = handler.answer(&packet).await.unwrap();
    let decoded = decode_response(&response, 0x4242, DnsRecordType::Ptr).unwrap();
    assert_eq!(decoded.ptr_names, vec![original]);
    assert_eq!(decoded.minimum_ttl, Some(60));
}

#[tokio::test]
async fn reloadable_tun_dns_handler_switches_snapshots_without_rebuilding_owner() {
    let domain = DomainName::new("reload.example.test").unwrap();
    let packet = encode_query(0x1212, &domain, DnsRecordType::A).unwrap();
    let handler = ReloadableAsyncDnsHandler::new(Some(RuntimeDnsHandler {
        resolver: Arc::new(FixedAddressResolver {
            address: Ipv4Addr::new(192, 0, 2, 10),
        }),
        fakeip: None,
    }));
    let response = handler.answer(&packet).await.unwrap();
    assert_eq!(
        decode_response(&response, 0x1212, DnsRecordType::A)
            .unwrap()
            .addresses
            .v4,
        vec![Ipv4Addr::new(192, 0, 2, 10)]
    );

    handler.replace(Some(RuntimeDnsHandler {
        resolver: Arc::new(FixedAddressResolver {
            address: Ipv4Addr::new(192, 0, 2, 11),
        }),
        fakeip: None,
    }));
    let response = handler.answer(&packet).await.unwrap();
    assert_eq!(
        decode_response(&response, 0x1212, DnsRecordType::A)
            .unwrap()
            .addresses
            .v4,
        vec![Ipv4Addr::new(192, 0, 2, 11)]
    );

    handler.replace(None);
    let error = handler.answer(&packet).await.unwrap_err();
    assert!(error.to_string().contains("DNS hijacking is disabled"));
}

#[tokio::test]
async fn disabled_supervisor_waits_for_reload_instead_of_only_shutdown() {
    let store = ConfigStore::open_memory().await.unwrap();
    let controller = crate::RuntimeController::from_builder(RuntimeBuilder::new(
        store,
        Arc::new(SystemAsyncIpResolver),
    ))
    .await
    .unwrap();
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    let waiting_controller = controller.clone();
    let waiting =
        tokio::spawn(
            async move { wait_for_shutdown_or_reload(&waiting_controller, shutdown_rx).await },
        );
    tokio::task::yield_now().await;
    controller.reload().await.unwrap();
    let result = tokio::time::timeout(Duration::from_secs(1), waiting)
        .await
        .unwrap()
        .unwrap();
    assert!(!result);
}
