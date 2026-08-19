use super::tun_test_support::*;
use super::*;

#[test]
fn stale_proxy_flow_and_backpressure_errors_are_recoverable() {
    assert!(is_recoverable_proxy_flow_error(&Error::new(
        ErrorKind::Closed,
        "flow command channel closed",
    )));
    assert!(is_recoverable_proxy_flow_error(&Error::new(
        ErrorKind::NotFound,
        "flow no longer exists",
    )));
    assert!(is_recoverable_proxy_flow_error(&Error::new(
        ErrorKind::Timeout,
        "flow command queue full",
    )));
    assert_eq!(
        proxy_input_flow_key(&ProxyInput::TcpData {
            flow: TunFlow {
                key: TunFlowKey {
                    network: Network::Tcp,
                    source: "192.0.2.1:1234".parse().unwrap(),
                    destination: "198.51.100.1:443".parse().unwrap(),
                },
            },
            payload: Vec::new(),
        })
        .network,
        Network::Tcp
    );
}

#[test]
fn validates_and_classifies_ip_packets() {
    let ipv4 = [
        0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 8, 8, 8, 8,
    ];
    assert_eq!(
        inspect_ip_packet(&ipv4).unwrap(),
        PacketInfo {
            version: IpPacketVersion::V4,
            length: 20,
            fragmented: false,
        }
    );
    let mut ipv6 = [0u8; 40];
    ipv6[0] = 0x60;
    ipv6[6] = 59;
    ipv6[7] = 64;
    ipv6[23] = 1;
    ipv6[39] = 1;
    assert_eq!(
        inspect_ip_packet(&ipv6).unwrap(),
        PacketInfo {
            version: IpPacketVersion::V6,
            length: 40,
            fragmented: false,
        }
    );
    assert!(inspect_ip_packet(&[0x45, 0, 0]).is_err());
}

#[test]
fn bounded_random_ip_and_transport_packets_never_panic() {
    let mut state = 0x243f_6a88_u32;
    for sample in 0..2048usize {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        let length = (state as usize ^ sample).min(2048);
        let mut packet = vec![0u8; length];
        for byte in &mut packet {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            *byte = (state >> 24) as u8;
        }
        let _ = inspect_ip_packet(&packet);
        let _ = parse_transport_tuple(&packet);
    }
}

#[test]
fn queue_device_exposes_ip_medium_and_bounded_rx() {
    let device = SmoltcpTunDevice::new(1500, 1).unwrap();
    let packet = vec![
        0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 8, 8, 8, 8,
    ];
    assert!(device.enqueue_rx(packet.clone()).unwrap());
    assert!(!device.enqueue_rx(packet.clone()).unwrap());
    assert_eq!(device.queued_rx().unwrap(), 1);
    assert_eq!(device.peek_rx_packet().unwrap(), Some(packet.clone()));
    assert_eq!(device.take_rx_packet().unwrap(), Some(packet));
    assert_eq!(device.queued_rx().unwrap(), 0);
    assert_eq!(device.capabilities().medium, Medium::Ip);
}

#[test]
fn dispatcher_skips_ipv4_and_ipv6_multicast_before_smoltcp_dispatch() {
    let local = Ipv4Address::new(10, 0, 0, 1);
    let remote = Ipv4Address::new(10, 0, 0, 2);
    let mut device = SmoltcpTunDevice::new(1500, 8).unwrap();
    let mut interface = Interface::new(
        Config::new(HardwareAddress::Ip),
        &mut device,
        Instant::from_millis(0),
    );
    interface.set_any_ip(true);
    interface.update_ip_addrs(|addresses| {
        addresses
            .push(IpCidr::new(IpAddress::Ipv4(local), 24))
            .unwrap();
        addresses
            .push(IpCidr::new(IpAddress::Ipv6("fe80::1".parse().unwrap()), 64))
            .unwrap();
    });
    let mut dispatcher = TunDispatcher::new(2048, 2048, 4)
        .unwrap()
        .with_skip_multicast(true);

    device
        .enqueue_rx(udp_packet(remote, local, 41000, 1900, b"ordinary"))
        .unwrap();
    device
        .enqueue_rx(udp_packet(
            remote,
            Ipv4Address::new(239, 255, 255, 250),
            41000,
            1900,
            b"ssdp",
        ))
        .unwrap();
    device
        .enqueue_rx(ipv6_udp_packet(
            "fe80::2".parse().unwrap(),
            "ff02::c".parse().unwrap(),
            41000,
            1900,
            b"ssdp6",
        ))
        .unwrap();

    dispatcher
        .poll_with(&mut interface, &mut device, Instant::from_millis(1))
        .unwrap();

    let events: Vec<_> = dispatcher.proxy_inputs().collect();
    let [ProxyInput::UdpDatagram { payload, .. }] = events.as_slice() else {
        panic!("expected only the ordinary UDP packet, got {events:?}");
    };
    assert_eq!(payload, b"ordinary");
    assert_eq!(device.queued_rx().unwrap(), 0);
}

#[test]
fn dispatcher_drops_cross_family_multicast_socket_matches_without_panicking() {
    let local = Ipv4Address::new(239, 255, 255, 250);
    let remote = Ipv4Address::new(10, 0, 0, 2);
    let mut device = SmoltcpTunDevice::new(1500, 8).unwrap();
    let mut interface = Interface::new(
        Config::new(HardwareAddress::Ip),
        &mut device,
        Instant::from_millis(0),
    );
    interface.set_any_ip(true);
    interface.update_ip_addrs(|addresses| {
        addresses
            .push(IpCidr::new(
                IpAddress::Ipv4(Ipv4Address::new(10, 0, 0, 1)),
                24,
            ))
            .unwrap();
        addresses
            .push(IpCidr::new(IpAddress::Ipv6("fe80::1".parse().unwrap()), 64))
            .unwrap();
    });
    let mut dispatcher = TunDispatcher::new(2048, 2048, 4).unwrap();

    // Create the IPv4 multicast-bound socket first. smoltcp 0.13 permits a
    // multicast-bound socket to accept a packet from the other IP family.
    device
        .enqueue_rx(udp_packet(remote, local, 41000, 1900, b"ssdp"))
        .unwrap();
    dispatcher
        .poll_with(&mut interface, &mut device, Instant::from_millis(1))
        .unwrap();
    assert_eq!(dispatcher.proxy_inputs().count(), 1);

    let mixed_flow = TunFlowKey {
        network: Network::Udp,
        source: "[fe80::2]:41000".parse().unwrap(),
        destination: "239.255.255.250:1900".parse().unwrap(),
    };
    let error = dispatcher.write_udp(mixed_flow, b"reply").unwrap_err();
    assert_eq!(error.kind, ErrorKind::InvalidInput);

    device
        .enqueue_rx(ipv6_udp_packet(
            "fe80::2".parse().unwrap(),
            "ff02::c".parse().unwrap(),
            41000,
            1900,
            b"ssdp6",
        ))
        .unwrap();
    dispatcher
        .poll_with(&mut interface, &mut device, Instant::from_millis(2))
        .unwrap();

    assert_eq!(dispatcher.proxy_inputs().count(), 0);
}

#[test]
fn fragmented_packets_are_preserved_but_each_fragment_must_fit_mtu() {
    let mut packet = vec![
        0x45, 0, 0, 24, 0, 1, 0x20, 0, 64, 17, 0, 0, 10, 0, 0, 1, 8, 8, 8, 8, 1, 2, 3, 4,
    ];
    let info = inspect_ip_packet(&packet).unwrap();
    assert!(info.fragmented);

    let device = SmoltcpTunDevice::new(576, 2).unwrap();
    assert!(device.enqueue_rx(packet.clone()).unwrap());

    packet[2..4].copy_from_slice(&577u16.to_be_bytes());
    packet.resize(577, 0);
    assert!(inspect_ip_packet(&packet).is_ok());
    assert!(device.enqueue_rx(packet).is_err());
}

#[test]
fn ipv6_fragment_header_is_classified_without_reassembly() {
    let mut packet = vec![0u8; 56];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&16u16.to_be_bytes());
    packet[6] = 44;
    packet[7] = 64;
    packet[40] = 17;
    packet[42] = 0;
    packet[43] = 1;
    assert!(inspect_ip_packet(&packet).unwrap().fragmented);
}

#[test]
fn ipv6_fragment_reassembler_reassembles_out_of_order_udp() {
    let source = Ipv6Addr::LOCALHOST;
    let destination = Ipv6Addr::LOCALHOST;
    let whole = ipv6_udp_packet(source, destination, 41000, 5353, b"fragmented-ipv6");
    let first = ipv6_fragment(&whole, 0, true, 16, 0x0102_0304);
    let second = ipv6_fragment(&whole, 16, false, whole.len() - 40 - 16, 0x0102_0304);
    let now = StdInstant::now();
    let mut reassembler = Ipv6FragmentReassembler::default();

    assert!(reassembler.push(&second, now).unwrap().is_none());
    let reassembled = reassembler.push(&first, now).unwrap().unwrap();
    assert_eq!(reassembled, whole);
    assert_eq!(reassembled[6], 17);
    assert_eq!(
        u16::from_be_bytes([reassembled[4], reassembled[5]]) as usize,
        whole.len() - 40
    );
    let udp = UdpPacket::new_checked(&reassembled[40..]).unwrap();
    assert_eq!(udp.src_port(), 41000);
    assert_eq!(udp.dst_port(), 5353);
    assert_eq!(udp.payload(), b"fragmented-ipv6");
}

#[test]
fn reassembled_ipv6_datagram_may_exceed_the_wire_mtu() {
    let packet = ipv6_udp_packet(
        Ipv6Addr::LOCALHOST,
        Ipv6Addr::LOCALHOST,
        41000,
        5353,
        &[0xa5; 2000],
    );
    let device = SmoltcpTunDevice::new(1280, 2).unwrap();
    assert!(packet.len() > device.mtu());
    assert!(device.enqueue_rx_reassembled(packet).unwrap());
    assert_eq!(device.queued_rx().unwrap(), 1);
}

#[test]
fn ipv6_fragment_reassembler_drops_overlap_and_expires_assemblies() {
    let whole = ipv6_udp_packet(
        Ipv6Addr::LOCALHOST,
        Ipv6Addr::LOCALHOST,
        41000,
        5353,
        b"overlap-check",
    );
    let first = ipv6_fragment(&whole, 0, true, 16, 0x0a0b_0c0d);
    let overlap = ipv6_fragment(&whole, 8, false, whole.len() - 40 - 8, 0x0a0b_0c0d);
    let later = StdInstant::now() + IPV6_FRAGMENT_TIMEOUT + StdDuration::from_secs(1);
    let mut reassembler = Ipv6FragmentReassembler::default();
    let now = StdInstant::now();

    assert!(reassembler.push(&first, now).unwrap().is_none());
    assert!(reassembler.push(&overlap, now).unwrap().is_none());
    assert!(reassembler.assemblies.is_empty());
    assert!(reassembler.push(&first, now).unwrap().is_none());
    reassembler.expire(later);
    assert!(reassembler.assemblies.is_empty());
}

#[test]
fn ipv6_fragment_reassembler_drops_fragment_count_overflow_without_poisoning() {
    let whole = ipv6_udp_packet(
        Ipv6Addr::LOCALHOST,
        Ipv6Addr::LOCALHOST,
        41000,
        5353,
        &[0xa5; 1024],
    );
    let now = StdInstant::now();
    let mut reassembler = Ipv6FragmentReassembler::default();

    // 128 eight-byte fragments reach the assembly limit; the next fragment
    // must be dropped and must not leave a partial assembly behind.
    for payload_offset in (0..1024).step_by(8) {
        let fragment = ipv6_fragment(&whole, payload_offset, true, 8, 0x1112_1314);
        assert!(reassembler.push(&fragment, now).unwrap().is_none());
    }
    let final_fragment = ipv6_fragment(&whole, 1024, false, 8, 0x1112_1314);
    assert!(reassembler.push(&final_fragment, now).unwrap().is_none());
    assert!(reassembler.assemblies.is_empty());

    // A later datagram with the same flow key can still complete normally.
    let recovered = ipv6_udp_packet(
        Ipv6Addr::LOCALHOST,
        Ipv6Addr::LOCALHOST,
        41000,
        5353,
        b"after-fragment-limit",
    );
    let first = ipv6_fragment(&recovered, 0, true, 8, 0x1112_1314);
    let second = ipv6_fragment(&recovered, 8, false, recovered.len() - 40 - 8, 0x1112_1314);
    assert_eq!(reassembler.push(&first, now).unwrap(), None);
    assert_eq!(reassembler.push(&second, now).unwrap(), Some(recovered));
}

fn ipv6_udp_packet(
    source: Ipv6Addr,
    destination: Ipv6Addr,
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut packet = vec![0; 40 + 8 + payload.len()];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&(8u16 + payload.len() as u16).to_be_bytes());
    packet[6] = 17;
    packet[7] = 64;
    packet[8..24].copy_from_slice(&source.octets());
    packet[24..40].copy_from_slice(&destination.octets());
    packet[40..42].copy_from_slice(&source_port.to_be_bytes());
    packet[42..44].copy_from_slice(&destination_port.to_be_bytes());
    packet[44..46].copy_from_slice(&(8u16 + payload.len() as u16).to_be_bytes());
    packet[46..48].copy_from_slice(&0u16.to_be_bytes());
    packet[48..].copy_from_slice(payload);
    packet
}

fn ipv6_udp_packet_with_hbh_routing_and_destination(payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0; 40 + 8 + 8 + 8 + 8 + payload.len()];
    packet[0] = 0x60;
    let payload_len = (packet.len() - 40) as u16;
    packet[4..6].copy_from_slice(&payload_len.to_be_bytes());
    packet[6] = 0; // Hop-by-Hop Options
    packet[7] = 64;
    packet[8..24].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
    packet[24..40].copy_from_slice(&"2001:db8::2".parse::<Ipv6Addr>().unwrap().octets());

    packet[40] = 43; // Hop-by-Hop -> Routing
    packet[41] = 0; // eight bytes
    packet[48] = 60; // Routing -> Destination Options
    packet[49] = 0; // eight bytes
    packet[56] = 17; // Destination Options -> UDP
    packet[57] = 0; // eight bytes
    packet[64..66].copy_from_slice(&41000u16.to_be_bytes());
    packet[66..68].copy_from_slice(&5353u16.to_be_bytes());
    packet[68..70].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    packet[70..72].copy_from_slice(&0u16.to_be_bytes());
    packet[72..].copy_from_slice(payload);
    packet
}

fn ipv6_fragment(
    packet: &[u8],
    payload_offset: usize,
    more: bool,
    payload_len: usize,
    identification: u32,
) -> Vec<u8> {
    let mut fragment = vec![0; 48 + payload_len];
    fragment[..40].copy_from_slice(&packet[..40]);
    fragment[4..6].copy_from_slice(&(8u16 + payload_len as u16).to_be_bytes());
    fragment[6] = 44;
    fragment[40] = packet[6];
    let offset_and_flags = ((payload_offset / 8) as u16) << 3 | u16::from(more);
    fragment[42..44].copy_from_slice(&offset_and_flags.to_be_bytes());
    fragment[44..48].copy_from_slice(&identification.to_be_bytes());
    fragment[48..].copy_from_slice(&packet[40 + payload_offset..40 + payload_offset + payload_len]);
    fragment
}

#[test]
fn tx_token_accepts_a_complete_datagram_before_tun_fragmentation() {
    let mut device = SmoltcpTunDevice::new(576, 2).unwrap();
    let token = phy::Device::transmit(&mut device, Instant::from_millis(0)).unwrap();
    phy::TxToken::consume(token, 577, |_| ());
    assert_eq!(device.queued_tx().unwrap(), 1);
}

#[test]
fn config_rejects_invalid_mtu_and_queue() {
    let mut config = TunConfig {
        mtu: 100,
        ..TunConfig::default()
    };
    assert!(config.validate().is_err());
    config.mtu = DEFAULT_MTU;
    config.queue_capacity = 0;
    assert!(config.validate().is_err());
}

#[test]
fn config_rejects_an_ipv6_mtu_below_the_protocol_minimum() {
    let config = TunConfig {
        mtu: 576,
        ipv6: vec![(Ipv6Addr::LOCALHOST, 128)],
        ..TunConfig::default()
    };
    let error = config.validate().unwrap_err();
    assert!(error.message.contains("at least 1280"));
}

#[cfg(unix)]
#[test]
fn owned_fd_entrypoint_rejects_invalid_config_before_claiming_descriptor() {
    use std::fs::File;
    use std::os::fd::OwnedFd;

    let file = File::open("/dev/null").unwrap();
    let fd: OwnedFd = file.into();
    let config = TunConfig {
        mtu: 128,
        ..TunConfig::default()
    };
    let error = match TunRuntime::from_owned_fd(config, fd) {
        Ok(_) => panic!("invalid TUN config unexpectedly succeeded"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    assert!(error.to_string().contains("MTU"));
}

#[cfg(all(feature = "tun-routes", target_os = "linux"))]
#[test]
fn linux_capability_probe_only_accepts_the_effective_capability_bit() {
    assert!(has_capability(1_u128 << CAP_NET_ADMIN, CAP_NET_ADMIN));
    assert!(!has_capability(0, CAP_NET_ADMIN));
    assert!(!has_capability(1_u128 << 11, CAP_NET_ADMIN));
}

#[cfg(all(feature = "tun-routes", target_os = "linux"))]
#[test]
fn linux_capability_probe_is_read_only_and_well_formed() {
    let capabilities = probe_linux_capabilities();
    assert!(matches!(
        capabilities.tun_device,
        CapabilityState::Available | CapabilityState::Unavailable
    ));
    assert!(matches!(
        capabilities.route_control,
        CapabilityState::Available | CapabilityState::Unavailable
    ));
    assert!(matches!(
        capabilities.multi_queue,
        CapabilityState::Available | CapabilityState::Unavailable | CapabilityState::Unknown
    ));
}

#[cfg(feature = "tun-routes")]
#[derive(Clone)]
struct RecordingRouteBackend {
    log: Arc<Mutex<Vec<String>>>,
    fail_add_at: Option<usize>,
    fail_remove_once: bool,
    add_count: usize,
    remove_failed: bool,
}

#[cfg(feature = "tun-routes")]
impl RecordingRouteBackend {
    fn new(log: Arc<Mutex<Vec<String>>>) -> Self {
        Self {
            log,
            fail_add_at: None,
            fail_remove_once: false,
            add_count: 0,
            remove_failed: false,
        }
    }

    fn route_label(route: &TunRoute) -> String {
        format!("{}/{}", route.network(), route.prefix)
    }
}

#[cfg(feature = "tun-routes")]
impl TunRouteBackend for RecordingRouteBackend {
    fn add_route(&mut self, route: &TunRoute) -> io::Result<()> {
        self.add_count += 1;
        self.log
            .lock()
            .unwrap()
            .push(format!("add {}", Self::route_label(route)));
        if self.fail_add_at == Some(self.add_count) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "synthetic add failure",
            ));
        }
        Ok(())
    }

    fn remove_route(&mut self, route: &TunRoute) -> io::Result<()> {
        self.log
            .lock()
            .unwrap()
            .push(format!("remove {}", Self::route_label(route)));
        if self.fail_remove_once && !self.remove_failed {
            self.remove_failed = true;
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "synthetic remove failure",
            ));
        }
        Ok(())
    }
}

#[cfg(feature = "tun-routes")]
#[test]
fn tun_route_canonicalizes_and_rejects_invalid_family() {
    let route = TunRoute::new("10.0.0.99".parse().unwrap(), 24).unwrap();
    assert_eq!(route.network(), "10.0.0.0".parse::<IpAddr>().unwrap());
    assert!(TunRoute::new("10.0.0.1".parse().unwrap(), 33).is_err());

    let mut route = TunRoute::new("10.0.0.0".parse().unwrap(), 24).unwrap();
    route.gateway = Some("2001:db8::1".parse().unwrap());
    assert!(route.validate().is_err());
}

#[cfg(feature = "tun-routes")]
#[test]
fn tun_route_apply_rolls_back_in_reverse_order() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let mut backend = RecordingRouteBackend::new(Arc::clone(&log));
    backend.fail_add_at = Some(2);
    let routes = vec![
        TunRoute::new("10.0.0.99".parse().unwrap(), 24).unwrap(),
        TunRoute::new("10.1.0.0".parse().unwrap(), 24).unwrap(),
    ];

    assert!(TunRouteLease::apply(backend, &routes).is_err());
    assert_eq!(
        *log.lock().unwrap(),
        vec!["add 10.0.0.0/24", "add 10.1.0.0/24", "remove 10.0.0.0/24",]
    );
}

#[cfg(feature = "tun-routes")]
#[test]
fn tun_route_close_is_idempotent_and_retains_failed_removals_for_retry() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let mut backend = RecordingRouteBackend::new(Arc::clone(&log));
    backend.fail_remove_once = true;
    let routes = vec![
        TunRoute::new("10.0.0.0".parse().unwrap(), 24).unwrap(),
        TunRoute::new("10.1.0.0".parse().unwrap(), 24).unwrap(),
    ];
    let mut lease = TunRouteLease::apply(backend, &routes).unwrap();

    assert!(lease.close().is_err());
    assert_eq!(lease.routes().len(), 1);
    assert!(lease.close().is_ok());
    assert!(lease.routes().is_empty());
    assert!(lease.close().is_ok());
    assert_eq!(
        *log.lock().unwrap(),
        vec![
            "add 10.0.0.0/24",
            "add 10.1.0.0/24",
            "remove 10.1.0.0/24",
            "remove 10.0.0.0/24",
            "remove 10.1.0.0/24",
        ]
    );
}

#[test]
fn transmit_reports_backpressure_instead_of_accepting_unbounded_packets() {
    let mut device = SmoltcpTunDevice::new(1500, 1).unwrap();
    let token = device.transmit(Instant::from_millis(0)).unwrap();
    token.consume(20, |packet| packet.fill(0x45));
    assert!(device.transmit(Instant::from_millis(1)).is_none());
}

#[test]
fn udp_socket_round_trips_through_smoltcp_ip_device() {
    let local = Ipv4Address::new(10, 0, 0, 1);
    let remote = Ipv4Address::new(10, 0, 0, 2);
    let mut device = SmoltcpTunDevice::new(1500, 8).unwrap();
    let mut interface = Interface::new(
        Config::new(HardwareAddress::Ip),
        &mut device,
        Instant::from_millis(0),
    );
    interface.update_ip_addrs(|addresses| {
        addresses
            .push(IpCidr::new(IpAddress::Ipv4(local), 24))
            .unwrap();
    });

    let rx_buffer = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0; 512]);
    let tx_buffer = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0; 512]);
    let mut sockets = SocketSet::new(vec![]);
    let handle = sockets.add(udp::Socket::new(rx_buffer, tx_buffer));
    sockets.get_mut::<udp::Socket>(handle).bind(5353).unwrap();

    device
        .enqueue_rx(udp_packet(remote, local, 41000, 5353, b"ping"))
        .unwrap();
    interface.poll(Instant::from_millis(1), &mut device, &mut sockets);

    let socket = sockets.get_mut::<udp::Socket>(handle);
    let (payload, metadata) = socket.recv().unwrap();
    assert_eq!(payload, b"ping");
    assert_eq!(metadata.endpoint.addr, IpAddress::Ipv4(remote));
    assert_eq!(metadata.endpoint.port, 41000);
    socket.send_slice(b"pong", metadata.endpoint).unwrap();
    interface.poll(Instant::from_millis(2), &mut device, &mut sockets);

    let response = device.take_tx().unwrap().unwrap();
    let ip = Ipv4Packet::new_checked(&response).unwrap();
    assert_eq!(ip.src_addr(), local);
    assert_eq!(ip.dst_addr(), remote);
    assert_eq!(ip.next_header(), IpProtocol::Udp);
    let udp = UdpPacket::new_checked(ip.payload()).unwrap();
    assert_eq!(udp.src_port(), 5353);
    assert_eq!(udp.dst_port(), 41000);
    assert_eq!(udp.payload(), b"pong");
}

#[test]
fn udp_socket_fragments_a_large_datagram_to_the_tun_mtu() {
    let local = Ipv4Address::new(198, 18, 0, 1);
    let remote = Ipv4Address::new(198, 18, 0, 2);
    let mut device = SmoltcpTunDevice::new(576, 64).unwrap();
    let mut interface = Interface::new(
        Config::new(HardwareAddress::Ip),
        &mut device,
        Instant::from_millis(0),
    );
    interface.update_ip_addrs(|addresses| {
        addresses
            .push(IpCidr::new(IpAddress::Ipv4(local), 15))
            .unwrap();
    });

    let rx_buffer = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 1], vec![0; 1]);
    let tx_buffer =
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 2], vec![0; 8 * 1024 + 64]);
    let mut sockets = SocketSet::new(vec![]);
    let handle = sockets.add(udp::Socket::new(rx_buffer, tx_buffer));
    sockets.get_mut::<udp::Socket>(handle).bind(18080).unwrap();

    let payload: Vec<u8> = (0..8192).map(|offset| (offset % 251) as u8).collect();
    sockets
        .get_mut::<udp::Socket>(handle)
        .send_slice(&payload, IpEndpoint::new(IpAddress::Ipv4(remote), 41000))
        .unwrap();

    interface.poll(Instant::from_millis(1), &mut device, &mut sockets);
    let whole = device
        .take_tx()
        .unwrap()
        .expect("smoltcp emitted a datagram");
    assert!(whole.len() > 576);
    let packets = fragment_ip_packet(&whole, 576, 0x1234).unwrap();
    assert!(packets.len() > 2, "large datagram was not fragmented");
    let mut reassembled = vec![0u8; 8 + payload.len()];
    let mut identification = None;
    for packet in &packets {
        assert!(packet.len() <= 576);
        let ip = Ipv4Packet::new_checked(packet).unwrap();
        assert_eq!(ip.src_addr(), local);
        assert_eq!(ip.dst_addr(), remote);
        assert_eq!(ip.next_header(), IpProtocol::Udp);
        identification.get_or_insert(ip.ident());
        assert_eq!(identification, Some(ip.ident()));
        let offset = ip.frag_offset() as usize;
        reassembled[offset..offset + ip.payload().len()].copy_from_slice(ip.payload());
    }
    assert_eq!(&reassembled[8..], payload.as_slice());
}

#[test]
fn ipv6_large_datagram_is_fragmented_at_the_tun_boundary() {
    let payload: Vec<u8> = (0..8192).map(|offset| (offset % 251) as u8).collect();
    let whole = ipv6_udp_packet(
        Ipv6Addr::LOCALHOST,
        "2001:db8::2".parse().unwrap(),
        41000,
        5353,
        &payload,
    );
    let packets = fragment_ip_packet(&whole, 576, 0x0102_0304).unwrap();
    assert!(packets.len() > 2);

    let mut reassembled = vec![0u8; whole.len() - 40];
    let mut identification = None;
    for packet in &packets {
        assert!(packet.len() <= 576);
        let ip = Ipv6Packet::new_checked(packet).unwrap();
        assert_eq!(ip.next_header(), IpProtocol::Ipv6Frag);
        assert_eq!(packet[40], 17);
        let fragment_id = u32::from_be_bytes(packet[44..48].try_into().unwrap());
        identification.get_or_insert(fragment_id);
        assert_eq!(identification, Some(0x0102_0304));
        let offset_and_flags = u16::from_be_bytes([packet[42], packet[43]]);
        let offset = usize::from(offset_and_flags >> 3) * 8;
        let fragment_payload = &packet[48..];
        reassembled[offset..offset + fragment_payload.len()].copy_from_slice(fragment_payload);
        if offset + fragment_payload.len() == reassembled.len() {
            assert_eq!(offset_and_flags & 1, 0);
        } else {
            assert_ne!(offset_and_flags & 1, 0);
        }
    }

    let mut restored = whole[..40].to_vec();
    restored[4..6].copy_from_slice(&((whole.len() - 40) as u16).to_be_bytes());
    restored[6] = 17;
    restored.extend_from_slice(&reassembled);
    assert_eq!(restored, whole);
}

#[test]
fn ipv6_extension_headers_are_split_at_the_wire_boundary() {
    let payload: Vec<u8> = (0..8192).map(|offset| (offset % 251) as u8).collect();
    let whole = ipv6_udp_packet_with_hbh_routing_and_destination(&payload);
    let packets = fragment_ip_packet(&whole, 576, 0x0a0b_0c0d).unwrap();
    assert!(packets.len() > 2);

    // IPv6 + Hop-by-Hop + Routing are unfragmentable and occur in every
    // fragment. The Destination Options header after Routing is the first
    // byte of the fragmentable part and is therefore reconstructed with it.
    let prefix_len = 40 + 8 + 8;
    let fragmentable_len = whole.len() - prefix_len;
    let mut reassembled = vec![0u8; fragmentable_len];
    let mut saw_first = false;
    for packet in &packets {
        assert!(packet.len() <= 576);
        assert_eq!(packet[6], 0); // Hop-by-Hop
        assert_eq!(packet[40], 43); // Routing
        assert_eq!(packet[48], 44); // Fragment Header
        assert_eq!(packet[56], 60); // Destination Options follows Fragment
        let fragment_id = u32::from_be_bytes(packet[60..64].try_into().unwrap());
        assert_eq!(fragment_id, 0x0a0b_0c0d);

        let offset_and_flags = u16::from_be_bytes([packet[58], packet[59]]);
        let offset = usize::from(offset_and_flags >> 3) * 8;
        let fragment_payload = &packet[64..];
        if offset == 0 {
            saw_first = true;
        }
        reassembled[offset..offset + fragment_payload.len()].copy_from_slice(fragment_payload);
        if offset + fragment_payload.len() == reassembled.len() {
            assert_eq!(offset_and_flags & 1, 0);
        } else {
            assert_ne!(offset_and_flags & 1, 0);
        }
    }
    assert!(saw_first);

    let mut restored = whole[..prefix_len].to_vec();
    restored[48] = 60;
    restored.extend_from_slice(&reassembled);
    assert_eq!(restored, whole);
}

#[test]
fn ipv6_transport_tuple_normalizes_extension_headers_for_smoltcp() {
    let packet = ipv6_udp_packet_with_hbh_routing_and_destination(b"extension-payload");
    let normalized = normalize_ipv6_extension_headers(&packet).unwrap();
    assert_eq!(normalized[6], 17);
    assert_eq!(normalized.len(), 40 + 8 + b"extension-payload".len());
    assert_eq!(&normalized[48..], b"extension-payload");

    let tuple = parse_transport_tuple(&packet).unwrap().unwrap();
    assert_eq!(tuple.protocol, IpProtocol::Udp);
    assert_eq!(tuple.source, "[::1]:41000".parse().unwrap());
    assert_eq!(tuple.destination, "[2001:db8::2]:5353".parse().unwrap());
}

#[test]
fn ipv6_output_fragmentation_rejects_an_existing_fragment_header() {
    let whole = ipv6_udp_packet(
        Ipv6Addr::LOCALHOST,
        "2001:db8::2".parse().unwrap(),
        41000,
        5353,
        &[0xa5; 1024],
    );
    let existing = ipv6_fragment(&whole, 0, true, 1024, 0x0102_0304);
    let error = fragment_ip_packet(&existing, 576, 0x0506_0708).unwrap_err();
    assert!(error.to_string().contains("already-fragmented"));
}

#[test]
fn tcp_listener_accepts_syn_and_emits_syn_ack() {
    let local = Ipv4Address::new(10, 0, 0, 1);
    let remote = Ipv4Address::new(10, 0, 0, 2);
    let mut device = SmoltcpTunDevice::new(1500, 8).unwrap();
    let mut interface = Interface::new(
        Config::new(HardwareAddress::Ip),
        &mut device,
        Instant::from_millis(0),
    );
    interface.update_ip_addrs(|addresses| {
        addresses
            .push(IpCidr::new(IpAddress::Ipv4(local), 24))
            .unwrap();
    });

    let rx_buffer = tcp::SocketBuffer::new(vec![0; 1024]);
    let tx_buffer = tcp::SocketBuffer::new(vec![0; 1024]);
    let mut sockets = SocketSet::new(vec![]);
    let handle = sockets.add(tcp::Socket::new(rx_buffer, tx_buffer));
    sockets.get_mut::<tcp::Socket>(handle).listen(8080).unwrap();

    device
        .enqueue_rx(tcp_syn_packet(remote, local, 41000, 8080, 100))
        .unwrap();
    interface.poll(Instant::from_millis(1), &mut device, &mut sockets);

    assert!(sockets.get::<tcp::Socket>(handle).is_active());
    let response = device.take_tx().unwrap().unwrap();
    let ip = Ipv4Packet::new_checked(&response).unwrap();
    let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
    assert_eq!(tcp.src_port(), 8080);
    assert_eq!(tcp.dst_port(), 41000);
    assert!(tcp.syn());
    assert!(tcp.ack());
    assert_eq!(tcp.ack_number(), TcpSeqNumber(101));
}

#[test]
fn tcp_listener_accepts_routed_destination_with_any_ip() {
    let local = Ipv4Address::new(198, 18, 0, 1);
    let remote = Ipv4Address::new(198, 18, 0, 2);
    let destination = Ipv4Address::new(203, 0, 113, 7);
    let mut device = SmoltcpTunDevice::new(1500, 8).unwrap();
    let mut interface = Interface::new(
        Config::new(HardwareAddress::Ip),
        &mut device,
        Instant::from_millis(0),
    );
    interface.set_any_ip(true);
    interface.update_ip_addrs(|addresses| {
        addresses
            .push(IpCidr::new(IpAddress::Ipv4(local), 15))
            .unwrap();
    });
    let mut dispatcher = TunDispatcher::new(1024, 1024, 4).unwrap();
    device
        .enqueue_rx(tcp_syn_packet(remote, destination, 41001, 443, 100))
        .unwrap();

    dispatcher
        .poll_with(&mut interface, &mut device, Instant::from_millis(1))
        .unwrap();

    let response = device.take_tx().unwrap().unwrap();
    let ip = Ipv4Packet::new_checked(&response).unwrap();
    let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
    assert_eq!(ip.dst_addr(), remote);
    assert_eq!(tcp.src_port(), 443);
    assert_eq!(tcp.dst_port(), 41001);
    assert!(tcp.syn());
    assert!(tcp.ack());
}

#[test]
fn icmp_socket_round_trips_echo_request_and_reply() {
    let local = Ipv4Address::new(10, 0, 0, 1);
    let remote = Ipv4Address::new(10, 0, 0, 2);
    let mut device = SmoltcpTunDevice::new(1500, 8).unwrap();
    let mut interface = Interface::new(
        Config::new(HardwareAddress::Ip),
        &mut device,
        Instant::from_millis(0),
    );
    interface.update_ip_addrs(|addresses| {
        addresses
            .push(IpCidr::new(IpAddress::Ipv4(local), 24))
            .unwrap();
    });

    let rx_buffer = icmp::PacketBuffer::new(vec![icmp::PacketMetadata::EMPTY; 2], vec![0; 256]);
    let tx_buffer = icmp::PacketBuffer::new(vec![icmp::PacketMetadata::EMPTY; 2], vec![0; 256]);
    let mut sockets = SocketSet::new(vec![]);
    let handle = sockets.add(icmp::Socket::new(rx_buffer, tx_buffer));
    sockets
        .get_mut::<icmp::Socket>(handle)
        .bind(icmp::Endpoint::Ident(7))
        .unwrap();

    device
        .enqueue_rx(icmp_echo_packet(remote, local, 7, 9, b"echo", false))
        .unwrap();
    interface.poll(Instant::from_millis(1), &mut device, &mut sockets);
    let socket = sockets.get_mut::<icmp::Socket>(handle);
    let (request, endpoint) = socket.recv().unwrap();
    let request = Icmpv4Repr::parse(
        &Icmpv4Packet::new_checked(request).unwrap(),
        &ChecksumCapabilities::default(),
    )
    .unwrap();
    assert!(matches!(
        request,
        Icmpv4Repr::EchoRequest {
            ident: 7,
            seq_no: 9,
            ..
        }
    ));
    socket
        .send_slice(
            &icmp_echo_packet(local, remote, 7, 9, b"echo", true)[20..],
            endpoint,
        )
        .unwrap();
    interface.poll(Instant::from_millis(2), &mut device, &mut sockets);

    let response = device.take_tx().unwrap().unwrap();
    let ip = Ipv4Packet::new_checked(&response).unwrap();
    let response = Icmpv4Repr::parse(
        &Icmpv4Packet::new_checked(ip.payload()).unwrap(),
        &ChecksumCapabilities::default(),
    )
    .unwrap();
    assert!(
        matches!(response, Icmpv4Repr::EchoReply { ident: 7, seq_no: 9, data } if data == b"echo")
    );
}

#[test]
fn interface_auto_replies_to_external_ipv4_echo_request() {
    let local = Ipv4Address::new(10, 0, 0, 1);
    let remote = Ipv4Address::new(10, 0, 0, 2);
    let destination = Ipv4Address::new(8, 8, 8, 8);
    let mut device = SmoltcpTunDevice::new(1500, 8).unwrap();
    let mut interface = Interface::new(
        Config::new(HardwareAddress::Ip),
        &mut device,
        Instant::from_millis(0),
    );
    interface.set_any_ip(true);
    interface.update_ip_addrs(|addresses| {
        addresses
            .push(IpCidr::new(IpAddress::Ipv4(local), 24))
            .unwrap();
    });

    device
        .enqueue_rx(icmp_echo_packet(remote, destination, 7, 9, b"echo", false))
        .unwrap();
    interface.poll(
        Instant::from_millis(1),
        &mut device,
        &mut SocketSet::new(vec![]),
    );

    let response = device.take_tx().unwrap().expect("ICMP echo reply");
    let ip = Ipv4Packet::new_checked(&response).unwrap();
    assert_eq!(ip.src_addr(), destination);
    assert_eq!(ip.dst_addr(), remote);
    let response = Icmpv4Repr::parse(
        &Icmpv4Packet::new_checked(ip.payload()).unwrap(),
        &ChecksumCapabilities::default(),
    )
    .unwrap();
    assert!(
        matches!(response, Icmpv4Repr::EchoReply { ident: 7, seq_no: 9, data } if data == b"echo")
    );
}

#[test]
fn interface_auto_replies_to_external_ipv6_echo_request() {
    let local: Ipv6Address = "fd00::1".parse().unwrap();
    let remote: Ipv6Address = "fd00::2".parse().unwrap();
    let destination: Ipv6Address = "2001:4860:4860::8888".parse().unwrap();
    let mut device = SmoltcpTunDevice::new(1500, 8).unwrap();
    let mut interface = Interface::new(
        Config::new(HardwareAddress::Ip),
        &mut device,
        Instant::from_millis(0),
    );
    interface.set_any_ip(true);
    interface.update_ip_addrs(|addresses| {
        addresses
            .push(IpCidr::new(IpAddress::Ipv6(local), 64))
            .unwrap();
    });

    device
        .enqueue_rx(icmpv6_echo_packet(
            remote,
            destination,
            7,
            9,
            b"echo6",
            false,
        ))
        .unwrap();
    interface.poll(
        Instant::from_millis(1),
        &mut device,
        &mut SocketSet::new(vec![]),
    );

    let response = device.take_tx().unwrap().expect("ICMPv6 echo reply");
    let ip = Ipv6Packet::new_checked(&response).unwrap();
    assert_eq!(ip.src_addr(), destination);
    assert_eq!(ip.dst_addr(), remote);
    let response = Icmpv6Repr::parse(
        &ip.src_addr(),
        &ip.dst_addr(),
        &Icmpv6Packet::new_checked(ip.payload()).unwrap(),
        &ChecksumCapabilities::default(),
    )
    .unwrap();
    assert!(
        matches!(response, Icmpv6Repr::EchoReply { ident: 7, seq_no: 9, data } if data == b"echo6")
    );
}

#[test]
fn dispatcher_intercepts_external_ipv4_echo_for_proxy_ping() {
    let local = Ipv4Address::new(10, 0, 0, 1);
    let remote = Ipv4Address::new(10, 0, 0, 2);
    let destination = Ipv4Address::new(8, 8, 8, 8);
    let mut device = SmoltcpTunDevice::new(1500, 8).unwrap();
    let mut interface = Interface::new(
        Config::new(HardwareAddress::Ip),
        &mut device,
        Instant::from_millis(0),
    );
    interface.set_any_ip(true);
    interface.update_ip_addrs(|addresses| {
        addresses
            .push(IpCidr::new(IpAddress::Ipv4(local), 24))
            .unwrap();
    });
    let mut dispatcher = TunDispatcher::new(2048, 2048, 4).unwrap();
    device
        .enqueue_rx(icmp_echo_packet(remote, destination, 7, 9, b"proxy", false))
        .unwrap();

    dispatcher
        .poll_with(&mut interface, &mut device, Instant::from_millis(1))
        .unwrap();

    let events: Vec<_> = dispatcher.proxy_inputs().collect();
    assert!(matches!(
        events.as_slice(),
        [ProxyInput::IcmpEchoRequest { flow, packet }]
            if flow.key.network == Network::Icmp
                && flow.key.source == SocketAddr::new(IpAddr::V4(remote), 0)
                && flow.key.destination == SocketAddr::new(IpAddr::V4(destination), 0)
                && packet.len() == 20 + 8 + 5
    ));
    assert_eq!(device.queued_rx().unwrap(), 0);
    assert_eq!(device.queued_tx().unwrap(), 0);
}

#[test]
fn dispatcher_intercepts_external_ipv6_echo_for_proxy_ping() {
    let local: Ipv6Address = "fd00::1".parse().unwrap();
    let remote: Ipv6Address = "fd00::2".parse().unwrap();
    let destination: Ipv6Address = "2001:4860:4860::8888".parse().unwrap();
    let mut device = SmoltcpTunDevice::new(1500, 8).unwrap();
    let mut interface = Interface::new(
        Config::new(HardwareAddress::Ip),
        &mut device,
        Instant::from_millis(0),
    );
    interface.set_any_ip(true);
    interface.update_ip_addrs(|addresses| {
        addresses
            .push(IpCidr::new(IpAddress::Ipv6(local), 64))
            .unwrap();
    });
    let mut dispatcher = TunDispatcher::new(2048, 2048, 4).unwrap();
    device
        .enqueue_rx(icmpv6_echo_packet(
            remote,
            destination,
            7,
            9,
            b"proxy6",
            false,
        ))
        .unwrap();

    dispatcher
        .poll_with(&mut interface, &mut device, Instant::from_millis(1))
        .unwrap();

    let events: Vec<_> = dispatcher.proxy_inputs().collect();
    assert!(matches!(
        events.as_slice(),
        [ProxyInput::IcmpEchoRequest { flow, packet }]
            if flow.key.network == Network::Icmp
                && flow.key.source == SocketAddr::new(IpAddr::V6(remote), 0)
                && flow.key.destination == SocketAddr::new(IpAddr::V6(destination), 0)
                && packet.len() == 40 + 8 + 6
    ));
    assert_eq!(device.queued_rx().unwrap(), 0);
    assert_eq!(device.queued_tx().unwrap(), 0);
}

#[test]
fn proxy_icmp_reply_rewrite_preserves_echo_identity_for_both_families() {
    let v4 = icmp_echo_packet(
        Ipv4Address::new(10, 0, 0, 2),
        Ipv4Address::new(8, 8, 8, 8),
        17,
        23,
        b"v4",
        false,
    );
    let v4_reply = rewrite_icmp_echo_reply(v4, true).unwrap();
    let v4_ip = Ipv4Packet::new_checked(&v4_reply).unwrap();
    assert_eq!(v4_ip.src_addr(), Ipv4Address::new(8, 8, 8, 8));
    assert_eq!(v4_ip.dst_addr(), Ipv4Address::new(10, 0, 0, 2));
    assert!(matches!(
        Icmpv4Repr::parse(
            &Icmpv4Packet::new_checked(v4_ip.payload()).unwrap(),
            &ChecksumCapabilities::default(),
        )
        .unwrap(),
        Icmpv4Repr::EchoReply { ident: 17, seq_no: 23, data } if data == b"v4"
    ));

    let v6_source: Ipv6Address = "fd00::2".parse().unwrap();
    let v6_destination: Ipv6Address = "2001:4860:4860::8888".parse().unwrap();
    let v6 = icmpv6_echo_packet(v6_source, v6_destination, 19, 29, b"v6", false);
    let v6_reply = rewrite_icmp_echo_reply(v6, true).unwrap();
    let v6_ip = Ipv6Packet::new_checked(&v6_reply).unwrap();
    assert_eq!(v6_ip.src_addr(), v6_destination);
    assert_eq!(v6_ip.dst_addr(), v6_source);
    assert!(matches!(
        Icmpv6Repr::parse(
            &v6_ip.src_addr(),
            &v6_ip.dst_addr(),
            &Icmpv6Packet::new_checked(v6_ip.payload()).unwrap(),
            &ChecksumCapabilities::default(),
        )
        .unwrap(),
        Icmpv6Repr::EchoReply { ident: 19, seq_no: 29, data } if data == b"v6"
    ));
}

#[test]
fn dispatcher_emits_udp_flow_and_writes_response_back_to_tun() {
    let local = Ipv4Address::new(10, 0, 0, 1);
    let remote = Ipv4Address::new(10, 0, 0, 2);
    let mut device = SmoltcpTunDevice::new(1500, 8).unwrap();
    let mut interface = Interface::new(
        Config::new(HardwareAddress::Ip),
        &mut device,
        Instant::from_millis(0),
    );
    interface.update_ip_addrs(|addresses| {
        addresses
            .push(IpCidr::new(IpAddress::Ipv4(local), 24))
            .unwrap();
    });
    let mut dispatcher = TunDispatcher::new(2048, 2048, 4).unwrap();
    device
        .enqueue_rx(udp_packet(remote, local, 41000, 5353, b"query"))
        .unwrap();

    dispatcher
        .poll_with(&mut interface, &mut device, Instant::from_millis(1))
        .unwrap();
    let events: Vec<_> = dispatcher.proxy_inputs().collect();
    let [ProxyInput::UdpDatagram { flow, payload }] = events.as_slice() else {
        panic!("expected one UDP datagram event, got {events:?}");
    };
    assert_eq!(payload, b"query");
    assert_eq!(flow.key.source, "10.0.0.2:41000".parse().unwrap());
    assert_eq!(flow.key.destination, "10.0.0.1:5353".parse().unwrap());
    dispatcher.write_udp(flow.key, b"reply").unwrap();
    dispatcher
        .poll_with(&mut interface, &mut device, Instant::from_millis(2))
        .unwrap();

    let response = device.take_tx().unwrap().unwrap();
    let ip = Ipv4Packet::new_checked(&response).unwrap();
    let udp = UdpPacket::new_checked(ip.payload()).unwrap();
    assert_eq!(udp.src_port(), 5353);
    assert_eq!(udp.dst_port(), 41000);
    assert_eq!(udp.payload(), b"reply");
}

#[test]
fn dispatcher_udp_routed_destination_preserves_virtual_source_address() {
    let portal = Ipv4Address::new(198, 18, 0, 1);
    let virtual_destination = Ipv4Address::new(198, 18, 0, 2);
    let remote = Ipv4Address::new(198, 18, 0, 3);
    let mut device = SmoltcpTunDevice::new(1500, 8).unwrap();
    let mut interface = Interface::new(
        Config::new(HardwareAddress::Ip),
        &mut device,
        Instant::from_millis(0),
    );
    interface.set_any_ip(true);
    interface.update_ip_addrs(|addresses| {
        addresses
            .push(IpCidr::new(IpAddress::Ipv4(virtual_destination), 15))
            .unwrap();
        addresses
            .push(IpCidr::new(IpAddress::Ipv4(portal), 15))
            .unwrap();
    });
    let mut dispatcher = TunDispatcher::new(2048, 2048, 4).unwrap();
    device
        .enqueue_rx(udp_packet(
            remote,
            virtual_destination,
            41000,
            18080,
            b"virtual-destination",
        ))
        .unwrap();

    dispatcher
        .poll_with(&mut interface, &mut device, Instant::from_millis(1))
        .unwrap();
    let events: Vec<_> = dispatcher.proxy_inputs().collect();
    let [ProxyInput::UdpDatagram { flow, payload }] = events.as_slice() else {
        panic!("expected one routed UDP datagram event");
    };
    assert_eq!(payload, b"virtual-destination");
    assert_eq!(flow.key.destination.ip(), IpAddr::V4(virtual_destination));
    dispatcher.write_udp(flow.key, b"reply").unwrap();
    dispatcher
        .poll_with(&mut interface, &mut device, Instant::from_millis(2))
        .unwrap();

    let response = device.take_tx().unwrap().unwrap();
    let ip = Ipv4Packet::new_checked(&response).unwrap();
    let udp = UdpPacket::new_checked(ip.payload()).unwrap();
    assert_eq!(ip.src_addr(), virtual_destination);
    assert_eq!(ip.dst_addr(), remote);
    assert_eq!(udp.src_port(), 18080);
    assert_eq!(udp.dst_port(), 41000);
    assert_eq!(udp.payload(), b"reply");
}

#[test]
fn dispatcher_reassembles_out_of_order_ipv4_udp_fragments() {
    let local = Ipv4Address::new(10, 0, 0, 1);
    let remote = Ipv4Address::new(10, 0, 0, 2);
    let whole = udp_packet(remote, local, 41000, 5353, b"fragmented-query");
    let first = ipv4_fragment(&whole, 0, true, 16);
    let second = ipv4_fragment(&whole, 16, false, whole.len() - 20 - 16);

    let mut device = SmoltcpTunDevice::new(1500, 8).unwrap();
    let mut interface = Interface::new(
        Config::new(HardwareAddress::Ip),
        &mut device,
        Instant::from_millis(0),
    );
    interface.update_ip_addrs(|addresses| {
        addresses
            .push(IpCidr::new(IpAddress::Ipv4(local), 24))
            .unwrap();
    });
    let mut dispatcher = TunDispatcher::new(2048, 2048, 4).unwrap();

    // The second fragment arrives first. The dispatcher must not try to
    // parse transport ports from its payload; smoltcp will hold it until the
    // first fragment completes the datagram.
    device.enqueue_rx(second).unwrap();
    dispatcher
        .poll_with(&mut interface, &mut device, Instant::from_millis(1))
        .unwrap();
    assert!(dispatcher.proxy_inputs().next().is_none());

    device.enqueue_rx(first).unwrap();
    dispatcher
        .poll_with(&mut interface, &mut device, Instant::from_millis(2))
        .unwrap();
    let events: Vec<_> = dispatcher.proxy_inputs().collect();
    let [ProxyInput::UdpDatagram { flow, payload }] = events.as_slice() else {
        panic!("expected one reassembled UDP event, got {events:?}");
    };
    assert_eq!(payload, b"fragmented-query");
    assert_eq!(flow.key.source, "10.0.0.2:41000".parse().unwrap());
    assert_eq!(flow.key.destination, "10.0.0.1:5353".parse().unwrap());
}

fn ipv4_fragment(packet: &[u8], payload_offset: usize, more: bool, payload_len: usize) -> Vec<u8> {
    let mut fragment = vec![0; 20 + payload_len];
    fragment[..20].copy_from_slice(&packet[..20]);
    fragment[20..].copy_from_slice(&packet[20 + payload_offset..20 + payload_offset + payload_len]);
    let fragment_len = fragment.len() as u16;
    let mut ip = Ipv4Packet::new_unchecked(&mut fragment);
    ip.set_total_len(fragment_len);
    ip.set_more_frags(more);
    ip.set_frag_offset(payload_offset as u16);
    ip.fill_checksum();
    fragment
}

#[test]
fn dispatcher_registers_tcp_syn_and_emits_open_event() {
    let local = Ipv4Address::new(10, 0, 0, 1);
    let remote = Ipv4Address::new(10, 0, 0, 2);
    let mut device = SmoltcpTunDevice::new(1500, 8).unwrap();
    let mut interface = Interface::new(
        Config::new(HardwareAddress::Ip),
        &mut device,
        Instant::from_millis(0),
    );
    interface.update_ip_addrs(|addresses| {
        addresses
            .push(IpCidr::new(IpAddress::Ipv4(local), 24))
            .unwrap();
    });
    let mut dispatcher = TunDispatcher::new(4096, 4096, 4).unwrap();
    device
        .enqueue_rx(tcp_syn_packet(remote, local, 41000, 8080, 100))
        .unwrap();

    dispatcher
        .poll_with(&mut interface, &mut device, Instant::from_millis(1))
        .unwrap();
    let events: Vec<_> = dispatcher.proxy_inputs().collect();
    assert!(
        events.is_empty(),
        "SYN must not open a proxy flow: {events:?}"
    );
    let response = device.take_tx().unwrap().unwrap();
    let ip = Ipv4Packet::new_checked(&response).unwrap();
    let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
    assert!(tcp.syn() && tcp.ack());
}

#[test]
fn dispatcher_relays_established_tcp_data_in_both_directions() {
    let local = Ipv4Address::new(10, 0, 0, 1);
    let remote = Ipv4Address::new(10, 0, 0, 2);
    let mut device = SmoltcpTunDevice::new(1500, 8).unwrap();
    let mut interface = Interface::new(
        Config::new(HardwareAddress::Ip),
        &mut device,
        Instant::from_millis(0),
    );
    interface.update_ip_addrs(|addresses| {
        addresses
            .push(IpCidr::new(IpAddress::Ipv4(local), 24))
            .unwrap();
    });
    let mut dispatcher = TunDispatcher::new(4096, 4096, 4).unwrap();
    device
        .enqueue_rx(tcp_syn_packet(remote, local, 41000, 8080, 100))
        .unwrap();
    dispatcher
        .poll_with(&mut interface, &mut device, Instant::from_millis(1))
        .unwrap();
    assert!(dispatcher.proxy_inputs().next().is_none());
    let flow = TunFlow {
        key: TunFlowKey {
            network: Network::Tcp,
            source: "10.0.0.2:41000".parse().unwrap(),
            destination: "10.0.0.1:8080".parse().unwrap(),
        },
    };
    let syn_ack = device.take_tx().unwrap().unwrap();
    let syn_ack_ip = Ipv4Packet::new_checked(&syn_ack).unwrap();
    let server_sequence = TcpPacket::new_checked(syn_ack_ip.payload())
        .unwrap()
        .seq_number()
        .0 as u32;

    device
        .enqueue_rx(tcp_data_packet(
            remote,
            local,
            41000,
            8080,
            101,
            server_sequence + 1,
            &[],
        ))
        .unwrap();
    dispatcher
        .poll_with(&mut interface, &mut device, Instant::from_millis(2))
        .unwrap();
    assert!(matches!(
        dispatcher.proxy_inputs().next(),
        Some(ProxyInput::TcpOpened { flow: event_flow }) if event_flow == flow
    ));

    device
        .enqueue_rx(tcp_data_packet(
            remote,
            local,
            41000,
            8080,
            101,
            server_sequence + 1,
            b"request",
        ))
        .unwrap();
    dispatcher
        .poll_with(&mut interface, &mut device, Instant::from_millis(3))
        .unwrap();
    assert!(matches!(
        dispatcher.proxy_inputs().next(),
        Some(ProxyInput::TcpData { flow: event_flow, payload })
            if event_flow == flow && payload == b"request"
    ));

    dispatcher.write_tcp(flow.key, b"response").unwrap();
    dispatcher
        .poll_with(&mut interface, &mut device, Instant::from_millis(4))
        .unwrap();
    let response = device.take_tx().unwrap().unwrap();
    let response_ip = Ipv4Packet::new_checked(&response).unwrap();
    let response_tcp = TcpPacket::new_checked(response_ip.payload()).unwrap();
    assert_eq!(response_tcp.src_port(), 8080);
    assert_eq!(response_tcp.dst_port(), 41000);
    assert_eq!(response_tcp.payload(), b"response");
}
