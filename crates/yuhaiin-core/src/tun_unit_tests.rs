use super::tun_test_support::*;
use super::*;

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
    let mut packet = vec![0u8; 48];
    packet[0] = 0x60;
    packet[6] = 44;
    packet[7] = 64;
    packet[40] = 17;
    packet[42] = 0;
    packet[43] = 1;
    assert!(inspect_ip_packet(&packet).unwrap().fragmented);
}

#[test]
fn tx_token_drops_packets_larger_than_mtu() {
    let mut device = SmoltcpTunDevice::new(576, 2).unwrap();
    let token = phy::Device::transmit(&mut device, Instant::from_millis(0)).unwrap();
    phy::TxToken::consume(token, 577, |_| ());
    assert_eq!(device.queued_tx().unwrap(), 0);
}

#[test]
fn config_rejects_invalid_mtu_and_queue() {
    let mut config = TunConfig::default();
    config.mtu = 100;
    assert!(config.validate().is_err());
    config.mtu = DEFAULT_MTU;
    config.queue_capacity = 0;
    assert!(config.validate().is_err());
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
    let events: Vec<_> = dispatcher.events().collect();
    let [TunEvent::UdpDatagram { flow, payload }] = events.as_slice() else {
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
    let events: Vec<_> = dispatcher.events().collect();
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
    assert!(dispatcher.events().next().is_none());
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
        dispatcher.events().next(),
        Some(TunEvent::TcpOpened { flow: event_flow }) if event_flow == flow
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
        dispatcher.events().next(),
        Some(TunEvent::TcpData { flow: event_flow, payload })
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
