use super::*;

fn key() -> NatKey {
    NatKey {
        network: Network::Udp,
        source: "192.0.2.10:40000".parse().unwrap(),
        destination: "198.51.100.1:443".parse().unwrap(),
    }
}

#[test]
fn nat_entry_can_be_touched_and_removed() {
    let table = NatTable::new();
    let key = key();
    table
        .insert(
            key.clone(),
            "203.0.113.10:50000".parse().unwrap(),
            Duration::from_secs(30),
        )
        .unwrap();
    assert_eq!(table.len().unwrap(), 1);
    assert_eq!(
        table.touch(&key).unwrap().unwrap().translated,
        "203.0.113.10:50000".parse().unwrap()
    );
    assert!(table.remove(&key).unwrap().is_some());
    assert_eq!(table.len().unwrap(), 0);
}

#[test]
fn expired_entry_is_removed_on_touch_or_sweep() {
    let table = NatTable::new();
    let key = key();
    table
        .insert(
            key.clone(),
            "203.0.113.10:50000".parse().unwrap(),
            Duration::from_millis(1),
        )
        .unwrap();
    std::thread::sleep(Duration::from_millis(3));
    assert!(table.touch(&key).unwrap().is_none());
    assert_eq!(table.sweep().unwrap(), 0);
}

#[test]
fn full_cone_mapping_is_shared_across_destinations() {
    let table = NatTable::new();
    let first = key();
    let second = NatKey {
        destination: "198.51.100.2:5353".parse().unwrap(),
        ..first.clone()
    };
    let translated = "203.0.113.10:50000".parse().unwrap();
    table
        .insert(first.clone(), translated, Duration::from_secs(30))
        .unwrap();
    table
        .insert(second.clone(), translated, Duration::from_secs(30))
        .unwrap();

    assert_eq!(table.len().unwrap(), 1);
    assert_eq!(
        table
            .lookup_translated(Network::Udp, translated, "192.0.2.200:9".parse().unwrap(),)
            .unwrap()
            .unwrap()
            .source,
        first.source
    );
    assert!(table.remove(&first).unwrap().is_some());
    assert_eq!(table.len().unwrap(), 1);
    assert!(table.remove(&second).unwrap().is_some());
    assert_eq!(table.len().unwrap(), 0);
    assert!(
        table
            .lookup_translated(Network::Udp, translated, "192.0.2.201:9".parse().unwrap(),)
            .unwrap()
            .is_none()
    );
}

#[test]
fn nat_stats_expose_full_cone_reuse_reverse_and_close_lifecycle() {
    let table = NatTable::new();
    let first = key();
    let second = NatKey {
        destination: "198.51.100.2:5353".parse().unwrap(),
        ..first.clone()
    };
    let placeholder = first.source;
    let translated = "127.0.0.1:41000".parse().unwrap();
    table
        .insert(first.clone(), placeholder, Duration::from_secs(30))
        .unwrap();
    table
        .insert(second.clone(), placeholder, Duration::from_secs(30))
        .unwrap();
    table.touch(&first).unwrap();
    assert!(
        table
            .lookup_translated(Network::Udp, placeholder, "203.0.113.7:9".parse().unwrap(),)
            .unwrap()
            .is_some()
    );
    table
        .bind_translated(Network::Udp, first.source, translated)
        .unwrap();
    table.remove(&first).unwrap();

    let active = table.stats().unwrap();
    assert_eq!(active.active_bindings, 1);
    assert_eq!(active.active_destinations, 1);
    assert_eq!(active.reverse_mappings, 1);
    assert_eq!(active.allocations, 1);
    assert_eq!(active.reuses, 1);
    assert_eq!(active.touch_hits, 1);
    assert_eq!(active.reverse_lookups, 1);
    assert_eq!(active.reverse_hits, 1);
    assert_eq!(active.translated_rebinds, 1);
    let rendered = active.render_prometheus();
    assert!(rendered.contains("# TYPE doradus_nat_active_bindings gauge"));
    assert!(rendered.contains("doradus_nat_active_bindings 1\n"));
    assert!(rendered.contains("doradus_nat_reverse_hits 1\n"));

    table.remove(&second).unwrap();
    let closed = table.stats().unwrap();
    assert_eq!(closed.active_bindings, 0);
    assert_eq!(closed.reverse_mappings, 0);
    assert_eq!(closed.explicit_closes, 1);
}

#[test]
fn translated_endpoint_can_be_rebound_after_transport_creation() {
    let table = NatTable::new();
    let first = key();
    let second = NatKey {
        destination: "198.51.100.2:5353".parse().unwrap(),
        ..first.clone()
    };
    let placeholder = first.source;
    let translated = "127.0.0.1:41000".parse().unwrap();
    table
        .insert(first.clone(), placeholder, Duration::from_secs(30))
        .unwrap();
    table
        .insert(second, placeholder, Duration::from_secs(30))
        .unwrap();

    let entry = table
        .bind_translated(Network::Udp, first.source, translated)
        .unwrap();
    assert_eq!(entry.translated, translated);
    assert!(
        table
            .lookup_translated(
                Network::Udp,
                placeholder,
                "198.51.100.200:9".parse().unwrap(),
            )
            .unwrap()
            .is_none()
    );
    assert_eq!(
        table
            .lookup_translated(Network::Udp, translated, "203.0.113.200:9".parse().unwrap(),)
            .unwrap()
            .unwrap()
            .source,
        first.source
    );
}

#[test]
fn translated_endpoint_cannot_be_claimed_by_two_sources() {
    let table = NatTable::new();
    let first = key();
    let second = NatKey {
        source: "192.0.2.11:40001".parse().unwrap(),
        ..first.clone()
    };
    let translated = "127.0.0.1:41001".parse().unwrap();
    table
        .insert(first.clone(), first.source, Duration::from_secs(30))
        .unwrap();
    table
        .insert(second.clone(), second.source, Duration::from_secs(30))
        .unwrap();
    table
        .bind_translated(Network::Udp, first.source, translated)
        .unwrap();
    assert!(
        table
            .bind_translated(Network::Udp, second.source, translated)
            .is_err()
    );
}

#[test]
fn tcp_and_udp_bindings_can_share_the_same_socket_address() {
    let table = NatTable::new();
    let udp = key();
    let tcp = NatKey {
        network: Network::Tcp,
        ..udp.clone()
    };
    let translated = "203.0.113.10:50001".parse().unwrap();

    // Go's comparable address includes AddressNetwork, so TCP and UDP may
    // legitimately reuse the same source port and translated address.
    table
        .insert(tcp.clone(), translated, Duration::from_secs(30))
        .unwrap();
    table
        .insert(udp.clone(), translated, Duration::from_secs(30))
        .unwrap();

    assert_eq!(table.len().unwrap(), 2);
    assert_eq!(
        table
            .lookup_translated(Network::Tcp, translated, "192.0.2.200:9".parse().unwrap())
            .unwrap()
            .unwrap()
            .network,
        Network::Tcp
    );
    assert_eq!(
        table
            .lookup_translated(Network::Udp, translated, "192.0.2.200:9".parse().unwrap())
            .unwrap()
            .unwrap()
            .network,
        Network::Udp
    );

    table.remove(&tcp).unwrap();
    assert_eq!(table.len().unwrap(), 1);
    assert!(
        table
            .lookup_translated(Network::Udp, translated, "192.0.2.200:9".parse().unwrap())
            .unwrap()
            .is_some()
    );
}

#[test]
fn udp_relay_accepts_an_unseen_external_source() {
    let table = NatTable::new();
    let relay = UdpNatRelay::bind(
        "127.0.0.1:0".parse().unwrap(),
        table,
        Duration::from_secs(2),
    )
    .unwrap();
    let destination = UdpSocket::bind("127.0.0.1:0").unwrap();
    destination
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let key = NatKey {
        network: Network::Udp,
        source: "192.0.2.10:40000".parse().unwrap(),
        destination: destination.local_addr().unwrap(),
    };
    relay.send_to(key.clone(), b"outbound").unwrap();
    let mut outbound = [0u8; 32];
    let (_, peer) = destination.recv_from(&mut outbound).unwrap();

    let external = UdpSocket::bind("127.0.0.1:0").unwrap();
    external
        .send_to(b"inbound", relay.local_addr().unwrap())
        .unwrap();
    let mut inbound = [0u8; 32];
    let (received_key, length, received_peer) = relay.recv_from(&mut inbound).unwrap();
    assert_eq!(received_key.source, key.source);
    assert_eq!(&inbound[..length], b"inbound");
    assert_eq!(received_peer, external.local_addr().unwrap());
    assert_ne!(received_peer, peer);
}

#[test]
fn udp_relay_keeps_full_cone_mapping_across_destinations_and_peers() {
    let table = NatTable::new();
    let relay = UdpNatRelay::bind(
        "127.0.0.1:0".parse().unwrap(),
        table.clone(),
        Duration::from_secs(2),
    )
    .unwrap();
    let destinations = [
        UdpSocket::bind("127.0.0.1:0").unwrap(),
        UdpSocket::bind("127.0.0.1:0").unwrap(),
    ];
    for destination in &destinations {
        destination
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
    }
    let source = "192.0.2.10:40000".parse().unwrap();

    for (index, destination) in destinations.iter().enumerate() {
        let key = NatKey {
            network: Network::Udp,
            source,
            destination: destination.local_addr().unwrap(),
        };
        relay
            .send_to(key, format!("outbound-{index}").as_bytes())
            .unwrap();
        let mut outbound = [0u8; 32];
        destination.recv_from(&mut outbound).unwrap();
    }
    assert_eq!(table.len().unwrap(), 1);

    // Neither peer has sent an outbound packet through the relay.  Both
    // must nevertheless be accepted because the mapping is endpoint
    // independent (full cone), and the source mapping must remain shared
    // by the two logical destinations above.
    for payload in [b"peer-a".as_slice(), b"peer-b".as_slice()] {
        let external = UdpSocket::bind("127.0.0.1:0").unwrap();
        external
            .send_to(payload, relay.local_addr().unwrap())
            .unwrap();
        let mut inbound = [0u8; 32];
        let (key, length, peer) = relay.recv_from(&mut inbound).unwrap();
        assert_eq!(key.source, source);
        assert_eq!(&inbound[..length], payload);
        assert_eq!(peer, external.local_addr().unwrap());
    }

    assert_eq!(relay.close().unwrap(), 2);
    assert_eq!(table.len().unwrap(), 0);
}

#[test]
fn full_cone_multi_destination_peer_matrix_survives_a_long_flow() {
    let table = NatTable::new();
    let relay = UdpNatRelay::bind(
        "127.0.0.1:0".parse().unwrap(),
        table.clone(),
        Duration::from_secs(30),
    )
    .unwrap();
    let destinations: Vec<_> = (0..4)
        .map(|_| UdpSocket::bind("127.0.0.1:0").unwrap())
        .collect();
    let peers: Vec<_> = (0..8)
        .map(|_| UdpSocket::bind("127.0.0.1:0").unwrap())
        .collect();
    for socket in destinations.iter().chain(peers.iter()) {
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
    }
    let source = "192.0.2.10:40000".parse().unwrap();

    for round in 0..512u16 {
        for (index, destination) in destinations.iter().enumerate() {
            let key = NatKey {
                network: Network::Udp,
                source,
                destination: destination.local_addr().unwrap(),
            };
            relay
                .send_to(key, format!("out-{round}-{index}").as_bytes())
                .unwrap();
            let mut outbound = [0u8; 64];
            destination.recv_from(&mut outbound).unwrap();
        }
        for (index, peer) in peers.iter().enumerate() {
            peer.send_to(
                format!("in-{round}-{index}").as_bytes(),
                relay.local_addr().unwrap(),
            )
            .unwrap();
            let mut inbound = [0u8; 64];
            let (key, length, received_peer) = relay.recv_from(&mut inbound).unwrap();
            assert_eq!(key.source, source);
            assert_eq!(received_peer, peer.local_addr().unwrap());
            assert_eq!(&inbound[..length], format!("in-{round}-{index}").as_bytes());
        }
        assert_eq!(table.len().unwrap(), 1);
    }

    assert_eq!(relay.close().unwrap(), destinations.len());
    assert_eq!(table.len().unwrap(), 0);
}

#[test]
fn full_cone_multi_source_matrix_survives_long_flows_and_abnormal_drop() {
    let table = NatTable::new();
    let mut relays = Vec::new();
    let mut destinations = Vec::new();
    let mut peers = Vec::new();
    for _ in 0..6 {
        relays.push(
            UdpNatRelay::bind(
                "127.0.0.1:0".parse().unwrap(),
                table.clone(),
                Duration::from_secs(30),
            )
            .unwrap(),
        );
        let destination = UdpSocket::bind("127.0.0.1:0").unwrap();
        destination
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        destinations.push(destination);
        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        peers.push(peer);
    }

    for round in 0..256u16 {
        for index in 0..relays.len() {
            let source = format!("192.0.2.{}:{}", 20 + index, 41000 + index)
                .parse()
                .unwrap();
            let destination = destinations[index].local_addr().unwrap();
            let key = NatKey {
                network: Network::Udp,
                source,
                destination,
            };
            relays[index]
                .send_to(key.clone(), format!("out-{round}-{index}").as_bytes())
                .unwrap();
            let mut outbound = [0u8; 64];
            destinations[index].recv_from(&mut outbound).unwrap();

            let payload = format!("in-{round}-{index}");
            peers[index]
                .send_to(payload.as_bytes(), relays[index].local_addr().unwrap())
                .unwrap();
            let mut inbound = [0u8; 64];
            let (received_key, length, received_peer) =
                relays[index].recv_from(&mut inbound).unwrap();
            assert_eq!(received_key.source, source);
            assert_eq!(received_peer, peers[index].local_addr().unwrap());
            assert_eq!(&inbound[..length], payload.as_bytes());
        }
        assert_eq!(table.len().unwrap(), relays.len());
    }

    // Even-indexed relays close through the explicit owner API; odd-indexed
    // relays simulate task abort/drop. Every source must release its full
    // endpoint-independent binding exactly once.
    for (index, relay) in relays.into_iter().enumerate() {
        if index % 2 == 0 {
            assert_eq!(relay.close().unwrap(), 1);
        } else {
            drop(relay);
        }
    }
    assert_eq!(table.len().unwrap(), 0);
}

#[test]
fn full_cone_repeated_generations_survive_long_soak_and_release_matrix() {
    let table = NatTable::new();
    let external_probe: SocketAddr = "203.0.113.250:9".parse().unwrap();

    // Recreate the owner relay repeatedly to model short-lived TUN task
    // generations.  Every generation keeps one source mapping while it
    // fans out to several logical destinations and receives from peers
    // that have never sent an outbound packet through the relay.
    for generation in 0..16u16 {
        let relay = UdpNatRelay::bind(
            "127.0.0.1:0".parse().unwrap(),
            table.clone(),
            Duration::from_secs(30),
        )
        .unwrap();
        let destinations: Vec<_> = (0..3)
            .map(|_| UdpSocket::bind("127.0.0.1:0").unwrap())
            .collect();
        let peers: Vec<_> = (0..4)
            .map(|_| UdpSocket::bind("127.0.0.1:0").unwrap())
            .collect();
        for socket in destinations.iter().chain(peers.iter()) {
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
        }
        let source: SocketAddr = format!("192.0.2.{}:{}", 40 + generation, 42000 + generation)
            .parse()
            .unwrap();

        for round in 0..256u16 {
            for (destination_index, destination) in destinations.iter().enumerate() {
                let key = NatKey {
                    network: Network::Udp,
                    source,
                    destination: destination.local_addr().unwrap(),
                };
                relay
                    .send_to(
                        key,
                        format!("generation-{generation}-out-{round}-{destination_index}")
                            .as_bytes(),
                    )
                    .unwrap();
                let mut outbound = [0u8; 128];
                destination.recv_from(&mut outbound).unwrap();
            }

            for (peer_index, peer) in peers.iter().enumerate() {
                let payload = format!("generation-{generation}-in-{round}-{peer_index}");
                peer.send_to(payload.as_bytes(), relay.local_addr().unwrap())
                    .unwrap();
                let mut inbound = [0u8; 128];
                let (key, length, received_peer) = relay.recv_from(&mut inbound).unwrap();
                assert_eq!(key.source, source);
                assert_eq!(received_peer, peer.local_addr().unwrap());
                assert_eq!(&inbound[..length], payload.as_bytes());
            }

            // Reverse lookup must remain endpoint independent even for a
            // completely unrelated external source.  Periodic sweeps
            // must not remove a mapping that is being touched by traffic.
            assert!(
                table
                    .lookup_translated(Network::Udp, relay.local_addr().unwrap(), external_probe)
                    .unwrap()
                    .is_some()
            );
            if round % 32 == 0 {
                assert_eq!(relay.sweep().unwrap(), 0);
            }
            assert_eq!(table.len().unwrap(), 1);
        }

        if generation % 2 == 0 {
            assert_eq!(relay.close().unwrap(), destinations.len());
        } else {
            drop(relay);
        }
        assert_eq!(table.len().unwrap(), 0);
    }
}

#[test]
fn udp_relay_sweep_releases_full_cone_mapping() {
    let table = NatTable::new();
    let relay = UdpNatRelay::bind(
        "127.0.0.1:0".parse().unwrap(),
        table,
        Duration::from_millis(40),
    )
    .unwrap();
    let destination = UdpSocket::bind("127.0.0.1:0").unwrap();
    let key = NatKey {
        network: Network::Udp,
        source: "192.0.2.10:40000".parse().unwrap(),
        destination: destination.local_addr().unwrap(),
    };
    relay.send_to(key, b"outbound").unwrap();
    std::thread::sleep(Duration::from_millis(60));
    assert_eq!(relay.sweep().unwrap(), 1);

    let external = UdpSocket::bind("127.0.0.1:0").unwrap();
    external
        .send_to(b"late", relay.local_addr().unwrap())
        .unwrap();
    let mut inbound = [0u8; 16];
    assert!(relay.recv_from(&mut inbound).is_err());
}

#[test]
fn udp_relay_close_releases_the_complete_source_binding() {
    let table = NatTable::new();
    let relay = UdpNatRelay::bind(
        "127.0.0.1:0".parse().unwrap(),
        table.clone(),
        Duration::from_secs(2),
    )
    .unwrap();
    let destination = UdpSocket::bind("127.0.0.1:0").unwrap();
    let key = NatKey {
        network: Network::Udp,
        source: "192.0.2.10:40000".parse().unwrap(),
        destination: destination.local_addr().unwrap(),
    };
    relay.send_to(key.clone(), b"outbound").unwrap();
    assert_eq!(table.len().unwrap(), 1);
    assert_eq!(relay.close().unwrap(), 1);
    assert_eq!(table.len().unwrap(), 0);
    assert_eq!(relay.close().unwrap(), 0);
}

#[test]
fn dropping_udp_relay_releases_full_cone_mapping() {
    let table = NatTable::new();
    let destination = UdpSocket::bind("127.0.0.1:0").unwrap();
    {
        let relay = UdpNatRelay::bind(
            "127.0.0.1:0".parse().unwrap(),
            table.clone(),
            Duration::from_secs(2),
        )
        .unwrap();
        let key = NatKey {
            network: Network::Udp,
            source: "192.0.2.10:40000".parse().unwrap(),
            destination: destination.local_addr().unwrap(),
        };
        relay.send_to(key, b"abnormal-exit").unwrap();
        let mut packet = [0u8; 32];
        destination.recv_from(&mut packet).unwrap();
        assert_eq!(table.len().unwrap(), 1);
    }
    assert_eq!(table.len().unwrap(), 0);
}

#[test]
fn udp_relay_rejects_a_source_bound_to_another_translated_endpoint() {
    let table = NatTable::new();
    let relay = UdpNatRelay::bind(
        "127.0.0.1:0".parse().unwrap(),
        table.clone(),
        Duration::from_secs(2),
    )
    .unwrap();
    let destination = UdpSocket::bind("127.0.0.1:0").unwrap();
    let key = NatKey {
        network: Network::Udp,
        source: "192.0.2.10:40000".parse().unwrap(),
        destination: destination.local_addr().unwrap(),
    };
    table
        .insert(
            key.clone(),
            "203.0.113.10:50000".parse().unwrap(),
            Duration::from_secs(2),
        )
        .unwrap();
    assert!(relay.send_to(key, b"outbound").is_err());
    assert_eq!(table.len().unwrap(), 1);
}

#[test]
fn zero_timeout_is_rejected() {
    assert!(
        NatTable::new()
            .insert(key(), "203.0.113.10:50000".parse().unwrap(), Duration::ZERO,)
            .is_err()
    );
}

#[test]
fn concurrent_insert_touch_and_sweep_preserve_a_full_cone_binding() {
    let table = Arc::new(NatTable::new());
    let translated = "203.0.113.10:50000".parse().unwrap();
    std::thread::scope(|scope| {
        for worker in 0..4 {
            let table = Arc::clone(&table);
            scope.spawn(move || {
                for round in 0..500 {
                    let key = NatKey {
                        network: Network::Udp,
                        source: "192.0.2.10:40000".parse().unwrap(),
                        destination: format!("198.51.100.{}:{}", worker + 1, 4000 + round)
                            .parse()
                            .unwrap(),
                    };
                    table
                        .insert(key.clone(), translated, Duration::from_secs(30))
                        .unwrap();
                    assert!(table.touch(&key).unwrap().is_some());
                    if round % 5 == 0 {
                        let _ = table.sweep().unwrap();
                    }
                }
            });
        }
        let sweep_table = Arc::clone(&table);
        scope.spawn(move || {
            for _ in 0..500 {
                let _ = sweep_table.sweep().unwrap();
            }
        });
        let lookup_table = Arc::clone(&table);
        scope.spawn(move || {
            for _ in 0..500 {
                let _ = lookup_table
                    .lookup_translated(Network::Udp, translated, "203.0.113.200:9".parse().unwrap())
                    .unwrap();
            }
        });
    });
    assert_eq!(table.len().unwrap(), 1);
    assert!(
        table
            .lookup_translated(Network::Udp, translated, "192.0.2.200:9".parse().unwrap(),)
            .unwrap()
            .is_some()
    );
}

#[test]
fn concurrent_relays_cannot_claim_one_relay_for_two_sources() {
    let table = NatTable::new();
    let relay = Arc::new(
        UdpNatRelay::bind(
            "127.0.0.1:0".parse().unwrap(),
            table.clone(),
            Duration::from_secs(2),
        )
        .unwrap(),
    );
    let destination = UdpSocket::bind("127.0.0.1:0").unwrap();
    let address = destination.local_addr().unwrap();
    std::thread::scope(|scope| {
        for source_port in [40000, 40001] {
            let relay = Arc::clone(&relay);
            scope.spawn(move || {
                let key = NatKey {
                    network: Network::Udp,
                    source: format!("192.0.2.10:{source_port}").parse().unwrap(),
                    destination: address,
                };
                relay.send_to(key, b"packet")
            });
        }
    });
    assert_eq!(table.len().unwrap(), 1);
}
