use super::*;

fn endpoint(port: u16) -> Endpoint {
    Endpoint::ip(Network::Udp, SocketAddr::from(([192, 0, 2, 1], port)))
}

#[test]
fn root_store_has_public_roots_without_custom_certificates() {
    let roots = root_store(&[]).unwrap();
    assert!(!roots.is_empty());
}

#[test]
fn retry_queue_has_bounded_frame_and_byte_capacity() {
    let mut queue = RetryQueue::new();
    for id in 0..MAX_UOT_RETRY_FRAMES as u64 {
        queue
            .push(PendingUotDatagram {
                id,
                target: endpoint(5353),
                payload: vec![id as u8],
            })
            .unwrap();
    }
    let error = queue
        .push(PendingUotDatagram {
            id: MAX_UOT_RETRY_FRAMES as u64,
            target: endpoint(5353),
            payload: vec![0],
        })
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Timeout);

    queue.remove_id(0);
    queue
        .push(PendingUotDatagram {
            id: MAX_UOT_RETRY_FRAMES as u64,
            target: endpoint(5353),
            payload: vec![0],
        })
        .unwrap();
    assert_eq!(queue.snapshot().len(), MAX_UOT_RETRY_FRAMES);

    let mut bytes = RetryQueue::new();
    bytes
        .push(PendingUotDatagram {
            id: 1,
            target: endpoint(5353),
            payload: vec![0; MAX_UOT_RETRY_BYTES],
        })
        .unwrap();
    let error = bytes
        .push(PendingUotDatagram {
            id: 2,
            target: endpoint(5353),
            payload: vec![0],
        })
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Timeout);
}

#[test]
fn retry_queue_acknowledges_exact_target_before_payload_fallback() {
    let first_target = endpoint(5353);
    let second_target = endpoint(5354);
    let mut queue = RetryQueue::new();
    queue
        .push(PendingUotDatagram {
            id: 1,
            target: first_target.clone(),
            payload: b"same".to_vec(),
        })
        .unwrap();
    queue
        .push(PendingUotDatagram {
            id: 2,
            target: second_target.clone(),
            payload: b"same".to_vec(),
        })
        .unwrap();

    queue.acknowledge(&second_target, b"same");
    assert_eq!(queue.snapshot(), vec![(first_target, b"same".to_vec())]);
    queue.acknowledge(&endpoint(5355), b"same");
    assert!(queue.snapshot().is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn coalesced_uot_flushes_a_low_traffic_datagram_without_recv() {
    let (client, mut peer) = tokio::io::duplex(4096);
    let (reader, writer) = tokio::io::split(Box::new(client) as BoxAsyncStream);
    let session = ChainUotSession::new(reader, writer, true);
    let target = endpoint(5353);

    session.send_to(&target, b"low-traffic").await.unwrap();
    let frame = tokio::time::timeout(Duration::from_secs(1), read_uot_frame(&mut peer))
        .await
        .expect("coalesced UOT frame was not flushed")
        .unwrap();
    let (decoded_target, payload, _) =
        doradus_protocol::yuubinsya::decode_uot_frame(&frame).unwrap();
    assert_eq!(decoded_target, target);
    assert_eq!(payload, b"low-traffic");
    session.shutdown().await.unwrap();
}

#[test]
fn runtime_stats_render_a_stable_prometheus_snapshot() {
    let stats = ChainRuntimeStats {
        h2_connections: 2,
        h2_active_streams: 5,
        h2_pool: H2PoolStats {
            connection_attempts: 7,
            connection_failures: 1,
            stream_capacity_rejections: 3,
            stream_open_failures: 2,
        },
    };
    let rendered = stats.render_prometheus();
    assert!(rendered.contains("# TYPE doradus_chain_h2_connections gauge"));
    assert!(rendered.contains("doradus_chain_h2_connections 2\n"));
    assert!(rendered.contains("doradus_chain_h2_active_streams 5\n"));
    assert!(rendered.contains("doradus_chain_h2_connection_attempts 7\n"));
    assert!(rendered.contains("doradus_chain_h2_stream_capacity_rejections 3\n"));
    assert!(rendered.ends_with('\n'));
}
