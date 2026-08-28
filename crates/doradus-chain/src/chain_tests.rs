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

#[tokio::test(flavor = "current_thread")]
async fn successful_uot_datagram_releases_its_retry_slot() {
    let (client, _peer) = tokio::io::duplex(4096);
    let (reader, writer) = tokio::io::split(Box::new(client) as BoxAsyncStream);
    let session = ChainUotSession::new(reader, writer, false);
    let chain =
        ChainClient::new(parse_config(r#"{"chain":[{"type":"direct","direct":{}}]}"#).unwrap())
            .unwrap();
    let datagram = ChainDatagram {
        client: chain,
        migrate_id: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        session: Mutex::new(Some(session)),
        reconnect_lock: Mutex::new(()),
        generation: std::sync::atomic::AtomicU64::new(1),
        closed: std::sync::atomic::AtomicBool::new(false),
        shutdown: watch::channel(false).0,
        next_retry_id: std::sync::atomic::AtomicU64::new(1),
        retry: Mutex::new(RetryQueue::new()),
        local_bind_addresses: Arc::new(Vec::new()),
        bind_interface: None,
        local_addr: StdMutex::new(None),
    };

    datagram.send_to(b"request", endpoint(443)).await.unwrap();

    assert!(datagram.retry.lock().await.snapshot().is_empty());
}
