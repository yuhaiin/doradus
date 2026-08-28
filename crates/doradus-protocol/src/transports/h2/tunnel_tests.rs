//! HTTP/2 tunnel tests.

use super::*;
use bytes::Bytes;
use http::Response;
use std::collections::VecDeque;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[tokio::test(flavor = "current_thread")]
async fn h2_connect_stream_preserves_underlying_local_endpoint() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move {
        let mut connection = h2::server::handshake(server_io).await.unwrap();
        let (request, mut respond) = connection.accept().await.unwrap().unwrap();
        assert_eq!(request.method(), http::Method::CONNECT);
        respond.send_response(Response::new(()), true).unwrap();
        while connection.accept().await.is_some() {}
    });

    let local = "192.0.2.10:45678".parse().unwrap();
    let connection = H2Connection::handshake_with_limits_and_local_addr(client_io, 1, Some(local))
        .await
        .unwrap();
    let (_stream, observed) = connection
        .open_connect_stream_with_local_addr(1)
        .await
        .unwrap();
    assert_eq!(observed, Some(local));
    connection.close().await;
    let _ = server.await;
}

#[tokio::test(flavor = "current_thread")]
async fn connect_stream_relays_bytes_in_both_directions() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move {
        let mut connection = h2::server::handshake(server_io).await.unwrap();
        let request = connection.accept().await.unwrap().unwrap();
        let (request, mut respond) = request;
        assert_eq!(request.method(), http::Method::CONNECT);
        let mut body = request.into_body();
        let send = respond.send_response(Response::new(()), false).unwrap();
        let echo = tokio::spawn(async move {
            let mut send = send;
            while let Some(data) = body.data().await {
                let Ok(data) = data else { break };
                if body.flow_control().release_capacity(data.len()).is_err() {
                    break;
                }
                if send.send_data(data, false).is_err() {
                    break;
                }
            }
            let _ = send.send_data(Bytes::new(), true);
        });
        // The h2 connection itself must keep being polled while the
        // request/response stream handles are active.
        while let Some(result) = connection.accept().await {
            if result.is_err() {
                break;
            }
        }
        let _ = echo.await;
    });

    let connection = H2Connection::handshake_with_limits(client_io, 128)
        .await
        .unwrap();
    let mut tunnel = connection.open_connect_stream(8).await.unwrap();
    tunnel.write_all(b"hello over h2").await.unwrap();
    tunnel.shutdown().await.unwrap();
    let mut response = vec![0; 13];
    tunnel.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"hello over h2");
    server.abort();
    let _ = server.await;
}

#[tokio::test(flavor = "current_thread")]
async fn hyper_connect_upgrade_respects_peer_flow_control() {
    let (client_io, server_io) = tokio::io::duplex(256 * 1024);
    let server = tokio::spawn(async move {
        let mut connection = h2::server::handshake(server_io).await.unwrap();
        let request = connection.accept().await.unwrap().unwrap();
        let (request, mut respond) = request;
        let _ = respond.send_response(Response::new(()), false).unwrap();
        let mut body = request.into_body();
        // Keep the connection driver active while the application body
        // is deliberately not released. Hyper's CONNECT upgrade must
        // stop at the peer's flow-control window instead of buffering
        // the entire application payload.
        let _ = connection.accept().await;
        let _ = body.data().await;
    });

    let connection = H2Connection::handshake_with_limits(client_io, 1)
        .await
        .unwrap();
    let mut stream = connection.open_connect_stream(1).await.unwrap();
    let payload = vec![0x5a; 128 * 1024];
    let send = tokio::spawn(async move { stream.write_all(&payload).await });
    tokio::time::sleep(Duration::from_millis(25)).await;
    assert!(
        !send.is_finished(),
        "CONNECT upgrade buffered past peer window"
    );

    connection.close().await;
    let _ = send.await;
    server.abort();
    let _ = server.await;
}

#[tokio::test(flavor = "current_thread")]
async fn random_peer_bytes_do_not_panic_or_hang_h2_handshake() {
    // The peer side deliberately is not an h2 implementation.  This is
    // a small deterministic wire-fuzz regression: malformed prefaces,
    // truncated settings, and arbitrary frame headers must become an
    // error (or a bounded timeout), never a task panic or an unbounded
    // wait in the client handshake.
    let mut state = 0x9e37_79b9_u32;
    for case in 0..96 {
        let (client_io, mut peer_io) = tokio::io::duplex(4096);
        let length = (next_random(&mut state) as usize % 1537).min(2048);
        let mut bytes = vec![0; length];
        for byte in &mut bytes {
            *byte = next_random(&mut state) as u8;
        }
        let peer = tokio::spawn(async move {
            let _ = peer_io.write_all(&bytes).await;
            let _ = peer_io.shutdown().await;
        });

        let result = timeout(
            Duration::from_millis(250),
            H2Connection::handshake_with_limits(client_io, 1),
        )
        .await;
        if let Ok(Ok(connection)) = result {
            connection.close().await;
        }
        timeout(Duration::from_millis(250), peer)
            .await
            .unwrap_or_else(|_| panic!("random h2 peer case {case} did not finish"))
            .unwrap_or_else(|error| panic!("random h2 peer case {case} panicked: {error}"));
    }
}

fn next_random(state: &mut u32) -> u32 {
    *state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
    *state
}

#[tokio::test(flavor = "current_thread")]
async fn malformed_h2_frames_after_settings_are_bounded() {
    // A valid server SETTINGS frame lets the client handshake complete;
    // each following frame is intentionally invalid at the connection or
    // stream level.  This exercises the live h2 driver rather than only
    // the preface error path above.
    let malformed_frames = [
        frame_header(0, 0x0, 0, 0),           // DATA on stream 0
        frame_header(0, 0x1, 0, 0),           // HEADERS on stream 0
        frame_header(0, 0x4, 0, 1),           // SETTINGS on stream 1
        frame_header(0, 0x6, 0, 1),           // PING on stream 1
        frame_header(0, 0x9, 0, 1),           // CONTINUATION without HEADERS
        frame_header(0, 0x0, 0, 0x8000_0001), // reserved stream-id bit
        frame_header(0x00ff_ffff, 0x0, 0, 1), // truncated oversized DATA
    ];
    for (case, malformed) in malformed_frames.into_iter().enumerate() {
        let (client_io, mut peer_io) = tokio::io::duplex(4096);
        let mut wire = Vec::with_capacity(9 + malformed.len());
        wire.extend_from_slice(&frame_header(0, 0x4, 0, 0)); // SETTINGS
        wire.extend_from_slice(&malformed);
        let peer = tokio::spawn(async move {
            let _ = peer_io.write_all(&wire).await;
            let _ = peer_io.shutdown().await;
        });

        let result = timeout(
            Duration::from_millis(250),
            H2Connection::handshake_with_limits(client_io, 1),
        )
        .await;
        if let Ok(Ok(connection)) = result {
            let _ = timeout(Duration::from_millis(250), async {
                while !connection.is_closed() {
                    tokio::task::yield_now().await;
                }
            })
            .await;
            connection.close().await;
        }
        timeout(Duration::from_millis(250), peer)
            .await
            .unwrap_or_else(|_| panic!("malformed h2 frame case {case} did not finish"))
            .unwrap_or_else(|error| panic!("malformed h2 frame case {case} panicked: {error}"));
    }
}

fn frame_header(length: u32, kind: u8, flags: u8, stream_id: u32) -> Vec<u8> {
    vec![
        (length >> 16) as u8,
        (length >> 8) as u8,
        length as u8,
        kind,
        flags,
        (stream_id >> 24) as u8,
        (stream_id >> 16) as u8,
        (stream_id >> 8) as u8,
        stream_id as u8,
    ]
}

#[test]
fn h2_pool_key_keeps_interface_binding_isolated() {
    let address = "127.0.0.1:443".parse().unwrap();
    let without_interface = H2PoolKey {
        address,
        bind_interface: None,
        tls_identity: "identity".to_owned(),
    };
    let with_interface = H2PoolKey {
        address,
        bind_interface: Some("eth0".to_owned()),
        tls_identity: "identity".to_owned(),
    };
    assert_ne!(without_interface, with_interface);
}

#[tokio::test(flavor = "current_thread")]
async fn pool_does_not_coalesce_different_tls_identities() {
    let (client_one, server_one) = tokio::io::duplex(64 * 1024);
    let (client_two, server_two) = tokio::io::duplex(64 * 1024);
    let server = |io| async move {
        let mut connection = h2::server::handshake(io).await.unwrap();
        let (request, mut respond) = connection.accept().await.unwrap().unwrap();
        assert_eq!(request.method(), http::Method::CONNECT);
        respond.send_response(Response::new(()), false).unwrap();
        while connection.accept().await.is_some() {}
    };
    let server_one = tokio::spawn(server(server_one));
    let server_two = tokio::spawn(server(server_two));
    let io = Arc::new(Mutex::new(VecDeque::from([client_one, client_two])));
    let address = "127.0.0.1:443".parse().unwrap();
    let pool = H2Pool::with_limits(2, Duration::from_secs(300));

    let first = pool
        .open_with_identity(&[address], "tls-identity-a", 1, {
            let io = Arc::clone(&io);
            move |_| {
                let io = Arc::clone(&io);
                async move {
                    let transport = io.lock().await.pop_front().ok_or_else(|| {
                        Error::new(ErrorKind::Closed, "first TLS identity transport missing")
                    })?;
                    H2Connection::handshake_with_limits(transport, 128).await
                }
            }
        })
        .await
        .unwrap();
    let second = pool
        .open_with_identity(&[address], "tls-identity-b", 1, {
            let io = Arc::clone(&io);
            move |_| {
                let io = Arc::clone(&io);
                async move {
                    let transport = io.lock().await.pop_front().ok_or_else(|| {
                        Error::new(ErrorKind::Closed, "second TLS identity transport missing")
                    })?;
                    H2Connection::handshake_with_limits(transport, 128).await
                }
            }
        })
        .await
        .unwrap();
    assert_eq!(pool.len().await, 2);
    assert_eq!(pool.active_streams().await, 2);
    assert_eq!(pool.stats().connection_attempts, 2);

    drop(first);
    drop(second);
    pool.close().await;
    server_one.abort();
    server_two.abort();
    let _ = server_one.await;
    let _ = server_two.await;
}

#[tokio::test(flavor = "current_thread")]
async fn pool_reuses_one_connection_for_multiple_connect_streams() {
    let (client_io, server_io) = tokio::io::duplex(128 * 1024);
    let server = tokio::spawn(async move {
        let mut connection = h2::server::handshake(server_io).await.unwrap();
        let (done_tx, mut done_rx) = tokio::sync::mpsc::channel(2);
        for _ in 0..2 {
            let (request, mut respond) = connection.accept().await.unwrap().unwrap();
            assert_eq!(request.method(), http::Method::CONNECT);
            let mut body = request.into_body();
            let mut send = respond.send_response(Response::new(()), false).unwrap();
            let done_tx = done_tx.clone();
            tokio::spawn(async move {
                while let Some(data) = body.data().await {
                    let Ok(data) = data else { break };
                    if body.flow_control().release_capacity(data.len()).is_err() {
                        break;
                    }
                    if send.send_data(data, false).is_err() {
                        break;
                    }
                }
                let _ = send.send_data(Bytes::new(), true);
                let _ = done_tx.send(()).await;
            });
        }
        drop(done_tx);
        let mut completed = 0;
        while completed < 2 {
            tokio::select! {
                _ = done_rx.recv() => completed += 1,
                result = connection.accept() => {
                    if result.is_none() {
                        break;
                    }
                }
            }
        }
    });

    let io = Arc::new(Mutex::new(Some(client_io)));
    let address = "127.0.0.1:443".parse().unwrap();
    let pool = H2Pool::new();
    let mut first = pool
        .open(&[address], 4, {
            let io = Arc::clone(&io);
            move |_| {
                let io = Arc::clone(&io);
                async move {
                    let io = io.lock().await.take().ok_or_else(|| {
                        Error::new(ErrorKind::Closed, "test h2 transport already taken")
                    })?;
                    H2Connection::handshake_with_limits(io, 128).await
                }
            }
        })
        .await
        .unwrap();
    let mut second = pool
        .open(&[address], 4, |_| async {
            Err(Error::new(
                ErrorKind::Closed,
                "pool should not create a second connection",
            ))
        })
        .await
        .unwrap();
    assert_eq!(pool.len().await, 1);
    assert_eq!(pool.active_streams().await, 2);

    first.write_all(b"first").await.unwrap();
    second.write_all(b"second").await.unwrap();
    let mut first_response = [0u8; 5];
    let mut second_response = [0u8; 6];
    first.read_exact(&mut first_response).await.unwrap();
    second.read_exact(&mut second_response).await.unwrap();
    assert_eq!(&first_response, b"first");
    assert_eq!(&second_response, b"second");

    pool.close().await;
    assert_eq!(pool.len().await, 0);
    server.abort();
    let _ = server.await;
}

#[tokio::test(flavor = "current_thread")]
async fn pool_falls_back_to_next_endpoint_after_connection_failure() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move {
        let mut connection = h2::server::handshake(server_io).await.unwrap();
        let (request, mut respond) = connection.accept().await.unwrap().unwrap();
        assert_eq!(request.method(), http::Method::CONNECT);
        respond.send_response(Response::new(()), false).unwrap();
        while connection.accept().await.is_some() {}
    });

    let unreachable_v6 = "[2001:db8::1]:443".parse().unwrap();
    let reachable_v4 = "127.0.0.1:443".parse().unwrap();
    let io = Arc::new(Mutex::new(Some(client_io)));
    let pool = H2Pool::new();
    let stream = tokio::time::timeout(
        Duration::from_secs(2),
        pool.open(&[unreachable_v6, reachable_v4], 1, {
            let io = Arc::clone(&io);
            move |address| {
                let io = Arc::clone(&io);
                async move {
                    if address == unreachable_v6 {
                        tokio::time::sleep(Duration::from_secs(5)).await;
                        return Err(Error::new(
                            ErrorKind::Io,
                            "simulated unreachable IPv6 endpoint",
                        ));
                    }
                    let io =
                        io.lock().await.take().ok_or_else(|| {
                            Error::new(ErrorKind::Closed, "test transport missing")
                        })?;
                    H2Connection::handshake_with_limits(io, 128).await
                }
            }
        }),
    )
    .await
    .expect("IPv4 fallback did not race the stalled IPv6 endpoint")
    .unwrap();
    assert_eq!(pool.stats().connection_attempts, 2);
    drop(stream);
    pool.close().await;
    server.abort();
    let _ = server.await;
}

#[tokio::test(flavor = "current_thread")]
async fn pool_rebuilds_after_the_underlying_h2_connection_ends() {
    let (client_one, server_one) = tokio::io::duplex(64 * 1024);
    let (client_two, server_two) = tokio::io::duplex(64 * 1024);
    let server_one = tokio::spawn(async move {
        let mut connection = h2::server::handshake(server_one).await.unwrap();
        let (request, mut respond) = connection.accept().await.unwrap().unwrap();
        assert_eq!(request.method(), http::Method::CONNECT);
        respond.send_response(Response::new(()), true).unwrap();
        connection.graceful_shutdown();
        while connection.accept().await.is_some() {}
    });
    let server_two = tokio::spawn(async move {
        let mut connection = h2::server::handshake(server_two).await.unwrap();
        let (request, mut respond) = connection.accept().await.unwrap().unwrap();
        assert_eq!(request.method(), http::Method::CONNECT);
        respond.send_response(Response::new(()), true).unwrap();
        connection.graceful_shutdown();
        while connection.accept().await.is_some() {}
    });

    let io = Arc::new(Mutex::new(VecDeque::from([client_one, client_two])));
    let address = "127.0.0.1:443".parse().unwrap();
    let pool = H2Pool::new();
    let first = pool
        .open(&[address], 1, {
            let io = Arc::clone(&io);
            move |_| {
                let io = Arc::clone(&io);
                async move {
                    let io = io.lock().await.pop_front().ok_or_else(|| {
                        Error::new(ErrorKind::Closed, "test h2 transports exhausted")
                    })?;
                    H2Connection::handshake_with_limits(io, 128).await
                }
            }
        })
        .await
        .unwrap();
    drop(first);
    server_one.await.unwrap();

    let second = tokio::time::timeout(
        Duration::from_secs(1),
        pool.open(&[address], 1, {
            let io = Arc::clone(&io);
            move |_| {
                let io = Arc::clone(&io);
                async move {
                    let io = io.lock().await.pop_front().ok_or_else(|| {
                        Error::new(ErrorKind::Closed, "pool did not rebuild h2 connection")
                    })?;
                    H2Connection::handshake_with_limits(io, 128).await
                }
            }
        }),
    )
    .await
    .expect("h2 pool reconnect timed out")
    .unwrap();
    drop(second);
    assert_eq!(pool.len().await, 1);
    pool.close().await;
    server_two.await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn pool_rebuilds_after_a_stream_error_on_a_live_connection() {
    let (client_one, server_one) = tokio::io::duplex(64 * 1024);
    let (client_two, server_two) = tokio::io::duplex(64 * 1024);
    let server_one = tokio::spawn(async move {
        let mut connection = h2::server::handshake(server_one).await.unwrap();
        for status in [http::StatusCode::OK, http::StatusCode::BAD_GATEWAY] {
            let (request, mut respond) = connection.accept().await.unwrap().unwrap();
            assert_eq!(request.method(), http::Method::CONNECT);
            respond
                .send_response(Response::builder().status(status).body(()).unwrap(), true)
                .unwrap();
        }
        while connection.accept().await.is_some() {}
    });
    let server_two = tokio::spawn(async move {
        let mut connection = h2::server::handshake(server_two).await.unwrap();
        let (request, mut respond) = connection.accept().await.unwrap().unwrap();
        assert_eq!(request.method(), http::Method::CONNECT);
        respond.send_response(Response::new(()), true).unwrap();
        connection.graceful_shutdown();
        while connection.accept().await.is_some() {}
    });

    let transports = Arc::new(Mutex::new(VecDeque::from([client_one, client_two])));
    let connection_attempts = Arc::new(AtomicUsize::new(0));
    let address = "127.0.0.1:443".parse().unwrap();
    let pool = H2Pool::with_limits(1, Duration::from_secs(300));
    let first = pool
        .open(&[address], 1, {
            let transports = Arc::clone(&transports);
            let connection_attempts = Arc::clone(&connection_attempts);
            move |_| {
                let transports = Arc::clone(&transports);
                let connection_attempts = Arc::clone(&connection_attempts);
                async move {
                    connection_attempts.fetch_add(1, Ordering::Relaxed);
                    let io = transports.lock().await.pop_front().ok_or_else(|| {
                        Error::new(ErrorKind::Closed, "test h2 transports exhausted")
                    })?;
                    H2Connection::handshake_with_limits(io, 128).await
                }
            }
        })
        .await
        .unwrap();
    drop(first);
    let second = pool
        .open(&[address], 1, {
            let transports = Arc::clone(&transports);
            let connection_attempts = Arc::clone(&connection_attempts);
            move |_| {
                let transports = Arc::clone(&transports);
                let connection_attempts = Arc::clone(&connection_attempts);
                async move {
                    connection_attempts.fetch_add(1, Ordering::Relaxed);
                    let io = transports.lock().await.pop_front().ok_or_else(|| {
                        Error::new(ErrorKind::Closed, "pool did not rebuild h2 connection")
                    })?;
                    H2Connection::handshake_with_limits(io, 128).await
                }
            }
        })
        .await
        .expect("pool should rebuild after a live connection rejects a stream");

    assert_eq!(connection_attempts.load(Ordering::Relaxed), 2);
    drop(second);
    pool.close().await;
    server_one.abort();
    let _ = server_one.await;
    server_two.await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn peer_goaway_closes_active_stream_and_rejects_new_streams() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (goaway_tx, goaway_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let mut connection = h2::server::handshake(server_io).await.unwrap();
        let (request, mut respond) = connection.accept().await.unwrap().unwrap();
        assert_eq!(request.method(), http::Method::CONNECT);
        respond.send_response(Response::new(()), false).unwrap();
        tokio::select! {
            _ = goaway_rx => {
                connection.abrupt_shutdown(h2::Reason::NO_ERROR);
                while connection.accept().await.is_some() {}
            }
            result = async {
                while connection.accept().await.is_some() {}
            } => result,
        }
    });
    let connection = H2Connection::handshake_with_limits(client_io, 128)
        .await
        .unwrap();
    let mut stream = connection.open_connect_stream(1).await.unwrap();
    goaway_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while !connection.is_closed() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("client did not observe peer GOAWAY");
    assert!(connection.open_connect_stream(1).await.is_err());
    let mut buffer = [0u8; 1];
    let result = tokio::time::timeout(Duration::from_secs(1), stream.read(&mut buffer))
        .await
        .expect("peer GOAWAY did not close the active relay");
    assert!(matches!(result, Ok(0) | Err(_)));
    tokio::time::timeout(Duration::from_secs(1), async {
        while connection.active_streams() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("peer GOAWAY left an active stream slot behind");
    server.await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn pool_opens_a_second_connection_when_one_reaches_stream_capacity() {
    let (client_one, server_one) = tokio::io::duplex(64 * 1024);
    let (client_two, server_two) = tokio::io::duplex(64 * 1024);
    let server = |io| async move {
        let mut connection = h2::server::handshake(io).await.unwrap();
        let (request, mut respond) = connection.accept().await.unwrap().unwrap();
        assert_eq!(request.method(), http::Method::CONNECT);
        respond.send_response(Response::new(()), false).unwrap();
        while connection.accept().await.is_some() {}
    };
    let server_one = tokio::spawn(server(server_one));
    let server_two = tokio::spawn(server(server_two));
    let io = Arc::new(Mutex::new(VecDeque::from([client_one, client_two])));
    let address = "127.0.0.1:443".parse().unwrap();
    let pool = H2Pool::with_limits(2, Duration::from_secs(300));
    let mut first = pool
        .open(&[address], 1, {
            let io = Arc::clone(&io);
            move |_| {
                let io = Arc::clone(&io);
                async move {
                    let io = io.lock().await.pop_front().unwrap();
                    H2Connection::handshake_with_limits(io, 1).await
                }
            }
        })
        .await
        .unwrap();
    let mut second = pool
        .open(&[address], 1, {
            let io = Arc::clone(&io);
            move |_| {
                let io = Arc::clone(&io);
                async move {
                    let io = io.lock().await.pop_front().unwrap();
                    H2Connection::handshake_with_limits(io, 1).await
                }
            }
        })
        .await
        .unwrap();
    assert_eq!(pool.len().await, 2);
    assert_eq!(pool.active_streams().await, 2);
    let stats = pool.stats();
    assert_eq!(stats.connection_attempts, 2);
    assert_eq!(stats.connection_failures, 0);
    assert_eq!(stats.stream_capacity_rejections, 1);
    first.shutdown().await.unwrap();
    second.shutdown().await.unwrap();
    pool.close().await;
    server_one.abort();
    server_two.abort();
    let _ = server_one.await;
    let _ = server_two.await;
}

#[tokio::test(flavor = "current_thread")]
async fn pool_close_drains_multiple_connections_in_parallel() {
    let (client_one, server_one) = tokio::io::duplex(64 * 1024);
    let (client_two, server_two) = tokio::io::duplex(64 * 1024);
    let server = |io| async move {
        let mut connection = h2::server::handshake(io).await.unwrap();
        let (request, mut respond) = connection.accept().await.unwrap().unwrap();
        assert_eq!(request.method(), http::Method::CONNECT);
        respond.send_response(Response::new(()), false).unwrap();
        while connection.accept().await.is_some() {}
    };
    let server_one = tokio::spawn(server(server_one));
    let server_two = tokio::spawn(server(server_two));
    let io = Arc::new(Mutex::new(VecDeque::from([client_one, client_two])));
    let address = "127.0.0.1:443".parse().unwrap();
    let pool = H2Pool::with_limits(2, Duration::from_secs(300));
    let first = pool
        .open(&[address], 1, {
            let io = Arc::clone(&io);
            move |_| {
                let io = Arc::clone(&io);
                async move {
                    H2Connection::handshake_with_limits(io.lock().await.pop_front().unwrap(), 1)
                        .await
                }
            }
        })
        .await
        .unwrap();
    let second = pool
        .open(&[address], 1, {
            let io = Arc::clone(&io);
            move |_| {
                let io = Arc::clone(&io);
                async move {
                    H2Connection::handshake_with_limits(io.lock().await.pop_front().unwrap(), 1)
                        .await
                }
            }
        })
        .await
        .unwrap();
    let started = tokio::time::Instant::now();
    pool.close().await;
    assert!(
        started.elapsed() < Duration::from_millis(1_800),
        "pool close exceeded one shared drain deadline: {:?}",
        started.elapsed()
    );
    assert_eq!(pool.len().await, 0);
    assert_eq!(pool.active_streams().await, 0);
    drop(first);
    drop(second);
    server_one.abort();
    server_two.abort();
    let _ = server_one.await;
    let _ = server_two.await;
}

#[tokio::test(flavor = "current_thread")]
async fn pool_reaps_only_idle_connections() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move {
        let mut connection = h2::server::handshake(server_io).await.unwrap();
        let (request, mut respond) = connection.accept().await.unwrap().unwrap();
        assert_eq!(request.method(), http::Method::CONNECT);
        respond.send_response(Response::new(()), true).unwrap();
        while connection.accept().await.is_some() {}
    });
    let io = Arc::new(Mutex::new(Some(client_io)));
    let address = "127.0.0.1:443".parse().unwrap();
    let pool = H2Pool::with_limits(1, Duration::from_millis(10));
    let stream = pool
        .open(&[address], 1, {
            let io = Arc::clone(&io);
            move |_| {
                let io = Arc::clone(&io);
                async move {
                    H2Connection::handshake_with_limits(io.lock().await.take().unwrap(), 128).await
                }
            }
        })
        .await
        .unwrap();
    assert_eq!(pool.active_streams().await, 1);
    pool.reap_idle().await;
    assert_eq!(pool.len().await, 1);
    drop(stream);
    tokio::time::sleep(Duration::from_millis(20)).await;
    pool.reap_idle().await;
    assert_eq!(pool.len().await, 0);
    server.abort();
    let _ = server.await;
}

#[tokio::test(flavor = "current_thread")]
async fn connection_drain_rejects_new_streams_and_has_a_deadline() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move {
        let mut connection = h2::server::handshake(server_io).await.unwrap();
        let (request, mut respond) = connection.accept().await.unwrap().unwrap();
        assert_eq!(request.method(), http::Method::CONNECT);
        respond.send_response(Response::new(()), false).unwrap();
        while connection.accept().await.is_some() {}
    });
    let connection = H2Connection::handshake_with_limits(client_io, 128)
        .await
        .unwrap();
    let mut stream = connection.open_connect_stream(1).await.unwrap();
    let started = Instant::now();
    connection.drain(Duration::from_millis(20)).await;
    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(connection.is_closed());
    assert!(connection.connection_task.lock().await.is_none());
    assert!(connection.relay_tasks.lock().await.is_empty());
    assert!(connection.open_connect_stream(1).await.is_err());
    let mut eof = [0u8; 1];
    assert_eq!(stream.read(&mut eof).await.unwrap(), 0);
    server.abort();
    let _ = server.await;
}

#[tokio::test(flavor = "current_thread")]
async fn real_tcp_connection_drain_releases_socket_and_server_task() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (server_io, _) = listener.accept().await.unwrap();
        let mut connection = h2::server::handshake(server_io).await.unwrap();
        let (request, mut respond) = connection.accept().await.unwrap().unwrap();
        assert_eq!(request.method(), http::Method::CONNECT);
        respond.send_response(Response::new(()), false).unwrap();
        while let Some(result) = connection.accept().await {
            if result.is_err() {
                break;
            }
        }
    });

    let client_io = tokio::net::TcpStream::connect(address).await.unwrap();
    let connection = H2Connection::handshake_with_limits(client_io, 1)
        .await
        .unwrap();
    let mut stream = connection.open_connect_stream(1).await.unwrap();
    connection.drain(Duration::from_millis(20)).await;

    assert!(connection.is_closed());
    assert_eq!(connection.active_streams(), 0);
    assert!(connection.connection_task.lock().await.is_none());
    assert!(connection.relay_tasks.lock().await.is_empty());
    let mut eof = [0u8; 1];
    assert_eq!(stream.read(&mut eof).await.unwrap(), 0);
    timeout(Duration::from_secs(1), server)
        .await
        .expect("real h2 server did not observe client teardown")
        .expect("real h2 server task panicked");
}

#[tokio::test(flavor = "current_thread")]
async fn failed_connect_response_releases_the_reserved_stream_slot() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move {
        let mut connection = h2::server::handshake(server_io).await.unwrap();
        let (request, mut respond) = connection.accept().await.unwrap().unwrap();
        assert_eq!(request.method(), http::Method::CONNECT);
        respond
            .send_response(
                Response::builder()
                    .status(http::StatusCode::BAD_GATEWAY)
                    .body(())
                    .unwrap(),
                true,
            )
            .unwrap();
    });
    let connection = H2Connection::handshake_with_limits(client_io, 1)
        .await
        .unwrap();
    assert!(connection.open_connect_stream(1).await.is_err());
    assert_eq!(connection.active_streams(), 0);
    connection.close().await;
    server.await.unwrap();
}
