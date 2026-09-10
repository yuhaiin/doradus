use super::*;

use std::future::pending;
use std::sync::Arc;
use std::time::{Duration, Instant};

use doradus_core::flow::FlowKey as TunFlowKey;
use doradus_core::proxy::AsyncDatagram;
use doradus_core::{BoxFuture, Endpoint, Network, Result};
use doradus_store::{ConfigStore, GoNodeRecord};
use tokio::sync::{Notify, mpsc, watch};

use crate::inbound::{InboundHandler, InboundSpec, UdpMode};
use crate::{RuntimeBuilder, RuntimeController};

fn flow(source: &str, destination: &str) -> TunFlowKey {
    TunFlowKey {
        network: Network::Udp,
        source: source.parse().unwrap(),
        destination: destination.parse().unwrap(),
    }
}

fn source_key(session_id: u64, source: &str) -> UdpSourceKey {
    UdpSourceKey {
        inbound_id: "inbound".to_owned(),
        session_id,
        source: source.parse().unwrap(),
        authentication: None,
    }
}

#[test]
fn pending_close_requires_the_opening_worker_session_and_source() {
    let key = source_key(7, "127.0.0.1:41000");
    let matching = flow("127.0.0.1:41000", "192.0.2.1:53");
    let other_session = flow("127.0.0.1:41000", "192.0.2.1:54");
    let other_source = flow("127.0.0.1:41001", "192.0.2.1:53");

    assert_eq!(
        opening_worker_key(std::iter::once((&key, 7, true)), 7, matching),
        Some(key.clone())
    );
    assert_eq!(
        opening_worker_key(std::iter::once((&key, 8, true)), 7, other_session),
        None
    );
    assert_eq!(
        opening_worker_key(std::iter::once((&key, 7, true)), 7, other_source),
        None
    );
    assert_eq!(
        opening_worker_key(std::iter::once((&key, 7, false)), 7, matching),
        None
    );
}

#[tokio::test]
async fn manager_owner_drop_signals_and_reaps_manager_task() {
    for _ in 0..8 {
        let mut owner = InboundUdpManager::new(Weak::new(), 1);
        let _ingress_keepalive = owner.ingress_tx.clone();
        let _command_keepalive = owner.command_tx.clone();
        let join = owner
            .join
            .take()
            .expect("manager owner must retain its task handle");

        drop(owner);

        tokio::time::timeout(Duration::from_secs(1), join)
            .await
            .expect("dropping the manager owner must stop its task")
            .expect("manager task panicked");
    }
}

struct PendingDatagram {
    send_started: Arc<Notify>,
    close_started: Arc<Notify>,
}

impl AsyncDatagram for PendingDatagram {
    fn send_to<'a>(&'a self, _: &'a [u8], _: Endpoint) -> BoxFuture<'a, Result<usize>> {
        let started = Arc::clone(&self.send_started);
        Box::pin(async move {
            started.notify_one();
            pending().await
        })
    }

    fn recv_from<'a>(&'a self, _: &'a mut [u8]) -> BoxFuture<'a, Result<(usize, Endpoint)>> {
        Box::pin(pending())
    }

    fn local_addr(&self) -> Result<Endpoint> {
        Ok(Endpoint::ip(
            Network::Udp,
            "127.0.0.1:41999".parse().unwrap(),
        ))
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        let started = Arc::clone(&self.close_started);
        Box::pin(async move {
            started.notify_one();
            pending().await
        })
    }
}

async fn direct_inbound() -> Arc<InboundHandler> {
    let store = ConfigStore::open_memory().await.unwrap();
    let controller = RuntimeController::from_builder(RuntimeBuilder::new(
        store,
        Arc::new(doradus_core::dns_resolver::SystemAsyncIpResolver),
    ))
    .await
    .unwrap();
    controller
        .store()
        .repository()
        .put_go_node(&GoNodeRecord {
            id: "direct".to_owned(),
            name: "Direct".to_owned(),
            group_name: "default".to_owned(),
            origin: "test".to_owned(),
            enabled: true,
            chain_types_json: br#"["direct"]"#.to_vec(),
            updated_at: 1,
            data_json: br#"{"protocol":"direct"}"#.to_vec(),
        })
        .await
        .unwrap();
    controller.reload().await.unwrap();
    let selector = controller
        .build_proxy_selector("", "direct", "", "", Duration::from_secs(2))
        .await
        .unwrap();
    let monitor = controller.monitor();
    InboundHandler::new(
        InboundSpec {
            id: "udp-lifecycle-test".to_owned(),
            name: "udp-lifecycle-test".to_owned(),
            protocol: "vless".to_owned(),
            listen: "127.0.0.1:19090".parse().unwrap(),
            username: String::new(),
            password: "00112233-4455-6677-8899-aabbccddeeff".to_owned(),
            auth: None,
            udp_mode: UdpMode::Enabled,
            protocol_udp: true,
            transports: vec!["normal".to_owned()],
            aead_password: None,
            aead_method: doradus_protocol::aead::CryptoMethod::Chacha20Poly1305,
            outbound_id: "direct".to_owned(),
            reverse_target: None,
            reverse_http: None,
        },
        selector,
        monitor,
    )
}

#[tokio::test]
async fn session_cancel_interrupts_pending_udp_send_and_bounded_close() {
    let inbound = direct_inbound().await;
    let (_manager_cancel_tx, cancel_rx) = watch::channel(false);
    let (session_cancel_tx, session_cancel_rx) = watch::channel(false);
    let (event_tx, _event_rx) = mpsc::channel(1);
    let (session_event_tx, mut session_event_rx) = mpsc::channel(1);
    let (reply_tx, _reply_rx) = mpsc::channel(1);
    let send_started = Arc::new(Notify::new());
    let close_started = Arc::new(Notify::new());
    let source: std::net::SocketAddr = "127.0.0.1:41000".parse().unwrap();
    let target = Endpoint::ip(Network::Udp, "192.0.2.1:9".parse().unwrap());
    let flow = flow("127.0.0.1:41999", "192.0.2.1:9");

    let worker = UdpFlowWorker {
        inbound: Arc::downgrade(&inbound),
        key: source_key(1, source.to_string().as_str()),
        generation: 1,
        rx: {
            let (tx, rx) = mpsc::channel(1);
            tx.try_send(UdpIngress {
                session_id: 1,
                session_cancel_rx: session_cancel_rx.clone(),
                id: doradus_types::InboundUdpFlowId {
                    peer: source,
                    target: target.clone(),
                    authentication: None,
                },
                peer: Endpoint::ip(Network::Udp, source),
                target: target.clone(),
                payload: b"pending-send".to_vec(),
                reply_tx,
                event_tx: session_event_tx.clone(),
            })
            .unwrap();
            rx
        },
        cancel_rx,
        session_cancel_rx,
        event_tx,
        datagram: Some(Arc::new(PendingDatagram {
            send_started: Arc::clone(&send_started),
            close_started: Arc::clone(&close_started),
        })),
        flow: Some(flow),
        reply_id: None,
        reply_peer: None,
        reply_tx: None,
        session_event_tx: None,
        observation: None,
        last_seen: Instant::now(),
    };
    let task = tokio::spawn(worker.run());

    tokio::time::timeout(Duration::from_secs(1), send_started.notified())
        .await
        .expect("worker must enter the pending datagram send");
    session_cancel_tx.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(1), close_started.notified())
        .await
        .expect("worker must begin datagram cleanup after session cancellation");

    tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .expect("pending close must be bounded during worker shutdown")
        .expect("worker task panicked");
    assert!(matches!(
        session_event_rx.try_recv(),
        Ok(InboundUdpSessionEvent::FlowClosed(_))
    ));
}
#[tokio::test]
async fn manager_exits_when_both_external_inputs_close() {
    let (ingress_tx, ingress_rx) = mpsc::channel(1);
    let (command_tx, command_rx) = mpsc::channel(1);
    let (_shutdown_tx, shutdown_rx) = oneshot::channel();
    let manager = tokio::spawn(run_udp_manager(
        Weak::new(),
        ingress_rx,
        command_rx,
        1,
        shutdown_rx,
    ));
    drop(ingress_tx);
    drop(command_tx);
    tokio::time::timeout(Duration::from_secs(1), manager)
        .await
        .expect("internal lifecycle sender must not keep the manager alive")
        .unwrap();
}

#[tokio::test]
async fn cancelled_worker_still_reports_closed_to_a_live_manager() {
    let key = source_key(1, "127.0.0.1:41000");
    let (event_tx, mut event_rx) = mpsc::channel(1);
    event_tx
        .try_send(UdpFlowEvent::Opened {
            key: key.clone(),
            generation: 1,
            flow: flow("127.0.0.1:41000", "192.0.2.1:9"),
        })
        .ok()
        .unwrap();
    let (_session_cancel_tx, session_cancel_rx) = watch::channel(false);
    let (reply_tx, _reply_rx) = mpsc::channel(1);
    let (session_event_tx, _session_event_rx) = mpsc::channel(1);
    let target = Endpoint::ip(Network::Udp, "192.0.2.1:9".parse().unwrap());
    let handle = spawn_udp_flow(
        Weak::new(),
        key.clone(),
        1,
        1,
        UdpIngress {
            session_id: 1,
            session_cancel_rx,
            id: UdpFlowId {
                peer: key.source,
                target: target.clone(),
                authentication: None,
            },
            peer: Endpoint::ip(Network::Udp, key.source),
            target,
            payload: vec![1],
            reply_tx,
            event_tx: session_event_tx,
        },
        event_tx,
    );
    handle.cancel_tx.send(true).unwrap();
    tokio::task::yield_now().await;
    assert!(
        !handle.join.is_finished(),
        "normal cancellation lost the Closed notification"
    );
    assert!(matches!(
        event_rx.recv().await,
        Some(UdpFlowEvent::Opened { .. })
    ));
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(1), event_rx.recv())
            .await
            .unwrap(),
        Some(UdpFlowEvent::Closed { generation: 1, .. })
    ));
    handle.join.await.unwrap();
}
