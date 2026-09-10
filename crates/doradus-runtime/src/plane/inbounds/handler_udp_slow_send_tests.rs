use super::*;

use std::future::pending;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use doradus_core::flow::FlowKey as TunFlowKey;
use doradus_core::{BoxFuture, Endpoint, Network, Result};
use doradus_store::{ConfigStore, GoNodeRecord};
use tokio::sync::Notify;

use crate::inbound::{InboundHandler, InboundSpec, UdpMode};
use crate::{RuntimeBuilder, RuntimeController};

struct SlowCodec {
    send_started: Arc<Notify>,
    send_dropped: Arc<AtomicBool>,
}

impl InboundUdpCodec for SlowCodec {
    type Request = InboundUdpRequest;
    type Response = InboundUdpResponse;

    fn recv<'a>(&'a mut self) -> BoxFuture<'a, Result<Option<InboundUdpRequest>>> {
        Box::pin(pending())
    }

    fn send<'a>(&'a mut self, _response: InboundUdpResponse) -> BoxFuture<'a, Result<()>> {
        let started = Arc::clone(&self.send_started);
        let dropped = Arc::clone(&self.send_dropped);
        Box::pin(async move {
            struct DropSignal(Arc<AtomicBool>);

            impl Drop for DropSignal {
                fn drop(&mut self) {
                    self.0.store(true, Ordering::Release);
                }
            }

            let _signal = DropSignal(dropped);
            started.notify_one();
            pending::<Result<()>>().await
        })
    }
}

impl InboundUdpFlowPolicy for SlowCodec {
    fn close_on_flow_end(&self) -> bool {
        true
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
    InboundHandler::new(
        InboundSpec {
            id: "udp-slow-send-test".to_owned(),
            name: "udp-slow-send-test".to_owned(),
            protocol: "vless".to_owned(),
            listen: "127.0.0.1:19091".parse().unwrap(),
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
        controller.monitor(),
    )
}

async fn check_slow_send_cancellation(management_close: bool) {
    let inbound = direct_inbound().await;
    let channels = inbound.udp().open_session(2);
    let send_started = Arc::new(Notify::new());
    let send_dropped = Arc::new(AtomicBool::new(false));
    let session = InboundUdpSession {
        codec: SlowCodec {
            send_started: Arc::clone(&send_started),
            send_dropped: Arc::clone(&send_dropped),
        },
        inbound: Arc::clone(&inbound),
        manager: Arc::clone(inbound.udp()),
        session_id: channels.session_id,
        reply_rx: channels.reply_rx,
        event_rx: channels.event_rx,
        reply_tx: channels.reply_tx.clone(),
        event_tx: channels.event_tx.clone(),
        session_cancel_tx: channels.session_cancel_tx,
    };
    let reply_tx = channels.reply_tx;
    let event_tx = channels.event_tx;
    let flow = TunFlowKey {
        network: Network::Udp,
        source: "127.0.0.1:41999".parse().unwrap(),
        destination: "192.0.2.1:53".parse().unwrap(),
    };
    let target = Endpoint::ip(Network::Udp, "192.0.2.1:53".parse().unwrap());
    let response = InboundUdpResponse {
        id: doradus_types::InboundUdpFlowId {
            peer: "127.0.0.1:41000".parse().unwrap(),
            target: target.clone(),
            authentication: None,
        },
        peer: Endpoint::ip(Network::Udp, "127.0.0.1:41000".parse().unwrap()),
        target,
        payload: b"slow-response".to_vec(),
    };

    let task = tokio::spawn(session.run());
    reply_tx.send(response).await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), send_started.notified())
        .await
        .expect("session must enter the slow codec send");

    // The reply is deliberately queued before FlowOpened. The session must
    // still observe the lifecycle events while the codec send is pending.
    event_tx
        .send(InboundUdpSessionEvent::FlowOpened(flow))
        .await
        .unwrap();
    if management_close {
        let observed = doradus_core::flow::Flow { key: flow };
        inbound.monitor().opened(observed, observed.context());
        assert_eq!(inbound.monitor().request_close(&["1".to_owned()]), 1);
    } else {
        event_tx
            .send(InboundUdpSessionEvent::FlowClosed(flow))
            .await
            .unwrap();
    }

    tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .expect("FlowClosed must interrupt a pending codec send")
        .expect("session task must not panic")
        .expect("session close should be successful");
    assert!(send_dropped.load(Ordering::Acquire));
}

#[tokio::test]
async fn flow_closed_interrupts_a_slow_codec_send_after_open_event_arrives() {
    check_slow_send_cancellation(false).await;
}

#[tokio::test]
async fn management_close_interrupts_a_slow_codec_send_before_open_event_is_consumed() {
    check_slow_send_cancellation(true).await;
}
