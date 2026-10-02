use super::*;
use crate::proxy::{DropAsyncProxy, StaticProxySelector};
use std::sync::{Mutex, mpsc as blocking_channel};

struct BlockedResolver {
    started: Arc<tokio::sync::Notify>,
    release: Mutex<blocking_channel::Receiver<()>>,
}

impl ProcessResolver for BlockedResolver {
    fn resolve(&self, _: Network, _: SocketAddr, _: SocketAddr) -> io::Result<Option<ProcessInfo>> {
        self.started.notify_one();
        self.release
            .lock()
            .unwrap()
            .recv_timeout(Duration::from_secs(3))
            .unwrap();
        Ok(Some(ProcessInfo {
            path: "/bin/client".into(),
            pid: 42,
            uid: 1000,
        }))
    }
}

#[derive(Default)]
struct OpenedContexts(Mutex<Vec<FlowContext>>);

impl TunFlowObserver for OpenedContexts {
    fn opened(&self, _: TunFlow, context: FlowContext) {
        self.0.lock().unwrap().push(context);
    }
    fn bytes(&self, _: TunFlowKey, _: TunFlowDirection, _: usize) {}
    fn closed(&self, _: TunFlowKey) {}
}

fn runtime() -> TunProxyRuntime {
    let proxy: Arc<dyn AsyncProxy> = Arc::new(DropAsyncProxy);
    TunProxyRuntime::new(
        Arc::new(StaticProxySelector {
            direct: proxy.clone(),
            proxy: proxy.clone(),
            bypass: proxy.clone(),
            drop: proxy,
        }),
        4,
    )
    .unwrap()
}

fn flow(port: u16) -> TunFlow {
    TunFlow {
        key: TunFlowKey {
            network: Network::Tcp,
            source: SocketAddr::from(([192, 0, 2, 1], port)),
            destination: "198.51.100.1:443".parse().unwrap(),
        },
    }
}

#[tokio::test(flavor = "current_thread")]
async fn blocked_process_lookup_keeps_existing_flows_and_executor_running() {
    let mut runtime = runtime();
    let observer = Arc::new(OpenedContexts::default());
    runtime.observer = Some(observer.clone());
    let started = Arc::new(tokio::sync::Notify::new());
    let (release, receiver) = blocking_channel::channel();
    runtime.set_process_resolver(Some(Arc::new(BlockedResolver {
        started: started.clone(),
        release: Mutex::new(receiver),
    })));
    let new_flow = flow(40_000);
    runtime
        .handle_proxy_input(ProxyInput::TcpOpened { flow: new_flow })
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), started.notified())
        .await
        .unwrap();
    assert!(observer.0.lock().unwrap().is_empty());

    let existing = flow(40_001);
    runtime.track_flow(existing.key).unwrap();
    let (command, mut commands) = mpsc::channel(4);
    runtime.tasks.insert_fixture(
        existing.key,
        ProxyTask {
            command,
            join: tokio::spawn(std::future::pending()),
        },
    );
    runtime
        .handle_proxy_input(ProxyInput::TcpData {
            flow: existing,
            payload: vec![7],
        })
        .unwrap();
    assert!(matches!(commands.try_recv(), Ok(ProxyCommand::Data(payload)) if payload == [7]));
    // The current-thread executor reaches this point while resolve() is
    // blocked, and routing/open observation still waits for its metadata.
    release.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(1), runtime.wait_for_output())
        .await
        .unwrap();
    runtime
        .process_proxy_outputs(&mut TunDispatcher::new(2048, 2048, 4).unwrap())
        .unwrap();
    let contexts = observer.0.lock().unwrap();
    assert_eq!(contexts.len(), 1);
    assert_eq!(contexts[0].process.as_deref(), Some("/bin/client"));
    assert_eq!(contexts[0].process_id, Some(42));
}

#[tokio::test]
async fn closed_flow_rejects_an_old_lookup_completion_after_source_reuse() {
    let mut runtime = runtime();
    let started = Arc::new(tokio::sync::Notify::new());
    let (release, receiver) = blocking_channel::channel();
    runtime.set_process_resolver(Some(Arc::new(BlockedResolver {
        started: started.clone(),
        release: Mutex::new(receiver),
    })));
    let flow = flow(40_000);
    runtime
        .handle_proxy_input(ProxyInput::TcpOpened { flow })
        .unwrap();
    started.notified().await;
    let source = udp_source_key(flow.key);
    let old_id = runtime.process_lookups.pending[&source].id;
    runtime
        .handle_proxy_input(ProxyInput::TcpClosed { flow })
        .unwrap();
    assert_eq!(runtime.task_len(), 0);
    runtime
        .handle_proxy_input(ProxyInput::TcpOpened { flow })
        .unwrap();
    let new_id = runtime.process_lookups.pending[&source].id;
    assert_ne!(old_id, new_id);
    runtime
        .complete_process_lookup(
            source,
            old_id,
            Some(ProcessInfo {
                path: "stale".into(),
                pid: 1,
                uid: 1,
            }),
            &mut TunDispatcher::new(2048, 2048, 4).unwrap(),
        )
        .unwrap();
    assert!(runtime.flow_tracker.cached_process(&source).is_none());
    assert_eq!(runtime.process_lookups.pending[&source].id, new_id);
    runtime.close();
    release.send(()).unwrap();
}

#[tokio::test]
async fn deferred_udp_replay_error_releases_every_dispatcher_destination() {
    let mut runtime = runtime();
    let table = NatTable::new();
    runtime
        .flow_tracker
        .with_nat(table.clone(), Duration::from_secs(30));
    let first = TunFlow {
        key: TunFlowKey {
            network: Network::Udp,
            ..flow(40_000).key
        },
    };
    let second = TunFlow {
        key: TunFlowKey {
            destination: "198.51.100.2:443".parse().unwrap(),
            ..first.key
        },
    };
    let source = udp_source_key(first.key);
    let mut dispatcher = TunDispatcher::new(2048, 2048, 4).unwrap();
    for flow in [first, second] {
        runtime.track_flow(flow.key).unwrap();
        dispatcher.ensure_udp_socket(flow.key.destination).unwrap();
        runtime
            .udp_tasks
            .flow_sources_mut()
            .insert(flow.key, source);
    }
    let (command, _commands) = mpsc::channel(1);
    command.try_send(UdpProxyCommand::Shutdown).unwrap();
    runtime.udp_tasks.insert_fixture(
        source,
        UdpProxyTask {
            command,
            join: tokio::spawn(std::future::pending()),
            flows: HashSet::from([first.key, second.key]),
        },
    );
    runtime.process_lookups.pending.insert(
        source,
        PendingLookup {
            id: 1,
            task: tokio::spawn(async {}),
            events: VecDeque::from([
                ProxyInput::UdpDatagram {
                    flow: first,
                    payload: vec![1],
                },
                ProxyInput::UdpDatagram {
                    flow: second,
                    payload: vec![2],
                },
            ]),
        },
    );
    runtime
        .complete_process_lookup(source, 1, None, &mut dispatcher)
        .unwrap();
    assert_eq!(runtime.task_len(), 0);
    assert!(table.is_empty().unwrap());
    // Dispatcher closes UDP sockets after its next poll so queued output
    // can drain before the socket is removed.
    let mut device = SmoltcpTunDevice::new(1500, 8).unwrap();
    let mut interface = smoltcp::iface::Interface::new(
        smoltcp::iface::Config::new(smoltcp::wire::HardwareAddress::Ip),
        &mut device,
        smoltcp::time::Instant::from_millis(0),
    );
    dispatcher
        .poll_with(
            &mut interface,
            &mut device,
            smoltcp::time::Instant::from_millis(1),
        )
        .unwrap();
    for flow in [first, second] {
        assert_eq!(
            dispatcher.write_udp(flow.key, b"reply").unwrap_err().kind,
            ErrorKind::NotFound
        );
    }
}
