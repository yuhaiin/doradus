//! Convert smoltcp socket state into owned TUN events.

use super::*;
use smoltcp::socket::{tcp, udp};
use smoltcp::wire::IpAddress;

impl TunDispatcher {
    pub(super) fn collect_events(&mut self) -> Result<()> {
        self.tcp_handles.clear();
        self.tcp_handles.extend(self.tcp.keys().copied());
        self.closed_tcp.clear();
        for index in 0..self.tcp_handles.len() {
            let handle = self.tcp_handles[index];
            let Some(state) = self.tcp.get_mut(&handle) else {
                continue;
            };
            let socket = self.sockets.get_mut::<tcp::Socket>(handle);
            let key = state.key.or_else(|| {
                let local = socket.local_endpoint()?;
                let remote = socket.remote_endpoint()?;
                Some(TunFlowKey {
                    network: Network::Tcp,
                    source: remote.into(),
                    destination: local.into(),
                })
            });
            state.key = key;
            let Some(key) = key else {
                continue;
            };
            self.tcp_by_key.insert(key, handle);
            let flow = TunFlow { key };
            if socket.is_active() && socket.may_send() && !state.opened {
                state.opened = true;
                self.events.push_back(TunEvent::TcpOpened { flow });
            }
            let mut event_bytes = 0usize;
            while socket.can_recv() && event_bytes < MAX_TCP_EVENT_BYTES_PER_POLL {
                let payload_capacity = socket
                    .recv_capacity()
                    .min(MAX_TCP_EVENT_PAYLOAD_BYTES)
                    .min(MAX_TCP_EVENT_BYTES_PER_POLL - event_bytes);
                let mut payload = vec![0; payload_capacity];
                match socket.recv_slice(&mut payload) {
                    Ok(length) if length != 0 => {
                        payload.truncate(length);
                        event_bytes = event_bytes.saturating_add(length);
                        self.events.push_back(TunEvent::TcpData { flow, payload });
                    }
                    Ok(_) => break,
                    Err(tcp::RecvError::Finished) => {
                        if !state.half_closed {
                            state.half_closed = true;
                            self.events.push_back(TunEvent::TcpHalfClosed { flow });
                        }
                        break;
                    }
                    Err(_) => break,
                }
            }
            if state.opened && socket.is_active() && !socket.may_recv() && !state.half_closed {
                state.half_closed = true;
                self.events.push_back(TunEvent::TcpHalfClosed { flow });
            }
            if !socket.is_open() && state.opened {
                self.events.push_back(TunEvent::TcpClosed { flow });
            }
            if !socket.is_open() {
                self.closed_tcp.push((handle, key));
            }
        }
        for (handle, key) in self.closed_tcp.drain(..) {
            self.tcp.remove(&handle);
            self.tcp_by_key.remove(&key);
            self.sockets.remove(handle);
        }

        self.udp_handles.clear();
        self.udp_handles.extend(self.udp.keys().copied());
        self.closed_udp.clear();
        for index in 0..self.udp_handles.len() {
            let handle = self.udp_handles[index];
            let Some(state) = self.udp.get(&handle) else {
                continue;
            };
            let local = state.local;
            let closing = state.closing;
            let socket = self.sockets.get_mut::<udp::Socket>(handle);
            while socket.can_recv() {
                let (payload, metadata) = socket.recv().map_err(|error| {
                    Error::new(ErrorKind::Protocol, format!("TUN UDP read: {error:?}"))
                })?;
                // A multicast-bound socket can receive both IP families in
                // smoltcp. Reject the invalid cross-family response before
                // constructing a flow or asking smoltcp to emit a packet.
                if metadata.local_address.is_some_and(|address| {
                    matches!(address, IpAddress::Ipv4(_)) != local.ip().is_ipv4()
                }) {
                    tun_debug(format!(
                        "TUN UDP packet dropped for IP family mismatch socket={} packet_destination={:?}",
                        local, metadata.local_address
                    ));
                    continue;
                }
                let flow = TunFlow {
                    key: TunFlowKey {
                        network: Network::Udp,
                        source: metadata.endpoint.into(),
                        destination: local,
                    },
                };
                tun_debug(format!(
                    "TUN UDP datagram flow={:?} bytes={}",
                    flow.key,
                    payload.len()
                ));
                self.events.push_back(TunEvent::UdpDatagram {
                    flow,
                    payload: payload.to_vec(),
                });
            }
            if closing {
                self.closed_udp.push((handle, local));
            }
        }
        for (handle, local) in self.closed_udp.drain(..) {
            self.udp_by_local.remove(&local);
            self.udp.remove(&handle);
            self.sockets.remove(handle);
        }
        Ok(())
    }
}
