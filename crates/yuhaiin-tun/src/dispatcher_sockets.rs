//! Socket lifecycle and proxy-facing writes for [`TunDispatcher`].

use super::*;
use smoltcp::socket::{tcp, udp};
use smoltcp::wire::{IpEndpoint, IpListenEndpoint};

impl TunDispatcher {
    /// Queue as much TCP payload as the smoltcp TX buffer accepts.
    ///
    /// `send_slice` is intentionally allowed to return a short write when the
    /// bounded socket buffer is nearly full. Callers must retain and retry
    /// `payload[written..]`.
    pub fn write_tcp(&mut self, flow: TunFlowKey, payload: &[u8]) -> Result<usize> {
        let handle = self
            .tcp_by_key
            .get(&flow)
            .copied()
            .ok_or_else(|| Error::new(ErrorKind::NotFound, "TUN TCP flow is not registered"))?;
        self.sockets
            .get_mut::<tcp::Socket>(handle)
            .send_slice(payload)
            .map_err(|error| Error::new(ErrorKind::Closed, format!("TUN TCP write: {error:?}")))
    }

    pub fn close_tcp(&mut self, flow: TunFlowKey) -> Result<()> {
        let handle = self
            .tcp_by_key
            .get(&flow)
            .copied()
            .ok_or_else(|| Error::new(ErrorKind::NotFound, "TUN TCP flow is not registered"))?;
        self.sockets.get_mut::<tcp::Socket>(handle).close();
        Ok(())
    }

    pub fn abort_tcp(&mut self, flow: TunFlowKey) -> Result<()> {
        let handle = self
            .tcp_by_key
            .get(&flow)
            .copied()
            .ok_or_else(|| Error::new(ErrorKind::NotFound, "TUN TCP flow is not registered"))?;
        self.sockets.get_mut::<tcp::Socket>(handle).abort();
        Ok(())
    }

    pub fn write_udp(&mut self, flow: TunFlowKey, payload: &[u8]) -> Result<()> {
        if flow.source.is_ipv4() != flow.destination.is_ipv4() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "TUN UDP flow has mixed IP versions: source={} destination={}",
                    flow.source, flow.destination
                ),
            ));
        }
        let handle = self
            .udp_by_local
            .get(&flow.destination)
            .copied()
            .ok_or_else(|| Error::new(ErrorKind::NotFound, "TUN UDP socket is not registered"))?;
        self.sockets
            .get_mut::<udp::Socket>(handle)
            .send_slice(payload, IpEndpoint::from(flow.source))
            .map_err(|error| Error::new(ErrorKind::Closed, format!("TUN UDP write: {error:?}")))
    }

    /// Queue a raw ICMP packet for the next TUN poll.
    pub fn write_icmp(&mut self, packet: Vec<u8>) -> Result<()> {
        inspect_ip_packet(&packet)?;
        if self.pending_icmp_to_tun.len() >= self.udp_packet_capacity {
            return Err(Error::new(
                ErrorKind::Timeout,
                "TUN ICMP output queue is full",
            ));
        }
        self.pending_icmp_to_tun.push_back(packet);
        Ok(())
    }

    pub fn close_udp(&mut self, flow: TunFlowKey) -> Result<()> {
        let Some(handle) = self.udp_by_local.get(&flow.destination).copied() else {
            return Ok(());
        };
        if let Some(state) = self.udp.get_mut(&handle) {
            // Keep the socket until the next smoltcp poll so already queued
            // UDP output is not silently discarded.
            state.closing = true;
        }
        Ok(())
    }

    pub(super) fn ensure_tcp_listener(&mut self, tuple: TransportTuple) -> Result<()> {
        let key = TunFlowKey {
            network: Network::Tcp,
            source: tuple.source,
            destination: tuple.destination,
        };
        if self.tcp_by_key.contains_key(&key)
            || self.tcp.values().any(|state| state.key == Some(key))
        {
            return Ok(());
        }
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; self.rx_buffer_size]),
            tcp::SocketBuffer::new(vec![0; self.tx_buffer_size]),
        );
        socket.set_congestion_control(tcp::CongestionControl::Cubic);
        socket
            .listen(IpListenEndpoint {
                addr: None,
                port: tuple.destination.port(),
            })
            .map_err(|error| {
                Error::new(ErrorKind::Unsupported, format!("TUN TCP listen: {error:?}"))
            })?;
        let handle = self.sockets.add(socket);
        self.tcp.insert(
            handle,
            TcpFlowState {
                key: Some(key),
                opened: false,
                half_closed: false,
            },
        );
        Ok(())
    }

    pub(crate) fn ensure_udp_socket(&mut self, local: SocketAddr) -> Result<()> {
        if self.udp_by_local.contains_key(&local) {
            return Ok(());
        }
        tun_debug(format!("TUN UDP socket prepare local={local}"));
        let mut socket = udp::Socket::new(
            udp::PacketBuffer::new(
                vec![udp::PacketMetadata::EMPTY; self.udp_packet_capacity],
                vec![0; self.rx_buffer_size],
            ),
            udp::PacketBuffer::new(
                vec![udp::PacketMetadata::EMPTY; self.udp_packet_capacity],
                vec![0; self.tx_buffer_size],
            ),
        );
        socket
            .bind(IpListenEndpoint::from(local))
            .map_err(|error| {
                Error::new(ErrorKind::Unsupported, format!("TUN UDP bind: {error:?}"))
            })?;
        let handle = self.sockets.add(socket);
        self.udp.insert(
            handle,
            UdpSocketState {
                local,
                closing: false,
            },
        );
        self.udp_by_local.insert(local, handle);
        Ok(())
    }
}
