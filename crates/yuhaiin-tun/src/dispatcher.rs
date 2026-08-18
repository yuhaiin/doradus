//! Smoltcp socket dispatch and packet classification.

use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpPacketVersion {
    V4,
    V6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketInfo {
    pub version: IpPacketVersion,
    pub length: usize,
    /// Whether this packet is one fragment of an IPv4/IPv6 datagram.
    ///
    /// This is a classification flag only. IPv4 reassembly is delegated to
    /// smoltcp; IPv6 fragments are reassembled at the TUN receive boundary
    /// before they reach smoltcp.
    pub fragmented: bool,
}

/// Events emitted after `TunDispatcher::poll` has allowed smoltcp to consume
/// packets and advance socket state.
///
/// Events own their payloads.  A runtime can therefore hand them to an async
/// proxy task without borrowing the smoltcp socket set or holding a mutex
/// across I/O.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunEvent {
    TcpOpened {
        flow: TunFlow,
    },
    TcpData {
        flow: TunFlow,
        payload: Vec<u8>,
    },
    TcpHalfClosed {
        flow: TunFlow,
    },
    TcpClosed {
        flow: TunFlow,
    },
    UdpDatagram {
        flow: TunFlow,
        payload: Vec<u8>,
    },
    /// An external ICMP echo request that must be measured by the selected
    /// proxy before the reply is written back to the TUN device. Local and
    /// same-subnet echo requests remain handled by smoltcp's automatic reply.
    IcmpEchoRequest {
        flow: TunFlow,
        packet: Vec<u8>,
    },
}

pub(crate) fn event_flow_key(event: &TunEvent) -> TunFlowKey {
    match event {
        TunEvent::TcpOpened { flow }
        | TunEvent::TcpData { flow, .. }
        | TunEvent::TcpHalfClosed { flow }
        | TunEvent::TcpClosed { flow }
        | TunEvent::UdpDatagram { flow, .. }
        | TunEvent::IcmpEchoRequest { flow, .. } => flow.key,
    }
}

pub(crate) fn is_recoverable_proxy_flow_error(error: &Error) -> bool {
    // A bounded per-flow command queue being full is backpressure on one
    // flow. The event loop cleans up that flow and continues serving all
    // other TUN flows; it must not tear down the owner task.
    matches!(
        error.kind,
        ErrorKind::Closed | ErrorKind::NotFound | ErrorKind::Timeout
    )
}

#[derive(Debug)]
pub(crate) struct TcpFlowState {
    key: Option<TunFlowKey>,
    opened: bool,
    half_closed: bool,
}

#[derive(Debug)]
pub(crate) struct UdpSocketState {
    local: SocketAddr,
    closing: bool,
}

/// The smoltcp-to-runtime adapter for the first TUN implementation.
///
/// `TunDispatcher` owns socket state and emits owned events.  It does not
/// perform routing or proxy I/O itself.  The caller can consume events,
/// construct a `FlowContext`, and later call `write_tcp`/`write_udp` with data
/// returned by its selected proxy.  This separation keeps the packet engine
/// deterministic and makes it possible to run proxy work on an async runtime
/// without blocking `Interface::poll`.
pub struct TunDispatcher {
    sockets: SocketSet<'static>,
    tcp: HashMap<SocketHandle, TcpFlowState>,
    tcp_by_key: HashMap<TunFlowKey, SocketHandle>,
    udp: HashMap<SocketHandle, UdpSocketState>,
    udp_by_local: HashMap<SocketAddr, SocketHandle>,
    events: VecDeque<TunEvent>,
    pending_icmp_tx: VecDeque<Vec<u8>>,
    tcp_handles: Vec<SocketHandle>,
    closed_tcp: Vec<(SocketHandle, TunFlowKey)>,
    udp_handles: Vec<SocketHandle>,
    closed_udp: Vec<(SocketHandle, SocketAddr)>,
    rx_buffer_size: usize,
    tx_buffer_size: usize,
    udp_packet_capacity: usize,
    skip_multicast: bool,
}

impl TunDispatcher {
    pub fn new(
        rx_buffer_size: usize,
        tx_buffer_size: usize,
        udp_packet_capacity: usize,
    ) -> Result<Self> {
        if rx_buffer_size == 0 || tx_buffer_size == 0 || udp_packet_capacity == 0 {
            return Err(Error::invalid("TUN dispatcher buffers must be non-zero"));
        }
        Ok(Self {
            sockets: SocketSet::new(Vec::new()),
            tcp: HashMap::new(),
            tcp_by_key: HashMap::new(),
            udp: HashMap::new(),
            udp_by_local: HashMap::new(),
            events: VecDeque::new(),
            pending_icmp_tx: VecDeque::new(),
            tcp_handles: Vec::new(),
            closed_tcp: Vec::new(),
            udp_handles: Vec::new(),
            closed_udp: Vec::new(),
            rx_buffer_size,
            tx_buffer_size,
            udp_packet_capacity,
            skip_multicast: false,
        })
    }

    /// Configure whether IP multicast packets should be discarded before
    /// smoltcp sees them.  The setting is intentionally applied at the
    /// dispatcher boundary so it also covers packets already buffered by an
    /// injected/mobile TUN device.
    pub fn with_skip_multicast(mut self, skip_multicast: bool) -> Self {
        self.skip_multicast = skip_multicast;
        self
    }

    pub fn set_skip_multicast(&mut self, skip_multicast: bool) {
        self.skip_multicast = skip_multicast;
    }

    pub fn events(&mut self) -> impl Iterator<Item = TunEvent> + '_ {
        self.events.drain(..)
    }

    /// Remove one queued event without allocating a temporary collection.
    ///
    /// The async runtime needs to consume an event before it can call back
    /// into the dispatcher to close a failed flow, so draining the queue into
    /// a `Vec` would add one allocation per dispatcher tick.
    pub fn next_event(&mut self) -> Option<TunEvent> {
        self.events.pop_front()
    }

    pub fn poll(
        &mut self,
        runtime: &mut TunRuntime,
        timestamp: Instant,
    ) -> Result<smoltcp::iface::PollResult> {
        self.poll_with(
            &mut runtime.interface,
            &mut runtime.smoltcp_device,
            timestamp,
        )
    }

    /// Return smoltcp's next timer deadline without polling the device.
    ///
    /// The async runtime uses this as a precise timer fallback for TCP
    /// retransmits and delayed ACKs. Data-plane events wake it immediately,
    /// so callers do not need a fixed-rate polling interval.
    pub(crate) fn poll_delay(
        &mut self,
        interface: &mut Interface,
        timestamp: Instant,
    ) -> Option<smoltcp::time::Duration> {
        interface.poll_delay(timestamp, &self.sockets)
    }

    pub fn poll_with(
        &mut self,
        interface: &mut Interface,
        device: &mut SmoltcpTunDevice,
        timestamp: Instant,
    ) -> Result<smoltcp::iface::PollResult> {
        self.flush_pending_icmp_tx(device)?;
        self.drop_skipped_multicast(device)?;
        self.prepare_rx_inner(Some(interface), device)?;
        let result = interface.poll(timestamp, device, &mut self.sockets);
        self.collect_events()?;
        Ok(result)
    }

    pub(crate) fn flush_pending_icmp_tx(&mut self, device: &SmoltcpTunDevice) -> Result<()> {
        while let Some(packet) = self.pending_icmp_tx.front().cloned() {
            if !device.enqueue_tx(packet)? {
                // Leave the packet pending. The outer TUN loop drains the
                // device TX queue independently, so a momentarily full queue
                // is backpressure rather than an inbound-fatal error.
                break;
            }
            self.pending_icmp_tx.pop_front();
        }
        Ok(())
    }

    fn drop_skipped_multicast(&self, device: &SmoltcpTunDevice) -> Result<()> {
        if !self.skip_multicast {
            return Ok(());
        }
        let dropped = device.drop_multicast_rx_packets()?;
        if dropped != 0 {
            tun_debug(format!("TUN multicast packets skipped count={dropped}"));
        }
        Ok(())
    }

    /// Create a socket for the packet at the head of the TUN RX queue before
    /// smoltcp consumes it.  TCP requires this for the first SYN; UDP sockets
    /// are keyed by their local destination endpoint and can receive multiple
    /// application source tuples.
    pub fn prepare_rx(&mut self, device: &SmoltcpTunDevice) -> Result<()> {
        self.prepare_rx_inner(None, device)
    }

    fn prepare_rx_inner(
        &mut self,
        interface: Option<&Interface>,
        device: &SmoltcpTunDevice,
    ) -> Result<()> {
        let Some(packet) = device.peek_rx_packet()? else {
            return Ok(());
        };
        tun_debug(format!("TUN prepare RX packet length={}", packet.len()));
        // smoltcp performs IPv4 reassembly after this hook. A non-initial
        // fragment has no transport header at its payload offset, so trying
        // to parse it here would turn a valid datagram into a malformed-packet
        // error. IPv6 fragments have already been reassembled at the TUN
        // receive boundary; this guard remains for directly injected device
        // packets and prevents extension fragments from reaching this hook.
        if is_non_initial_fragment(&packet)? {
            return Ok(());
        }
        if let Some(interface) = interface
            && let Ok(Some((source, destination))) = parse_icmp_echo_request(&packet)
            && should_proxy_icmp_request(interface, source, destination)
        {
            let packet = device.take_rx_packet()?.ok_or_else(|| {
                Error::new(
                    ErrorKind::Io,
                    "TUN ICMP request disappeared before dispatch",
                )
            })?;
            let flow = TunFlow {
                key: TunFlowKey {
                    network: Network::Icmp,
                    source,
                    destination,
                },
            };
            tun_debug(format!("TUN external ICMP echo request flow={flow:?}"));
            self.events
                .push_back(TunEvent::IcmpEchoRequest { flow, packet });
            return Ok(());
        }
        let Some(tuple) = parse_dispatch_transport_tuple(&packet)? else {
            tun_debug("TUN prepare RX packet has no transport tuple");
            return Ok(());
        };
        tun_debug(format!("TUN prepare RX tuple={tuple:?}"));
        match tuple.protocol {
            IpProtocol::Tcp if tuple.tcp_syn => self.ensure_tcp_listener(tuple),
            IpProtocol::Udp => self.ensure_udp_socket(tuple.destination),
            _ => Ok(()),
        }
    }

    /// Queue as much TCP payload as the smoltcp TX buffer accepts.
    ///
    /// `send_slice` is intentionally allowed to return a short write when the
    /// bounded socket buffer is nearly full. Callers must retain and retry
    /// `payload[written..]`; treating `Ok(written)` as an all-or-nothing
    /// result silently drops bytes under sustained TUN output.
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
    ///
    /// ICMP echo replies do not belong to a smoltcp socket. They are produced
    /// by the proxy-level ping path and therefore bypass the socket set while
    /// still crossing the same bounded TX queue as ordinary TUN output.
    pub fn write_icmp(&mut self, packet: Vec<u8>) -> Result<()> {
        inspect_ip_packet(&packet)?;
        if self.pending_icmp_tx.len() >= self.udp_packet_capacity {
            return Err(Error::new(
                ErrorKind::Timeout,
                "TUN ICMP output queue is full",
            ));
        }
        self.pending_icmp_tx.push_back(packet);
        Ok(())
    }

    pub fn close_udp(&mut self, flow: TunFlowKey) -> Result<()> {
        let Some(handle) = self.udp_by_local.get(&flow.destination).copied() else {
            return Ok(());
        };
        if let Some(state) = self.udp.get_mut(&handle) {
            // Keep the socket until the next smoltcp poll. A preceding
            // UdpData output may already be queued in its TX packet buffer;
            // removing it here would silently drop that packet.
            state.closing = true;
        }
        Ok(())
    }

    fn ensure_tcp_listener(&mut self, tuple: TransportTuple) -> Result<()> {
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
                // A TUN gateway must accept destinations that are not local
                // interface addresses. smoltcp keeps the packet's actual
                // local endpoint on the established socket, so a wildcard
                // listener preserves the original destination in the flow
                // key while allowing ordinary Internet routes.
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

    fn collect_events(&mut self) -> Result<()> {
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
                // `recv_capacity` is the remaining socket buffer, not the
                // size of the next packet. Keep each event bounded so a fast
                // TUN stream cannot retain one large Vec for a short read.
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
                // smoltcp intentionally lets a socket bound to a multicast
                // address accept multicast packets without comparing the
                // exact destination.  With both IP families enabled that can
                // deliver an IPv6 multicast datagram to an IPv4 socket (or
                // vice versa).  Never expose that as a mixed-family flow;
                // doing so would make smoltcp panic while constructing the
                // response IP header.
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

pub(crate) fn is_non_initial_fragment(packet: &[u8]) -> Result<bool> {
    let version = IpVersion::of_packet(packet)
        .map_err(|_| Error::invalid("TUN packet is not IPv4 or IPv6"))?;
    match version {
        IpVersion::Ipv4 => {
            let packet = smoltcp::wire::Ipv4Packet::new_checked(packet)
                .map_err(|_| Error::invalid("malformed IPv4 packet"))?;
            Ok(packet.frag_offset() != 0)
        }
        IpVersion::Ipv6 => Ok(ipv6_has_fragment_header(packet)),
    }
}

pub(crate) fn ip_packet_has_multicast_destination(packet: &[u8]) -> Result<bool> {
    match IpVersion::of_packet(packet)
        .map_err(|_| Error::invalid("TUN packet is not IPv4 or IPv6"))?
    {
        IpVersion::Ipv4 => {
            let packet = smoltcp::wire::Ipv4Packet::new_checked(packet)
                .map_err(|_| Error::invalid("malformed IPv4 packet"))?;
            Ok(packet.dst_addr().is_multicast())
        }
        IpVersion::Ipv6 => {
            let packet = smoltcp::wire::Ipv6Packet::new_checked(packet)
                .map_err(|_| Error::invalid("malformed IPv6 packet"))?;
            Ok(packet.dst_addr().is_multicast())
        }
    }
}

/// smoltcp's IP medium parser intentionally keeps the common path small and
/// does not expose transport payloads behind IPv6 extension headers. TUN is an
/// IP gateway, though, so normalize the bounded extension chain before the
/// packet reaches smoltcp. The UDP checksum is independent of extension
/// headers, and the original source/destination addresses remain unchanged.
/// Normalize the bounded IPv6 extension-header chain into the form consumed
/// by smoltcp's IP-medium parser.
pub fn normalize_ipv6_extension_headers(packet: &[u8]) -> Result<Cow<'_, [u8]>> {
    if IpVersion::of_packet(packet).ok() != Some(IpVersion::Ipv6) {
        return Ok(Cow::Borrowed(packet));
    }
    smoltcp::wire::Ipv6Packet::new_checked(packet)
        .map_err(|_| Error::invalid("malformed IPv6 packet"))?;

    let mut next_header = packet[6];
    let mut offset = 40usize;
    let mut headers = 0usize;
    while let Some(header_length) = match next_header {
        // Hop-by-Hop, Routing and Destination Options use 8-octet units.
        0 | 43 | 60 => {
            if offset.checked_add(2).is_none_or(|end| end > packet.len()) {
                return Err(Error::invalid("truncated IPv6 extension header"));
            }
            Some(
                usize::from(packet[offset + 1])
                    .checked_add(1)
                    .and_then(|units| units.checked_mul(8))
                    .ok_or_else(|| Error::invalid("IPv6 extension header length overflow"))?,
            )
        }
        // Authentication Header uses 32-bit units and counts the fixed
        // eight-byte prefix as two units.
        51 => {
            if offset.checked_add(2).is_none_or(|end| end > packet.len()) {
                return Err(Error::invalid("truncated IPv6 authentication header"));
            }
            Some(
                usize::from(packet[offset + 1])
                    .checked_add(2)
                    .and_then(|units| units.checked_mul(4))
                    .ok_or_else(|| Error::invalid("IPv6 authentication header length overflow"))?,
            )
        }
        // Fragment headers must be reassembled at recv_from_tun before this
        // function. Leave a directly injected fragment untouched so the
        // existing non-initial-fragment guard remains authoritative.
        44 => return Ok(Cow::Borrowed(packet)),
        _ => None,
    } {
        if header_length < 8
            || offset
                .checked_add(header_length)
                .is_none_or(|end| end > packet.len())
        {
            return Err(Error::invalid("truncated IPv6 extension header"));
        }
        next_header = packet[offset];
        offset += header_length;
        headers += 1;
        if headers > 16 {
            return Err(Error::invalid("IPv6 extension header chain is too long"));
        }
    }

    if offset == 40 {
        return Ok(Cow::Borrowed(packet));
    }
    let payload_length = packet.len() - offset;
    let payload_length = u16::try_from(payload_length)
        .map_err(|_| Error::invalid("normalized IPv6 packet is too large"))?;
    let mut normalized = Vec::with_capacity(40 + usize::from(payload_length));
    normalized.extend_from_slice(&packet[..40]);
    normalized[4..6].copy_from_slice(&payload_length.to_be_bytes());
    normalized[6] = next_header;
    normalized.extend_from_slice(&packet[offset..]);
    Ok(Cow::Owned(normalized))
}

pub(crate) fn parse_dispatch_transport_tuple(packet: &[u8]) -> Result<Option<TransportTuple>> {
    let version = IpVersion::of_packet(packet)
        .map_err(|_| Error::invalid("TUN packet is not IPv4 or IPv6"))?;
    if version != IpVersion::Ipv4 {
        return parse_transport_tuple(packet);
    }

    let ip = smoltcp::wire::Ipv4Packet::new_checked(packet)
        .map_err(|_| Error::invalid("malformed IPv4 packet"))?;
    if !ip.more_frags() {
        return parse_transport_tuple(packet);
    }

    // The first fragment carries the transport header, but its UDP/TCP
    // length can describe the complete datagram and therefore exceed this
    // fragment's payload. Read only the fixed fields needed to create the
    // smoltcp socket; checksum and full-length validation happen after
    // smoltcp reassembles the datagram.
    if ip.frag_offset() != 0 {
        return Ok(None);
    }
    let payload = ip.payload();
    let source = IpAddr::V4(ip.src_addr());
    let destination = IpAddr::V4(ip.dst_addr());
    match ip.next_header() {
        IpProtocol::Tcp if payload.len() >= 4 => Ok(Some(TransportTuple {
            protocol: IpProtocol::Tcp,
            source: SocketAddr::new(source, u16::from_be_bytes([payload[0], payload[1]])),
            destination: SocketAddr::new(destination, u16::from_be_bytes([payload[2], payload[3]])),
            tcp_syn: payload.get(13).is_some_and(|flags| flags & 0x02 != 0),
        })),
        IpProtocol::Udp if payload.len() >= 8 => Ok(Some(TransportTuple {
            protocol: IpProtocol::Udp,
            source: SocketAddr::new(source, u16::from_be_bytes([payload[0], payload[1]])),
            destination: SocketAddr::new(destination, u16::from_be_bytes([payload[2], payload[3]])),
            tcp_syn: false,
        })),
        _ => Ok(None),
    }
}
