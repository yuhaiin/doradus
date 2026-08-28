use super::*;

#[derive(Debug, Default)]
pub(crate) struct PacketQueue {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
    capacity: usize,
}

impl PacketQueue {
    fn new(capacity: usize) -> Self {
        Self {
            rx: VecDeque::with_capacity(capacity),
            tx: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    fn push_rx(&mut self, packet: Vec<u8>) -> bool {
        if self.rx.len() >= self.capacity {
            return false;
        }
        self.rx.push_back(packet);
        true
    }

    fn push_tx(&mut self, packet: Vec<u8>) -> bool {
        if self.tx.len() >= self.capacity {
            return false;
        }
        self.tx.push_back(packet);
        true
    }

    fn pop_tx(&mut self) -> Option<Vec<u8>> {
        self.tx.pop_front()
    }

    fn pop_rx(&mut self) -> Option<Vec<u8>> {
        self.rx.pop_front()
    }
}

pub struct QueueRxToken {
    packet: Vec<u8>,
}

impl phy::RxToken for QueueRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.packet)
    }
}

pub struct QueueTxToken {
    queue: Arc<Mutex<PacketQueue>>,
    timestamp: Instant,
    max_packet_size: usize,
}

impl phy::TxToken for QueueTxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut packet = vec![0u8; len];
        let result = f(&mut packet);
        if len <= self.max_packet_size
            && let Ok(mut queue) = self.queue.lock()
        {
            let _ = queue.push_tx(packet);
        }
        let _ = self.timestamp;
        result
    }
}

/// A smoltcp `Device` backed by bounded in-memory queues.
///
/// Async TUN I/O is deliberately kept outside smoltcp's synchronous token API:
/// `recv_from_tun` fills the RX queue and `send_to_tun` drains the TX queue.
/// This keeps the runtime boundary small and makes the packet engine testable
/// with no privileged TUN device.
pub struct SmoltcpTunDevice {
    queue: Arc<Mutex<PacketQueue>>,
    mtu: usize,
}

impl SmoltcpTunDevice {
    pub fn new(mtu: usize, queue_capacity: usize) -> Result<Self> {
        if !(576..=9216).contains(&mtu) || queue_capacity == 0 {
            return Err(Error::invalid("invalid smoltcp TUN device configuration"));
        }
        Ok(Self {
            queue: Arc::new(Mutex::new(PacketQueue::new(queue_capacity))),
            mtu,
        })
    }

    pub fn mtu(&self) -> usize {
        self.mtu
    }

    pub fn enqueue_rx(&self, packet: Vec<u8>) -> Result<bool> {
        inspect_ip_packet_with_mtu(&packet, self.mtu)?;
        self.enqueue_rx_validated(packet)
    }

    pub(crate) fn enqueue_tx(&self, packet: Vec<u8>) -> Result<bool> {
        inspect_ip_packet_with_mtu(&packet, self.mtu)?;
        self.queue
            .lock()
            .map(|mut queue| queue.push_tx(packet))
            .map_err(|_| Error::new(crate::ErrorKind::Io, "TUN packet queue poisoned"))
    }

    /// Enqueue a packet reassembled from IPv6 wire fragments.
    ///
    /// A reassembled datagram is allowed to be larger than the interface MTU;
    /// only each individual packet crossing the TUN boundary must fit that
    /// MTU.  Keep this path separate from [`Self::enqueue_rx`] so a caller
    /// cannot accidentally bypass the wire-packet validation for ordinary
    /// TUN input.
    pub fn enqueue_rx_reassembled(&self, packet: Vec<u8>) -> Result<bool> {
        inspect_ip_packet(&packet)?;
        if packet.len() > MAX_SMOLTCP_PACKET_SIZE {
            return Err(Error::invalid("reassembled TUN packet is too large"));
        }
        self.enqueue_rx_validated(packet)
    }

    fn enqueue_rx_validated(&self, packet: Vec<u8>) -> Result<bool> {
        self.queue
            .lock()
            .map(|mut queue| queue.push_rx(packet))
            .map_err(|_| Error::new(crate::ErrorKind::Io, "TUN packet queue poisoned"))
    }

    pub fn take_tx(&self) -> Result<Option<Vec<u8>>> {
        self.queue
            .lock()
            .map(|mut queue| queue.pop_tx())
            .map_err(|_| Error::new(crate::ErrorKind::Io, "TUN packet queue poisoned"))
    }

    /// Inspect the next TX packet without removing it.
    pub fn peek_tx_packet(&self) -> Result<Option<Vec<u8>>> {
        self.queue
            .lock()
            .map(|queue| queue.tx.front().cloned())
            .map_err(|_| Error::new(crate::ErrorKind::Io, "TUN packet queue poisoned"))
    }

    /// Inspect the next RX packet without removing it.
    ///
    /// This is primarily useful for a dispatcher that must choose an ICMP
    /// identifier or another socket before handing the packet to smoltcp.
    pub fn peek_rx_packet(&self) -> Result<Option<Vec<u8>>> {
        self.queue
            .lock()
            .map(|queue| queue.rx.front().cloned())
            .map_err(|_| Error::new(crate::ErrorKind::Io, "TUN packet queue poisoned"))
    }

    /// Inspect the next RX packet without cloning it or removing it.
    ///
    /// The dispatcher only needs a classification before smoltcp consumes the
    /// packet. Keeping the callback under the short queue lock avoids copying
    /// every ordinary TUN packet on the hot path.
    pub(crate) fn with_rx_packet<T>(&self, inspect: impl FnOnce(&[u8]) -> T) -> Result<Option<T>> {
        self.queue
            .lock()
            .map(|queue| queue.rx.front().map(|packet| inspect(packet)))
            .map_err(|_| Error::new(crate::ErrorKind::Io, "TUN packet queue poisoned"))
    }

    /// Remove the next RX packet without handing it to smoltcp.
    ///
    /// A dispatcher may use this for packets it deliberately handles outside
    /// the socket set, or for control traffic that is not part of the current
    /// protocol loop. Normal data-plane code should let `Interface::poll`
    /// consume the queue instead.
    pub fn take_rx_packet(&self) -> Result<Option<Vec<u8>>> {
        self.queue
            .lock()
            .map(|mut queue| queue.pop_rx())
            .map_err(|_| Error::new(crate::ErrorKind::Io, "TUN packet queue poisoned"))
    }

    pub fn queued_rx(&self) -> Result<usize> {
        self.queue
            .lock()
            .map(|queue| queue.rx.len())
            .map_err(|_| Error::new(crate::ErrorKind::Io, "TUN packet queue poisoned"))
    }

    pub fn queued_tx(&self) -> Result<usize> {
        self.queue
            .lock()
            .map(|queue| queue.tx.len())
            .map_err(|_| Error::new(crate::ErrorKind::Io, "TUN packet queue poisoned"))
    }

    pub(crate) fn drop_multicast_rx_packets(&self) -> Result<usize> {
        let mut queue = self
            .queue
            .lock()
            .map_err(|_| Error::new(crate::ErrorKind::Io, "TUN packet queue poisoned"))?;
        let packets: Vec<_> = queue.rx.drain(..).collect();
        let mut keep = Vec::with_capacity(packets.len());
        let mut dropped = 0;
        for packet in &packets {
            match ip_packet_has_multicast_destination(packet) {
                Ok(true) => {
                    dropped += 1;
                    keep.push(false);
                }
                Ok(false) => keep.push(true),
                Err(error) => {
                    queue.rx.extend(packets);
                    return Err(error);
                }
            }
        }
        queue.rx.extend(
            packets
                .into_iter()
                .zip(keep)
                .filter_map(|(packet, keep)| keep.then_some(packet)),
        );
        Ok(dropped)
    }
}

impl phy::Device for SmoltcpTunDevice {
    type RxToken<'a> = QueueRxToken;
    type TxToken<'a> = QueueTxToken;

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        // Do not advertise the OS wire MTU here.  smoltcp 0.13 drops an
        // oversized IPv6 packet instead of fragmenting it.  We keep the
        // complete datagram in this bounded queue and fragment both IP
        // versions at the asynchronous TUN boundary below.
        capabilities.max_transmission_unit = MAX_SMOLTCP_PACKET_SIZE;
        capabilities.medium = Medium::Ip;
        capabilities.checksum = ChecksumCapabilities::default();
        capabilities
    }

    fn receive(&mut self, timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = self.queue.lock().ok()?.rx.pop_front()?;
        Some((
            QueueRxToken { packet },
            QueueTxToken {
                queue: Arc::clone(&self.queue),
                timestamp,
                max_packet_size: MAX_SMOLTCP_PACKET_SIZE,
            },
        ))
    }

    fn transmit(&mut self, timestamp: Instant) -> Option<Self::TxToken<'_>> {
        let queue = self.queue.lock().ok()?;
        if queue.tx.len() >= queue.capacity {
            return None;
        }
        drop(queue);
        Some(QueueTxToken {
            queue: Arc::clone(&self.queue),
            timestamp,
            max_packet_size: MAX_SMOLTCP_PACKET_SIZE,
        })
    }
}
