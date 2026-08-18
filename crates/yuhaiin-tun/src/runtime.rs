//! Async TUN device lifecycle and smoltcp polling.

use super::*;

pub struct TunRuntime {
    #[cfg(feature = "tun-routes")]
    route_lease: Option<TunRouteLease>,
    device: AsyncDevice,
    pub(crate) smoltcp_device: SmoltcpTunDevice,
    pub(crate) interface: Interface,
    buffer: Vec<u8>,
    ipv6_fragments: Ipv6FragmentReassembler,
    fragment_identification: AtomicU32,
    pcap_capture: Option<Arc<TunPcapCapture>>,
    #[cfg(any(target_os = "android", target_os = "ios", target_os = "tvos"))]
    configured_name: Option<String>,
}

impl TunRuntime {
    /// Assemble the packet engine around an already-created asynchronous TUN.
    ///
    /// Desktop callers normally use [`Self::open`]. Android/iOS VPN hosts
    /// create the device through their platform API and pass ownership of the
    /// resulting `tun-rs::AsyncDevice` here. This keeps the platform fd/FFI
    /// boundary outside smoltcp and avoids a second packet-stack path.
    pub fn from_async_device(config: TunConfig, device: AsyncDevice) -> io::Result<Self> {
        config
            .validate()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
        let pcap_capture = TunPcapCapture::from_env()?;
        #[cfg(any(target_os = "android", target_os = "ios", target_os = "tvos"))]
        let configured_name = config.name.clone();
        let mut smoltcp_device = SmoltcpTunDevice::new(config.mtu, config.queue_capacity)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
        let mut interface = Interface::new(
            Config::new(HardwareAddress::Ip),
            &mut smoltcp_device,
            Instant::from_millis(0),
        );
        // A TUN gateway receives packets for arbitrary routed destinations;
        // they are not necessarily assigned to the TUN interface itself.
        // smoltcp's AnyIP mode accepts those packets while retaining the
        // original destination endpoint for the dispatcher flow key.
        interface.set_any_ip(true);
        if let Some((address, prefix)) = config.ipv4 {
            interface.update_ip_addrs(|addresses| {
                let _ = addresses.push(IpCidr::new(IpAddress::Ipv4(address), prefix));
            });
        }
        for (address, prefix) in &config.ipv6 {
            interface.update_ip_addrs(|addresses| {
                let _ = addresses.push(IpCidr::new(IpAddress::Ipv6(*address), *prefix));
            });
        }
        Ok(Self {
            #[cfg(feature = "tun-routes")]
            route_lease: None,
            device,
            smoltcp_device,
            interface,
            buffer: vec![0; config.mtu.max(65535)],
            ipv6_fragments: Ipv6FragmentReassembler::default(),
            fragment_identification: AtomicU32::new(0),
            pcap_capture,
            #[cfg(any(target_os = "android", target_os = "ios", target_os = "tvos"))]
            configured_name,
        })
    }

    /// Build the TUN runtime from an owned platform file descriptor.
    ///
    /// The caller transfers ownership of `fd` to this method. On success the
    /// returned runtime closes it when the runtime is dropped; on an invalid
    /// configuration the `OwnedFd` is left to its normal drop path. This is
    /// the safe boundary for Android `VpnService`, iOS `PacketTunnelProvider`
    /// and macOS utun hosts that already created the device outside Rust.
    ///
    /// `tun-rs` still requires the descriptor to refer to a real TUN/TAP
    /// device. A plain socket or pipe is not a supported substitute and is
    /// rejected by the platform data plane when it is used.
    #[cfg(unix)]
    pub fn from_owned_fd(config: TunConfig, fd: OwnedFd) -> io::Result<Self> {
        config
            .validate()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
        let device = yuhaiin_platform::async_device_from_owned_fd(fd)?;
        Self::from_async_device(config, device)
    }

    #[cfg(not(any(target_os = "android", target_os = "ios", target_os = "tvos")))]
    pub fn open(config: TunConfig) -> io::Result<Self> {
        config
            .validate()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
        let mut builder = DeviceBuilder::new().mtu(config.mtu as u16);
        if let Some(name) = config.name.as_deref() {
            builder = builder.name(name);
        }
        if let Some((address, prefix)) = config.ipv4 {
            builder = builder.ipv4(address, prefix, None);
        }
        for (address, prefix) in &config.ipv6 {
            builder = builder.ipv6(*address, *prefix);
        }
        let device = builder.build_async()?;
        Self::from_async_device(config, device)
    }

    /// Mobile platforms receive their TUN from the host VPN API rather than
    /// creating a desktop device. Callers must provide that device through
    /// [`Self::from_async_device`].
    #[cfg(any(target_os = "android", target_os = "ios", target_os = "tvos"))]
    pub fn open(_config: TunConfig) -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "this platform requires an injected TUN device",
        ))
    }

    /// Open a TUN device and install its owned routes as one startup
    /// operation. If route setup fails, dropping the partially initialized
    /// runtime closes the TUN descriptor so callers never receive a device
    /// without the route contract they requested.
    #[cfg(feature = "tun-routes")]
    pub fn open_with_routes<B>(
        config: TunConfig,
        backend: B,
        routes: &[TunRoute],
    ) -> io::Result<Self>
    where
        B: TunRouteBackend + 'static,
    {
        let mut runtime = Self::open(config)?;
        if let Err(error) = runtime.install_routes(backend, routes) {
            drop(runtime);
            return Err(error);
        }
        Ok(runtime)
    }

    pub fn smoltcp_device(&self) -> &SmoltcpTunDevice {
        &self.smoltcp_device
    }

    /// Return the kernel-assigned TUN interface name.
    ///
    /// A caller may request a name in [`TunConfig`], but the OS is the
    /// authority on the final name. Exposing the resolved value lets route
    /// ownership and teardown diagnostics refer to the same device.
    pub fn name(&self) -> io::Result<String> {
        #[cfg(any(target_os = "android", target_os = "ios", target_os = "tvos"))]
        {
            return Ok(self
                .configured_name
                .clone()
                .unwrap_or_else(|| "fd".to_owned()));
        }
        #[cfg(not(any(target_os = "android", target_os = "ios", target_os = "tvos")))]
        {
            self.device.name()
        }
    }

    /// Install and own a reversible route set for this TUN device.
    ///
    /// The backend is injected so callers can use the Linux netlink backend in
    /// production and a deterministic fake backend in tests. A second route
    /// lease is rejected until the first one has been closed successfully.
    #[cfg(feature = "tun-routes")]
    pub fn install_routes<B>(&mut self, backend: B, routes: &[TunRoute]) -> io::Result<()>
    where
        B: TunRouteBackend + 'static,
    {
        if self.route_lease.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "TUN routes are already installed",
            ));
        }
        self.route_lease = Some(TunRouteLease::apply(backend, routes)?);
        Ok(())
    }

    /// Install routes through Linux netlink after the TUN device exists.
    ///
    /// Address/device creation remains owned by `tun-rs`; this method only
    /// installs the explicit routes supplied by the application.
    #[cfg(all(feature = "tun-routes", target_os = "linux"))]
    pub fn install_linux_routes(&mut self, routes: &[TunRoute]) -> io::Result<()> {
        let interface = self.device.name()?;
        self.install_routes(LinuxTunRouteBackend::new(interface)?, routes)
    }

    /// Remove all routes owned by this runtime. Failed removals remain tracked
    /// and can be retried; a successful close makes the method idempotent.
    #[cfg(feature = "tun-routes")]
    pub fn close_routes(&mut self) -> io::Result<()> {
        let Some(mut lease) = self.route_lease.take() else {
            return Ok(());
        };
        match lease.close() {
            Ok(()) => Ok(()),
            Err(error) => {
                self.route_lease = Some(lease);
                Err(error)
            }
        }
    }

    /// Explicitly tear down this runtime.
    ///
    /// Route cleanup runs before `self` is consumed and the underlying TUN
    /// file descriptor is dropped. Cleanup errors are returned to the caller;
    /// the destructor still performs its final best-effort cleanup.
    pub fn shutdown(self) -> io::Result<()> {
        #[cfg(feature = "tun-routes")]
        {
            let mut this = self;
            this.close_routes()?;
        }
        #[cfg(not(feature = "tun-routes"))]
        let _ = self;
        Ok(())
    }

    /// Add an address to the smoltcp interface after the OS TUN device has
    /// been opened.
    ///
    /// This is useful for a gateway layout where the OS-facing TUN address
    /// and the virtual service address are different. The OS address remains
    /// managed by `TunConfig`; this method only changes the packet stack.
    pub fn add_ip_address(&mut self, address: IpAddress, prefix: u8) -> Result<()> {
        if (matches!(address, IpAddress::Ipv4(_)) && prefix > 32)
            || (matches!(address, IpAddress::Ipv6(_)) && prefix > 128)
        {
            return Err(Error::invalid("TUN address prefix is out of range"));
        }
        let mut result = Ok(());
        self.interface.update_ip_addrs(|addresses| {
            result = addresses.push(IpCidr::new(address, prefix));
        });
        result.map_err(|_| Error::invalid("smoltcp IP address capacity is exhausted"))
    }

    fn prepend_address(&mut self, address: IpAddress, prefix: u8) -> Result<()> {
        if (matches!(address, IpAddress::Ipv4(_)) && prefix > 32)
            || (matches!(address, IpAddress::Ipv6(_)) && prefix > 128)
        {
            return Err(Error::invalid("TUN address prefix is out of range"));
        }
        if self
            .interface
            .ip_addrs()
            .iter()
            .any(|cidr| cidr.address() == address)
        {
            return Ok(());
        }
        let mut addresses = Vec::with_capacity(self.interface.ip_addrs().len() + 1);
        addresses.push(IpCidr::new(address, prefix));
        addresses.extend_from_slice(self.interface.ip_addrs());
        self.replace_ip_addresses(&addresses)
    }

    /// Put an IPv4 routed endpoint first so wildcard UDP sockets use it as
    /// their source address when returning a packet through the TUN gateway.
    pub fn prepend_ipv4_address(&mut self, address: Ipv4Addr, prefix: u8) -> Result<()> {
        self.prepend_address(IpAddress::Ipv4(address), prefix)
    }

    /// Put an IPv6 routed endpoint first for the same gateway/source-address
    /// contract as [`Self::prepend_ipv4_address`].  Without this, Linux can
    /// install an IPv6 route successfully while smoltcp still has no virtual
    /// address from which to emit the reply packet.
    pub fn prepend_ipv6_address(&mut self, address: Ipv6Addr, prefix: u8) -> Result<()> {
        self.prepend_address(IpAddress::Ipv6(address), prefix)
    }

    /// Replace the smoltcp interface address order without changing the OS
    /// address already applied to the TUN device.
    pub fn replace_ip_addresses(&mut self, addresses: &[IpCidr]) -> Result<()> {
        let mut result = Ok(());
        self.interface.update_ip_addrs(|current| {
            current.clear();
            for address in addresses {
                if current.push(*address).is_err() {
                    result = Err(());
                    break;
                }
            }
        });
        result.map_err(|_| Error::invalid("smoltcp IP address capacity is exhausted"))
    }

    pub async fn recv_from_tun(&mut self) -> io::Result<usize> {
        let length = self.device.recv(&mut self.buffer).await?;
        if let Some(capture) = &self.pcap_capture {
            capture.record(&self.buffer[..length]);
        }
        tun_debug(format!(
            "TUN packet received length={} prefix={:02x?}",
            length,
            &self.buffer[..length.min(32)]
        ));
        let packet = self
            .ipv6_fragments
            .push(&self.buffer[..length], StdInstant::now())
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
        let Some(packet) = packet else {
            // A fragment assembly is either waiting for more wire packets or
            // has been deliberately discarded (overlap, size, or capacity).
            // The TUN read itself succeeded, so do not tear down the whole
            // inbound just because one hostile datagram was dropped.
            return Ok(length);
        };
        let packet = normalize_ipv6_extension_headers(&packet)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?
            .into_owned();
        let accepted = self
            .smoltcp_device
            .enqueue_rx_reassembled(packet)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
        if !accepted {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "TUN RX queue is full",
            ));
        }
        Ok(length)
    }

    #[cfg(feature = "async-proxy")]
    fn expire_ipv6_fragments(&mut self) {
        self.ipv6_fragments.expire(StdInstant::now());
    }

    pub async fn send_to_tun(&self) -> io::Result<Option<usize>> {
        let Some(packet) = self
            .smoltcp_device
            .take_tx()
            .map_err(|error| io::Error::other(error.to_string()))?
        else {
            return Ok(None);
        };
        let fragments = fragment_ip_packet(
            &packet,
            self.smoltcp_device.mtu(),
            self.fragment_identification
                .fetch_add(1, AtomicOrdering::Relaxed),
        )
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
        let mut sent = 0;
        for fragment in fragments {
            if let Some(capture) = &self.pcap_capture {
                capture.record(&fragment);
            }
            tun_debug(format!(
                "TUN packet sending length={} prefix={:02x?}",
                fragment.len(),
                &fragment[..fragment.len().min(32)]
            ));
            sent += self.device.send(&fragment).await?;
        }
        Ok(Some(sent))
    }

    pub fn poll_smoltcp(
        &mut self,
        timestamp: Instant,
        sockets: &mut SocketSet<'_>,
    ) -> smoltcp::iface::PollResult {
        self.interface
            .poll(timestamp, &mut self.smoltcp_device, sockets)
    }

    /// Run the complete first-generation TUN data-plane loop.
    ///
    /// The loop has one packet-reader future and one timer branch.  Both paths
    /// advance smoltcp, drain proxy outputs, dispatch owned flow events, and
    /// flush all available TX packets.  The proxy runtime remains injectable;
    /// this method only owns lifecycle ordering and never selects a route by
    /// itself.
    #[cfg(feature = "async-proxy")]
    pub async fn run_dispatcher(
        &mut self,
        dispatcher: &mut TunDispatcher,
        proxy_runtime: &mut TunProxyRuntime,
        tick: Duration,
    ) -> io::Result<()> {
        self.run_dispatcher_until(
            dispatcher,
            proxy_runtime,
            tick,
            std::future::pending::<()>(),
        )
        .await
    }

    /// Run the TUN data plane until the caller's shutdown future completes.
    ///
    /// The shutdown branch is part of the runtime contract rather than an
    /// outer task convention: it closes all proxy flow tasks before returning
    /// so graceful stop and force-cancel have the same ownership boundary.
    #[cfg(feature = "async-proxy")]
    pub async fn run_dispatcher_until<F>(
        &mut self,
        dispatcher: &mut TunDispatcher,
        proxy_runtime: &mut TunProxyRuntime,
        tick: Duration,
        shutdown: F,
    ) -> io::Result<()>
    where
        F: std::future::Future<Output = ()>,
    {
        if tick.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "TUN dispatcher tick must be non-zero",
            ));
        }
        let started = std::time::Instant::now();
        let mut ticker = tokio::time::interval(tick);
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                result = self.recv_from_tun() => {
                    if let Err(error) = result {
                        proxy_runtime.close();
                        return Err(error);
                    }
                }
                _ = ticker.tick() => {}
                _ = &mut shutdown => {
                    proxy_runtime
                        .close_graceful(DEFAULT_GRACEFUL_CLOSE_TIMEOUT)
                        .await;
                    return Ok(());
                }
            }
            let elapsed = started.elapsed();
            self.expire_ipv6_fragments();
            let timestamp = Instant::from_millis(elapsed.as_millis().min(i64::MAX as u128) as i64);
            if let Err(error) = dispatcher.poll(self, timestamp) {
                proxy_runtime.close();
                return Err(io::Error::other(error.to_string()));
            }
            for event in dispatcher.events().collect::<Vec<_>>() {
                let flow = event_flow_key(&event);
                if let Err(error) = proxy_runtime.handle_event_async(event).await {
                    // A transport can finish between smoltcp emitting a
                    // packet and the next command being delivered to its
                    // bounded flow queue.  That is a per-flow failure, not a
                    // reason to tear down the TUN supervisor and all other
                    // flows.  Close the kernel flow here and continue with
                    // the next packet; protocol/IO/timeout errors still fail
                    // the dispatcher as before.
                    if is_recoverable_proxy_flow_error(&error) {
                        tun_debug(format!(
                            "TUN proxy flow ended before event {:?}: {error}",
                            flow
                        ));
                        match flow.network {
                            Network::Tcp => {
                                let _ = dispatcher.abort_tcp(flow);
                            }
                            Network::Udp => {
                                let _ = dispatcher.close_udp(flow);
                            }
                            Network::Icmp | Network::Any => {}
                        }
                        continue;
                    }
                    proxy_runtime.close();
                    return Err(io::Error::other(error.to_string()));
                }
            }
            if let Err(error) = proxy_runtime.poll_outputs(dispatcher) {
                proxy_runtime.close();
                return Err(io::Error::other(error.to_string()));
            }
            // ICMP replies are queued by `poll_outputs`, while TCP/UDP
            // replies are emitted through smoltcp's normal poll path. Flush
            // the raw ICMP queue before handing packets back to the kernel so
            // an echo request does not wait for another TUN tick (or get lost
            // if the runtime is stopped immediately after the proxy reply).
            if let Err(error) = dispatcher.flush_pending_icmp_tx(&self.smoltcp_device) {
                proxy_runtime.close();
                return Err(io::Error::other(error.to_string()));
            }
            if let Err(error) = proxy_runtime.sweep(dispatcher) {
                proxy_runtime.close();
                return Err(io::Error::other(error.to_string()));
            }
            loop {
                match self.send_to_tun().await {
                    Ok(Some(_)) => {}
                    Ok(None) => break,
                    Err(error) => {
                        proxy_runtime.close();
                        return Err(error);
                    }
                }
            }
            // A current-thread runtime can keep the TUN reader ready while a
            // newly opened proxy is still connecting. Yield once per loop so
            // flow tasks get a chance to consume their bounded command queue;
            // otherwise a large upload can fill that queue before the proxy
            // task is ever polled.
            tokio::task::yield_now().await;
        }
    }
}

impl Drop for TunRuntime {
    fn drop(&mut self) {
        #[cfg(feature = "tun-routes")]
        {
            let _ = self.close_routes();
        }
    }
}
