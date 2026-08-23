//! Async TUN device lifecycle and smoltcp polling.

use super::*;

#[cfg(target_os = "macos")]
use super::macos_dns::MacosDnsLease;

struct PassthroughInputInterceptor;

impl ProxyInputInterceptor for PassthroughInputInterceptor {
    fn intercept(&mut self, input: ProxyInput) -> Result<ProxyInputAction> {
        Ok(ProxyInputAction::Forward(input))
    }
}

const DEFAULT_TUN_WRITE_STALL_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg(target_os = "macos")]
const MACOS_TUN_OPEN_ATTEMPTS: usize = 64;

struct TunWrite {
    packet: Vec<u8>,
    identification: u32,
}

struct TunWriter {
    tx: mpsc::Sender<TunWrite>,
    join: tokio::task::JoinHandle<io::Result<()>>,
}

#[cfg(not(any(target_os = "android", target_os = "ios", target_os = "tvos")))]
fn build_async_device(config: &TunConfig) -> io::Result<AsyncDevice> {
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
    builder.build_async()
}

impl Drop for TunWriter {
    fn drop(&mut self) {
        self.join.abort();
    }
}

async fn write_tun_fragment(device: &AsyncDevice, packet: &[u8]) -> io::Result<()> {
    let deadline = tokio::time::Instant::now() + DEFAULT_TUN_WRITE_STALL_TIMEOUT;

    loop {
        match device.try_send(packet) {
            Ok(written) => {
                if written != packet.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        format!("partial TUN write: {written}/{}", packet.len()),
                    ));
                }

                return Ok(());
            }

            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                tokio::time::timeout_at(deadline, device.writable())
                    .await
                    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TUN writer stalled"))??;
            }

            Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                continue;
            }

            Err(error) => return Err(error),
        }
    }
}

pub struct TunRuntime {
    #[cfg(feature = "tun-routes")]
    route_lease: Option<TunRouteLease>,
    #[cfg(target_os = "macos")]
    dns_lease: Option<MacosDnsLease>,
    device: Arc<AsyncDevice>,
    pub(crate) smoltcp_device: SmoltcpTunDevice,
    pub(crate) interface: Interface,
    buffer: Vec<u8>,
    ipv6_fragments: Ipv6FragmentReassembler,
    fragment_identification: AtomicU32,
    pcap_capture: Option<Arc<TunPcapCapture>>,

    writer_queue_capacity: usize,

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
        let mut smoltcp_device =
            SmoltcpTunDevice::new(config.mtu, config.queue_capacity).map_err(|error: Error| {
                io::Error::new(io::ErrorKind::InvalidInput, error.to_string())
            })?;
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
            #[cfg(target_os = "macos")]
            dns_lease: None,
            device: Arc::new(device),
            smoltcp_device,
            interface,
            // A raw TUN read is bounded by the configured device MTU. Large
            // IPv6 datagrams are reassembled after the read, so this buffer
            // does not need to reserve the full 65 KiB smoltcp datagram size.
            buffer: vec![0; config.mtu],
            ipv6_fragments: Ipv6FragmentReassembler::default(),
            fragment_identification: AtomicU32::new(0),
            pcap_capture,

            writer_queue_capacity: config.queue_capacity.max(1),

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
        let device = async_device_from_owned_fd(fd)?;
        Self::from_async_device(config, device)
    }

    #[cfg(not(any(target_os = "android", target_os = "ios", target_os = "tvos")))]
    pub fn open(mut config: TunConfig) -> io::Result<Self> {
        config
            .validate()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;

        #[cfg(target_os = "macos")]
        {
            let mut name = platform::resolve_macos_tun_name(config.name.as_deref());
            for _ in 0..MACOS_TUN_OPEN_ATTEMPTS {
                config.name = Some(name.clone());
                match build_async_device(&config) {
                    Ok(device) => return Self::from_async_device(config, device),
                    Err(error) if error.kind() == io::ErrorKind::ResourceBusy => {
                        name = platform::next_macos_tun_name(&name);
                    }
                    Err(error) => return Err(error),
                }
            }
            return Err(io::Error::new(
                io::ErrorKind::ResourceBusy,
                format!(
                    "no available macOS utun interface after {MACOS_TUN_OPEN_ATTEMPTS} attempts"
                ),
            ));
        }

        #[cfg(not(target_os = "macos"))]
        {
            let device = build_async_device(&config)?;
            Self::from_async_device(config, device)
        }
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

    /// Install the Go-compatible macOS DNS lease for this TUN runtime.
    ///
    /// The lease snapshots the selected network service's DNS servers, applies
    /// the TUN gateway addresses as DNS servers, follows default-interface
    /// changes when no service is pinned, and restores the snapshot on drop.
    #[cfg(target_os = "macos")]
    pub fn install_macos_dns(&mut self, network_service: Option<&str>, dns_servers: &[IpAddr]) {
        let _ = self.dns_lease.take();
        match MacosDnsLease::apply(network_service, dns_servers) {
            Ok(lease) => self.dns_lease = Some(lease),
            Err(error) => tun_debug(format!("macOS DNS setup failed: {error}")),
        }
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

    /// Install routes through Darwin's route socket for the utun device.
    ///
    /// The portal addresses are used as implicit gateways, matching the Go
    /// implementation. Explicit per-route gateways still take precedence.
    #[cfg(all(feature = "tun-routes", target_os = "macos"))]
    pub fn install_macos_routes(
        &mut self,
        routes: &[TunRoute],
        ipv4_gateway: Option<Ipv4Addr>,
        ipv6_gateway: Option<Ipv6Addr>,
    ) -> io::Result<()> {
        let interface = self.device.name()?;
        self.install_routes(
            MacosTunRouteBackend::new(interface, ipv4_gateway, ipv6_gateway)?,
            routes,
        )
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
            .push_borrowed(&self.buffer[..length], StdInstant::now())
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
        let Some(packet) = packet else {
            // A fragment assembly is either waiting for more wire packets or
            // has been deliberately discarded (overlap, size, or capacity).
            // The TUN read itself succeeded, so do not tear down the whole
            // inbound just because one hostile datagram was dropped.
            return Ok(length);
        };
        let packet = normalize_ipv6_extension_headers(packet.as_ref())
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?
            .into_owned();
        let accepted = self
            .smoltcp_device
            .enqueue_rx_reassembled(packet)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
        if !accepted {
            tun_debug(format!(
                "TUN RX queue is full, dropping packet length={length}"
            ));
            return Ok(length);
        }
        Ok(length)
    }

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

    async fn wait_smoltcp_timer(delay: Option<smoltcp::time::Duration>) {
        match delay {
            Some(delay) => {
                tokio::time::sleep(Duration::from_micros(delay.total_micros())).await;
            }
            None => {
                std::future::pending::<()>().await;
            }
        }
    }

    /// Run the TUN data plane until the caller's shutdown future completes.
    ///
    /// The shutdown branch is part of the runtime contract rather than an
    /// outer task convention: it closes all proxy flow tasks before returning
    /// so graceful stop and force-cancel have the same ownership boundary.
    /// An input interceptor is optional because most callers only need the
    /// normal forward path; runtime-owned policy such as inbound DNS handling
    /// can provide one without requiring a second dispatcher entry point.
    pub async fn run_dispatcher_until<F>(
        &mut self,
        dispatcher: &mut TunDispatcher,
        proxy_runtime: &mut TunProxyRuntime,
        input_interceptor: Option<&mut dyn ProxyInputInterceptor>,
        shutdown: F,
    ) -> io::Result<()>
    where
        F: std::future::Future<Output = ()>,
    {
        let mut passthrough = PassthroughInputInterceptor;
        let interceptor: &mut dyn ProxyInputInterceptor =
            input_interceptor.unwrap_or(&mut passthrough);
        let started = std::time::Instant::now();
        tokio::pin!(shutdown);
        let mut tun_writer = self.start_tun_writer();
        let mut writer_backpressured = false;

        loop {
            let timestamp = elapsed_timestamp(started);

            let next_poll_delay = dispatcher.poll_delay(&mut self.interface, timestamp);

            let interceptor_output = tokio::select! {
                result = self.recv_from_tun() => {
                    if let Err(error) = result {
                        proxy_runtime.close();
                        return Err(error);
                    }

                    None
                }

                _ = proxy_runtime.wait_for_output() => {
                    None
                }

                output = interceptor.wait_for_output() => {
                    Some(output)
                }

                _ = TunRuntime::wait_smoltcp_timer(next_poll_delay) => {
                    None
                }

                permit = tun_writer.tx.reserve(),
                    if writer_backpressured =>
                {
                    if permit.is_err() {
                        proxy_runtime.close();

                        return Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "TUN writer queue closed",
                        ));
                    }

                    None
                }

                result = &mut tun_writer.join => {
                    proxy_runtime.close();

                    return match result {
                        Ok(Ok(())) => Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "TUN writer stopped unexpectedly",
                        )),

                        Ok(Err(error)) => Err(error),

                        Err(error) => Err(io::Error::other(
                            format!(
                                "TUN writer task failed: {error}"
                            )
                        )),
                    };
                }

                _ = &mut shutdown => {
                    proxy_runtime
                        .close_graceful(
                            DEFAULT_GRACEFUL_CLOSE_TIMEOUT
                        )
                        .await;

                    return Ok(());
                }
            };

            if let Some(output) = interceptor_output {
                self.apply_proxy_input_action(dispatcher, proxy_runtime, output)?;
            }

            writer_backpressured = match self
                .drive_data_plane_once(
                    dispatcher,
                    proxy_runtime,
                    started,
                    interceptor,
                    &tun_writer.tx,
                )
                .await
            {
                Ok(backpressured) => backpressured,

                Err(error) => {
                    proxy_runtime.close();
                    return Err(error);
                }
            };
        }
    }

    async fn drive_data_plane_once(
        &mut self,
        dispatcher: &mut TunDispatcher,
        proxy_runtime: &mut TunProxyRuntime,
        started: std::time::Instant,
        interceptor: &mut dyn ProxyInputInterceptor,
        tun_writer: &mpsc::Sender<TunWrite>,
    ) -> io::Result<bool> {
        self.expire_ipv6_fragments();

        // TUN / smoltcp -> proxy
        dispatcher
            .poll(self, elapsed_timestamp(started))
            .map_err(|error| io::Error::other(error.to_string()))?;
        self.dispatch_proxy_inputs(dispatcher, proxy_runtime, interceptor)?;

        // proxy -> smoltcp / TUN
        proxy_runtime
            .process_proxy_outputs(dispatcher)
            .map_err(|error| io::Error::other(error.to_string()))?;

        dispatcher
            .flush_pending_icmp_to_tun(&self.smoltcp_device)
            .map_err(|error| io::Error::other(error.to_string()))?;

        // Lifecycle / maintenance
        proxy_runtime
            .sweep(dispatcher)
            .map_err(|error| io::Error::other(error.to_string()))?;

        // smoltcp -> OS TUN
        let writer_backpressured = self.flush_to_tun(tun_writer)?;

        // A current-thread runtime can keep the TUN reader ready while a
        // newly opened proxy is still connecting. Yield once per loop so flow
        // tasks get a chance to consume their bounded command queue.
        tokio::task::yield_now().await;
        Ok(writer_backpressured)
    }

    fn dispatch_proxy_inputs(
        &mut self,
        dispatcher: &mut TunDispatcher,
        proxy_runtime: &mut TunProxyRuntime,
        interceptor: &mut dyn ProxyInputInterceptor,
    ) -> io::Result<()> {
        while let Some(event) = dispatcher.next_proxy_input() {
            let action = interceptor
                .intercept(event)
                .map_err(|error| io::Error::other(error.to_string()))?;
            self.apply_proxy_input_action(dispatcher, proxy_runtime, action)?;
        }
        Ok(())
    }

    fn apply_proxy_input_action(
        &mut self,
        dispatcher: &mut TunDispatcher,
        proxy_runtime: &mut TunProxyRuntime,
        action: ProxyInputAction,
    ) -> io::Result<()> {
        match action {
            ProxyInputAction::Forward(event) => {
                let flow = proxy_input_flow_key(&event);
                if let Err(error) = proxy_runtime.handle_proxy_input(event) {
                    // A transport can finish between smoltcp emitting a packet
                    // and the next command being delivered to its bounded flow
                    // queue. Close only that kernel flow and keep the supervisor
                    // alive for unrelated flows.
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
                        return Ok(());
                    }
                    return Err(io::Error::other(error.to_string()));
                }
            }
            ProxyInputAction::Reply { flow, payload } => {
                if let Err(error) = dispatcher.write_udp(flow, &payload) {
                    tun_debug(format!(
                        "TUN interceptor UDP reply dropped flow={flow:?} bytes={} error={error}",
                        payload.len()
                    ));
                }
            }
            ProxyInputAction::Deferred | ProxyInputAction::Drop => {}
        }
        Ok(())
    }

    fn flush_to_tun(&self, writer: &mpsc::Sender<TunWrite>) -> io::Result<bool> {
        loop {
            let permit = match writer.try_reserve() {
                Ok(permit) => permit,

                Err(mpsc::error::TrySendError::Full(_)) => {
                    // true = writer backpressured
                    return Ok(true);
                }

                Err(mpsc::error::TrySendError::Closed(_)) => {
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "TUN writer stopped",
                    ));
                }
            };

            let Some(packet) = self
                .smoltcp_device
                .take_tx()
                .map_err(|error| io::Error::other(error.to_string()))?
            else {
                return Ok(false);
            };

            permit.send(TunWrite {
                packet,
                identification: self
                    .fragment_identification
                    .fetch_add(1, AtomicOrdering::Relaxed),
            });
        }
    }

    fn start_tun_writer(&self) -> TunWriter {
        let (tx, mut rx) = mpsc::channel::<TunWrite>(self.writer_queue_capacity);

        let device = Arc::clone(&self.device);
        let capture = self.pcap_capture.clone();
        let mtu = self.smoltcp_device.mtu();

        let join = tokio::spawn(async move {
            while let Some(write) = rx.recv().await {
                let fragments = fragment_ip_packet(&write.packet, mtu, write.identification)
                    .map_err(|error| {
                        io::Error::new(io::ErrorKind::InvalidData, error.to_string())
                    })?;

                for fragment in fragments {
                    if let Some(capture) = &capture {
                        capture.record(&fragment);
                    }

                    tun_debug(format!(
                        "TUN packet sending length={} prefix={:02x?}",
                        fragment.len(),
                        &fragment[..fragment.len().min(32)]
                    ));

                    write_tun_fragment(&device, &fragment).await?;
                }
            }

            Ok(())
        });

        TunWriter { tx, join }
    }
}

fn elapsed_timestamp(started: std::time::Instant) -> Instant {
    let elapsed = started.elapsed();
    Instant::from_micros(elapsed.as_micros().min(i64::MAX as u128) as i64)
}

impl Drop for TunRuntime {
    fn drop(&mut self) {
        #[cfg(feature = "tun-routes")]
        {
            let _ = self.close_routes();
        }
    }
}
