//! The first TUN data-plane adapter.
//!
//! This module intentionally exposes one implementation only:
//! `tun-rs::AsyncDevice` is the OS boundary and smoltcp is the packet/socket
//! engine.  There is no tun2socket implementation and no second userspace
//! stack to keep in sync with this one.
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{self, ChecksumCapabilities, DeviceCapabilities, Medium};
use smoltcp::time::Instant;
#[cfg(test)]
use smoltcp::wire::IpEndpoint;
use smoltcp::wire::{
    HardwareAddress, Icmpv4Packet, Icmpv4Repr, Icmpv6Packet, Icmpv6Repr, IpAddress, IpCidr,
    IpProtocol, IpVersion, Ipv4Packet, Ipv6Packet, TcpPacket, UdpPacket,
};
use smoltcp::wire::{Icmpv4Message, Icmpv6Message};
use std::borrow::Cow;
#[cfg(feature = "async-proxy")]
use std::collections::HashSet;
use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
#[cfg(unix)]
use std::os::fd::OwnedFd;
#[cfg(all(feature = "tun-routes", target_os = "linux"))]
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex, OnceLock};
#[cfg(feature = "async-proxy")]
use std::time::Duration;
use std::time::{Duration as StdDuration, Instant as StdInstant, SystemTime, UNIX_EPOCH};
mod platform;
#[cfg(not(any(target_os = "android", target_os = "ios", target_os = "tvos")))]
pub use platform::DeviceBuilder;
pub use platform::{AsyncDevice, async_device_from_owned_fd, enable_loopback};

#[cfg(feature = "async-proxy")]
use tokio::sync::{Notify, mpsc};

#[cfg(feature = "async-proxy")]
use futures_util::stream::FuturesUnordered;
#[cfg(feature = "async-proxy")]
use futures_util::{FutureExt, StreamExt};

#[cfg(feature = "async-proxy")]
use yuhaiin_core::Endpoint;
#[cfg(feature = "async-proxy")]
use yuhaiin_core::RouteMode;
#[cfg(feature = "async-proxy")]
use yuhaiin_core::nat::{NatKey, NatTable};
#[cfg(feature = "async-proxy")]
use yuhaiin_core::process::{ProcessResolver, default_process_resolver};
#[cfg(test)]
pub use yuhaiin_core::{BoxFuture, DomainName, IpSet};
use yuhaiin_core::{Error, ErrorKind, Network, Result};
pub use yuhaiin_core::{FlowContext, LocalBoxFuture};
#[cfg(test)]
pub use yuhaiin_core::{dns, process, proxy};

pub use yuhaiin_core::flow::{Flow as TunFlow, FlowKey as TunFlowKey};
#[cfg(feature = "async-proxy")]
pub use yuhaiin_core::flow::{FlowDirection as TunFlowDirection, FlowObserver as TunFlowObserver};

#[cfg(feature = "async-proxy")]
use yuhaiin_core::dns::{AsyncDnsHandler, DnsHandler, answer_query};

#[cfg(feature = "async-proxy")]
use yuhaiin_core::proxy::{AsyncProxy, AsyncProxySelector, stream_local_addr, stream_remote_addr};

mod config;
mod dispatcher;
mod packet;
#[path = "proxy.rs"]
mod proxy_runtime;
mod runtime;

pub use config::*;
pub use dispatcher::*;
pub use packet::*;
#[cfg(feature = "async-proxy")]
pub use proxy_runtime::*;
pub use runtime::*;
#[allow(unused_imports)]
pub(crate) use {config::*, dispatcher::*, packet::*, proxy_runtime::*, runtime::*};

fn tun_debug(message: impl std::fmt::Display) {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    if *ENABLED.get_or_init(|| std::env::var_os("YUHAIIN_TUN_DEBUG").is_some()) {
        eprintln!("yuhaiin-rust: tun-debug: {message}");
    }
}

const PCAP_LINKTYPE_RAW: u32 = 101;
const PCAP_SNAPLEN: u32 = 262_144;

/// A deliberately small classic-PCAP writer for raw IP packets crossing the
/// TUN boundary.  Keeping this local avoids making packet capture a runtime
/// dependency and lets Wireshark/tcpdump inspect the exact virtual packets
/// without adding Ethernet headers that never existed on the TUN device.
struct TunPcapWriter {
    file: File,
}

impl TunPcapWriter {
    fn create(path: &PathBuf) -> io::Result<Self> {
        let mut file = File::create(path)?;
        // Little-endian PCAP global header, version 2.4, raw IP link type.
        file.write_all(&0xa1b2c3d4u32.to_le_bytes())?;
        file.write_all(&2u16.to_le_bytes())?;
        file.write_all(&4u16.to_le_bytes())?;
        file.write_all(&0u32.to_le_bytes())?;
        file.write_all(&0u32.to_le_bytes())?;
        file.write_all(&PCAP_SNAPLEN.to_le_bytes())?;
        file.write_all(&PCAP_LINKTYPE_RAW.to_le_bytes())?;
        file.flush()?;
        Ok(Self { file })
    }

    fn write_packet(&mut self, packet: &[u8]) -> io::Result<()> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let original_len = packet.len().min(u32::MAX as usize) as u32;
        let included_len = packet.len().min(PCAP_SNAPLEN as usize) as u32;
        self.file
            .write_all(&(timestamp.as_secs().min(u32::MAX as u64) as u32).to_le_bytes())?;
        self.file
            .write_all(&timestamp.subsec_micros().to_le_bytes())?;
        self.file.write_all(&included_len.to_le_bytes())?;
        self.file.write_all(&original_len.to_le_bytes())?;
        self.file.write_all(&packet[..included_len as usize])?;
        self.file.flush()
    }
}

struct TunPcapCapture {
    writer: Mutex<Option<TunPcapWriter>>,
}

impl TunPcapCapture {
    fn from_env() -> io::Result<Option<Arc<Self>>> {
        let Some(path) = std::env::var_os("YUHAIIN_TUN_PCAP") else {
            return Ok(None);
        };
        if path.is_empty() {
            return Ok(None);
        }
        let path = PathBuf::from(path);
        let writer = TunPcapWriter::create(&path)?;
        eprintln!("yuhaiin-rust: TUN PCAP capture enabled: {}", path.display());
        Ok(Some(Arc::new(Self {
            writer: Mutex::new(Some(writer)),
        })))
    }

    fn record(&self, packet: &[u8]) {
        let Ok(mut writer) = self.writer.lock() else {
            return;
        };
        let Some(writer_ref) = writer.as_mut() else {
            return;
        };
        if let Err(error) = writer_ref.write_packet(packet) {
            *writer = None;
            eprintln!("yuhaiin-rust: TUN PCAP capture disabled: {error}");
        }
    }
}

pub const DEFAULT_MTU: usize = 1500;
pub const DEFAULT_QUEUE_CAPACITY: usize = 256;
const MAX_TCP_EVENT_BYTES_PER_POLL: usize = 64 * 1024;
// Most TCP reads are smaller than the socket's full receive capacity. Keep
// the owned event buffer bounded independently so a short read does not
// retain a 64 KiB allocation until the async proxy consumes it.
const MAX_TCP_EVENT_PAYLOAD_BYTES: usize = 16 * 1024;
const IPV6_FRAGMENT_MAX_ENTRIES: usize = 32;
const IPV6_FRAGMENT_MAX_FRAGMENTS: usize = 128;
const IPV6_FRAGMENT_MAX_PACKET: usize = MAX_SMOLTCP_PACKET_SIZE;
const IPV6_FRAGMENT_TIMEOUT: StdDuration = StdDuration::from_secs(15);
// The smoltcp device is allowed to produce one complete IP datagram. The
// real wire MTU is applied by `fragment_ip_packet` immediately before the
// datagram crosses the OS TUN boundary.
const MAX_SMOLTCP_PACKET_SIZE: usize = 40 + u16::MAX as usize;

#[cfg(feature = "async-proxy")]
const DEFAULT_GRACEFUL_CLOSE_TIMEOUT: Duration = Duration::from_secs(1);

#[cfg(test)]
mod tun_pcap_tests {
    use super::{PCAP_LINKTYPE_RAW, TunPcapWriter};
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn writes_raw_pcap_header_and_packet() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "yuhaiin-rust-tun-{pid}-{suffix}.pcap",
            pid = std::process::id()
        ));
        let mut writer = TunPcapWriter::create(&path).unwrap();
        writer.write_packet(&[0x45, 0x00, 0x00]).unwrap();
        drop(writer);

        let bytes = fs::read(&path).unwrap();
        assert_eq!(&bytes[..4], &[0xd4, 0xc3, 0xb2, 0xa1]);
        assert_eq!(
            u32::from_le_bytes(bytes[20..24].try_into().unwrap()),
            PCAP_LINKTYPE_RAW
        );
        assert_eq!(
            u32::from_le_bytes(bytes[24 + 8..24 + 12].try_into().unwrap()),
            3
        );
        assert_eq!(&bytes[40..], &[0x45, 0x00, 0x00]);
        fs::remove_file(path).unwrap();
    }
}

#[cfg(test)]
#[path = "tun_proxy_tests.rs"]
mod tun_proxy_tests;
#[cfg(test)]
#[path = "tun_runtime_tests.rs"]
mod tun_runtime_tests;
#[cfg(test)]
#[path = "tun_test_support.rs"]
mod tun_test_support;
#[cfg(test)]
#[path = "tun_unit_tests.rs"]
mod tun_unit_tests;
