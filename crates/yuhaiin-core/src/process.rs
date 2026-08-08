//! Process ownership lookup for flow-aware routing.
//!
//! Process lookup is deliberately a small, synchronous boundary.  The TUN
//! runtime only calls it when a flow is opened, so a platform implementation
//! can inspect the operating system without putting a blocking lookup inside
//! the proxy I/O task. Linux and Android use the proc filesystem; all other
//! platforms safely fall back to `None` until they provide their native
//! socket-ownership implementation.

use std::io;
use std::net::SocketAddr;
#[cfg(any(target_os = "linux", target_os = "android"))]
use std::path::Path;
use std::sync::Arc;

use crate::Network;

/// Process metadata attached to a flow context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessInfo {
    /// The executable path when the platform exposes it.
    pub path: String,
    pub pid: u32,
    pub uid: u32,
}

/// Platform boundary used by TUN routing to enrich a flow with process data.
///
/// A lookup failure is intentionally non-fatal: process metadata is an
/// optional routing matcher and a missing `/proc` permission must not stop
/// ordinary proxying.  Implementations can still return an I/O error so
/// callers that want diagnostics can distinguish it from a successful miss.
pub trait ProcessResolver: Send + Sync {
    fn resolve(
        &self,
        network: Network,
        source: SocketAddr,
        destination: SocketAddr,
    ) -> io::Result<Option<ProcessInfo>>;
}

/// Construct the resolver supported by the current target.
pub fn default_process_resolver() -> Option<Arc<dyn ProcessResolver>> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        return Some(Arc::new(LinuxProcResolver::default()));
    }

    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        None
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[derive(Debug, Clone)]
pub struct LinuxProcResolver {
    proc_root: std::path::PathBuf,
}

#[cfg(any(target_os = "linux", target_os = "android"))]
impl Default for LinuxProcResolver {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
impl LinuxProcResolver {
    pub fn new() -> Self {
        Self {
            proc_root: std::path::PathBuf::from("/proc"),
        }
    }

    /// Use a proc-compatible tree, primarily for deterministic unit tests.
    ///
    /// Production callers should use [`Self::new`].  The resolver never
    /// creates or modifies this path.
    pub fn with_proc_root(path: impl Into<std::path::PathBuf>) -> Self {
        Self {
            proc_root: path.into(),
        }
    }

    pub fn resolve_with_error(
        &self,
        network: Network,
        source: SocketAddr,
        destination: SocketAddr,
    ) -> io::Result<Option<ProcessInfo>> {
        let Some(socket) = self.find_socket(network, source, destination)? else {
            return Ok(None);
        };
        self.find_process(socket.inode, socket.uid)
    }

    fn find_socket(
        &self,
        network: Network,
        source: SocketAddr,
        destination: SocketAddr,
    ) -> io::Result<Option<SocketEntry>> {
        let (v4_name, v6_name) = match network {
            Network::Tcp => ("tcp", "tcp6"),
            Network::Udp => ("udp", "udp6"),
            Network::Icmp | Network::Any => return Ok(None),
        };

        for (name, ipv6) in [(v4_name, false), (v6_name, true)] {
            let path = self.proc_root.join("net").join(name);
            let text = match std::fs::read_to_string(path) {
                Ok(text) => text,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error),
            };
            for entry in parse_socket_table(&text, ipv6)? {
                if entry.matches(network, source, destination) {
                    return Ok(Some(entry));
                }
            }
        }
        Ok(None)
    }

    fn find_process(&self, inode: u64, uid: u32) -> io::Result<Option<ProcessInfo>> {
        let expected = format!("socket:[{inode}]");
        let entries = match std::fs::read_dir(&self.proc_root) {
            Ok(entries) => entries,
            Err(error) => return Err(error),
        };

        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(_) => continue,
            };
            let pid_text = entry.file_name();
            let Some(pid_text) = pid_text.to_str() else {
                continue;
            };
            let Ok(pid) = pid_text.parse::<u32>() else {
                continue;
            };
            let process_dir = entry.path();
            if read_process_uid(&process_dir).ok() != Some(uid) {
                continue;
            }

            let fd_dir = process_dir.join("fd");
            let fds = match std::fs::read_dir(fd_dir) {
                Ok(fds) => fds,
                Err(_) => continue,
            };
            for fd in fds {
                let Ok(fd) = fd else { continue };
                let Ok(target) = std::fs::read_link(fd.path()) else {
                    continue;
                };
                if target.to_string_lossy() != expected {
                    continue;
                }

                let path = read_process_path(&process_dir).ok();
                let Some(path) = path.filter(|path| !path.is_empty()) else {
                    continue;
                };
                return Ok(Some(ProcessInfo { path, pid, uid }));
            }
        }
        Ok(None)
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
impl ProcessResolver for LinuxProcResolver {
    fn resolve(
        &self,
        network: Network,
        source: SocketAddr,
        destination: SocketAddr,
    ) -> io::Result<Option<ProcessInfo>> {
        self.resolve_with_error(network, source, destination)
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SocketEntry {
    local: SocketAddr,
    remote: SocketAddr,
    uid: u32,
    inode: u64,
}

#[cfg(any(target_os = "linux", target_os = "android"))]
impl SocketEntry {
    fn matches(&self, network: Network, source: SocketAddr, destination: SocketAddr) -> bool {
        if self.local.port() != source.port()
            || !same_or_unspecified(self.local, source)
            || self.local.is_ipv4() != source.is_ipv4()
        {
            return false;
        }

        match network {
            Network::Tcp => self.remote == destination,
            Network::Udp => {
                self.remote == destination
                    || self.remote.port() == 0
                    || self.remote.ip().is_unspecified()
            }
            Network::Icmp | Network::Any => false,
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn same_or_unspecified(left: SocketAddr, right: SocketAddr) -> bool {
    left.ip() == right.ip() || left.ip().is_unspecified()
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn parse_socket_table(text: &str, ipv6: bool) -> io::Result<Vec<SocketEntry>> {
    let mut entries = Vec::new();
    for line in text.lines().skip(1) {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() <= 9 {
            continue;
        }
        let local = parse_proc_endpoint(fields[1], ipv6)?;
        let remote = parse_proc_endpoint(fields[2], ipv6)?;
        let uid = fields[7].parse::<u32>().map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid proc socket uid: {error}"),
            )
        })?;
        let inode = fields[9].parse::<u64>().map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid proc socket inode: {error}"),
            )
        })?;
        entries.push(SocketEntry {
            local,
            remote,
            uid,
            inode,
        });
    }
    Ok(entries)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn parse_proc_endpoint(value: &str, ipv6: bool) -> io::Result<SocketAddr> {
    let (address, port) = value.split_once(':').ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "proc socket endpoint has no port",
        )
    })?;
    let port = u16::from_str_radix(port, 16).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid proc socket port: {error}"),
        )
    })?;
    if ipv6 {
        if address.len() != 32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "proc IPv6 socket address must contain 32 hex digits",
            ));
        }
        let mut bytes = [0u8; 16];
        for (chunk, output) in address
            .as_bytes()
            .chunks_exact(8)
            .zip(bytes.chunks_exact_mut(4))
        {
            let word = u32::from_str_radix(std::str::from_utf8(chunk).unwrap_or_default(), 16)
                .map_err(|error| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("invalid proc IPv6 socket address: {error}"),
                    )
                })?;
            output.copy_from_slice(&word.to_le_bytes());
        }
        Ok(SocketAddr::new(
            std::net::Ipv6Addr::from(bytes).into(),
            port,
        ))
    } else {
        if address.len() != 8 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "proc IPv4 socket address must contain 8 hex digits",
            ));
        }
        let value = u32::from_str_radix(address, 16).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid proc IPv4 socket address: {error}"),
            )
        })?;
        Ok(SocketAddr::new(
            std::net::Ipv4Addr::from(value.to_le_bytes()).into(),
            port,
        ))
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn read_process_uid(process_dir: &Path) -> io::Result<u32> {
    let status = std::fs::read_to_string(process_dir.join("status"))?;
    let uid = status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:").map(str::trim))
        .and_then(|line| line.split_whitespace().next())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "process has no Uid field"))?;
    uid.parse::<u32>().map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid process uid: {error}"),
        )
    })
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn read_process_path(process_dir: &Path) -> io::Result<String> {
    match std::fs::read_link(process_dir.join("exe")) {
        Ok(path) => Ok(path.to_string_lossy().into_owned()),
        Err(_) => {
            let comm = std::fs::read_to_string(process_dir.join("comm"))?;
            Ok(comm.trim().to_owned())
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream, UdpSocket};

    #[test]
    fn parses_linux_proc_endpoints_in_kernel_byte_order() {
        assert_eq!(
            parse_proc_endpoint("0100007F:CFC0", false).unwrap(),
            "127.0.0.1:53184".parse().unwrap()
        );
        assert_eq!(
            parse_proc_endpoint("00000000000000000000000001000000:0035", true).unwrap(),
            "[::1]:53".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn parses_socket_table_uid_and_inode() {
        let table = "  sl local_address rem_address st tx_queue rx_queue tr uid timeout inode\n   0: 0100007F:CFC0 0200007F:01BB 01 00000000:00000000 00:00000000 00000000 1000 0 12345 1";
        let entries = parse_socket_table(table, false).unwrap();
        assert_eq!(entries[0].local, "127.0.0.1:53184".parse().unwrap());
        assert_eq!(entries[0].remote, "127.0.0.2:443".parse().unwrap());
        assert_eq!(entries[0].uid, 1000);
        assert_eq!(entries[0].inode, 12345);
    }

    #[test]
    fn resolves_current_tcp_socket_to_this_process() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let destination = listener.local_addr().unwrap();
        let stream = TcpStream::connect(destination).unwrap();
        let source = stream.local_addr().unwrap();
        let resolver = LinuxProcResolver::default();
        let resolved = resolver
            .resolve(Network::Tcp, source, destination)
            .unwrap()
            .expect("current process TCP socket should be visible in /proc");
        assert_eq!(resolved.pid, std::process::id());
        assert!(!resolved.path.is_empty());
        drop(stream);
        drop(listener);
    }

    #[test]
    fn resolves_current_udp_socket_with_unconnected_remote() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let source = socket.local_addr().unwrap();
        let destination = "127.0.0.1:9".parse().unwrap();
        let resolver = LinuxProcResolver::default();
        let resolved = resolver
            .resolve(Network::Udp, source, destination)
            .unwrap()
            .expect("current process UDP socket should be visible in /proc");
        assert_eq!(resolved.pid, std::process::id());
        assert!(!resolved.path.is_empty());
    }
}
