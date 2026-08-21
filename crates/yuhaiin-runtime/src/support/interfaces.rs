use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use crate::RuntimeSettings;

/// The management API contract used by the Go `tools.Interfaces` handler.
///
/// Keep this as the shared response type instead of making the API layer
/// construct a second, slightly different DTO. Go omits loopback interfaces
/// and returns addresses in CIDR form, so the platform discovery code below
/// normalizes to that same shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InterfaceInfo {
    pub name: String,
    pub addresses: Vec<String>,
}

pub fn discover_interfaces() -> Vec<InterfaceInfo> {
    #[cfg(target_os = "linux")]
    if let Ok(interfaces) = linux::discover() {
        return interfaces;
    }

    fallback()
}

/// Find the interface owning an address using the same address snapshot that
/// backs `tools.interfaces`.  This is intentionally best-effort: a socket can
/// be created by a platform-specific binder that is not represented in the
/// portable interface listing, in which case the connection field stays empty
/// instead of reporting a guessed interface.
pub fn interface_for_ip(ip: std::net::IpAddr) -> Option<String> {
    let by_address = discover_interfaces().into_iter().find_map(|interface| {
        interface
            .addresses
            .iter()
            .any(|cidr| cidr_contains(cidr, ip))
            .then_some(interface.name)
    });
    by_address.or_else(|| {
        #[cfg(target_os = "linux")]
        {
            linux::route_interface_for_ip(ip)
        }
        #[cfg(not(target_os = "linux"))]
        {
            None
        }
    })
}

/// Resolve the explicit interface setting into concrete source addresses.
/// This remains the fallback for platforms without an interface-level socket
/// binding API. The automatic default-interface mode is represented by the
/// dynamic marker below and is resolved by core for every new socket.
pub(crate) fn bind_addresses_for_settings(settings: &RuntimeSettings) -> Vec<IpAddr> {
    if settings.use_default_interface {
        return Vec::new();
    }

    let requested = settings.net_interface.trim();
    let name = if requested.eq_ignore_ascii_case("default") {
        #[cfg(target_os = "linux")]
        {
            linux::route_interface_for_ip(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED))
        }
        #[cfg(not(target_os = "linux"))]
        {
            None
        }
    } else if requested.is_empty() {
        None
    } else {
        Some(requested.to_owned())
    };
    let Some(name) = name else {
        return Vec::new();
    };
    discover_interfaces()
        .into_iter()
        .find(|interface| interface.name == name)
        .map(|interface| {
            interface
                .addresses
                .iter()
                .filter_map(|cidr| cidr.split_once('/').and_then(|(ip, _)| ip.parse().ok()))
                .collect()
        })
        .unwrap_or_default()
}

/// Resolve the global outbound interface policy without taking a snapshot of
/// the current default route. The marker is intentionally passed through the
/// runtime and resolved by core immediately before each socket is created, so
/// a network change does not require rebuilding every proxy.
pub(crate) fn bind_interface_for_settings(settings: &RuntimeSettings) -> Option<String> {
    if settings.use_default_interface {
        return Some(yuhaiin_core::proxy::DEFAULT_INTERFACE.to_owned());
    }
    let requested = settings.net_interface.trim();
    if requested.eq_ignore_ascii_case("default") {
        return Some(yuhaiin_core::proxy::DEFAULT_INTERFACE.to_owned());
    }
    (!requested.is_empty()).then(|| requested.to_owned())
}

fn cidr_contains(cidr: &str, ip: std::net::IpAddr) -> bool {
    let Some((network, prefix)) = cidr.rsplit_once('/') else {
        return false;
    };
    let Ok(prefix) = prefix.parse::<u8>() else {
        return false;
    };
    match (network.parse::<std::net::IpAddr>(), ip) {
        (Ok(std::net::IpAddr::V4(network)), std::net::IpAddr::V4(ip)) if prefix <= 32 => {
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            u32::from(network) & mask == u32::from(ip) & mask
        }
        (Ok(std::net::IpAddr::V6(network)), std::net::IpAddr::V6(ip)) if prefix <= 128 => {
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            u128::from(network) & mask == u128::from(ip) & mask
        }
        _ => false,
    }
}

fn assemble(
    devices: &BTreeMap<u32, (String, bool)>,
    addresses: impl IntoIterator<Item = (u32, String)>,
) -> Vec<InterfaceInfo> {
    let mut by_index = devices
        .values()
        .filter(|(_, loopback)| !*loopback)
        .map(|(name, _)| (name.clone(), BTreeSet::new()))
        .collect::<BTreeMap<_, _>>();

    for (index, address) in addresses {
        let Some((name, _)) = devices.get(&index) else {
            continue;
        };
        if let Some(existing) = by_index.get_mut(name) {
            existing.insert(address);
        }
    }

    by_index
        .into_iter()
        .map(|(name, addresses)| InterfaceInfo {
            name,
            addresses: addresses.into_iter().collect(),
        })
        .collect()
}

fn fallback() -> Vec<InterfaceInfo> {
    let mut devices = BTreeMap::new();
    let Ok(entries) = std::fs::read_dir("/sys/class/net") else {
        return Vec::new();
    };

    for entry in entries.flatten() {
        let Some(name) = entry.file_name().to_str().map(ToOwned::to_owned) else {
            continue;
        };
        if name == "lo" || is_loopback(&entry.path()) {
            continue;
        }
        let index = devices.len() as u32;
        devices.insert(index, (name, false));
    }

    let addresses = ipv6_proc_addresses(&devices);
    assemble(&devices, addresses)
}

fn is_loopback(path: &std::path::Path) -> bool {
    std::fs::read_to_string(path.join("flags"))
        .ok()
        .and_then(|flags| u32::from_str_radix(flags.trim().trim_start_matches("0x"), 16).ok())
        .is_some_and(|flags| flags & 0x8 != 0)
}

#[cfg(target_os = "linux")]
fn ipv6_proc_addresses(devices: &BTreeMap<u32, (String, bool)>) -> Vec<(u32, String)> {
    let names = devices
        .iter()
        .map(|(index, (name, _))| (name.as_str(), *index))
        .collect::<BTreeMap<_, _>>();
    let Ok(content) = std::fs::read_to_string("/proc/net/if_inet6") else {
        return Vec::new();
    };

    content
        .lines()
        .filter_map(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            if fields.len() < 6 || fields[0].len() != 32 {
                return None;
            }
            let index = names.get(fields[5])?;
            let prefix = u8::from_str_radix(fields[2], 16).ok()?;
            let mut bytes = [0u8; 16];
            for (offset, chunk) in fields[0].as_bytes().chunks_exact(2).enumerate() {
                bytes[offset] = u8::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
            }
            Some((
                *index,
                format!("{}/{prefix}", std::net::Ipv6Addr::from(bytes)),
            ))
        })
        .collect()
}

#[cfg(not(target_os = "linux"))]
fn ipv6_proc_addresses(_devices: &BTreeMap<u32, (String, bool)>) -> Vec<(u32, String)> {
    Vec::new()
}

#[cfg(target_os = "linux")]
mod linux {
    use super::{InterfaceInfo, assemble};
    use netlink_packet_core::{
        NLM_F_DUMP, NLM_F_REQUEST, NetlinkHeader, NetlinkMessage, NetlinkPayload,
    };
    use netlink_packet_route::address::{AddressAttribute, AddressMessage};
    use netlink_packet_route::{AddressFamily, RouteNetlinkMessage};
    use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_ROUTE};
    use std::collections::BTreeMap;
    use std::io;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    pub(super) fn discover() -> io::Result<Vec<InterfaceInfo>> {
        let devices = devices()?;
        let addresses = dump_addresses()?;
        Ok(assemble(&devices, addresses))
    }

    pub(super) fn route_interface_for_ip(ip: IpAddr) -> Option<String> {
        match ip {
            IpAddr::V4(ip) => route_interface_v4(ip),
            IpAddr::V6(ip) => route_interface_v6(ip),
        }
    }

    fn route_interface_v4(ip: Ipv4Addr) -> Option<String> {
        let content = std::fs::read_to_string("/proc/net/route").ok()?;
        let target = u32::from(ip);
        content
            .lines()
            .skip(1)
            .filter_map(|line| {
                let fields = line.split_whitespace().collect::<Vec<_>>();
                if fields.len() < 8 {
                    return None;
                }
                let destination = u32::from_str_radix(fields[1], 16).ok()?;
                let mask = u32::from_str_radix(fields[7], 16).ok()?;
                let prefix = mask.count_ones();
                let destination = u32::from_le(destination);
                let mask = u32::from_le(mask);
                (target & mask == destination & mask).then_some((prefix, fields[0].to_owned()))
            })
            .max_by_key(|(prefix, _)| *prefix)
            .map(|(_, interface)| interface)
    }

    fn route_interface_v6(ip: Ipv6Addr) -> Option<String> {
        let content = std::fs::read_to_string("/proc/net/ipv6_route").ok()?;
        let target = ip.octets();
        content
            .lines()
            .filter_map(|line| {
                let fields = line.split_whitespace().collect::<Vec<_>>();
                if fields.len() < 10 || fields[0].len() != 32 {
                    return None;
                }
                let prefix = u8::from_str_radix(fields[1], 16).ok()?;
                if prefix > 128 {
                    return None;
                }
                let mut network = [0u8; 16];
                for (offset, chunk) in fields[0].as_bytes().chunks_exact(2).enumerate() {
                    network[offset] =
                        u8::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
                }
                (prefix_matches(network, target, prefix)).then_some((prefix, fields[9].to_owned()))
            })
            .max_by_key(|(prefix, _)| *prefix)
            .map(|(_, interface)| interface)
    }

    fn prefix_matches(network: [u8; 16], target: [u8; 16], prefix: u8) -> bool {
        let full_bytes = usize::from(prefix / 8);
        if network[..full_bytes] != target[..full_bytes] {
            return false;
        }
        let remaining = prefix % 8;
        remaining == 0
            || (network[full_bytes] & (u8::MAX << (8 - remaining)))
                == (target[full_bytes] & (u8::MAX << (8 - remaining)))
    }

    fn devices() -> io::Result<BTreeMap<u32, (String, bool)>> {
        let mut devices = BTreeMap::new();
        for entry in std::fs::read_dir("/sys/class/net")? {
            let entry = entry?;
            let Some(name) = entry.file_name().to_str().map(ToOwned::to_owned) else {
                continue;
            };
            let Ok(index) =
                std::fs::read_to_string(entry.path().join("ifindex")).and_then(|value| {
                    value
                        .trim()
                        .parse::<u32>()
                        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
                })
            else {
                continue;
            };
            let loopback = name == "lo"
                || std::fs::read_to_string(entry.path().join("flags"))
                    .ok()
                    .and_then(|flags| {
                        u32::from_str_radix(flags.trim().trim_start_matches("0x"), 16).ok()
                    })
                    .is_some_and(|flags| flags & 0x8 != 0);
            devices.insert(index, (name, loopback));
        }
        Ok(devices)
    }

    fn dump_addresses() -> io::Result<Vec<(u32, String)>> {
        let mut socket = Socket::new(NETLINK_ROUTE)?;
        socket.bind_auto()?;
        socket.connect(&SocketAddr::new(0, 0))?;

        let mut header = NetlinkHeader::default();
        header.flags = NLM_F_DUMP | NLM_F_REQUEST;
        header.sequence_number = 1;
        let mut packet = NetlinkMessage::new(
            header,
            NetlinkPayload::from(RouteNetlinkMessage::GetAddress(AddressMessage::default())),
        );
        packet.finalize();
        let mut request = vec![0; packet.header.length as usize];
        packet.serialize(&mut request);
        socket.send(&request, 0)?;

        let mut receive_buffer = vec![0; 16 * 1024];
        let mut addresses = Vec::new();
        loop {
            let size = socket.recv(&mut &mut receive_buffer[..], 0)?;
            let mut offset = 0;
            while offset < size {
                let message = NetlinkMessage::<RouteNetlinkMessage>::deserialize(
                    &receive_buffer[offset..size],
                )
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
                let length = message.header.length as usize;
                if length == 0 || offset.saturating_add(length) > size {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid netlink message length",
                    ));
                }
                offset += length;

                match message.payload {
                    NetlinkPayload::Done(_) => return Ok(addresses),
                    NetlinkPayload::Error(error) => {
                        return Err(io::Error::other(format!("netlink address dump: {error:?}")));
                    }
                    NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewAddress(entry))
                        if matches!(
                            entry.header.family,
                            AddressFamily::Inet | AddressFamily::Inet6
                        ) =>
                    {
                        if let Some(address) = format_address(&entry) {
                            addresses.push((entry.header.index, address));
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    fn format_address(entry: &AddressMessage) -> Option<String> {
        let address = entry
            .attributes
            .iter()
            .find_map(|attribute| match attribute {
                AddressAttribute::Local(address) => Some(*address),
                _ => None,
            })
            .or_else(|| {
                entry
                    .attributes
                    .iter()
                    .find_map(|attribute| match attribute {
                        AddressAttribute::Address(address) => Some(*address),
                        _ => None,
                    })
            })?;
        Some(format!("{address}/{}", entry.header.prefix_len))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assemble_matches_go_interface_contract() {
        let devices = BTreeMap::from([
            (1, ("lo".to_owned(), true)),
            (2, ("eth0".to_owned(), false)),
            (3, ("tun0".to_owned(), false)),
        ]);
        let actual = assemble(
            &devices,
            [
                (1, "127.0.0.1/8".to_owned()),
                (2, "192.0.2.10/24".to_owned()),
                (2, "2001:db8::10/64".to_owned()),
                (2, "192.0.2.10/24".to_owned()),
                (999, "198.51.100.1/24".to_owned()),
            ],
        );

        assert_eq!(
            actual,
            vec![
                InterfaceInfo {
                    name: "eth0".to_owned(),
                    addresses: vec!["192.0.2.10/24".to_owned(), "2001:db8::10/64".to_owned(),],
                },
                InterfaceInfo {
                    name: "tun0".to_owned(),
                    addresses: Vec::new(),
                },
            ]
        );
    }

    #[test]
    fn interface_lookup_matches_ipv4_and_ipv6_cidrs() {
        assert!(cidr_contains("192.0.2.0/24", "192.0.2.44".parse().unwrap()));
        assert!(!cidr_contains(
            "192.0.2.0/24",
            "192.0.3.44".parse().unwrap()
        ));
        assert!(cidr_contains(
            "2001:db8::/32",
            "2001:db8:1::44".parse().unwrap()
        ));
        assert!(!cidr_contains(
            "2001:db8::/32",
            "2001:db9::44".parse().unwrap()
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn live_discovery_excludes_loopback() {
        let interfaces = discover_interfaces();
        assert!(!interfaces.iter().any(|interface| interface.name == "lo"));
        assert!(interfaces.iter().all(|interface| {
            interface.addresses.iter().all(|address| {
                address
                    .rsplit_once('/')
                    .is_some_and(|(_, prefix)| !prefix.is_empty())
            })
        }));
    }

    #[test]
    fn default_interface_setting_keeps_dynamic_marker() {
        let settings = RuntimeSettings::default();
        assert_eq!(
            bind_interface_for_settings(&settings).as_deref(),
            Some(yuhaiin_core::proxy::DEFAULT_INTERFACE)
        );
    }

    #[test]
    fn explicit_interface_setting_is_not_replaced_by_default_marker() {
        let settings = RuntimeSettings {
            use_default_interface: false,
            net_interface: "enp0s5".to_owned(),
            ..RuntimeSettings::default()
        };
        assert_eq!(
            bind_interface_for_settings(&settings).as_deref(),
            Some("enp0s5")
        );
    }
}
