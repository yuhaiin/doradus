use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

/// The management API contract used by the Go `tools.Interfaces` handler.
///
/// Keep this as the shared response type instead of making the API layer
/// construct a second, slightly different DTO. Go omits loopback interfaces
/// and returns addresses in CIDR form, so the platform discovery code below
/// normalizes to that same shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct InterfaceInfo {
    pub name: String,
    pub addresses: Vec<String>,
}

pub(crate) fn discover_interfaces() -> Vec<InterfaceInfo> {
    #[cfg(target_os = "linux")]
    if let Ok(interfaces) = linux::discover() {
        return interfaces;
    }

    fallback()
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

    pub(super) fn discover() -> io::Result<Vec<InterfaceInfo>> {
        let devices = devices()?;
        let addresses = dump_addresses()?;
        Ok(assemble(&devices, addresses))
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
}
