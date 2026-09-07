use std::sync::Mutex;

use openvpn_connect::{
    ExternalTun, ExternalTunConfig, ExternalTunInfo, ExternalTunIo, ExternalTunStartConfig,
};
use smoltcp::wire::{IpCidr, Ipv4Address, Ipv4Cidr, Ipv6Address, Ipv6Cidr};
use tokio::sync::mpsc;

const DEFAULT_MTU: usize = 1_500;
const EVENT_QUEUE_CAPACITY: usize = 256;

pub(crate) enum TunEvent {
    Started {
        io: ExternalTunIo,
        addresses: Vec<IpCidr>,
        mtu: usize,
    },
    Packet(Vec<u8>),
    Stopped,
}

#[derive(Default)]
struct TunState {
    info: ExternalTunInfo,
}

pub(crate) struct ExternalTunBridge {
    events: mpsc::Sender<TunEvent>,
    state: Mutex<TunState>,
}

impl ExternalTunBridge {
    pub(crate) fn channel() -> (Self, mpsc::Receiver<TunEvent>) {
        let (events, receiver) = mpsc::channel(EVENT_QUEUE_CAPACITY);
        (
            Self {
                events,
                state: Mutex::new(TunState::default()),
            },
            receiver,
        )
    }
}

impl ExternalTun for ExternalTunBridge {
    fn configure(&self, config: &ExternalTunConfig) -> bool {
        config.layer == 3
    }

    fn start(&self, config: &ExternalTunStartConfig, io: ExternalTunIo) {
        let parsed = ParsedTunOptions::parse(&config.options);
        let mtu = parsed.mtu.unwrap_or(DEFAULT_MTU).max(576);
        let addresses = parsed.addresses();
        if addresses.is_empty() {
            let _ = io.error("OpenVPN did not provide a usable IPv4 or IPv6 tunnel address");
            return;
        }

        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .info = parsed.external_info(mtu);
        if io.pre_tun_config().is_err() || io.pre_route_config().is_err() {
            return;
        }
        if self
            .events
            .blocking_send(TunEvent::Started {
                io: io.clone(),
                addresses,
                mtu,
            })
            .is_err()
        {
            let _ = io.error("doradus OpenVPN userspace TUN driver is closed");
            return;
        }
        let _ = io.connected();
    }

    fn stop(&self) {
        let _ = self.events.try_send(TunEvent::Stopped);
    }

    fn send(&self, packet: &[u8]) -> bool {
        self.events
            .try_send(TunEvent::Packet(packet.to_vec()))
            .is_ok()
    }

    fn info(&self) -> ExternalTunInfo {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .info
            .clone()
    }
}

#[derive(Default)]
struct ParsedTunOptions {
    ipv4: Option<std::net::Ipv4Addr>,
    ipv4_prefix: Option<u8>,
    gateway_ipv4: Option<std::net::Ipv4Addr>,
    ipv6: Option<std::net::Ipv6Addr>,
    ipv6_prefix: Option<u8>,
    gateway_ipv6: Option<std::net::Ipv6Addr>,
    mtu: Option<usize>,
}

impl ParsedTunOptions {
    fn parse(options: &str) -> Self {
        let mut parsed = Self::default();
        for line in options.lines() {
            let mut parts = line.split_whitespace();
            let Some(kind) = parts.next() else { continue };
            match kind {
                "ifconfig" => {
                    parsed.ipv4 = parts.next().and_then(|value| value.parse().ok());
                    if let Some(value) = parts.next() {
                        if let Ok(mask) = value.parse::<std::net::Ipv4Addr>() {
                            parsed.ipv4_prefix = ipv4_mask_prefix(mask);
                        } else {
                            parsed.gateway_ipv4 = value.parse().ok();
                        }
                    }
                }
                "ifconfig-ipv6" => {
                    if let Some(value) = parts.next() {
                        let (address, prefix) = value.split_once('/').unwrap_or((value, "128"));
                        parsed.ipv6 = address.parse().ok();
                        parsed.ipv6_prefix =
                            prefix.parse::<u8>().ok().filter(|value| *value <= 128);
                    }
                    parsed.gateway_ipv6 = parts.next().and_then(|value| value.parse().ok());
                }
                "tun-mtu" => {
                    parsed.mtu = parts.next().and_then(|value| value.parse::<usize>().ok());
                }
                _ => {}
            }
        }
        parsed
    }

    fn addresses(&self) -> Vec<IpCidr> {
        let mut addresses = Vec::with_capacity(2);
        if let Some(ip) = self.ipv4 {
            addresses.push(IpCidr::Ipv4(Ipv4Cidr::new(
                Ipv4Address::from_octets(ip.octets()),
                self.ipv4_prefix.unwrap_or(32),
            )));
        }
        if let Some(ip) = self.ipv6 {
            addresses.push(IpCidr::Ipv6(Ipv6Cidr::new(
                Ipv6Address::from_octets(ip.octets()),
                self.ipv6_prefix.unwrap_or(128),
            )));
        }
        addresses
    }

    fn external_info(&self, mtu: usize) -> ExternalTunInfo {
        ExternalTunInfo {
            name: "doradus-openvpn".to_owned(),
            vpn_ipv4: self.ipv4.map(|value| value.to_string()).unwrap_or_default(),
            vpn_ipv6: self.ipv6.map(|value| value.to_string()).unwrap_or_default(),
            gateway_ipv4: self
                .gateway_ipv4
                .map(|value| value.to_string())
                .unwrap_or_default(),
            gateway_ipv6: self
                .gateway_ipv6
                .map(|value| value.to_string())
                .unwrap_or_default(),
            mtu: i32::try_from(mtu).unwrap_or(DEFAULT_MTU as i32),
            interface_index: None,
        }
    }
}

fn ipv4_mask_prefix(mask: std::net::Ipv4Addr) -> Option<u8> {
    let value = u32::from(mask);
    let prefix = value.leading_ones() as u8;
    let expected = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    (value == expected).then_some(prefix)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_ipv6_and_mtu_from_openvpn_tun_options() {
        let parsed = ParsedTunOptions::parse(
            "ifconfig 10.8.0.2 255.255.255.0\nifconfig-ipv6 2001:db8::2/64 2001:db8::1\ntun-mtu 1420\n",
        );
        assert_eq!(parsed.ipv4.unwrap().to_string(), "10.8.0.2");
        assert_eq!(parsed.ipv4_prefix, Some(24));
        assert_eq!(parsed.ipv6.unwrap().to_string(), "2001:db8::2");
        assert_eq!(parsed.ipv6_prefix, Some(64));
        assert_eq!(parsed.mtu, Some(1420));
        assert_eq!(parsed.addresses().len(), 2);
    }
}
