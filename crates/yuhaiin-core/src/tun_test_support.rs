pub(super) use smoltcp::iface::{Config, Interface, SocketSet};
pub(super) use smoltcp::phy::{ChecksumCapabilities, Device, Medium, TxToken};
pub(super) use smoltcp::socket::{icmp, tcp, udp};
pub(super) use smoltcp::wire::{
    HardwareAddress, Icmpv4Packet, Icmpv4Repr, Icmpv6Packet, Icmpv6Repr, IpAddress, IpProtocol,
    Ipv4Address, Ipv4Packet, Ipv4Repr, Ipv6Address, Ipv6Packet, Ipv6Repr, TcpControl, TcpPacket,
    TcpRepr, TcpSeqNumber, UdpPacket, UdpRepr,
};

pub(super) fn udp_packet(
    source: Ipv4Address,
    destination: Ipv4Address,
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut bytes = vec![0; 20 + 8 + payload.len()];
    let ip_address_source = IpAddress::Ipv4(source);
    let ip_address_destination = IpAddress::Ipv4(destination);
    {
        let mut ip = Ipv4Packet::new_unchecked(&mut bytes[..]);
        Ipv4Repr {
            src_addr: source,
            dst_addr: destination,
            next_header: IpProtocol::Udp,
            payload_len: 8 + payload.len(),
            hop_limit: 64,
        }
        .emit(&mut ip, &ChecksumCapabilities::default());
        UdpRepr {
            src_port: source_port,
            dst_port: destination_port,
        }
        .emit(
            &mut UdpPacket::new_unchecked(ip.payload_mut()),
            &ip_address_source,
            &ip_address_destination,
            payload.len(),
            |packet| packet.copy_from_slice(payload),
            &ChecksumCapabilities::default(),
        );
    }
    bytes
}

pub(super) fn tcp_syn_packet(
    source: Ipv4Address,
    destination: Ipv4Address,
    source_port: u16,
    destination_port: u16,
    sequence: u32,
) -> Vec<u8> {
    let mut bytes = vec![0; 20 + 20];
    let ip_address_source = IpAddress::Ipv4(source);
    let ip_address_destination = IpAddress::Ipv4(destination);
    {
        let mut ip = Ipv4Packet::new_unchecked(&mut bytes[..]);
        Ipv4Repr {
            src_addr: source,
            dst_addr: destination,
            next_header: IpProtocol::Tcp,
            payload_len: 20,
            hop_limit: 64,
        }
        .emit(&mut ip, &ChecksumCapabilities::default());
        TcpRepr {
            src_port: source_port,
            dst_port: destination_port,
            control: TcpControl::Syn,
            seq_number: TcpSeqNumber(sequence as i32),
            ack_number: None,
            window_len: 4096,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None, None, None],
            timestamp: None,
            payload: &[],
        }
        .emit(
            &mut TcpPacket::new_unchecked(ip.payload_mut()),
            &ip_address_source,
            &ip_address_destination,
            &ChecksumCapabilities::default(),
        );
    }
    bytes
}

pub(super) fn tcp_data_packet(
    source: Ipv4Address,
    destination: Ipv4Address,
    source_port: u16,
    destination_port: u16,
    sequence: u32,
    acknowledgement: u32,
    payload: &[u8],
) -> Vec<u8> {
    let mut bytes = vec![0; 20 + 20 + payload.len()];
    let ip_address_source = IpAddress::Ipv4(source);
    let ip_address_destination = IpAddress::Ipv4(destination);
    {
        let mut ip = Ipv4Packet::new_unchecked(&mut bytes[..]);
        Ipv4Repr {
            src_addr: source,
            dst_addr: destination,
            next_header: IpProtocol::Tcp,
            payload_len: 20 + payload.len(),
            hop_limit: 64,
        }
        .emit(&mut ip, &ChecksumCapabilities::default());
        TcpRepr {
            src_port: source_port,
            dst_port: destination_port,
            control: TcpControl::Psh,
            seq_number: TcpSeqNumber(sequence as i32),
            ack_number: Some(TcpSeqNumber(acknowledgement as i32)),
            window_len: 4096,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None, None, None],
            timestamp: None,
            payload,
        }
        .emit(
            &mut TcpPacket::new_unchecked(ip.payload_mut()),
            &ip_address_source,
            &ip_address_destination,
            &ChecksumCapabilities::default(),
        );
    }
    bytes
}

pub(super) fn icmp_echo_packet(
    source: Ipv4Address,
    destination: Ipv4Address,
    ident: u16,
    sequence: u16,
    payload: &[u8],
    reply: bool,
) -> Vec<u8> {
    let icmp_repr = if reply {
        Icmpv4Repr::EchoReply {
            ident,
            seq_no: sequence,
            data: payload,
        }
    } else {
        Icmpv4Repr::EchoRequest {
            ident,
            seq_no: sequence,
            data: payload,
        }
    };
    let mut bytes = vec![0; 20 + icmp_repr.buffer_len()];
    {
        let mut ip = Ipv4Packet::new_unchecked(&mut bytes[..]);
        Ipv4Repr {
            src_addr: source,
            dst_addr: destination,
            next_header: IpProtocol::Icmp,
            payload_len: icmp_repr.buffer_len(),
            hop_limit: 64,
        }
        .emit(&mut ip, &ChecksumCapabilities::default());
        icmp_repr.emit(
            &mut Icmpv4Packet::new_unchecked(ip.payload_mut()),
            &ChecksumCapabilities::default(),
        );
    }
    bytes
}

pub(super) fn icmpv6_echo_packet(
    source: Ipv6Address,
    destination: Ipv6Address,
    ident: u16,
    sequence: u16,
    payload: &[u8],
    reply: bool,
) -> Vec<u8> {
    let icmp_repr = if reply {
        Icmpv6Repr::EchoReply {
            ident,
            seq_no: sequence,
            data: payload,
        }
    } else {
        Icmpv6Repr::EchoRequest {
            ident,
            seq_no: sequence,
            data: payload,
        }
    };
    let mut bytes = vec![0; 40 + icmp_repr.buffer_len()];
    {
        let mut ip = Ipv6Packet::new_unchecked(&mut bytes[..]);
        Ipv6Repr {
            src_addr: source,
            dst_addr: destination,
            next_header: IpProtocol::Icmpv6,
            payload_len: icmp_repr.buffer_len(),
            hop_limit: 64,
        }
        .emit(&mut ip);
        icmp_repr.emit(
            &source,
            &destination,
            &mut Icmpv6Packet::new_unchecked(ip.payload_mut()),
            &ChecksumCapabilities::default(),
        );
    }
    bytes
}
