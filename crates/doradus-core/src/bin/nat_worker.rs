use std::env;
use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use std::thread;
use std::time::Duration;

use doradus_core::Network;
use doradus_core::nat::{NatKey, UdpNatRelay};

fn usage() -> ! {
    eprintln!("usage: nat-worker <bind> <source> <destination> <ready-file> <event-file>");
    std::process::exit(2);
}

fn parse_addr(value: Option<String>) -> SocketAddr {
    value
        .unwrap_or_else(|| usage())
        .parse()
        .unwrap_or_else(|_| usage())
}

fn write_ready(path: &Path, address: SocketAddr) {
    fs::write(path, format!("{address}\n")).unwrap_or_else(|error| {
        eprintln!("write ready file {}: {error}", path.display());
        std::process::exit(1);
    });
}

fn main() {
    let mut arguments = env::args().skip(1);
    let bind = parse_addr(arguments.next());
    let source = parse_addr(arguments.next());
    let destination = parse_addr(arguments.next());
    let ready = arguments.next().unwrap_or_else(|| usage());
    let event = arguments.next().unwrap_or_else(|| usage());

    let table = doradus_core::nat::NatTable::new();
    let relay = UdpNatRelay::bind(bind, table, Duration::from_secs(30)).unwrap_or_else(|error| {
        eprintln!("bind NAT relay: {error}");
        std::process::exit(1);
    });
    let key = NatKey {
        network: Network::Udp,
        source,
        destination,
    };
    relay.send_to(key, b"bootstrap").unwrap_or_else(|error| {
        eprintln!("create NAT mapping: {error}");
        std::process::exit(1);
    });
    write_ready(Path::new(&ready), relay.local_addr().unwrap());

    let mut buffer = [0u8; 2048];
    loop {
        match relay.recv_from(&mut buffer) {
            Ok((received_key, length, peer)) => {
                let record = format!(
                    "source={} peer={} payload={}\n",
                    received_key.source,
                    peer,
                    String::from_utf8_lossy(&buffer[..length])
                );
                fs::write(&event, record).unwrap_or_else(|error| {
                    eprintln!("write event file {}: {error}", event);
                    std::process::exit(1);
                });
            }
            Err(error) if error.kind == doradus_core::ErrorKind::Timeout => {
                thread::yield_now();
            }
            Err(error) => {
                eprintln!("receive NAT packet: {error}");
                std::process::exit(1);
            }
        }
    }
}
