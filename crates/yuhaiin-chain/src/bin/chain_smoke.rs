use std::env;
use std::time::Duration;

use yuhaiin_chain::{ChainClient, parse_config};
use yuhaiin_core::{DomainName, Endpoint, Network};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = env::args()
        .nth(1)
        .ok_or("usage: chain-smoke CONFIG.json [tcp|uot]")?;
    let mode = env::args().nth(2).unwrap_or_else(|| "tcp".to_owned());
    let json = std::fs::read_to_string(path)?;
    let chain = parse_config(&json)?;
    println!(
        "chain-config-valid fixed={} concurrency={} sni={}",
        chain.fixed_addresses.len(),
        chain.http2.concurrency,
        chain.tls.server_name()
    );
    let client = ChainClient::new(chain.clone())?;

    match mode.as_str() {
        "tcp" => {
            let target =
                env::var("YUHAIIN_CHAIN_TARGET").unwrap_or_else(|_| "example.com:443".to_owned());
            let destination = endpoint(&target, Network::Tcp)?;
            let mut session = client.connect_tcp(destination).await?;
            println!("yuubinsya-tcp-header-sent");
            if env::var_os("YUHAIIN_CHAIN_PROBE").is_some() {
                session
                    .write_all(b"GET / HTTP/1.0\r\nHost: example.com\r\nConnection: close\r\n\r\n")
                    .await?;
                let mut response = vec![0u8; 4096];
                let length =
                    tokio::time::timeout(Duration::from_secs(5), session.read(&mut response))
                        .await??;
                println!("tcp-probe-reply-bytes={length}");
            }
        }
        "uot" => {
            let target =
                env::var("YUHAIIN_CHAIN_TARGET").unwrap_or_else(|_| "example.com:53".to_owned());
            let destination = endpoint(&target, Network::Udp)?;
            let mut session = client.connect_uot(0).await?;
            let probe = env::var_os("YUHAIIN_CHAIN_PROBE").is_some();
            let payload = if probe {
                dns_probe_query()
            } else {
                b"probe".to_vec()
            };
            session.send_to(&destination, &payload).await?;
            println!("yuubinsya-uot-frame-sent migrate_id={}", session.migrate_id);
            if probe {
                let (source, payload) =
                    tokio::time::timeout(Duration::from_secs(5), session.recv_from()).await??;
                println!("uot-reply source={source} bytes={}", payload.len());
            }
        }
        other => return Err(format!("unknown mode {other}, expected tcp or uot").into()),
    }
    Ok(())
}

fn dns_probe_query() -> Vec<u8> {
    // A small, valid A query for example.com, suitable for a UDP-over-TCP
    // round trip without pulling DNS policy into this transport smoke binary.
    vec![
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e', b'x',
        b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
    ]
}

fn endpoint(value: &str, network: Network) -> Result<Endpoint, Box<dyn std::error::Error>> {
    if let Ok(address) = value.parse() {
        return Ok(Endpoint::ip(network, address));
    }
    let (host, port) = value
        .rsplit_once(':')
        .ok_or("target must be HOST:PORT or IP:PORT")?;
    Ok(Endpoint::domain(
        network,
        DomainName::new(host)?,
        port.parse()?,
    ))
}
