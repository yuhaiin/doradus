use super::*;

pub(super) fn chain_mode_is_set() -> bool {
    std::env::var("DORADUS_TUN_CHAIN")
        .ok()
        .is_some_and(|value| !value.trim().is_empty())
}

pub(super) fn configured_tun_portal() -> String {
    std::env::var("DORADUS_TUN_PORTAL").unwrap_or_else(|_| "198.18.0.1/15".to_owned())
}

pub(super) fn configured_tun_portal_v6() -> Option<String> {
    std::env::var("DORADUS_TUN_PORTAL_V6")
        .ok()
        .filter(|value| !value.trim().is_empty())
}

pub(super) fn configured_tun_routes() -> Vec<String> {
    match std::env::var("DORADUS_TUN_ROUTE") {
        Ok(value) if value.eq_ignore_ascii_case("none") || value.trim().is_empty() => Vec::new(),
        Ok(value) => vec![value],
        Err(_) => vec!["198.18.0.2/32".to_owned()],
    }
}

pub(super) fn configured_tun_source() -> std::io::Result<std::net::IpAddr> {
    std::env::var("DORADUS_TUN_SOURCE")
        .unwrap_or_else(|_| "198.18.0.1".to_owned())
        .parse()
        .map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid DORADUS_TUN_SOURCE: {error}"),
            )
        })
}

pub(super) fn configured_tun_ipv6_source() -> std::io::Result<Ipv6Addr> {
    std::env::var("DORADUS_TUN_IPV6_SOURCE")
        .unwrap_or_else(|_| "fd00:253::1".to_owned())
        .parse()
        .map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid DORADUS_TUN_IPV6_SOURCE: {error}"),
            )
        })
}

pub(super) fn configured_tun_target() -> std::io::Result<SocketAddr> {
    std::env::var("DORADUS_TUN_TARGET")
        .unwrap_or_else(|_| "198.18.0.2:18080".to_owned())
        .parse()
        .map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid DORADUS_TUN_TARGET: {error}"),
            )
        })
}

pub(super) fn configured_tun_udp_target() -> std::io::Result<SocketAddr> {
    std::env::var("DORADUS_TUN_UDP_TARGET").map_or_else(
        |_| configured_tun_target(),
        |value| {
            value.parse().map_err(|error| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("invalid DORADUS_TUN_UDP_TARGET: {error}"),
                )
            })
        },
    )
}

pub(super) fn configured_tun_ipv6_target() -> std::io::Result<SocketAddrV6> {
    let value = std::env::var("DORADUS_TUN_IPV6_TARGET")
        .unwrap_or_else(|_| "[fd00:253::2]:18080".to_owned());
    value.parse().map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid DORADUS_TUN_IPV6_TARGET: {error}"),
        )
    })
}
