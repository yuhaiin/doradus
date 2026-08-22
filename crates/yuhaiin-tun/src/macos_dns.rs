use std::io;
use std::net::IpAddr;
use std::process::Command;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

const NETWORKSETUP: &str = "/usr/sbin/networksetup";
const DEFAULT_ROUTE_CHECK_INTERVAL: Duration = Duration::from_secs(5);

struct AppliedDns {
    service: String,
    backup: Vec<String>,
}

impl AppliedDns {
    fn restore(&self) {
        if let Err(error) = set_dns_servers(&self.service, &self.backup) {
            crate::tun_debug(format!(
                "restore macOS DNS failed service={:?}: {error}",
                self.service
            ));
        }
    }
}

pub(crate) struct MacosDnsLease {
    state: Arc<Mutex<AppliedDns>>,
    stop: Option<Sender<()>>,
    join: Option<JoinHandle<()>>,
}

impl MacosDnsLease {
    pub(crate) fn apply(network_service: Option<&str>, dns_servers: &[IpAddr]) -> io::Result<Self> {
        let dns_servers = dns_servers
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();

        let requested_service = network_service
            .map(str::trim)
            .filter(|service| !service.is_empty());
        let service = match requested_service {
            Some(service) => service.to_owned(),
            None => default_network_service().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "default macOS network service unavailable",
                )
            })?,
        };

        let applied = apply_service(&service, &dns_servers)?;
        let state = Arc::new(Mutex::new(applied));

        if requested_service.is_some() {
            return Ok(Self {
                state,
                stop: None,
                join: None,
            });
        }

        let (stop, receiver) = mpsc::channel();
        let monitor_state = Arc::clone(&state);
        let monitor_dns = dns_servers.clone();
        let join = match thread::Builder::new()
            .name("yuhaiin-macos-dns".to_owned())
            .spawn(move || monitor_default_service(receiver, monitor_state, monitor_dns))
        {
            Ok(join) => join,
            Err(error) => {
                state
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .restore();
                return Err(error);
            }
        };

        Ok(Self {
            state,
            stop: Some(stop),
            join: Some(join),
        })
    }
}

impl Drop for MacosDnsLease {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .restore();
    }
}

fn monitor_default_service(
    receiver: Receiver<()>,
    state: Arc<Mutex<AppliedDns>>,
    dns_servers: Vec<String>,
) {
    loop {
        match receiver.recv_timeout(DEFAULT_ROUTE_CHECK_INTERVAL) {
            Ok(()) | Err(RecvTimeoutError::Disconnected) => return,
            Err(RecvTimeoutError::Timeout) => {}
        }

        let Some(service) = default_network_service() else {
            continue;
        };
        let mut applied = state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if applied.service == service {
            continue;
        }

        applied.restore();
        match apply_service(&service, &dns_servers) {
            Ok(next) => *applied = next,
            Err(error) => crate::tun_debug(format!(
                "apply macOS DNS after network change failed service={service:?}: {error}"
            )),
        }
    }
}

fn apply_service(service: &str, dns_servers: &[String]) -> io::Result<AppliedDns> {
    let backup = match get_dns_servers(service) {
        Ok(backup) => backup,
        Err(error) => {
            crate::tun_debug(format!(
                "read macOS DNS failed service={service:?}: {error}"
            ));
            Vec::new()
        }
    };
    set_dns_servers(service, dns_servers)?;
    Ok(AppliedDns {
        service: service.to_owned(),
        backup,
    })
}

fn get_dns_servers(service: &str) -> io::Result<Vec<String>> {
    let output = Command::new(NETWORKSETUP)
        .args(["-getdnsservers", service])
        .output()?;
    ensure_success("get DNS servers", service, &output)?;
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.trim().parse::<IpAddr>().ok())
        .map(|address| address.to_string())
        .collect())
}

fn set_dns_servers(service: &str, dns_servers: &[String]) -> io::Result<()> {
    let mut command = Command::new(NETWORKSETUP);
    command.args(["-setdnsservers", service]);
    if dns_servers.is_empty() {
        command.arg("empty");
    } else {
        command.args(dns_servers);
    }
    let output = command.output()?;
    ensure_success("set DNS servers", service, &output)
}

fn ensure_success(operation: &str, service: &str, output: &std::process::Output) -> io::Result<()> {
    if output.status.success() {
        return Ok(());
    }
    Err(io::Error::other(format!(
        "{operation} for service {service:?} failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    )))
}

fn default_network_service() -> Option<String> {
    let output = Command::new("/sbin/route")
        .args(["-n", "get", "default"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let interface = parse_default_route_interface(&String::from_utf8_lossy(&output.stdout))?;
    hardware_port_for_device(&interface).ok()
}

fn parse_default_route_interface(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        (key.trim() == "interface")
            .then(|| value.trim())
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
    })
}

fn hardware_port_for_device(device: &str) -> io::Result<String> {
    let output = Command::new(NETWORKSETUP)
        .arg("-listallhardwareports")
        .output()?;
    ensure_success("list hardware ports", device, &output)?;

    for block in String::from_utf8_lossy(&output.stdout).split("\n\n") {
        let mut port = None;
        let mut found_device = None;
        for line in block.lines() {
            if let Some(value) = line.strip_prefix("Hardware Port:") {
                port = Some(value.trim().to_owned());
            } else if let Some(value) = line.strip_prefix("Device:") {
                found_device = Some(value.trim());
            }
        }
        if found_device == Some(device) {
            if let Some(port) = port.filter(|port| !port.is_empty()) {
                return Ok(port);
            }
        }
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("macOS hardware port for device {device:?} not found"),
    ))
}

#[cfg(test)]
mod tests {
    use super::parse_default_route_interface;

    #[test]
    fn parses_default_route_interface() {
        let output = "routing:
        interface: en0
        gateway: 192.0.2.1
        ";
        assert_eq!(
            parse_default_route_interface(output).as_deref(),
            Some("en0")
        );
    }

    #[test]
    fn ignores_missing_default_route_interface() {
        assert_eq!(parse_default_route_interface("gateway: 192.0.2.1"), None);
    }
}
