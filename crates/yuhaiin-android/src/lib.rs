//! JNI host boundary for the Android VPN service.
//!
//! Android owns the VpnService permission flow and establishes the TUN
//! device. Rust owns the descriptor after nativeStart succeeds, then runs
//! the same RuntimeService used by the desktop binary. No Android API or
//! JNI type crosses into the runtime crates.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;
use std::sync::atomic::{AtomicI64, AtomicU16, Ordering};
use std::sync::{Arc, Mutex, OnceLock, mpsc};
use std::thread::{self, JoinHandle};

use jni::Env;
use jni::EnvUnowned;
use jni::errors::{Error as JniError, ThrowRuntimeExAndDefault};
use jni::objects::{JClass, JString};
use jni::sys::{jint, jlong};
use tokio::runtime::Builder;
use tokio::sync::oneshot;
use yuhaiin_api::service::{InjectedTun, RuntimeService, ServiceOptions};
use yuhaiin_runtime::TunRuntimeConfig;

const DEFAULT_QUEUE_CAPACITY: usize = 256;
const DEFAULT_CHANNEL_CAPACITY: usize = 256;
const DEFAULT_SOCKET_BUFFER_SIZE: usize = 8 * 1024;
const DEFAULT_UDP_PACKET_CAPACITY: usize = 64;

struct NativeRuntime {
    stop: Mutex<Option<oneshot::Sender<()>>>,
    thread: Mutex<Option<JoinHandle<()>>>,
    api_port: Arc<AtomicU16>,
}

static NEXT_HANDLE: AtomicI64 = AtomicI64::new(1);
static RUNTIMES: OnceLock<Mutex<HashMap<i64, NativeRuntime>>> = OnceLock::new();

fn runtimes() -> &'static Mutex<HashMap<i64, NativeRuntime>> {
    RUNTIMES.get_or_init(|| Mutex::new(HashMap::new()))
}

fn jni_string(env: &mut Env<'_>, value: JString<'_>, name: &str) -> jni::errors::Result<String> {
    value.try_to_string(env).map_err(|error| {
        JniError::ParseFailed(format!("{name} is not a valid Java string: {error}"))
    })
}

fn parse_ipv4(value: &str, name: &str) -> std::result::Result<Ipv4Addr, String> {
    value
        .parse()
        .map_err(|error| format!("{name} is not a valid IPv4 address: {error}"))
}

fn parse_ipv6(value: &str, name: &str) -> std::result::Result<Ipv6Addr, String> {
    value
        .parse()
        .map_err(|error| format!("{name} is not a valid IPv6 address: {error}"))
}

fn prefix(value: jint, max: u8, name: &str) -> std::result::Result<u8, String> {
    u8::try_from(value)
        .ok()
        .filter(|value| *value <= max)
        .ok_or_else(|| format!("{name} prefix is outside 0..={max}: {value}"))
}

fn injected_tun(
    fd: jint,
    mtu: jint,
    ipv4: &str,
    ipv4_prefix: jint,
    ipv6: &str,
    ipv6_prefix: jint,
) -> std::result::Result<InjectedTun, String> {
    if fd < 0 {
        return Err(format!("TUN fd is invalid: {fd}"));
    }
    // Take ownership before validating the remaining arguments so every
    // failure path closes the descriptor transferred by detachFd().
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let mtu = usize::try_from(mtu).map_err(|_| format!("TUN MTU is invalid: {mtu}"))?;
    let ipv4 = parse_ipv4(ipv4, "TUN IPv4")?;
    let ipv4_prefix = prefix(ipv4_prefix, 32, "TUN IPv4")?;
    let ipv6 = parse_ipv6(ipv6, "TUN IPv6")?;
    let ipv6_prefix = prefix(ipv6_prefix, 128, "TUN IPv6")?;

    let config = TunRuntimeConfig {
        inbound_id: None,
        enabled: true,
        tun: yuhaiin_tun::TunConfig {
            name: Some("android-vpn".to_owned()),
            ipv4: Some((ipv4, ipv4_prefix)),
            ipv6: vec![(ipv6, ipv6_prefix)],
            mtu,
            queue_capacity: DEFAULT_QUEUE_CAPACITY,
            skip_multicast: true,
        },
        network_service: None,
        routes: Vec::new(),
        direct_id: String::new(),
        proxy_id: None,
        bypass_id: String::new(),
        drop_id: String::new(),
        channel_capacity: DEFAULT_CHANNEL_CAPACITY,
        socket_rx_buffer_size: DEFAULT_SOCKET_BUFFER_SIZE,
        socket_tx_buffer_size: DEFAULT_SOCKET_BUFFER_SIZE,
        udp_packet_capacity: DEFAULT_UDP_PACKET_CAPACITY,
    };
    Ok(InjectedTun { fd, config })
}

fn run_service(
    database: String,
    web_root: String,
    tun: InjectedTun,
    api_port: Arc<AtomicU16>,
    ready: mpsc::SyncSender<std::result::Result<SocketAddr, String>>,
    mut stop_rx: oneshot::Receiver<()>,
) {
    let error_ready = ready.clone();
    let result = (|| -> std::result::Result<(), String> {
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| format!("create Tokio runtime: {error}"))?;
        let local = tokio::task::LocalSet::new();
        local.block_on(&runtime, async move {
            let database = std::path::PathBuf::from(database);
            let mut options = ServiceOptions::new(
                database,
                "127.0.0.1:0"
                    .parse()
                    .expect("the Android API listen address is valid"),
            );
            options.injected_tun = Some(tun);
            if !web_root.is_empty() {
                options.external_web = Some(std::path::PathBuf::from(web_root));
            }
            let service = RuntimeService::start(options)
                .await
                .map_err(|error| format!("start Rust runtime: {error}"))?;
            let address = service.address();
            api_port.store(address.port(), Ordering::Release);
            if ready.send(Ok(address)).is_err() {
                let _ = service.shutdown();
                return Ok::<(), String>(());
            }

            let shutdown = service.shutdown_handle();
            let mut wait = Box::pin(service.wait());
            tokio::select! {
                result = &mut wait => result.map_err(|error| format!("Rust runtime stopped: {error}")),
                _ = &mut stop_rx => {
                    let _ = shutdown.send(true);
                    wait.await.map_err(|error| format!("stop Rust runtime: {error}"))
                }
            }
        })
    })();

    if let Err(error) = result {
        let _ = error_ready.send(Err(error));
    }
}

fn stop_runtime(runtime: NativeRuntime) {
    if let Some(stop) = runtime.stop.into_inner().ok().flatten() {
        let _ = stop.send(());
    }
    if let Some(thread) = runtime.thread.into_inner().ok().flatten() {
        let _ = thread.join();
    }
}

/// Start the Rust runtime and consume the detached Android TUN fd.
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_asutorufa_yuhaiin_rust_RustRuntime_nativeStart<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _class: JClass<'local>,
    database: JString<'_>,
    tun_fd: jint,
    mtu: jint,
    ipv4: JString<'_>,
    ipv4_prefix: jint,
    ipv6: JString<'_>,
    ipv6_prefix: jint,
    web_root: JString<'_>,
) -> jlong {
    unowned_env
        .with_env(|env| -> jni::errors::Result<jlong> {
            let database = jni_string(env, database, "database")?;
            let ipv4 = jni_string(env, ipv4, "TUN IPv4")?;
            let ipv6 = jni_string(env, ipv6, "TUN IPv6")?;
            let web_root = jni_string(env, web_root, "web root")?;
            native_start(NativeStartConfig {
                database,
                web_root,
                tun_fd,
                mtu,
                ipv4,
                ipv4_prefix,
                ipv6,
                ipv6_prefix,
            })
            .map_err(JniError::ParseFailed)
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

struct NativeStartConfig {
    database: String,
    web_root: String,
    tun_fd: jint,
    mtu: jint,
    ipv4: String,
    ipv4_prefix: jint,
    ipv6: String,
    ipv6_prefix: jint,
}

fn native_start(config: NativeStartConfig) -> std::result::Result<jlong, String> {
    let tun = injected_tun(
        config.tun_fd,
        config.mtu,
        &config.ipv4,
        config.ipv4_prefix,
        &config.ipv6,
        config.ipv6_prefix,
    )?;
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);
    let (stop_tx, stop_rx) = oneshot::channel();
    let api_port = Arc::new(AtomicU16::new(0));
    let thread_api_port = Arc::clone(&api_port);
    let database = config.database;
    let web_root = config.web_root;
    let thread = thread::Builder::new()
        .name("yuhaiin-rust-android".to_owned())
        .spawn(move || run_service(database, web_root, tun, thread_api_port, ready_tx, stop_rx))
        .map_err(|error| format!("spawn Rust runtime: {error}"))?;

    match ready_rx.recv() {
        Ok(Ok(_address)) => {
            let handle = NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);
            let runtime = NativeRuntime {
                stop: Mutex::new(Some(stop_tx)),
                thread: Mutex::new(Some(thread)),
                api_port,
            };
            runtimes()
                .lock()
                .expect("runtime registry is not poisoned")
                .insert(handle, runtime);
            Ok(handle)
        }
        Ok(Err(error)) => {
            let _ = thread.join();
            Err(error)
        }
        Err(error) => {
            let _ = thread.join();
            Err(format!("Rust runtime exited before startup: {error}"))
        }
    }
}

/// Stop the runtime identified by nativeStart.
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_asutorufa_yuhaiin_rust_RustRuntime_nativeStop(
    _env: EnvUnowned<'_>,
    _class: JClass<'_>,
    handle: jlong,
) {
    if handle == 0 {
        return;
    }
    if let Some(runtime) = runtimes()
        .lock()
        .expect("runtime registry is not poisoned")
        .remove(&handle)
    {
        stop_runtime(runtime);
    }
}

/// Return the ephemeral localhost management port used by the Rust service.
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_asutorufa_yuhaiin_rust_RustRuntime_nativeApiPort(
    _env: EnvUnowned<'_>,
    _class: JClass<'_>,
    handle: jlong,
) -> jint {
    runtimes()
        .lock()
        .expect("runtime registry is not poisoned")
        .get(&handle)
        .map(|runtime| runtime.api_port.load(Ordering::Acquire) as jint)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::prefix;

    #[test]
    fn validates_jni_prefixes_without_touching_a_file_descriptor() {
        assert_eq!(prefix(24, 32, "ipv4").unwrap(), 24);
        assert!(prefix(-1, 32, "ipv4").is_err());
        assert!(prefix(129, 128, "ipv6").is_err());
    }
}
