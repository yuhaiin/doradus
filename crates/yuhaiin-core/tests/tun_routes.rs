#![cfg(feature = "tun-routes")]

#[cfg(target_os = "linux")]
mod linux {
    use std::io::BufRead;
    use std::net::IpAddr;
    use std::path::PathBuf;
    use std::process::{Child, Command, Stdio};

    use yuhaiin_core::tun::{
        LinuxTunRouteBackend, TunConfig, TunRoute, TunRouteLease, TunRuntime,
        probe_linux_capabilities,
    };

    #[test]
    fn invalid_interface_fails_without_installing_a_route() {
        let route = TunRoute::new("198.18.0.0".parse::<IpAddr>().unwrap(), 15).unwrap();
        let backend = LinuxTunRouteBackend::new("yuhaiin-nonexistent-interface").unwrap();
        assert!(TunRouteLease::apply(backend, &[route]).is_err());
    }

    /// Run in a user namespace without a matching network namespace. The
    /// process has a private user namespace but does not own the host network
    /// namespace, so netlink route mutation must fail with no lease returned.
    #[test]
    #[ignore = "requires an isolated user namespace without CAP_NET_ADMIN in the host network namespace"]
    fn route_permission_error_fails_closed_without_a_lease() {
        let capabilities = probe_linux_capabilities();
        assert!(matches!(
            capabilities.route_control,
            yuhaiin_core::tun::CapabilityState::Available
                | yuhaiin_core::tun::CapabilityState::Unavailable
                | yuhaiin_core::tun::CapabilityState::Unknown
        ));
        let route = TunRoute::new("198.18.0.0".parse::<IpAddr>().unwrap(), 15).unwrap();
        let backend = LinuxTunRouteBackend::new("lo").unwrap();
        let error = match TunRouteLease::apply(backend, std::slice::from_ref(&route)) {
            Ok(mut lease) => {
                let close_result = lease.close();
                panic!(
                    "route installation unexpectedly succeeded in a permission test; cleanup={close_result:?}"
                );
            }
            Err(error) => error,
        };
        assert!(matches!(
            error.kind(),
            std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::Other
        ));
    }

    /// Run in a private user namespace while keeping the host network
    /// namespace. TUN creation must not silently bypass the kernel permission
    /// boundary; if a platform does allow it, clean up before failing.
    #[test]
    #[ignore = "requires an isolated user namespace without CAP_NET_ADMIN in the host network namespace"]
    fn tun_open_without_net_admin_fails_closed() {
        let requested_name = format!("yhperm{}", std::process::id());
        let result = TunRuntime::open(TunConfig {
            name: Some(requested_name),
            ipv4: Some(("10.0.0.1".parse().unwrap(), 24)),
            ipv6: Vec::new(),
            mtu: 1500,
            queue_capacity: 8,
        });
        match result {
            Ok(runtime) => {
                let _ = runtime.shutdown();
                panic!("TUN creation unexpectedly bypassed the permission boundary");
            }
            Err(error) => assert!(matches!(
                error.kind(),
                std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::Other
            )),
        }
    }

    /// Exercise the recovery boundary in one parent process: a child with a
    /// private user namespace must fail to create TUN, while the privileged
    /// owner that remains in the isolated network namespace can open and
    /// close a fresh device afterwards.
    #[test]
    #[ignore = "requires an isolated network namespace with CAP_NET_ADMIN and unshare"]
    fn tun_permission_failure_does_not_poison_later_privileged_open() {
        let test_binary = std::env::current_exe().unwrap();
        let status = Command::new("unshare")
            .args([
                "-Ur",
                test_binary.to_str().unwrap(),
                "--exact",
                "linux::tun_open_without_net_admin_fails_closed",
                "--ignored",
                "--nocapture",
            ])
            .status()
            .expect("permission recovery test requires unshare");
        assert!(status.success(), "permission probe child failed");

        let name = format!("yhrec{}", std::process::id());
        let runtime = TunRuntime::open(TunConfig {
            name: Some(name.clone()),
            ipv4: Some(("10.0.0.1".parse().unwrap(), 24)),
            ipv6: Vec::new(),
            mtu: 1500,
            queue_capacity: 8,
        })
        .unwrap();
        assert_eq!(runtime.name().unwrap(), name);
        runtime.shutdown().unwrap();
    }

    /// Run this only inside an isolated user/network namespace. It changes
    /// only that namespace's route table and verifies actual netlink add,
    /// reverse delete, and repeated close behavior.
    #[test]
    #[ignore = "requires an isolated network namespace with CAP_NET_ADMIN"]
    fn linux_netlink_route_lease_adds_and_rolls_back() {
        let status = Command::new("ip")
            .args(["link", "set", "lo", "up"])
            .status()
            .expect("isolated route test requires the ip command for loopback setup");
        assert!(status.success(), "failed to bring isolated loopback up");

        let capabilities = probe_linux_capabilities();
        assert!(matches!(
            capabilities.route_control,
            yuhaiin_core::tun::CapabilityState::Available
        ));

        let mut route = TunRoute::new("198.18.0.0".parse::<IpAddr>().unwrap(), 15).unwrap();
        route.metric = Some(42_424);
        let route_copy = route.clone();
        let backend = LinuxTunRouteBackend::new("lo").unwrap();
        let mut lease = TunRouteLease::apply(backend, &[route]).unwrap();
        assert_eq!(lease.routes(), &[route_copy]);
        lease.close().unwrap();
        lease.close().unwrap();
    }

    /// Verify the production owner ordering: route deletion is attempted
    /// before the TUN fd is dropped, and the named device is gone afterwards.
    #[test]
    #[ignore = "requires an isolated network namespace with CAP_NET_ADMIN"]
    fn tun_shutdown_removes_device_and_owned_route() {
        let status = Command::new("ip")
            .args(["link", "set", "lo", "up"])
            .status()
            .expect("isolated TUN test requires the ip command");
        assert!(status.success());

        let requested_name = format!("yhrt{}", std::process::id());
        let mut runtime = TunRuntime::open(TunConfig {
            name: Some(requested_name),
            ipv4: Some(("10.0.0.1".parse().unwrap(), 24)),
            ipv6: Vec::new(),
            mtu: 1500,
            queue_capacity: 8,
        })
        .unwrap();
        let name = runtime.name().unwrap();
        let route = TunRoute::new("198.18.0.0".parse().unwrap(), 15).unwrap();
        runtime.install_linux_routes(&[route]).unwrap();
        assert!(
            Command::new("ip")
                .args(["link", "show", &name])
                .status()
                .unwrap()
                .success()
        );
        runtime.shutdown().unwrap();
        assert!(
            !Command::new("ip")
                .args(["link", "show", &name])
                .status()
                .unwrap()
                .success()
        );
    }

    /// Simulate an external device removal between TUN creation and route
    /// installation. The route operation must fail without retaining a lease,
    /// and shutdown must remain safe and idempotent afterwards.
    #[test]
    #[ignore = "requires an isolated network namespace with CAP_NET_ADMIN"]
    fn route_install_fails_closed_after_device_disappears() {
        let status = Command::new("ip")
            .args(["link", "set", "lo", "up"])
            .status()
            .expect("isolated TUN test requires the ip command");
        assert!(status.success());

        let mut runtime = TunRuntime::open(TunConfig {
            name: Some(format!("yhgone{}", std::process::id())),
            ipv4: Some(("10.0.0.1".parse().unwrap(), 24)),
            ipv6: Vec::new(),
            mtu: 1500,
            queue_capacity: 8,
        })
        .unwrap();
        let name = runtime.name().unwrap();
        assert!(
            Command::new("ip")
                .args(["link", "show", &name])
                .status()
                .unwrap()
                .success()
        );
        assert!(
            Command::new("ip")
                .args(["link", "delete", &name])
                .status()
                .unwrap()
                .success()
        );

        let route = TunRoute::new("198.18.0.0".parse().unwrap(), 15).unwrap();
        assert!(runtime.install_linux_routes(&[route]).is_err());
        runtime.shutdown().unwrap();
        assert!(
            !Command::new("ip")
                .args(["link", "show", &name])
                .status()
                .unwrap()
                .success()
        );
    }

    /// Route configuration is part of TUN startup, not a best-effort side
    /// effect. If the injected backend rejects the first route, the helper
    /// must drop the already-created device and a later owner must be able to
    /// reuse the same name.
    #[test]
    #[ignore = "requires an isolated network namespace with CAP_NET_ADMIN"]
    fn tun_open_with_routes_rolls_back_device_and_allows_recovery() {
        let status = Command::new("ip")
            .args(["link", "set", "lo", "up"])
            .status()
            .expect("isolated TUN rollback test requires the ip command");
        assert!(status.success());

        let name = format!("yhcfg{}", std::process::id());
        let config = TunConfig {
            name: Some(name.clone()),
            ipv4: Some(("10.0.0.1".parse().unwrap(), 24)),
            ipv6: Vec::new(),
            mtu: 1500,
            queue_capacity: 8,
        };
        let route = TunRoute::new("198.18.0.0".parse().unwrap(), 15).unwrap();
        let backend = LinuxTunRouteBackend::new("yuhaiin-route-does-not-exist").unwrap();
        assert!(TunRuntime::open_with_routes(config, backend, &[route]).is_err());
        assert!(
            !Command::new("ip")
                .args(["link", "show", &name])
                .status()
                .unwrap()
                .success()
        );

        let runtime = TunRuntime::open(TunConfig {
            name: Some(name.clone()),
            ipv4: Some(("10.0.0.1".parse().unwrap(), 24)),
            ipv6: Vec::new(),
            mtu: 1500,
            queue_capacity: 8,
        })
        .unwrap();
        assert_eq!(runtime.name().unwrap(), name);
        runtime.shutdown().unwrap();
    }

    fn tun_smoke_binary() -> PathBuf {
        if let Some(path) = std::env::var_os("CARGO_BIN_EXE_tun-smoke") {
            return PathBuf::from(path);
        }
        std::env::current_exe()
            .unwrap()
            .parent()
            .and_then(std::path::Path::parent)
            .unwrap()
            .join("tun-smoke")
    }

    fn wait_for_tun_started(child: &mut Child) {
        let stdout = child.stdout.take().expect("TUN smoke stdout must be piped");
        let mut reader = std::io::BufReader::new(stdout);
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        assert_eq!(line.trim(), "tun-opened");
    }

    /// Verify the kernel resource owner boundary across processes: a second
    /// owner cannot take the same TUN name, while a fresh owner can restart
    /// after the first process is force-stopped.
    #[test]
    #[ignore = "requires an isolated network namespace with CAP_NET_ADMIN"]
    fn tun_name_is_exclusive_and_reusable_after_process_stop() {
        let status = Command::new("ip")
            .args(["link", "set", "lo", "up"])
            .status()
            .expect("isolated TUN test requires the ip command");
        assert!(status.success());

        let name = format!("yhmp{}", std::process::id());
        let binary = tun_smoke_binary();
        assert!(
            binary.is_file(),
            "TUN smoke binary missing: {}",
            binary.display()
        );
        let mut first = Command::new(&binary)
            .env("YUHAIIN_TUN_NAME", &name)
            .env("YUHAIIN_TUN_HOLD_MS", "10000")
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        wait_for_tun_started(&mut first);

        let second = Command::new(&binary)
            .env("YUHAIIN_TUN_NAME", &name)
            .env("YUHAIIN_TUN_HOLD_MS", "50")
            .output()
            .unwrap();
        assert!(
            !second.status.success(),
            "second TUN owner unexpectedly succeeded"
        );

        first.kill().unwrap();
        let _ = first.wait();

        let mut restarted = Command::new(&binary)
            .env("YUHAIIN_TUN_NAME", &name)
            .env("YUHAIIN_TUN_HOLD_MS", "10000")
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        wait_for_tun_started(&mut restarted);
        restarted.kill().unwrap();
        let _ = restarted.wait();
    }
}
