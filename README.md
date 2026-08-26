# yuhaiin-rust

Rust implementation of the yuhaiin network proxy runtime.

> **Work in progress**
>
> The project is still under active development. It is usable for development
> and evaluation, but it is not presented as a production-ready release.

## Current status

The current development version has passed basic smoke testing on macOS and
Linux. The main data-plane paths are working, including:

- TUN packet processing and proxying;
- route matching and route-list handling;
- DNS resolution, DNS listeners, DNS interception, and FakeIP;
- TCP and UDP inbounds and outbounds;
- proxy chains, TLS, HTTP/2, and selected protocol interoperability; and
- runtime configuration reload and service lifecycle checks.

These results describe the current development baseline, not a guarantee that
every platform, protocol combination, network environment, or production
configuration is supported. TUN and route tests may require elevated
permissions and platform-specific capabilities.

## Building

This is a Cargo workspace. A normal development build is:

~~~bash
cargo build --workspace
~~~

The default runtime features include TUN, Linux route support, encrypted DNS
transports, WebSocket, and HTTP termination. See the crate manifests for the
feature combinations available to a particular target.

Run the workspace tests with:

~~~bash
cargo test --workspace --all-features
~~~

Some integration and platform tests require Podman, a TUN device, or elevated
network permissions. The Makefile provides named smoke-test entry points; run
the help target to see the available commands.

## Architecture

The workspace separates runtime-independent types, reusable protocol and
routing logic, persistence/platform adapters, and runtime/API assembly.

- yuhaiin-types contains shared models and contracts.
- yuhaiin-dns contains DNS models, codecs, cache, and transports.
- yuhaiin-core contains async proxy, flow, socket, and NAT primitives.
- yuhaiin-trie contains route indexes and matchers.
- yuhaiin-protocol and yuhaiin-chain implement protocol and chain behavior.
- yuhaiin-store handles SQLite, migration, and Go compatibility.
- yuhaiin-tun handles the TUN packet engine.
- yuhaiin-runtime assembles snapshots, selectors, inbounds, TUN, and DNS.
- yuhaiin-api provides the HTTP API and service host.

See [the architecture and change guide](docs/ARCHITECTURE.md) for call paths,
reload boundaries, testing guidance, and module navigation.

## Replacing the Go service

[Release replacement and rollback](docs/RELEASE_REPLACEMENT.md) documents the
safe migration procedure, SQLite backup requirements, systemd/launchd
integration, and rollback limitations.

## License

This project is licensed under the
[GNU General Public License v3.0 or later](https://www.gnu.org/licenses/gpl-3.0.html).
