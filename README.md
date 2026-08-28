# Doradus

Doradus is a new, standalone Rust network proxy project. It is being developed
from the original `yuhaiin-rust` codebase while establishing its own product
identity, runtime paths, service names, and release artifacts.

The project intentionally keeps the established protocol contracts, API
routes, configuration shape, and observable behavior compatible where they are
already supported. Doradus uses its own service identity and a new native
state database, separate from existing service installations.

## Name

The name comes from 30 Doradus, a large and active star-forming region in the
Large Magellanic Cloud, also known as the Tarantula Nebula. NASA describes it
as approximately 170,000 light-years away and one of the brightest nearby
star-forming regions:

[NASA Science: Hubble Probes Interior of Tarantula Nebula](https://science.nasa.gov/centers-and-facilities/goddard/hubble-probes-interior-of-tarantula-nebula/)

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

- `doradus-types` contains shared models and contracts.
- `doradus-dns` contains DNS models, codecs, cache, and transports.
- `doradus-core` contains async proxy, flow, socket, and NAT primitives.
- `doradus-trie` contains route indexes and matchers.
- `doradus-protocol` and `doradus-chain` implement protocol and chain behavior.
- `doradus-store` handles SQLite and the future legacy compatibility boundary.
- `doradus-tun` handles the TUN packet engine.
- `doradus-runtime` assembles snapshots, selectors, inbounds, TUN, and DNS.
- `doradus-api` provides the HTTP API and service host.

The default HTTP API listener is `0.0.0.0:58080`. Use `-host` and `-path` at
startup; runtime controls are not configured through the old service
environment variables.

See [the architecture and change guide](docs/ARCHITECTURE.md) for call paths,
reload boundaries, testing guidance, and module navigation.

## Compatibility and future migration

[Doradus compatibility and future migration](docs/COMPATIBILITY_MIGRATION.md)
documents the current compatibility boundary and the design constraints for a
future explicit migration from legacy state.

## License

This project preserves the original license, copyright notices, and
contribution history. It is licensed under the
[GNU General Public License v3.0 or later](https://www.gnu.org/licenses/gpl-3.0.html).
