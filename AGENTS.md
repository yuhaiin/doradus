# AGENTS.md

## Rust Async / Runtime Dependency Guidelines

This project uses Rust `async/await`, but core business logic should avoid unnecessary coupling to a specific async runtime such as Tokio.

### Core Principles

* `async` does not imply Tokio. Rust-native `async fn`, `.await`, `Future`, and related primitives are runtime-independent.
* Do not create and maintain a parallel synchronous API merely because the project uses async, unless synchronous usage is an explicit first-class requirement.
* Prefer isolating **runtime-specific APIs** rather than avoiding async itself.
* Pure computation, parsing, validation, transformation, and other non-I/O logic should remain ordinary synchronous `fn`s.
* Do not make functions `async` unless they actually need asynchronous behavior or must satisfy an async interface.
* Avoid speculative abstraction solely for the possibility of replacing the runtime in the future.

## Architecture Boundaries

Prefer the following dependency direction:

```text
Domain / Core
    ↓
Application / Ports
    ↓
Infrastructure / Runtime Adapters
    ↓
Tokio / OS / Network / Database
```

Core business logic should generally not depend directly on Tokio.

Tokio is acceptable in:

* `main.rs`
* application bootstrap code
* runtime initialization
* infrastructure and adapter layers
* Tokio-specific networking, filesystem, process, timer, and task implementations
* modules explicitly responsible for runtime integration

For example:

```rust
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // application bootstrap
    Ok(())
}
```

This is normal and should not be abstracted merely for runtime independence.

## Avoid Tokio Types in Core and Public APIs

Unless a module is explicitly a Tokio adapter, avoid exposing Tokio-specific types through public, domain, or application-layer APIs.

Avoid:

```rust
pub async fn handle(
    stream: tokio::net::TcpStream,
) -> Result<()> {
    // ...
}
```

Avoid:

```rust
pub fn subscribe(
    &self,
) -> tokio::sync::mpsc::Receiver<Event> {
    // ...
}
```

Avoid:

```rust
pub struct Service {
    tx: tokio::sync::mpsc::Sender<Message>,
}
```

Be especially careful with:

```text
tokio::net::*
tokio::fs::*
tokio::process::*
tokio::time::*
tokio::sync::*
tokio::task::*
tokio::spawn
tokio::select!
```

These APIs may be used, but they should remain close to appropriate runtime or infrastructure boundaries whenever practical.

## Prefer Runtime-Neutral Core Logic

Prefer:

```rust
pub fn parse(input: &[u8]) -> Result<Model> {
    // pure business logic
}

pub async fn process(model: Model) -> Result<Output> {
    // async orchestration without runtime-specific types
}
```

Instead of:

```rust
pub async fn parse(input: &[u8]) -> Result<Model> {
    // no asynchronous operation
}
```

When generating or modifying code, the agent should actively check whether a function actually needs to be async.

If a function contains no asynchronous operation and does not need to satisfy an async trait or interface, prefer a normal `fn`.

## Keep I/O Near the Edge

Separate I/O from business logic whenever practical.

Prefer:

```rust
pub fn decode(bytes: &[u8]) -> Result<Request> {
    // parsing and validation
}

pub async fn load_request(...) -> Result<Request> {
    let bytes = ...;
    decode(&bytes)
}
```

Avoid mixing filesystem, socket, timer, process, or other runtime-specific operations directly into core domain logic.

## Runtime Abstraction

Do not automatically create a trait around every Tokio API.

Introduce an abstraction or port only when at least one of the following is true:

* a runtime-specific type would otherwise enter core business logic;
* the capability needs to be replaced in tests;
* multiple real implementations already exist or are planned;
* runtime replacement is an explicit project requirement;
* the dependency would force downstream users to adopt Tokio;
* the abstraction improves a meaningful architectural boundary.

For example, if the domain genuinely depends on a notion of time, an abstraction may be appropriate:

```rust
pub trait Clock {
    fn now(&self) -> Instant;

    fn sleep(
        &self,
        duration: Duration,
    ) -> impl Future<Output = ()> + Send;
}
```

A Tokio implementation can then live in the infrastructure layer.

However, if `tokio::time::sleep` is only used internally by a retry adapter, a dedicated abstraction is usually unnecessary.

## Async Traits and I/O Traits

Replacing a concrete Tokio type with a generic parameter does not necessarily make code runtime-independent.

For example:

```rust
async fn read<R>(reader: &mut R)
where
    R: tokio::io::AsyncRead + Unpin,
{
}
```

This is still Tokio-dependent because `tokio::io::AsyncRead` is a Tokio API.

If runtime independence is an explicit requirement for a module, prefer:

* standard-library abstractions where available;
* project-defined ports;
* or deliberately chosen runtime-neutral ecosystem abstractions.

Do not hide runtime coupling behind generic type parameters and call it runtime-neutral.

## Task Spawning

`tokio::spawn` is a major source of runtime coupling.

Core business logic should generally not decide how work is scheduled.

Avoid:

```rust
pub async fn execute(&self) {
    tokio::spawn(async move {
        // business work
    });
}
```

Prefer one of the following:

* let the caller decide whether work should run concurrently;
* return a `Future` and let a higher layer schedule it;
* perform spawning in an application or runtime adapter;
* introduce an executor/task abstraction only when there is a real need.

Guiding principle:

> Core describes the work; the runtime decides how the work is scheduled.

## Channels and Synchronization

Avoid exposing `tokio::sync::*` types as cross-layer interfaces unless the runtime dependency is intentional.

Be especially careful with:

```text
tokio::sync::mpsc::Sender
tokio::sync::mpsc::Receiver
tokio::sync::oneshot::Sender
tokio::sync::watch::Receiver
tokio::sync::Mutex
tokio::sync::RwLock
```

Using these internally within a module is fine.

If a channel becomes part of a module boundary, prefer exposing business semantics instead of the transport mechanism.

Prefer:

```rust
pub trait EventSink {
    async fn publish(&self, event: Event) -> Result<()>;
}
```

Instead of:

```rust
pub fn sender(&self) -> tokio::sync::mpsc::Sender<Event>;
```

## Do Not Build Parallel Sync APIs by Default

Do not automatically provide both:

```rust
pub async fn fetch(...)
```

and:

```rust
pub fn fetch_blocking(...)
```

A synchronous API should only exist when there is a concrete requirement, such as:

* the crate explicitly supports both sync and async users;
* synchronous usage is a product requirement;
* synchronous environments are an important first-class use case;
* upstream ecosystem constraints require a synchronous interface.

Do not create blocking APIs by casually wrapping async code with a runtime:

```rust
pub fn fetch_sync(...) -> Result<Data> {
    runtime.block_on(fetch(...))
}
```

This is only acceptable at a carefully controlled boundary where runtime nesting, worker blocking, and execution-context issues have been considered.

## Dependency Review

When adding dependencies, check:

1. Does this crate require a specific async runtime?
2. Will it introduce Tokio-specific types into core or public APIs?
3. Is runtime coupling being introduced only for convenience?
4. Is there a simpler design with a cleaner boundary?
5. Is runtime-neutrality worth the abstraction cost in this specific case?

Do not replace a small and well-contained Tokio dependency with a significantly more complex abstraction framework merely for theoretical portability.

## Feature Flags

For a general-purpose library that explicitly intends to support multiple runtimes, feature flags may be appropriate:

```toml
[features]
default = ["runtime-tokio"]

runtime-tokio = [...]
runtime-other = [...]
```

Do not introduce multi-runtime feature flags unless multi-runtime support is an actual project requirement.

Application binaries normally do not need runtime abstraction through Cargo features.

## Code Review Checklist

When adding or modifying async code, check:

* [ ] Does this function actually need to be `async`?
* [ ] Can pure logic be extracted into synchronous functions?
* [ ] Are any `tokio::*` types leaking into core or public APIs?
* [ ] Is `tokio::spawn` being used inside code that should not control scheduling?
* [ ] Are Tokio channels being exposed as business-layer interfaces?
* [ ] Are timers, sockets, filesystem operations, and other runtime-specific concerns kept near infrastructure boundaries?
* [ ] Does a newly introduced abstraction solve a real boundary problem?
* [ ] Are we unnecessarily maintaining both sync and async APIs?
* [ ] If the runtime were replaced later, would most changes remain confined to infrastructure/runtime adapters?

## Decision Priority

When tradeoffs are unclear, prefer the following order:

```text
Correctness
  >
Code clarity
  >
Sound architectural boundaries
  >
Testability
  >
Runtime replaceability
  >
Theoretical runtime agnosticism
```

The goal is not to eliminate Tokio from the project.

The goal is:

> **Tokio may be the current runtime implementation, but it should not accidentally become the protocol of the entire architecture.**

In short:

> **Use async freely. Contain Tokio deliberately.**
