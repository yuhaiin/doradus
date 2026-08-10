SHELL := /bin/bash

CARGO ?= cargo
RUSTC ?= rustc
CACHE_ROOT ?= $(HOME)/.cache/yuhaiin-rust
CARGO_TARGET_DIR ?= $(CACHE_ROOT)/cargo-target
ANDROID_NDK ?= /opt/android-ndk
ANDROID_API ?= 35
ANDROID_TARGET ?= aarch64-linux-android
ANDROID_CLANG ?= $(ANDROID_NDK)/toolchains/llvm/prebuilt/linux-x86_64/bin/$(ANDROID_TARGET)$(ANDROID_API)-clang
ANDROID_LLVM_AR ?= $(ANDROID_NDK)/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-ar
MUSL ?= 0
MUSL_TARGET ?= x86_64-unknown-linux-musl
RUST_SYSROOT ?= $(shell $(RUSTC) --print sysroot)
RUST_HOST ?= $(shell $(RUSTC) -vV | sed -n 's/^host: //p')
MUSL_LINKER ?= $(RUST_SYSROOT)/lib/rustlib/$(RUST_HOST)/bin/rust-lld

# FEATURES is additive to the package's default features. Set
# NO_DEFAULT_FEATURES=1 when a smaller feature set is required.
FEATURES ?=
NO_DEFAULT_FEATURES ?= 0

CARGO_COMMON_ARGS := --target-dir "$(CARGO_TARGET_DIR)"
ifeq ($(MUSL),1)
CARGO_TARGET_ARGS := --target "$(MUSL_TARGET)"
CARGO_BUILD_ENV := RUSTFLAGS="$(RUSTFLAGS) -C linker=$(MUSL_LINKER)"
DEBUG_BINARY_DIR := $(CARGO_TARGET_DIR)/$(MUSL_TARGET)/debug
RELEASE_BINARY_DIR := $(CARGO_TARGET_DIR)/$(MUSL_TARGET)/release
else
CARGO_TARGET_ARGS :=
CARGO_BUILD_ENV :=
DEBUG_BINARY_DIR := $(CARGO_TARGET_DIR)/debug
RELEASE_BINARY_DIR := $(CARGO_TARGET_DIR)/release
endif
ifeq ($(NO_DEFAULT_FEATURES),1)
FEATURE_ARGS := --no-default-features
endif
ifneq ($(strip $(FEATURES)),)
FEATURE_ARGS += --features "$(FEATURES)"
endif

RUNTIME_PACKAGE := yuhaiin-runtime
RUNTIME_BIN := yuhaiin

.PHONY: help cache-usage build build-debug build-release build-musl build-release-musl build-all-bins build-tun-smoke build-tun-service-smoke tun-service-smoke tun-mtu-smoke build-transparent-service-smoke transparent-service-smoke api-contract-smoke api-reload-flow-smoke go-api-parity-smoke production-parity-smoke go-rust-stats-smoke service-chain-smoke benchmark-throughput benchmark-tun-throughput dns-source-smoke doh-source-smoke socks5-udp-associate-smoke node-latency-dns-smoke stats-concurrency-smoke startup-logs-smoke \
	build-chain-smoke run version check test fmt fmt-check clippy \
	android-aarch64

help:
	@printf '%s\n' \
		'make cache-usage        show generated Rust cache usage' \
		'make build              build the yuhaiin runtime binary (debug)' \
		'make build-release      build the yuhaiin runtime binary (release)' \
		'make build MUSL=1       build a static musl debug binary' \
		'make build-musl         alias for make build MUSL=1' \
		'make build-release-musl build a static musl release binary' \
		'make build-all-bins     build every workspace binary' \
		'make build-tun-smoke    build the privileged TUN smoke binary' \
		'make build-tun-service-smoke build the runtime-owned TUN smoke binary' \
		'make tun-service-smoke run the runtime-owned TUN lifecycle and echo smoke' \
		'make tun-mtu-smoke run the runtime-owned TUN MTU boundary matrix' \
		'make transparent-service-smoke run REDIRECT TCP smoke; rootless Podman records TPROXY skip' \
		'make api-contract-smoke run the frontend management API process contract in Podman' \
		'make api-reload-flow-smoke verify mutation reloads the real data plane and survives restart' \
		'make go-api-parity-smoke compare read and core mutation API responses against a Go state snapshot' \
		'make production-parity-smoke compare several stopped production SQLite snapshots' \
		'make go-rust-stats-smoke run concurrent Go/Rust SQLite statistics smoke in Podman' \
		'make service-chain-smoke run inbound/router/outbound protocol chains in Podman' \
		'make benchmark-throughput run the release inbound/router/outbound throughput benchmark in Podman' \
		'make benchmark-tun-throughput run the privileged TUN packet throughput benchmark in Podman' \
		'make dns-source-smoke   run UDP/TCP resolver source-bind smoke in Podman' \
		'make doh-source-smoke   run DoH/DoT source-bind smoke in Podman' \
		'make socks5-udp-associate-smoke run real SOCKS5 UDP chain smoke in Podman' \
		'make node-latency-dns-smoke run API DNS latency chain smoke in Podman' \
		'make stats-concurrency-smoke run concurrent statistics/restart smoke in Podman' \
		'make startup-logs-smoke run foreground startup log smoke' \
		'make run ARGS="..."    run the runtime binary with arguments' \
		'make version            run the binary version command' \
		'make check              cargo check for the whole workspace' \
		'make test               run the full workspace test suite' \
		'make fmt-check          verify Rust formatting' \
		'make clippy             run workspace Clippy checks' \
		'make android-aarch64   cross-build for Android arm64' \
		'' \
		'CARGO_TARGET_DIR=$(CARGO_TARGET_DIR)' \
		'FEATURES=$(FEATURES)' \
		'NO_DEFAULT_FEATURES=$(NO_DEFAULT_FEATURES)' \
		'MUSL=$(MUSL) MUSL_TARGET=$(MUSL_TARGET) MUSL_LINKER=$(MUSL_LINKER)'

cache-usage:
	@du -h -d 2 "$(CACHE_ROOT)" 2>/dev/null | sort -h | tail -25

build: build-debug

build-debug:
	$(CARGO_BUILD_ENV) $(CARGO) build $(CARGO_COMMON_ARGS) $(CARGO_TARGET_ARGS) -p $(RUNTIME_PACKAGE) --bin $(RUNTIME_BIN) $(FEATURE_ARGS)
	@printf 'binary: %s/%s\n' "$(DEBUG_BINARY_DIR)" "$(RUNTIME_BIN)"

build-release:
	$(CARGO_BUILD_ENV) $(CARGO) build $(CARGO_COMMON_ARGS) $(CARGO_TARGET_ARGS) --release -p $(RUNTIME_PACKAGE) --bin $(RUNTIME_BIN) $(FEATURE_ARGS)
	@printf 'binary: %s/%s\n' "$(RELEASE_BINARY_DIR)" "$(RUNTIME_BIN)"

build-musl:
	$(MAKE) MUSL=1 build-debug

build-release-musl:
	$(MAKE) MUSL=1 build-release

build-all-bins:
	$(CARGO) build $(CARGO_COMMON_ARGS) --workspace --bins --all-features

build-tun-smoke:
	$(CARGO) build $(CARGO_COMMON_ARGS) -p yuhaiin-core --bin tun-smoke --features tun
	@printf 'binary: %s/debug/tun-smoke\n' "$(CARGO_TARGET_DIR)"

build-tun-service-smoke:
	$(CARGO) build $(CARGO_COMMON_ARGS) -p $(RUNTIME_PACKAGE) --bin tun-service-smoke --all-features
	@printf 'binary: %s/debug/tun-service-smoke\n' "$(CARGO_TARGET_DIR)"

tun-service-smoke:
	./scripts/integration/tun-service.sh

tun-mtu-smoke:
	./scripts/integration/tun-mtu.sh

build-transparent-service-smoke:
	$(CARGO) build $(CARGO_COMMON_ARGS) -p $(RUNTIME_PACKAGE) --bin transparent-service-smoke --all-features
	@printf 'binary: %s/debug/transparent-service-smoke\n' "$(CARGO_TARGET_DIR)"

transparent-service-smoke:
	./scripts/integration/transparent-service.sh

api-contract-smoke:
	./scripts/integration/api-contract.sh

api-reload-flow-smoke:
	./scripts/integration/api-reload-flow.sh

go-api-parity-smoke:
	./scripts/integration/go-api-parity.sh

production-parity-smoke:
	./scripts/integration/production-parity.sh

go-rust-stats-smoke:
	./scripts/integration/go-rust-stats.sh

service-chain-smoke:
	./scripts/integration/service-chain.sh

benchmark-throughput:
	./scripts/benchmark/throughput.sh

benchmark-tun-throughput:
	./scripts/benchmark/tun-throughput.sh

dns-source-smoke:
	./scripts/integration/dns-source-bind.sh

doh-source-smoke:
	./scripts/integration/doh-source-bind.sh

socks5-udp-associate-smoke:
	./scripts/integration/socks5-udp-associate.sh

node-latency-dns-smoke:
	./scripts/integration/node-latency-dns.sh

stats-concurrency-smoke:
	./scripts/integration/stats-concurrency.sh

startup-logs-smoke:
	CARGO_TARGET_DIR="$(CARGO_TARGET_DIR)" $(CARGO) test $(CARGO_COMMON_ARGS) -p $(RUNTIME_PACKAGE) --all-features --offline --test startup_logs -- --nocapture

build-chain-smoke:
	$(CARGO) build $(CARGO_COMMON_ARGS) -p yuhaiin-chain --bin chain-smoke
	@printf 'binary: %s/debug/chain-smoke\n' "$(CARGO_TARGET_DIR)"

run:
	$(CARGO) run $(CARGO_COMMON_ARGS) -p $(RUNTIME_PACKAGE) --bin $(RUNTIME_BIN) $(FEATURE_ARGS) -- $(ARGS)

version: build-debug
	"$(DEBUG_BINARY_DIR)/$(RUNTIME_BIN)" version

check:
	$(CARGO) check $(CARGO_COMMON_ARGS) --workspace --all-features

test:
	$(CARGO) test $(CARGO_COMMON_ARGS) --workspace --all-features

fmt:
	$(CARGO) fmt --all

fmt-check:
	$(CARGO) fmt --all -- --check

clippy:
	$(CARGO) clippy $(CARGO_COMMON_ARGS) --workspace --all-targets --all-features -- -D warnings

android-aarch64:
	@test -x "$(ANDROID_CLANG)" || { \
		echo "Android linker not found: $(ANDROID_CLANG)" >&2; \
		echo "Set ANDROID_NDK, ANDROID_API, or ANDROID_CLANG to override it." >&2; \
		exit 1; \
	}
	@test -x "$(ANDROID_LLVM_AR)" || { \
		echo "Android llvm-ar not found: $(ANDROID_LLVM_AR)" >&2; \
		echo "Set ANDROID_NDK or ANDROID_LLVM_AR to override it." >&2; \
		exit 1; \
	}
	CC_aarch64_linux_android="$(ANDROID_CLANG)" \
	AR_aarch64_linux_android="$(ANDROID_LLVM_AR)" \
	CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$(ANDROID_CLANG)" \
		$(CARGO) build $(CARGO_COMMON_ARGS) --target $(ANDROID_TARGET) --release -p $(RUNTIME_PACKAGE) --bin $(RUNTIME_BIN) $(FEATURE_ARGS)
	@printf 'binary: %s/%s/release/%s\n' "$(CARGO_TARGET_DIR)" "$(ANDROID_TARGET)" "$(RUNTIME_BIN)"
