SHELL := /bin/bash

CARGO ?= cargo
CARGO_TARGET_DIR ?= $(HOME)/.cache/yuhaiin-rust/cargo-target
ANDROID_NDK ?= /opt/android-ndk
ANDROID_API ?= 35
ANDROID_TARGET ?= aarch64-linux-android
ANDROID_CLANG ?= $(ANDROID_NDK)/toolchains/llvm/prebuilt/linux-x86_64/bin/$(ANDROID_TARGET)$(ANDROID_API)-clang
ANDROID_LLVM_AR ?= $(ANDROID_NDK)/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-ar

# FEATURES is additive to the package's default features. Set
# NO_DEFAULT_FEATURES=1 when a smaller feature set is required.
FEATURES ?=
NO_DEFAULT_FEATURES ?= 0

CARGO_COMMON_ARGS := --target-dir "$(CARGO_TARGET_DIR)"
ifeq ($(NO_DEFAULT_FEATURES),1)
FEATURE_ARGS := --no-default-features
endif
ifneq ($(strip $(FEATURES)),)
FEATURE_ARGS += --features "$(FEATURES)"
endif

RUNTIME_PACKAGE := yuhaiin-runtime
RUNTIME_BIN := yuhaiin

.PHONY: help build build-debug build-release build-all-bins build-tun-smoke \
	build-chain-smoke run version check test fmt fmt-check clippy \
	android-aarch64

help:
	@printf '%s\n' \
		'make build              build the yuhaiin runtime binary (debug)' \
		'make build-release      build the yuhaiin runtime binary (release)' \
		'make build-all-bins     build every workspace binary' \
		'make build-tun-smoke    build the privileged TUN smoke binary' \
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
		'NO_DEFAULT_FEATURES=$(NO_DEFAULT_FEATURES)'

build: build-debug

build-debug:
	$(CARGO) build $(CARGO_COMMON_ARGS) -p $(RUNTIME_PACKAGE) --bin $(RUNTIME_BIN) $(FEATURE_ARGS)
	@printf 'binary: %s/debug/%s\n' "$(CARGO_TARGET_DIR)" "$(RUNTIME_BIN)"

build-release:
	$(CARGO) build $(CARGO_COMMON_ARGS) --release -p $(RUNTIME_PACKAGE) --bin $(RUNTIME_BIN) $(FEATURE_ARGS)
	@printf 'binary: %s/release/%s\n' "$(CARGO_TARGET_DIR)" "$(RUNTIME_BIN)"

build-all-bins:
	$(CARGO) build $(CARGO_COMMON_ARGS) --workspace --bins --all-features

build-tun-smoke:
	$(CARGO) build $(CARGO_COMMON_ARGS) -p yuhaiin-core --bin tun-smoke --features tun
	@printf 'binary: %s/debug/tun-smoke\n' "$(CARGO_TARGET_DIR)"

build-chain-smoke:
	$(CARGO) build $(CARGO_COMMON_ARGS) -p yuhaiin-chain --bin chain-smoke
	@printf 'binary: %s/debug/chain-smoke\n' "$(CARGO_TARGET_DIR)"

run:
	$(CARGO) run $(CARGO_COMMON_ARGS) -p $(RUNTIME_PACKAGE) --bin $(RUNTIME_BIN) $(FEATURE_ARGS) -- $(ARGS)

version: build-debug
	"$(CARGO_TARGET_DIR)/debug/$(RUNTIME_BIN)" version

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
