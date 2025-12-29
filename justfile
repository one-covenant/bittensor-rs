#!/usr/bin/env just --justfile

export RUST_BACKTRACE := "full"
export SKIP_WASM_BUILD := "1"
export RUST_BIN_DIR := "target/x86_64-unknown-linux-gnu"
export TARGET := "x86_64-unknown-linux-gnu"
export RUSTV := "stable"
export RELEASE_NAME := "development"
export BITTENSOR_OFFLINE := "1"

# Format check (matches CI)
fmt:
  @echo "Running cargo fmt check..."
  cargo +{{RUSTV}} fmt -p bittensor-rs -- --check

# Format fix
fmt-fix:
  @echo "Running cargo fmt..."
  cargo +{{RUSTV}} fmt -p bittensor-rs

# Check (matches CI scope)
check:
  @echo "Running cargo check..."
  cargo +{{RUSTV}} check -p bittensor-rs --all-features

# Test (matches CI)
test:
  @echo "Running cargo test..."
  cargo +{{RUSTV}} test -p bittensor-rs --all-features

# Clippy (matches CI - strict, all warnings are errors)
clippy:
  @echo "Running cargo clippy..."
  cargo +{{RUSTV}} clippy -p bittensor-rs --all-features -- -D warnings

# Clippy with auto-fix
clippy-fix:
  @echo "Running cargo clippy with automatic fixes..."
  cargo +{{RUSTV}} clippy --fix --allow-dirty --allow-staged -p bittensor-rs --all-features -- -A warnings

# Cargo fix
fix:
  @echo "Running cargo fix..."
  cargo +{{RUSTV}} fix -p bittensor-rs --allow-dirty --allow-staged

# Run all CI checks locally
ci:
  @echo "Running full CI suite..."
  just fmt
  just clippy
  just test

# Lint and fix (convenience)
lint:
  @echo "Formatting..."
  just fmt-fix
  @echo "Running clippy fix..."
  just clippy-fix
  @echo "Running clippy check..."
  just clippy
