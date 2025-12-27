# Bittensor Rust SDK

[![CI](https://github.com/one-covenant/bittensor-rs/workflows/CI/badge.svg)](https://github.com/one-covenant/bittensor-rs/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A collection of Rust crates for interacting with the [Bittensor](https://bittensor.com) blockchain network.

## Workspace Structure

This monorepo contains the following crates:

| Crate | Description | Crates.io |
|-------|-------------|-----------|
| [`bittensor-rs`](./bittensor-rs) | Core SDK for Bittensor chain interactions | [![Crates.io](https://img.shields.io/crates/v/bittensor-rs.svg)](https://crates.io/crates/bittensor-rs) |
| [`bittensor-wallet`](./bittensor-wallet) | Wallet management with Python bindings | - |
| [`lightning-tensor`](./lightning-tensor) | Terminal UI for Bittensor | - |

## Quick Start

### Using bittensor-rs

Add to your `Cargo.toml`:

```toml
[dependencies]
bittensor-rs = "0.1"
```

```rust
use bittensor::{config::BittensorConfig, Service};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Connect to Finney mainnet
    let config = BittensorConfig::finney("my_wallet", "my_hotkey", 1);
    let service = Service::new(config).await?;
    
    // Query metagraph
    let metagraph = service.get_metagraph(1).await?;
    println!("Found {} neurons", metagraph.hotkeys.len());
    
    Ok(())
}
```

## Development

### Prerequisites

- Rust 1.70 or later
- Protocol Buffers compiler (`protoc`)

### Building

```bash
# Build all crates
cargo build --workspace

# Build with all features
cargo build --workspace --all-features

# Run tests
cargo test --workspace

# Run specific crate tests
cargo test -p bittensor-rs
```

### Using Just (Recommended)

This project includes a [justfile](./justfile) for common tasks:

```bash
# Install just: https://github.com/casey/just
cargo install just

# See available commands
just --list
```

## Documentation

- [bittensor-rs API docs](https://docs.rs/bittensor-rs) - Full API documentation on docs.rs
- [bittensor-wallet README](./bittensor-wallet/README.md) - Wallet crate documentation

## Contributing

Contributions are welcome! Please follow these guidelines:

1. **Conventional Commits**: Use [conventional commit](https://www.conventionalcommits.org/) format:
   - `feat: add new feature`
   - `fix: resolve bug`
   - `docs: update documentation`
   - `chore: maintenance task`

2. **Pull Requests**: All changes should go through PR review

3. **Testing**: Add tests for new functionality

## Release Process

This repository uses [release-please](https://github.com/googleapis/release-please) for automated releases:

1. Merge PRs with conventional commits to `main`
2. Release-please automatically creates/updates a release PR with changelog
3. Merge the release PR to trigger a GitHub release
4. The publish workflow automatically publishes to crates.io

## License

MIT License - see [LICENSE](LICENSE) for details.

## Related Projects

- [Bittensor](https://github.com/opentensor/bittensor) - Python SDK and CLI
- [Subtensor](https://github.com/opentensor/subtensor) - Bittensor blockchain node

