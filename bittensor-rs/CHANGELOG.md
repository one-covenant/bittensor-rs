# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - Initial Release

### Features

- **Connection Management**
  - Connection pooling with configurable pool size
  - Automatic health checks and connection monitoring
  - Circuit breaker pattern for cascade failure prevention
  - Exponential backoff retry logic with jitter

- **Chain Queries**
  - `get_metagraph` / `get_selective_metagraph` - Subnet metagraph data
  - `get_neuron` / `get_neuron_lite` - Neuron information
  - `get_balance` / `get_stake` - Account balances and stake
  - `get_subnet_info` / `get_subnet_hyperparameters` - Subnet configuration
  - `get_total_subnets` / `subnet_exists` - Subnet enumeration

- **Extrinsics (Transactions)**
  - Staking: `add_stake`, `remove_stake`, `delegate_stake`, `undelegate_stake`
  - Weights: `set_weights`, `commit_weights`, `reveal_weights`
  - Transfer: `transfer`, `transfer_keep_alive`, `transfer_all`
  - Registration: `serve_axon`, `serve_prometheus`, `burned_register`
  - Subnet: `register_network`, `set_subnet_identity`
  - Children: `set_children`, `set_childkey_take`, `revoke_children`
  - Root: `root_register`, `set_root_weights`

- **Wallet Management**
  - Load wallets from Bittensor CLI format (`~/.bittensor/wallets`)
  - Create wallets from mnemonic or hex seed
  - Sign and verify messages
  - Subxt-compatible signer for transactions

- **Error Handling**
  - Comprehensive error types with categories
  - Retry configuration per error category
  - Detailed error messages with context

- **Configuration**
  - Network presets: Finney, Testnet, Local
  - Custom endpoint configuration
  - Connection pool settings
  - Read-only mode support

### Dependencies

- `subxt` 0.44.0 for Substrate interactions
- `tokio` for async runtime
- `sp-core` / `sp-runtime` for cryptography

[Unreleased]: https://github.com/one-covenant/bittensor-rs/compare/bittensor-rs-v0.1.0...HEAD
[0.1.0]: https://github.com/one-covenant/bittensor-rs/releases/tag/bittensor-rs-v0.1.0

