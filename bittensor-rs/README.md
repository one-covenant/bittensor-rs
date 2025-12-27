# bittensor-rs

[![Crates.io](https://img.shields.io/crates/v/bittensor-rs.svg)](https://crates.io/crates/bittensor-rs)
[![Documentation](https://docs.rs/bittensor-rs/badge.svg)](https://docs.rs/bittensor-rs)
[![CI](https://github.com/one-covenant/bittensor-rs/workflows/CI/badge.svg)](https://github.com/one-covenant/bittensor-rs/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A standalone Rust SDK for interacting with the [Bittensor](https://bittensor.com) blockchain network.

## Features

- **Connection Pooling** - Automatic connection management with health checks, failover, and circuit breaker patterns
- **Wallet Management** - Load wallets, sign transactions, and manage keys compatible with the Bittensor CLI
- **Chain Queries** - Query metagraph data, neuron information, subnet details, balances, and stake
- **Extrinsics** - Submit transactions for staking, weight setting, registration, transfers, and more
- **Retry Logic** - Built-in exponential backoff with configurable retry strategies
- **Type-Safe API** - Strongly typed interfaces generated from Bittensor chain metadata

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
bittensor-rs = "0.1"
```

## Quick Start

```rust
use bittensor::{config::BittensorConfig, Service};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create configuration for Finney mainnet
    let config = BittensorConfig::finney("my_wallet", "my_hotkey", 1);
    
    // Initialize the service (connects to the chain)
    let service = Service::new(config).await?;
    
    // Query the metagraph
    let metagraph = service.get_metagraph(1).await?;
    println!("Found {} neurons on subnet 1", metagraph.hotkeys.len());
    
    // Get current block
    let block = service.get_block_number().await?;
    println!("Current block: {}", block);
    
    Ok(())
}
```

## Configuration

The SDK supports multiple network configurations:

```rust
use bittensor::config::BittensorConfig;

// Finney mainnet
let config = BittensorConfig::finney("wallet", "hotkey", 1);

// Test network
let config = BittensorConfig::testnet("wallet", "hotkey", 1);

// Local development
let config = BittensorConfig::local("wallet", "hotkey", 1);

// Custom endpoint with connection pool settings
let config = BittensorConfig::finney("wallet", "hotkey", 1)
    .with_endpoint("wss://custom-endpoint.com:443")
    .with_pool_size(5)
    .with_read_only(true);
```

## Core Modules

### Chain Queries

```rust
use bittensor::{get_metagraph, get_balance, get_neuron, get_subnet_info};

// Get the full metagraph for a subnet
let metagraph = get_metagraph(&client, netuid).await?;

// Query account balance
let balance = get_balance(&client, &account_id).await?;

// Get neuron info by UID
let neuron = get_neuron(&client, netuid, uid).await?;

// Get subnet hyperparameters
let info = get_subnet_info(&client, netuid).await?;
```

### Extrinsics (Transactions)

```rust
use bittensor::extrinsics::{
    set_weights, add_stake, transfer, serve_axon,
    WeightsParams, StakeParams, TransferParams, ServeAxonParams,
};

// Set weights on a subnet
let params = WeightsParams {
    netuid: 1,
    uids: vec![0, 1, 2],
    weights: vec![100, 200, 300],
    version_key: 0,
};
set_weights(&client, &signer, params).await?;

// Add stake to a hotkey
let params = StakeParams {
    hotkey: hotkey_account,
    amount_rao: 1_000_000_000, // 1 TAO
};
add_stake(&client, &signer, params).await?;

// Transfer TAO
let params = TransferParams {
    dest: destination_account,
    amount_rao: 500_000_000,
};
transfer(&client, &signer, params).await?;
```

### Wallet Management

```rust
use bittensor::wallet::Wallet;

// Load an existing wallet from ~/.bittensor/wallets
let wallet = Wallet::load("my_wallet", "my_hotkey")?;

// Get the hotkey address
println!("Hotkey: {}", wallet.hotkey());

// Sign arbitrary data
let signature = wallet.sign(b"message to sign");

// Create from mnemonic
let wallet = Wallet::from_mnemonic("wallet", "hotkey", "word1 word2 ...")?;
```

### Connection Management

The SDK includes robust connection handling:

```rust
use bittensor::{ConnectionPool, ConnectionPoolBuilder, HealthChecker};

// Build a connection pool with custom settings
let pool = ConnectionPoolBuilder::new(endpoints)
    .max_connections(5)
    .retry_config(RetryConfig::network())
    .build();

// Get connection metrics
let metrics = service.connection_metrics().await;
println!("Healthy connections: {}/{}", 
    metrics.healthy_connections, 
    metrics.total_connections);

// Force reconnection if needed
service.force_reconnect().await?;
```

## Error Handling

The SDK provides detailed error types with retry classification:

```rust
use bittensor::{BittensorError, ErrorCategory};

match service.get_metagraph(1).await {
    Ok(metagraph) => { /* success */ }
    Err(e) => {
        match e.category() {
            ErrorCategory::Transient => {
                // Retry with backoff
            }
            ErrorCategory::Network => {
                // Network issues, try reconnecting
            }
            ErrorCategory::Permanent => {
                // Don't retry
            }
            _ => {}
        }
    }
}
```

## Feature Flags

| Feature | Description | Default |
|---------|-------------|---------|
| `wallet` | Enable wallet management functionality | ✓ |
| `generate-metadata` | Build-time metadata generation | |

## Supported Operations

### Queries
- `get_metagraph` / `get_selective_metagraph` - Subnet metagraph data
- `get_neuron` / `get_neuron_lite` - Neuron information
- `get_balance` / `get_stake` - Account balances
- `get_subnet_info` / `get_subnet_hyperparameters` - Subnet configuration
- `get_total_subnets` / `subnet_exists` - Subnet enumeration

### Extrinsics
- **Staking**: `add_stake`, `remove_stake`, `delegate_stake`, `undelegate_stake`
- **Weights**: `set_weights`, `commit_weights`, `reveal_weights`
- **Transfer**: `transfer`, `transfer_keep_alive`, `transfer_all`
- **Registration**: `serve_axon`, `serve_prometheus`, `burned_register`
- **Subnet**: `register_network`, `set_subnet_identity`
- **Children**: `set_children`, `set_childkey_take`, `revoke_children`
- **Root**: `root_register`, `set_root_weights`

## Requirements

- Rust 1.70 or later
- Tokio runtime

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Related Projects

- [Bittensor](https://github.com/opentensor/bittensor) - Python SDK
- [Subtensor](https://github.com/opentensor/subtensor) - Bittensor blockchain node

