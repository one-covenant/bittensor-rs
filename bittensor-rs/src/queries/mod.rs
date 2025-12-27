//! # Chain Queries
//!
//! Read-only queries against Bittensor blockchain state.
//!
//! This module provides functions for querying:
//!
//! - **Account**: Balances, stake amounts, and stake info
//! - **Metagraph**: Full or selective metagraph data for subnets
//! - **Neurons**: Individual neuron info and UID lookups
//! - **Subnets**: Subnet existence, hyperparameters, and metadata
//!
//! # Example
//!
//! ```rust,no_run
//! use bittensor::queries::{get_metagraph, get_balance, get_neuron};
//!
//! # async fn example(client: &subxt::OnlineClient<subxt::PolkadotConfig>) -> Result<(), Box<dyn std::error::Error>> {
//! // Get metagraph for subnet 1
//! let metagraph = get_metagraph(client, 1).await?;
//!
//! // Check account balance
//! let balance = get_balance(client, &account_id).await?;
//!
//! // Get specific neuron by UID
//! let neuron = get_neuron(client, 1, 0).await?;
//! # Ok(())
//! # }
//! ```
//!
//! All query functions accept a subxt `OnlineClient` and return typed results.

mod account;
mod metagraph;
mod neuron;
mod subnet;

pub use account::{
    get_balance, get_stake, get_stake_info_for_coldkey, get_total_network_stake, StakeInfo,
};
pub use metagraph::{fields, get_metagraph, Metagraph, SelectiveMetagraph};
pub use neuron::{get_neuron, get_neuron_lite, get_uid_for_hotkey, NeuronInfo, NeuronInfoLite};
pub use subnet::{
    get_subnet_hyperparameters, get_subnet_info, get_total_subnets, subnet_exists,
    SubnetHyperparameters, SubnetInfo,
};
