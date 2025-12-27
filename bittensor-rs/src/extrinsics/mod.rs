//! # Extrinsics (Transactions)
//!
//! Submit signed transactions to the Bittensor blockchain.
//!
//! This module provides functions for all Bittensor chain operations:
//!
//! | Category | Functions |
//! |----------|-----------|
//! | **Staking** | [`add_stake`], [`remove_stake`], [`delegate_stake`], [`undelegate_stake`] |
//! | **Transfer** | [`transfer`], [`transfer_keep_alive`], [`transfer_all`] |
//! | **Weights** | [`set_weights`], [`commit_weights`], [`reveal_weights`] |
//! | **Registration** | [`serve_axon`], [`serve_prometheus`], [`burned_register`] |
//! | **Subnet** | [`register_network`], [`set_subnet_identity`] |
//! | **Children** | [`set_children`], [`set_childkey_take`], [`revoke_children`] |
//! | **Root** | [`root_register`], [`set_root_weights`] |
//!
//! # Example
//!
//! ```rust,no_run
//! use bittensor::extrinsics::{set_weights, WeightsParams, add_stake, StakeParams};
//!
//! # async fn example(
//! #     client: &subxt::OnlineClient<subxt::PolkadotConfig>,
//! #     signer: &subxt_signer::sr25519::Keypair,
//! #     hotkey: subxt::config::polkadot::AccountId32,
//! # ) -> Result<(), Box<dyn std::error::Error>> {
//! // Set weights on subnet 1
//! let params = WeightsParams {
//!     netuid: 1,
//!     uids: vec![0, 1, 2],
//!     weights: vec![100, 200, 300],
//!     version_key: 0,
//! };
//! let response = set_weights(client, signer, params).await?;
//!
//! // Add stake to a hotkey (1 TAO = 1e9 rao)
//! let stake_params = StakeParams {
//!     hotkey,
//!     amount_rao: 1_000_000_000,
//! };
//! add_stake(client, signer, stake_params).await?;
//! # Ok(())
//! # }
//! ```
//!
//! All extrinsic functions return [`ExtrinsicResponse`] with transaction status.

mod children;
mod registration;
mod response;
mod root;
mod staking;
mod subnet;
mod transfer;
mod weights;

pub use children::{revoke_children, set_childkey_take, set_children, ChildKey, SetChildrenParams};
pub use registration::{
    burned_register, serve_axon, serve_prometheus, ServeAxonParams, ServePrometheusParams,
};
pub use response::{ExtrinsicResponse, ExtrinsicStatus};
pub use root::{set_root_weights, RootWeightsParams};
pub use staking::{add_stake, delegate_stake, remove_stake, undelegate_stake, StakeParams};
pub use subnet::{
    register_network, register_network_with_identity, root_register, set_subnet_identity,
    SubnetIdentity,
};
pub use transfer::{transfer, transfer_all, transfer_keep_alive, TransferParams};
pub use weights::{commit_weights, reveal_weights, set_weights, CommitRevealParams, WeightsParams};
