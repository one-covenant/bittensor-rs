//! # Lightning Tensor
//!
//! High-performance CLI/TUI for the Bittensor network.
//!
//! This crate provides both a command-line interface (CLI) and a terminal user interface (TUI)
//! for interacting with the Bittensor blockchain network.
//!
//! ## Features
//!
//! - **Wallet Management**: Create, manage, and sign with wallets
//! - **Staking**: Add, remove, and manage stake positions
//! - **Transfers**: Send TAO between accounts
//! - **Subnets**: View and interact with subnets
//! - **Weights**: Set, commit, and reveal weights
//! - **Root Network**: Root network registration and weights
//! - **Crowdfunding**: Create and manage crowdfunding campaigns

pub mod cli;
pub mod config;
pub mod context;
pub mod errors;
pub mod models;
pub mod services;
pub mod tui;

// Re-exports for convenience
pub use config::Config;
pub use context::AppContext;
pub use errors::{Error, Result};

