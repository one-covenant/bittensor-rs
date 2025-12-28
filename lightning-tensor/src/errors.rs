//! # Unified Error Handling
//!
//! Centralized error types for the lightning-tensor application.

use thiserror::Error;

/// Main result type for lightning-tensor operations
pub type Result<T> = std::result::Result<T, Error>;

/// Unified error type for lightning-tensor
#[derive(Error, Debug)]
pub enum Error {
    // ========================
    // Configuration Errors
    // ========================
    #[error("Configuration error: {message}")]
    Config { message: String },

    #[error("Invalid network: {network}. Valid options: finney, test, local, or custom URL")]
    InvalidNetwork { network: String },

    // ========================
    // Wallet Errors
    // ========================
    #[error("Wallet error: {message}")]
    Wallet { message: String },

    #[error("Wallet not found: {name}")]
    WalletNotFound { name: String },

    #[error("Wallet already exists: {name}")]
    WalletAlreadyExists { name: String },

    #[error("Invalid password")]
    InvalidPassword,

    #[error("Hotkey not found: {name}")]
    HotkeyNotFound { name: String },

    // ========================
    // Network/RPC Errors
    // ========================
    #[error("Network error: {message}")]
    Network { message: String },

    #[error("Connection failed: {endpoint}")]
    ConnectionFailed { endpoint: String },

    #[error("RPC error: {message}")]
    Rpc { message: String },

    #[error("Transaction failed: {message}")]
    Transaction { message: String },

    #[error("Transaction timeout after {seconds}s")]
    TransactionTimeout { seconds: u64 },

    // ========================
    // Staking Errors
    // ========================
    #[error("Staking error: {message}")]
    Staking { message: String },

    #[error("Insufficient balance: required {required} TAO, available {available} TAO")]
    InsufficientBalance { required: f64, available: f64 },

    #[error("Invalid stake amount: {message}")]
    InvalidStakeAmount { message: String },

    // ========================
    // Subnet Errors
    // ========================
    #[error("Subnet not found: netuid {netuid}")]
    SubnetNotFound { netuid: u16 },

    #[error("Subnet error: {message}")]
    Subnet { message: String },

    // ========================
    // Weights Errors
    // ========================
    #[error("Invalid weights: {message}")]
    InvalidWeights { message: String },

    #[error("Weights error: {message}")]
    Weights { message: String },

    // ========================
    // UI Errors
    // ========================
    #[error("UI error: {message}")]
    Ui { message: String },

    #[error("User cancelled operation")]
    UserCancelled,

    // ========================
    // IO Errors
    // ========================
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("TOML parse error: {0}")]
    TomlParse(#[from] toml::de::Error),

    // ========================
    // External Library Errors
    // ========================
    #[error("Bittensor SDK error: {0}")]
    BittensorSdk(#[from] bittensor_rs::BittensorError),

    #[error("Wallet library error: {0}")]
    WalletLib(#[from] bittensor_rs::wallet::KeyfileError),
}

impl Error {
    /// Create a config error
    pub fn config(message: impl Into<String>) -> Self {
        Self::Config {
            message: message.into(),
        }
    }

    /// Create a wallet error
    pub fn wallet(message: impl Into<String>) -> Self {
        Self::Wallet {
            message: message.into(),
        }
    }

    /// Create a network error
    pub fn network(message: impl Into<String>) -> Self {
        Self::Network {
            message: message.into(),
        }
    }

    /// Create a transaction error
    pub fn transaction(message: impl Into<String>) -> Self {
        Self::Transaction {
            message: message.into(),
        }
    }

    /// Create a staking error
    pub fn staking(message: impl Into<String>) -> Self {
        Self::Staking {
            message: message.into(),
        }
    }

    /// Create a subnet error
    pub fn subnet(message: impl Into<String>) -> Self {
        Self::Subnet {
            message: message.into(),
        }
    }

    /// Create a UI error
    pub fn ui(message: impl Into<String>) -> Self {
        Self::Ui {
            message: message.into(),
        }
    }

    /// Check if error is recoverable (can retry)
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            Error::Network { .. }
                | Error::ConnectionFailed { .. }
                | Error::Rpc { .. }
                | Error::TransactionTimeout { .. }
        )
    }

    /// Check if error is user-facing (show to user without stack trace)
    pub fn is_user_facing(&self) -> bool {
        matches!(
            self,
            Error::InvalidPassword
                | Error::UserCancelled
                | Error::WalletNotFound { .. }
                | Error::WalletAlreadyExists { .. }
                | Error::InsufficientBalance { .. }
                | Error::InvalidNetwork { .. }
        )
    }
}
