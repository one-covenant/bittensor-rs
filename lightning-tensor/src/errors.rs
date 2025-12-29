use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    #[error("Bittensor error: {0}")]
    BittensorError(#[from] bittensor_rs::BittensorError),
    #[error("Wallet error: {0}")]
    WalletError(#[from] crate::wallet_compat::WalletError),
    #[error("Configuration error: {0}")]
    ConfigError(String),
}
