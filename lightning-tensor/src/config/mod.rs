//! # Configuration Module
//!
//! Application configuration management including network settings,
//! wallet defaults, and user preferences.

mod settings;

pub use settings::{Config, NetworkConfig, WalletConfig};

use crate::errors::{Error, Result};
use std::path::PathBuf;

/// Default config file name
pub const CONFIG_FILE_NAME: &str = "config.toml";

/// Get the default config directory
pub fn default_config_dir() -> Result<PathBuf> {
    dirs::config_dir()
        .map(|p| p.join("lightning-tensor"))
        .ok_or_else(|| Error::config("Could not determine config directory"))
}

/// Get the default wallet directory
pub fn default_wallet_dir() -> Result<PathBuf> {
    dirs::home_dir()
        .map(|p| p.join(".bittensor").join("wallets"))
        .ok_or_else(|| Error::config("Could not determine home directory"))
}

/// Get the config file path
pub fn config_file_path() -> Result<PathBuf> {
    default_config_dir().map(|p| p.join(CONFIG_FILE_NAME))
}
