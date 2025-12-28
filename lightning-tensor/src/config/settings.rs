//! # Configuration Settings
//!
//! Defines configuration structures and loading/saving logic.

use crate::errors::{Error, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Main application configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Network configuration
    #[serde(default)]
    pub network: NetworkConfig,

    /// Wallet configuration
    #[serde(default)]
    pub wallet: WalletConfig,

    /// UI preferences
    #[serde(default)]
    pub ui: UiConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            network: NetworkConfig::default(),
            wallet: WalletConfig::default(),
            ui: UiConfig::default(),
        }
    }
}

impl Config {
    /// Load configuration from file
    pub fn load(path: &PathBuf) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }

        let content = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    }

    /// Save configuration to file
    pub fn save(&self, path: &PathBuf) -> Result<()> {
        // Create parent directory if it doesn't exist
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let content = toml::to_string_pretty(self)
            .map_err(|e| Error::config(format!("Failed to serialize config: {}", e)))?;
        std::fs::write(path, content)?;
        Ok(())
    }

    /// Load from default location or create default
    pub fn load_or_default() -> Result<Self> {
        match super::config_file_path() {
            Ok(path) => Self::load(&path),
            Err(_) => Ok(Self::default()),
        }
    }

    /// Get bittensor-rs config for the current network
    pub fn to_bittensor_config(
        &self,
        wallet_name: &str,
        hotkey_name: &str,
        netuid: u16,
    ) -> bittensor_rs::BittensorConfig {
        match self.network.network.as_str() {
            "finney" => bittensor_rs::BittensorConfig::finney(wallet_name, hotkey_name, netuid),
            "test" => bittensor_rs::BittensorConfig::testnet(wallet_name, hotkey_name, netuid),
            "local" => bittensor_rs::BittensorConfig::local(wallet_name, hotkey_name, netuid),
            custom_endpoint => bittensor_rs::BittensorConfig {
                wallet_name: wallet_name.to_string(),
                hotkey_name: hotkey_name.to_string(),
                network: "custom".to_string(),
                netuid,
                chain_endpoint: Some(custom_endpoint.to_string()),
                ..Default::default()
            },
        }
    }
}

/// Network configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Network name: "finney", "test", "local", or custom URL
    #[serde(default = "default_network")]
    pub network: String,

    /// Connection timeout in seconds
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,

    /// Number of retry attempts
    #[serde(default = "default_retries")]
    pub retries: u32,

    /// Custom chain endpoints (optional)
    #[serde(default)]
    pub endpoints: Vec<String>,
}

fn default_network() -> String {
    "finney".to_string()
}

fn default_timeout() -> u64 {
    30
}

fn default_retries() -> u32 {
    3
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            network: default_network(),
            timeout_secs: default_timeout(),
            retries: default_retries(),
            endpoints: Vec::new(),
        }
    }
}

impl NetworkConfig {
    /// Create config for Finney mainnet
    pub fn finney() -> Self {
        Self {
            network: "finney".to_string(),
            ..Default::default()
        }
    }

    /// Create config for testnet
    pub fn testnet() -> Self {
        Self {
            network: "test".to_string(),
            ..Default::default()
        }
    }

    /// Create config for local network
    pub fn local() -> Self {
        Self {
            network: "local".to_string(),
            ..Default::default()
        }
    }

    /// Create config for custom endpoint
    pub fn custom(endpoint: impl Into<String>) -> Self {
        Self {
            network: endpoint.into(),
            ..Default::default()
        }
    }
}

/// Wallet configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletConfig {
    /// Default wallet name
    #[serde(default)]
    pub default_wallet: Option<String>,

    /// Default hotkey name
    #[serde(default)]
    pub default_hotkey: Option<String>,

    /// Wallet directory path (None = use default ~/.bittensor/wallets)
    #[serde(default)]
    pub wallet_dir: Option<PathBuf>,

    /// Default subnet for operations
    #[serde(default = "default_netuid")]
    pub default_netuid: u16,
}

fn default_netuid() -> u16 {
    1
}

impl Default for WalletConfig {
    fn default() -> Self {
        Self {
            default_wallet: None,
            default_hotkey: None,
            wallet_dir: None,
            default_netuid: default_netuid(),
        }
    }
}

impl WalletConfig {
    /// Get the wallet directory, using default if not specified
    pub fn get_wallet_dir(&self) -> Result<PathBuf> {
        match &self.wallet_dir {
            Some(dir) => Ok(dir.clone()),
            None => super::default_wallet_dir(),
        }
    }
}

/// UI configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiConfig {
    /// Enable colors in CLI output
    #[serde(default = "default_true")]
    pub colors: bool,

    /// Show spinners/progress bars
    #[serde(default = "default_true")]
    pub progress: bool,

    /// Verbose output
    #[serde(default)]
    pub verbose: bool,

    /// TUI refresh rate in milliseconds
    #[serde(default = "default_refresh_rate")]
    pub refresh_rate_ms: u64,
}

fn default_true() -> bool {
    true
}

fn default_refresh_rate() -> u64 {
    100
}

impl Default for UiConfig {
    fn default() -> Self {
        Self {
            colors: true,
            progress: true,
            verbose: false,
            refresh_rate_ms: default_refresh_rate(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.network.network, "finney");
        assert_eq!(config.network.timeout_secs, 30);
        assert_eq!(config.wallet.default_netuid, 1);
    }

    #[test]
    fn test_config_serialization() {
        let config = Config::default();
        let toml_str = toml::to_string(&config).unwrap();
        let parsed: Config = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.network.network, config.network.network);
    }
}
