//! # Application Context
//!
//! Shared context for CLI and TUI operations, providing access to
//! the Bittensor service, wallet, and configuration.

use crate::config::Config;
use crate::errors::{Error, Result};
use bittensor_rs::wallet::Wallet;
use bittensor_rs::Service;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Application context shared between CLI and TUI
///
/// Provides thread-safe access to the Bittensor service, current wallet,
/// and application configuration.
pub struct AppContext {
    /// Bittensor service for chain interactions (lazy initialized)
    service: RwLock<Option<Arc<Service>>>,

    /// Current active wallet (if any)
    wallet: RwLock<Option<Wallet>>,

    /// Application configuration
    config: Config,

    /// Wallet directory path
    wallet_dir: PathBuf,
}

impl AppContext {
    /// Create a new application context
    pub fn new(config: Config) -> Result<Self> {
        let wallet_dir = config.wallet.get_wallet_dir()?;

        Ok(Self {
            service: RwLock::new(None),
            wallet: RwLock::new(None),
            config,
            wallet_dir,
        })
    }

    /// Create context with default configuration
    pub fn with_defaults() -> Result<Self> {
        let config = Config::load_or_default()?;
        Self::new(config)
    }

    /// Get the application configuration
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Get the wallet directory
    pub fn wallet_dir(&self) -> &PathBuf {
        &self.wallet_dir
    }

    /// Check if connected to the network
    pub async fn is_connected(&self) -> bool {
        self.service.read().await.is_some()
    }

    /// Get the current service (if connected)
    pub async fn service(&self) -> Option<Arc<Service>> {
        self.service.read().await.clone()
    }

    /// Get the current service or return error
    pub async fn require_service(&self) -> Result<Arc<Service>> {
        self.service
            .read()
            .await
            .clone()
            .ok_or_else(|| Error::network("Not connected to network. Run 'lt connect' first."))
    }

    /// Connect to the Bittensor network
    ///
    /// # Arguments
    ///
    /// * `wallet_name` - Name of the wallet to use for signing
    /// * `hotkey_name` - Name of the hotkey to use
    /// * `netuid` - Subnet ID for operations
    pub async fn connect(
        &self,
        wallet_name: &str,
        hotkey_name: &str,
        netuid: u16,
    ) -> Result<Arc<Service>> {
        let bittensor_config = self
            .config
            .to_bittensor_config(wallet_name, hotkey_name, netuid);

        let service = Service::new(bittensor_config).await?;
        let service = Arc::new(service);

        *self.service.write().await = Some(Arc::clone(&service));

        Ok(service)
    }

    /// Connect with default wallet settings from config
    pub async fn connect_with_defaults(&self) -> Result<Arc<Service>> {
        // Use defaults from config, or fallback to sensible defaults for read-only access
        let wallet_name = self
            .config
            .wallet
            .default_wallet.as_deref()
            .unwrap_or("default");

        let hotkey_name = self
            .config
            .wallet
            .default_hotkey.as_deref()
            .unwrap_or("default");

        let netuid = self.config.wallet.default_netuid;

        self.connect(wallet_name, hotkey_name, netuid).await
    }

    /// Disconnect from the network
    pub async fn disconnect(&self) {
        *self.service.write().await = None;
    }

    /// Get the current wallet (if loaded)
    pub async fn wallet(&self) -> Option<Wallet> {
        self.wallet.read().await.clone()
    }

    /// Get the current wallet or return error
    pub async fn require_wallet(&self) -> Result<bittensor_rs::wallet::Wallet> {
        self.wallet
            .read()
            .await
            .clone()
            .ok_or_else(|| Error::wallet("No wallet loaded. Use 'lt wallet load' first."))
    }

    /// Load a wallet by name with default hotkey
    pub async fn load_wallet(&self, name: &str) -> Result<Wallet> {
        self.load_wallet_with_hotkey(name, "default").await
    }

    /// Load a wallet by name with specific hotkey
    pub async fn load_wallet_with_hotkey(&self, name: &str, hotkey: &str) -> Result<Wallet> {
        let wallet_path = self.wallet_dir.join(name);

        if !wallet_path.exists() {
            return Err(Error::WalletNotFound {
                name: name.to_string(),
            });
        }

        let wallet = Wallet::load_from_path(name, hotkey, &self.wallet_dir)
            .map_err(|e| Error::wallet(format!("Failed to load wallet: {}", e)))?;
        *self.wallet.write().await = Some(wallet.clone());

        Ok(wallet)
    }

    /// Unload the current wallet
    pub async fn unload_wallet(&self) {
        *self.wallet.write().await = None;
    }

    /// List available wallets
    pub fn list_wallets(&self) -> Result<Vec<String>> {
        if !self.wallet_dir.exists() {
            return Ok(Vec::new());
        }

        let mut wallets = Vec::new();

        for entry in std::fs::read_dir(&self.wallet_dir)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                if let Some(name) = entry.file_name().to_str() {
                    wallets.push(name.to_string());
                }
            }
        }

        wallets.sort();
        Ok(wallets)
    }

    /// Get network name
    pub fn network_name(&self) -> &str {
        &self.config.network.network
    }

    /// Get default netuid
    pub fn default_netuid(&self) -> u16 {
        self.config.wallet.default_netuid
    }
}

/// Builder for AppContext with fluent API
pub struct AppContextBuilder {
    config: Config,
    wallet_name: Option<String>,
    hotkey_name: Option<String>,
    netuid: Option<u16>,
}

impl AppContextBuilder {
    pub fn new() -> Self {
        Self {
            config: Config::default(),
            wallet_name: None,
            hotkey_name: None,
            netuid: None,
        }
    }

    pub fn with_config(mut self, config: Config) -> Self {
        self.config = config;
        self
    }

    pub fn with_network(mut self, network: impl Into<String>) -> Self {
        self.config.network.network = network.into();
        self
    }

    pub fn with_wallet(mut self, wallet_name: impl Into<String>) -> Self {
        self.wallet_name = Some(wallet_name.into());
        self
    }

    pub fn with_hotkey(mut self, hotkey_name: impl Into<String>) -> Self {
        self.hotkey_name = Some(hotkey_name.into());
        self
    }

    pub fn with_netuid(mut self, netuid: u16) -> Self {
        self.netuid = Some(netuid);
        self
    }

    pub fn build(self) -> Result<AppContext> {
        let mut config = self.config;

        if let Some(wallet) = self.wallet_name {
            config.wallet.default_wallet = Some(wallet);
        }
        if let Some(hotkey) = self.hotkey_name {
            config.wallet.default_hotkey = Some(hotkey);
        }
        if let Some(netuid) = self.netuid {
            config.wallet.default_netuid = netuid;
        }

        AppContext::new(config)
    }
}

impl Default for AppContextBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_context_builder() {
        let ctx = AppContextBuilder::new()
            .with_network("test")
            .with_wallet("my_wallet")
            .with_hotkey("my_hotkey")
            .with_netuid(18)
            .build()
            .unwrap();

        assert_eq!(ctx.config.network.network, "test");
        assert_eq!(
            ctx.config.wallet.default_wallet,
            Some("my_wallet".to_string())
        );
        assert_eq!(ctx.config.wallet.default_netuid, 18);
    }
}
