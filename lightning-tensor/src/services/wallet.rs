//! # Wallet Service
//!
//! Business logic for wallet operations using bittensor_rs::wallet.

use crate::errors::{Error, Result};
use bittensor_rs::wallet::Wallet;
use std::path::PathBuf;

/// Service for wallet operations
pub struct WalletService {
    wallet_dir: PathBuf,
}

impl WalletService {
    /// Create a new wallet service
    pub fn new(wallet_dir: PathBuf) -> Self {
        Self { wallet_dir }
    }

    /// Get the wallet directory
    pub fn wallet_dir(&self) -> &PathBuf {
        &self.wallet_dir
    }

    /// Create a new wallet with random mnemonic
    /// Note: The new bittensor_rs wallet API creates a wallet with hotkey in one step
    pub fn create_wallet(&self, name: &str, _words: u8, _password: &str) -> Result<Wallet> {
        let wallet_path = self.wallet_dir.join(name);

        if wallet_path.exists() {
            return Err(Error::WalletAlreadyExists {
                name: name.to_string(),
            });
        }

        // Create wallet directory structure
        std::fs::create_dir_all(&wallet_path)?;
        std::fs::create_dir_all(wallet_path.join("hotkeys"))?;

        // Create random wallet with default hotkey
        let wallet = Wallet::create_random(name, "default")
            .map_err(|e| Error::wallet(format!("Failed to create wallet: {}", e)))?;

        // Save the hotkey address to coldkeypub.txt for compatibility
        // Note: bittensor_rs wallet stores hotkey, not coldkey by default
        let coldkeypub_path = wallet_path.join("coldkeypub.txt");
        std::fs::write(&coldkeypub_path, wallet.hotkey().to_string())
            .map_err(|e| Error::wallet(format!("Failed to save coldkeypub: {}", e)))?;

        Ok(wallet)
    }

    /// Load an existing wallet with default hotkey
    pub fn load_wallet(&self, name: &str) -> Result<Wallet> {
        self.load_wallet_with_hotkey(name, "default")
    }

    /// Load an existing wallet with specific hotkey
    pub fn load_wallet_with_hotkey(&self, name: &str, hotkey: &str) -> Result<Wallet> {
        let wallet_path = self.wallet_dir.join(name);

        if !wallet_path.exists() {
            return Err(Error::WalletNotFound {
                name: name.to_string(),
            });
        }

        Wallet::load_from_path(name, hotkey, &self.wallet_dir)
            .map_err(|e| Error::wallet(format!("Failed to load wallet: {}", e)))
    }

    /// List all wallets
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

    /// List hotkeys for a wallet
    pub fn list_hotkeys(&self, wallet_name: &str) -> Result<Vec<String>> {
        let hotkeys_dir = self.wallet_dir.join(wallet_name).join("hotkeys");

        if !hotkeys_dir.exists() {
            return Ok(Vec::new());
        }

        let mut hotkeys = Vec::new();

        for entry in std::fs::read_dir(&hotkeys_dir)? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                if let Some(name) = entry.file_name().to_str() {
                    hotkeys.push(name.to_string());
                }
            }
        }

        hotkeys.sort();
        Ok(hotkeys)
    }

    /// Create a new hotkey for a wallet
    pub fn create_hotkey(
        &self,
        wallet_name: &str,
        hotkey_name: &str,
        _password: &str,
    ) -> Result<String> {
        // Create a new random wallet with the specified hotkey name
        let wallet = Wallet::create_random(wallet_name, hotkey_name)
            .map_err(|e| Error::wallet(format!("Failed to create hotkey: {}", e)))?;

        Ok(wallet.hotkey().to_string())
    }

    /// Sign a message with the wallet's hotkey
    pub fn sign_message(
        &self,
        wallet_name: &str,
        message: &str,
        _password: &str,
    ) -> Result<String> {
        let wallet = self.load_wallet(wallet_name)?;
        let signature = wallet.sign(message.as_bytes());
        Ok(format!("0x{}", hex::encode(signature)))
    }

    /// Verify a signature
    pub fn verify_signature(
        &self,
        message: &str,
        signature: &str,
        pubkey: Option<&str>,
    ) -> Result<bool> {
        let sig_bytes = hex::decode(signature.trim_start_matches("0x"))
            .map_err(|_| Error::wallet("Invalid signature hex"))?;

        if sig_bytes.len() != 64 {
            return Err(Error::wallet("Signature must be 64 bytes"));
        }

        let mut sig_array = [0u8; 64];
        sig_array.copy_from_slice(&sig_bytes);

        let signature = sp_core::sr25519::Signature::from_raw(sig_array);

        if let Some(pk) = pubkey {
            // Decode public key
            let pk_str = pk.trim_start_matches("0x");
            let pk_bytes =
                hex::decode(pk_str).map_err(|_| Error::wallet("Invalid public key hex"))?;

            if pk_bytes.len() != 32 {
                return Err(Error::wallet("Public key must be 32 bytes"));
            }

            let mut pk_array = [0u8; 32];
            pk_array.copy_from_slice(&pk_bytes);

            let public = sp_core::sr25519::Public::from_raw(pk_array);

            use sp_core::Pair;
            Ok(sp_core::sr25519::Pair::verify(
                &signature,
                message.as_bytes(),
                &public,
            ))
        } else {
            Err(Error::wallet("Public key required for verification"))
        }
    }

    /// Regenerate wallet from mnemonic
    pub fn regen_wallet(&self, name: &str, mnemonic: &str, _password: &str) -> Result<Wallet> {
        let wallet_path = self.wallet_dir.join(name);

        // Create wallet directory if needed
        std::fs::create_dir_all(&wallet_path)?;
        std::fs::create_dir_all(wallet_path.join("hotkeys"))?;

        let wallet = Wallet::from_mnemonic(name, "default", mnemonic)
            .map_err(|e| Error::wallet(format!("Failed to regenerate wallet: {}", e)))?;

        // Save the hotkey address
        let coldkeypub_path = wallet_path.join("coldkeypub.txt");
        std::fs::write(&coldkeypub_path, wallet.hotkey().to_string())
            .map_err(|e| Error::wallet(format!("Failed to save coldkeypub: {}", e)))?;

        Ok(wallet)
    }

    /// Delete a wallet
    pub fn delete_wallet(&self, name: &str) -> Result<()> {
        let wallet_path = self.wallet_dir.join(name);

        if !wallet_path.exists() {
            return Err(Error::WalletNotFound {
                name: name.to_string(),
            });
        }

        std::fs::remove_dir_all(wallet_path)?;
        Ok(())
    }
}
