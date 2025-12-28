//! # Wallet Service
//!
//! Business logic for wallet operations.

use crate::errors::{Error, Result};
use bittensor_wallet::Wallet;
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

    /// Create a new wallet
    pub fn create_wallet(&self, name: &str, words: u8, password: &str) -> Result<Wallet> {
        let wallet_path = self.wallet_dir.join(name);
        
        if wallet_path.exists() {
            return Err(Error::WalletAlreadyExists { name: name.to_string() });
        }
        
        // Create wallet directory
        std::fs::create_dir_all(&wallet_path)?;
        
        let mut wallet = Wallet::new(name, wallet_path);
        wallet.create_new_wallet(words as u32, password)?;
        
        Ok(wallet)
    }

    /// Load an existing wallet
    pub fn load_wallet(&self, name: &str) -> Result<Wallet> {
        let wallet_path = self.wallet_dir.join(name);
        
        if !wallet_path.exists() {
            return Err(Error::WalletNotFound { name: name.to_string() });
        }
        
        Ok(Wallet::new(name, wallet_path))
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
    pub fn create_hotkey(&self, wallet_name: &str, hotkey_name: &str, password: &str) -> Result<String> {
        let mut wallet = self.load_wallet(wallet_name)?;
        wallet.create_new_hotkey(hotkey_name, password)?;
        
        let address = wallet.get_hotkey_ss58(hotkey_name)?;
        Ok(address)
    }

    /// Sign a message with the coldkey
    pub fn sign_message(&self, wallet_name: &str, _message: &str, password: &str) -> Result<String> {
        let wallet = self.load_wallet(wallet_name)?;
        let public = wallet.get_coldkey(password)?;
        
        // For now, just return a placeholder - actual signing requires the private key
        // The Wallet struct stores encrypted mnemonic, so we'd need to derive the keypair
        // TODO: Implement actual message signing when private key derivation is available
        Ok(format!("0x{}", hex::encode(public.0)))
    }

    /// Verify a signature
    pub fn verify_signature(&self, message: &str, signature: &str, pubkey: Option<&str>) -> Result<bool> {
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
            let pk_bytes = hex::decode(pk_str)
                .map_err(|_| Error::wallet("Invalid public key hex"))?;
            
            if pk_bytes.len() != 32 {
                return Err(Error::wallet("Public key must be 32 bytes"));
            }
            
            let mut pk_array = [0u8; 32];
            pk_array.copy_from_slice(&pk_bytes);
            
            let public = sp_core::sr25519::Public::from_raw(pk_array);
            
            use sp_core::Pair;
            Ok(sp_core::sr25519::Pair::verify(&signature, message.as_bytes(), &public))
        } else {
            Err(Error::wallet("Public key required for verification"))
        }
    }

    /// Regenerate wallet from mnemonic
    pub fn regen_wallet(&self, name: &str, mnemonic: &str, password: &str) -> Result<Wallet> {
        let wallet_path = self.wallet_dir.join(name);
        
        // Create wallet directory if needed
        std::fs::create_dir_all(&wallet_path)?;
        
        let mut wallet = Wallet::new(name, wallet_path);
        wallet.regenerate_wallet(mnemonic, password)?;
        
        Ok(wallet)
    }

    /// Delete a wallet
    pub fn delete_wallet(&self, name: &str) -> Result<()> {
        let wallet_path = self.wallet_dir.join(name);
        
        if !wallet_path.exists() {
            return Err(Error::WalletNotFound { name: name.to_string() });
        }
        
        std::fs::remove_dir_all(wallet_path)?;
        Ok(())
    }
}
