//! Wallet compatibility layer for lightning-tensor
//!
//! This module provides a minimal wallet implementation for the TUI app,
//! replacing the previous bittensor-wallet dependency.

use crate::errors::AppError;
use sp_core::sr25519::{Pair, Public, Signature};
use sp_core::Pair as PairTrait;
use std::path::PathBuf;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum WalletError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Wallet not found: {0}")]
    NotFound(String),
    #[error("Invalid password")]
    InvalidPassword,
    #[error("Keypair error: {0}")]
    KeypairError(String),
    #[error("Encryption error: {0}")]
    EncryptionError(String),
}

/// A minimal wallet implementation for lightning-tensor TUI
#[derive(Clone)]
pub struct Wallet {
    pub name: String,
    pub path: PathBuf,
    pub balance: Option<f64>,
    keypair: Option<Pair>,
}

impl std::fmt::Debug for Wallet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Wallet")
            .field("name", &self.name)
            .field("path", &self.path)
            .field("balance", &self.balance)
            .field("has_keypair", &self.keypair.is_some())
            .finish()
    }
}

impl Wallet {
    /// Create a new wallet wrapper
    pub fn new(name: &str, path: PathBuf) -> Self {
        Self {
            name: name.to_string(),
            path,
            balance: None,
            keypair: None,
        }
    }

    /// Create a new wallet with a generated keypair
    pub fn create_new_wallet(&mut self, _word_count: u32, _password: &str) -> Result<(), WalletError> {
        // Generate a random keypair (always 12 words for simplicity)
        let (pair, phrase, _) = Pair::generate_with_phrase(None);
        
        self.keypair = Some(pair);
        
        // Save mnemonic to wallet directory
        let wallet_dir = self.path.join(&self.name);
        std::fs::create_dir_all(&wallet_dir)?;
        
        // Note: In production, this should be encrypted with the password
        let mnemonic_path = wallet_dir.join("mnemonic.txt");
        std::fs::write(mnemonic_path, phrase)?;
        
        Ok(())
    }

    /// Fetch balance from the network (stub - returns cached value)
    pub async fn fetch_balance(&mut self) -> Result<(), AppError> {
        // TODO: Implement actual balance fetching via bittensor-rs
        // For now, just use a placeholder
        if self.balance.is_none() {
            self.balance = Some(0.0);
        }
        Ok(())
    }

    /// Get the active hotkey keypair
    pub fn get_active_hotkey(&self, _password: &str) -> Result<KeypairWrapper, WalletError> {
        match &self.keypair {
            Some(pair) => Ok(KeypairWrapper(pair.clone())),
            None => Err(WalletError::NotFound("No keypair loaded".to_string())),
        }
    }

    /// Get the coldkey public key
    pub fn get_coldkey(&self, _password: &str) -> Result<Public, WalletError> {
        match &self.keypair {
            Some(pair) => Ok(pair.public()),
            None => Err(WalletError::NotFound("No keypair loaded".to_string())),
        }
    }

    /// Verify a signature
    pub fn verify(&self, message: &[u8], signature: &[u8], _password: &str) -> Result<bool, WalletError> {
        let sig: Signature = signature
            .try_into()
            .map_err(|_| WalletError::KeypairError("Invalid signature length".to_string()))?;
        
        match &self.keypair {
            Some(pair) => Ok(Pair::verify(&sig, message, &pair.public())),
            None => Err(WalletError::NotFound("No keypair loaded".to_string())),
        }
    }

    /// Change the wallet password (stub)
    pub async fn change_password(&mut self, _old_password: &str, _new_password: &str) -> Result<(), WalletError> {
        // TODO: Implement actual password change with re-encryption
        Ok(())
    }
}

/// Wrapper around sr25519::Pair to provide signing interface
#[derive(Clone)]
pub struct KeypairWrapper(Pair);

impl KeypairWrapper {
    /// Sign a message
    pub fn sign(&self, message: &[u8], _password: &str) -> Result<Signature, WalletError> {
        Ok(self.0.sign(message))
    }
}

