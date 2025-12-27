//! # Wallet Signer
//!
//! A subxt-compatible signer wrapper for Bittensor wallets.

use subxt_signer::sr25519::Keypair;

/// A signer that wraps an sr25519 keypair for use with subxt
///
/// This implements the signing required by subxt for signing extrinsics.
#[derive(Clone)]
pub struct WalletSigner {
    inner: Keypair,
}

impl WalletSigner {
    /// Create a new signer from a subxt-signer keypair
    ///
    /// # Example
    ///
    /// ```ignore
    /// use bittensor::wallet::WalletSigner;
    /// use subxt_signer::sr25519::Keypair;
    ///
    /// let keypair = Keypair::from_uri(&"//Alice".parse().unwrap()).unwrap();
    /// let signer = WalletSigner::new(keypair);
    /// ```
    pub fn new(keypair: Keypair) -> Self {
        Self { inner: keypair }
    }

    /// Create a signer from an sp_core sr25519 Pair
    ///
    /// This converts the sp_core keypair to a subxt-signer keypair.
    pub fn from_sp_core_pair(pair: sp_core::sr25519::Pair) -> Self {
        use sp_core::Pair;
        // Get the seed bytes from the pair by converting to raw bytes
        // The secret key is the first 64 bytes (32 bytes key + 32 bytes nonce)
        let seed = pair.to_raw_vec();
        let keypair = Keypair::from_secret_key(seed[..32].try_into().unwrap())
            .expect("Valid 32-byte seed");
        Self { inner: keypair }
    }

    /// Create a signer from a seed phrase (mnemonic or hex seed)
    pub fn from_seed(seed: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        use subxt_signer::SecretUri;
        
        let uri: SecretUri = seed.parse()?;
        let keypair = Keypair::from_uri(&uri)?;
        Ok(Self { inner: keypair })
    }

    /// Get the underlying Keypair for advanced usage
    pub fn keypair(&self) -> &Keypair {
        &self.inner
    }

    /// Get the public key bytes
    pub fn public_key(&self) -> [u8; 32] {
        self.inner.public_key().0
    }
}

impl std::fmt::Debug for WalletSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WalletSigner")
            .field("public_key", &hex::encode(self.public_key()))
            .finish()
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signer_from_uri() {
        let signer = WalletSigner::from_seed("//Alice").unwrap();
        // Alice's public key should be well-known
        assert!(!signer.public_key().iter().all(|&b| b == 0));
    }

    #[test]
    fn test_signer_debug() {
        let signer = WalletSigner::from_seed("//Alice").unwrap();
        let debug_str = format!("{:?}", signer);
        assert!(debug_str.contains("WalletSigner"));
        assert!(debug_str.contains("public_key"));
    }
}
