use crate::errors::WalletError;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::{password_hash::SaltString, Argon2, PasswordHasher};

use bip39::Mnemonic;
use serde::{Deserialize, Serialize};
use sp_core::{sr25519, Pair};
use sp_runtime::traits::IdentifyAccount;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ColdKeyPair {
    pub public: sr25519::Public,
    private_key: Vec<u8>,
    is_encrypted: bool,
}

impl AsRef<[u8]> for ColdKeyPair {
    fn as_ref(&self) -> &[u8] {
        &self.private_key
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HotKeyPair {
    pub public: sr25519::Public,
    pub private: Vec<u8>,
}

pub trait KeyPair {
    fn public(&self) -> &sr25519::Public;
    fn sign(&self, message: &[u8]) -> Result<sr25519::Signature, WalletError>;
    fn to_mnemonic(&self) -> String;
    fn to_seed(&self) -> Vec<u8>;
}

impl KeyPair for ColdKeyPair {
    /// Returns a reference to the public key of the ColdKeyPair.
    ///
    /// # Returns
    ///
    /// * `&sr25519::Public` - A reference to the sr25519 public key.
    fn public(&self) -> &sr25519::Public {
        &self.public
    }

    /// Signs a message using the private key associated with this ColdKeyPair.
    ///
    /// # Arguments
    ///
    /// * `message` - A byte slice containing the message to be signed.
    ///
    /// # Returns
    ///
    /// * `Result<sr25519::Signature, WalletError>` - The signature of the message or an error.
    ///
    /// # Errors
    ///
    /// Returns `WalletError::EncryptedKeyError` if the ColdKeyPair is encrypted.
    ///
    /// # Example
    ///
    /// ```
    /// # use bittensor_wallet::{ColdKeyPair, KeyPair};
    /// # let cold_key_pair = ColdKeyPair::new(); // Assume this is a valid ColdKeyPair
    /// let message = b"Hello, world!";
    /// match cold_key_pair.sign(message) {
    ///     Ok(signature) => println!("Signature: {:?}", signature),
    ///     Err(e) => eprintln!("Error: {:?}", e),
    /// }
    /// ```
    /// Signs a message using the private key associated with this ColdKeyPair.
    ///
    /// # Arguments
    ///
    /// * `message` - A byte slice containing the message to be signed.
    ///
    /// # Returns
    ///
    /// * `Result<sr25519::Signature, WalletError>` - The signature of the message or an error.
    ///
    /// # Errors
    ///
    /// * `WalletError::EncryptedKeyError` - If the ColdKeyPair is encrypted.
    /// * `WalletError::InvalidPrivateKey` - If the private key is invalid.
    ///
    /// # Example
    ///
    /// ```
    /// # use bittensor_wallet::{ColdKeyPair, KeyPair};
    /// # let cold_key_pair = ColdKeyPair::new(); // Assume this is a valid ColdKeyPair
    /// let message: &[u8] = b"Hello, world!";
    /// match cold_key_pair.sign(message) {
    ///     Ok(signature) => println!("Signature: {:?}", signature),
    ///     Err(e) => eprintln!("Error: {:?}", e),
    /// }
    /// ```
    fn sign(&self, message: &[u8]) -> Result<sr25519::Signature, WalletError> {
        if self.is_encrypted {
            return Err(WalletError::EncryptedKeyError(
                "Cannot sign with an encrypted ColdKeyPair. Use sign_encrypted() instead."
                    .to_string(),
            ));
        }

        // Create a pair from the private key
        let pair: sr25519::Pair = sr25519::Pair::from_seed_slice(&self.private_key)
            .map_err(|_| WalletError::InvalidPrivateKey)?;

        // Sign the message and return the signature
        Ok(pair.sign(message))
    }

    /// Attempts to generate a mnemonic phrase from the ColdKeyPair.
    ///
    /// # Returns
    ///
    /// * `String` - This operation is not allowed for ColdKeyPair, so it always returns an error message.
    ///

    fn to_mnemonic(&self) -> String {
        "Getting mnemonic from ColdKeyPair is not allowed".to_string()
    }

    /// Attempts to retrieve the seed from the ColdKeyPair.
    ///
    /// # Returns
    ///
    /// * `Vec<u8>` - This operation is not allowed for ColdKeyPair, so it always returns an empty vector.
    ///

    fn to_seed(&self) -> Vec<u8> {
        Vec::new()
    }
}

impl KeyPair for HotKeyPair {
    /// Returns a reference to the public key of the HotKeyPair.
    ///
    /// # Returns
    ///
    /// * `&sr25519::Public` - A reference to the public key.
    fn public(&self) -> &sr25519::Public {
        &self.public
    }

    /// Signs a message using the private key of the HotKeyPair.
    ///
    /// # Arguments
    ///
    /// * `message` - A byte slice containing the message to be signed.
    ///
    /// # Returns
    ///
    /// * `sr25519::Signature` - The signature of the message.
    ///
    /// # Panics
    ///
    /// This function will panic if the private key is invalid and cannot produce a valid pair.
    fn sign(&self, message: &[u8]) -> Result<sr25519::Signature, WalletError> {
        let pair = sr25519::Pair::from_seed_slice(&self.private)
            .map_err(|_| WalletError::KeyDerivationError)?;
        Ok(pair.sign(message))
    }

    /// Generates a mnemonic phrase from the private key of the HotKeyPair.
    ///
    /// # Returns
    ///
    /// * `String` - The mnemonic phrase as a string.
    ///
    /// # Panics
    ///
    /// This function will panic if the private key is invalid and cannot produce a valid mnemonic.
    fn to_mnemonic(&self) -> String {
        let entropy = &self.private[..32]; // Use only the first 32 bytes
        let mnemonic = Mnemonic::from_entropy(entropy)
            .expect("Valid 32-byte entropy should always produce a valid mnemonic");
        mnemonic.to_string()
    }

    /// Returns a copy of the private key (seed) of the HotKeyPair.
    ///
    /// # Returns
    ///
    /// * `Vec<u8>` - A vector containing the private key bytes.
    ///
    /// # Security Considerations
    ///
    /// This method returns the raw private key. Use with caution and ensure
    /// proper security measures are in place when handling the private key.
    fn to_seed(&self) -> Vec<u8> {
        self.private.clone()
    }
}

impl ColdKeyPair {
    /// Creates a new ColdKeyPair instance with the given public key and encrypted private key.
    ///
    /// # Arguments
    ///
    /// * `public` - The public key of type `sr25519::Public`.
    /// * `encrypted_private` - The encrypted private key as a vector of bytes.
    ///
    /// # Returns
    ///
    /// A new `ColdKeyPair` instance.
    pub fn new(public: sr25519::Public, private_key: Vec<u8>, is_encrypted: bool) -> Self {
        Self {
            public,
            private_key,
            is_encrypted,
        }
    }

    /// Generates a new ColdKeyPair with a fresh key pair.
    ///
    /// # Returns
    ///
    /// A new `ColdKeyPair` instance with generated public and private keys.
    pub fn generate() -> Self {
        let (pair, _) = sr25519::Pair::generate();
        let public = pair.public();
        let private = pair.to_raw_vec();
        Self {
            public,
            private_key: private,
            is_encrypted: false,
        }
    }

    /// Creates a new ColdKeyPair from a mnemonic phrase.
    ///
    /// # Arguments
    ///
    /// * `mnemonic` - A string slice that holds the mnemonic phrase.
    /// * `password` - An optional string slice that holds the password for encryption.
    ///
    /// # Returns
    ///
    /// * `Result<Self, WalletError>` - A new ColdKeyPair if successful, or a WalletError if the operation fails.
    ///
    pub fn from_mnemonic(mnemonic: &str, password: Option<&str>) -> Result<Self, WalletError> {
        log::debug!("Attempting to create ColdKeyPair from mnemonic");

        // Parse the mnemonic phrase
        let mnemonic = match Mnemonic::parse(mnemonic) {
            Ok(m) => m,
            Err(e) => {
                log::error!("Failed to parse mnemonic: {:?}", e);
                return Err(WalletError::InvalidMnemonic);
            }
        };

        // Generate the seed from the mnemonic
        let seed = mnemonic.to_seed(password.unwrap_or(""));
        log::debug!("Generated seed from mnemonic");

        // Generate the sr25519 keypair from the seed
        let pair = match sr25519::Pair::from_seed_slice(&seed[..32]) {
            Ok(p) => p,
            Err(e) => {
                log::error!("Failed to create keypair from seed: {:?}", e);
                return Err(WalletError::KeyDerivationError);
            }
        };

        let public = pair.public();
        let private = pair.to_raw_vec();

        log::debug!("Created keypair successfully");

        // Create a ColdKeyPair instance
        let cold_keypair = Self {
            public,
            private_key: private,
            is_encrypted: false,
        };

        // If a password is provided, encrypt the private key
        if let Some(pwd) = password {
            match cold_keypair.encrypt(pwd) {
                Ok(encrypted_keypair) => Ok(encrypted_keypair),
                Err(e) => {
                    log::error!("Failed to encrypt private key: {:?}", e);
                    Err(e)
                }
            }
        } else {
            Ok(cold_keypair)
        }
    }

    /// Encrypts the private key using AES-GCM encryption with a password-derived key.
    ///
    /// This function performs the following steps:
    /// 1. Generates a random salt for key derivation
    /// 2. Uses Argon2 to derive a key from the password
    /// 3. Creates an AES-GCM cipher instance
    /// 4. Generates a random nonce for AES-GCM
    /// 5. Encrypts the private key
    /// 6. Combines salt, nonce, and ciphertext into a single vector
    ///
    /// # Arguments
    ///
    /// * `password` - A string slice that holds the password for encryption.
    ///
    /// # Returns
    ///
    /// * `Result<Vec<u8>, WalletError>` - A vector of encrypted bytes if successful, or a WalletError if encryption fails.
    ///
    pub fn encrypt(&self, password: &str) -> Result<Self, WalletError> {
        if self.is_encrypted {
            return Err(WalletError::EncryptionError(
                "KeyPair is already encrypted".to_string(),
            ));
        }

        log::debug!("Starting encryption process");
        log::debug!("Original private key length: {}", self.private_key.len());

        // Generate a random salt
        let salt = SaltString::generate(&mut rand::thread_rng());
        log::debug!("Generated salt: {}", salt.as_str());

        // Derive a key from the password using Argon2
        let argon2 = Argon2::default();
        log::debug!("Argon2 parameters: {:?}", argon2.params());
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| {
                log::debug!("Failed to hash password: {:?}", e);
                WalletError::EncryptionError(format!("Failed to hash password: {}", e))
            })?;
        let derived_key = password_hash.hash.unwrap();
        log::debug!("Password hashed successfully");
        log::debug!(
            "Derived key (first 4 bytes): {:?}",
            &derived_key.as_bytes()[..4]
        );

        // Create a new AES-GCM cipher instance
        let cipher = Aes256Gcm::new_from_slice(derived_key.as_bytes()).map_err(|e| {
            log::debug!("Failed to create AES-GCM cipher: {:?}", e);
            WalletError::EncryptionError(format!("Failed to create AES-GCM cipher: {}", e))
        })?;
        log::debug!("AES-GCM cipher created successfully");

        // Generate a random 12-byte nonce
        let nonce_bytes = rand::random::<[u8; 12]>();
        let nonce = Nonce::from_slice(&nonce_bytes);
        log::debug!("Generated nonce: {:?}", nonce);

        // Encrypt the private key
        let ciphertext = cipher
            .encrypt(nonce, self.private_key.as_ref())
            .map_err(|e| {
                log::debug!("Encryption failed: {:?}", e);
                WalletError::EncryptionError(format!("AES-GCM encryption failed: {}", e))
            })?;
        log::debug!(
            "Encryption successful. Ciphertext length: {}",
            ciphertext.len()
        );

        // Combine salt, nonce, and ciphertext
        let mut encrypted_data = salt.as_str().as_bytes().to_vec();
        encrypted_data.extend_from_slice(&nonce_bytes);
        encrypted_data.extend_from_slice(&ciphertext);

        log::debug!("Final encrypted data length: {}", encrypted_data.len());

        // Return a new ColdKeyPair instance with encrypted data
        Ok(Self {
            public: self.public,
            private_key: encrypted_data,
            is_encrypted: true,
        })
    }

    pub fn sign_encrypted(
        &self,
        message: &[u8],
        password: &str,
    ) -> Result<sr25519::Signature, WalletError> {
        if !self.is_encrypted {
            return Err(WalletError::DecryptionError(
                "KeyPair is not encrypted".to_string(),
            ));
        }

        let decrypted_private_key = self.decrypt(password, &self.private_key)?;
        let pair = sr25519::Pair::from_seed_slice(&decrypted_private_key)
            .map_err(|_| WalletError::KeyDerivationError)?;
        Ok(pair.sign(message))
    }

    /// Decrypts the encrypted private key using AES-GCM decryption with a password-derived key.
    ///
    /// This function performs the following steps:
    /// 1. Extracts salt, nonce, and ciphertext from the encrypted data
    /// 2. Uses Argon2 to derive a key from the password and salt
    /// 3. Creates an AES-GCM cipher instance
    /// 4. Decrypts the ciphertext
    ///
    /// # Arguments
    ///
    /// * `password` - A string slice that holds the password for decryption.
    /// * `encrypted_data` - A byte slice containing the encrypted data (salt + nonce + ciphertext).
    ///
    /// # Returns
    ///
    /// * `Result<Vec<u8>, WalletError>` - A vector of decrypted bytes if successful, or a WalletError if decryption fails.
    ///
    pub fn decrypt(&self, password: &str, encrypted_data: &[u8]) -> Result<Vec<u8>, WalletError> {
        log::debug!("Starting decryption process");
        log::debug!("Encrypted data length: {}", encrypted_data.len());

        if encrypted_data.len() < 34 {
            // 22 (salt) + 12 (nonce)
            log::debug!("Encrypted data too short: {}", encrypted_data.len());
            return Err(WalletError::DecryptionError(
                "Encrypted data too short".to_string(),
            ));
        }

        let salt =
            SaltString::from_b64(std::str::from_utf8(&encrypted_data[..22]).map_err(|e| {
                log::debug!("Invalid salt UTF-8: {:?}", e);
                WalletError::DecryptionError(format!("Invalid salt UTF-8: {}", e))
            })?)
            .map_err(|e| {
                log::debug!("Invalid salt: {:?}", e);
                WalletError::DecryptionError(format!("Invalid salt: {}", e))
            })?;
        let nonce = Nonce::from_slice(&encrypted_data[22..34]);
        let ciphertext = &encrypted_data[34..];

        log::debug!("Salt: {}", salt.as_str());
        log::debug!("Nonce: {:?}", nonce);
        log::debug!("Ciphertext length: {}", ciphertext.len());

        // Derive the key from the password using Argon2
        let argon2 = Argon2::default();
        log::debug!("Argon2 parameters: {:?}", argon2.params());
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| {
                log::debug!("Failed to hash password: {:?}", e);
                WalletError::DecryptionError(format!("Failed to hash password: {}", e))
            })?;
        let derived_key = password_hash.hash.unwrap();
        log::debug!("Password hashed successfully");
        log::debug!(
            "Derived key (first 4 bytes): {:?}",
            &derived_key.as_bytes()[..4]
        );

        // Create a new AES-GCM cipher instance
        let cipher = Aes256Gcm::new_from_slice(derived_key.as_bytes()).map_err(|e| {
            log::debug!("Failed to create AES-GCM cipher: {:?}", e);
            WalletError::DecryptionError(format!("Failed to create AES-GCM cipher: {}", e))
        })?;
        log::debug!("AES-GCM cipher created successfully");

        // Decrypt the private key
        let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|e| {
            log::debug!("Decryption failed: {:?}", e);
            WalletError::DecryptionError(format!("Decryption failed: {}", e))
        })?;
        log::debug!(
            "Decryption successful. Plaintext length: {}",
            plaintext.len()
        );

        Ok(plaintext)
    }

    /// Re-encrypts the private key with a new password.
    ///
    /// This function decrypts the private key using the old password,
    /// then re-encrypts it with the new password.
    ///
    /// # Arguments
    ///
    /// * `old_password` - A string slice that holds the current password.
    /// * `new_password` - A string slice that holds the new password to encrypt with.
    ///
    /// # Returns
    ///
    /// * `Result<(), WalletError>` - Ok(()) if successful, or a WalletError if an error occurred.
    ///
    /// # Errors
    ///
    /// Returns a `WalletError::NotEncrypted` if the key is not currently encrypted.
    ///
    /// # Example
    ///
    /// ```
    /// # use bittensor_wallet::ColdKeyPair;
    /// # let mut keypair = ColdKeyPair::generate();
    /// # keypair.encrypt("old_password").unwrap();
    /// let result = keypair.re_encrypt("old_password", "new_password");
    /// assert!(result.is_ok());
    /// ```

    pub fn re_encrypt(
        &mut self,
        old_password: &str,
        new_password: &str,
    ) -> Result<(), WalletError> {
        if !self.is_encrypted {
            return Err(WalletError::NotEncrypted);
        }

        // Decrypt the private key using the old password
        let decrypted_private_key = self.decrypt(old_password, &self.private_key)?;

        // Create a new ColdKeyPair with the decrypted private key
        let new_keypair = ColdKeyPair::new(self.public, decrypted_private_key, false);

        // Encrypt the new keypair with the new password
        let encrypted_keypair = new_keypair.encrypt(new_password)?;

        // Update self with the new encrypted data
        self.private_key = encrypted_keypair.private_key;
        self.is_encrypted = true;

        Ok(())
    }

    pub fn to_json(&self) -> Result<String, WalletError> {
        serde_json::to_string(self).map_err(|e| WalletError::SerializationError(e.to_string()))
    }

    pub fn from_json(json: &str) -> Result<Self, WalletError> {
        serde_json::from_str(json).map_err(|e| WalletError::DeserializationError(e.to_string()))
    }
}

impl HotKeyPair {
    pub fn new(public: sr25519::Public, private: Vec<u8>) -> Self {
        Self { public, private }
    }

    pub fn generate() -> Self {
        let (pair, _) = sr25519::Pair::generate();
        let public = pair.public();
        let private = pair.to_raw_vec();
        Self { public, private }
    }
}

/// Implements the `IdentifyAccount` trait for `ColdKeyPair`.
///
/// This implementation allows a `ColdKeyPair` to be converted into an `AccountId32`,
/// which is typically used to identify accounts in the Substrate ecosystem.
///

impl IdentifyAccount for ColdKeyPair {
    type AccountId = sp_runtime::AccountId32;

    fn into_account(self) -> Self::AccountId {
        // Convert the public key to an AccountId32
        self.public.into()
    }
}

/// Implements the `IdentifyAccount` trait for `HotKeyPair`.
///
/// This implementation allows a `HotKeyPair` to be converted into an `AccountId32`,
/// which is typically used to identify accounts in the Substrate ecosystem.
///

impl IdentifyAccount for HotKeyPair {
    type AccountId = sp_runtime::AccountId32;

    fn into_account(self) -> Self::AccountId {
        // Convert the public key to an AccountId32
        self.public.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    /// Helper function to create a test cold keypair with encrypted private key
    ///
    /// This function generates a new ColdKeyPair, encrypts its private key with a test password,
    /// and returns the keypair (with encrypted private key) along with the password used.
    ///
    /// # Returns
    ///
    /// * `(ColdKeyPair, String)` - A tuple containing:
    ///   - The generated ColdKeyPair with its private key encrypted
    ///   - The password used for encryption
    ///
    /// # Example
    ///
    /// ```
    /// let (encrypted_keypair, password) = create_test_cold_keypair();
    /// assert!(encrypted_keypair.is_encrypted());
    /// ```
    fn create_test_cold_keypair() -> (ColdKeyPair, String) {
        let password: String = "test_password".to_string();
        let keypair: ColdKeyPair = ColdKeyPair::generate();

        // Encrypt the keypair
        let encrypted_keypair = keypair
            .encrypt(&password)
            .expect("Encryption should succeed");

        (encrypted_keypair, password)
    }

    #[test]
    fn test_generate_cold_keypair() {
        let keypair = ColdKeyPair::generate();
        let public_key_length: usize =
            <sr25519::Public as AsRef<[u8]>>::as_ref(&keypair.public).len();
        assert_eq!(public_key_length, 32);
        assert!(!keypair.private_key.is_empty());
    }

    #[test]
    fn test_generate_hot_keypair() {
        let keypair = HotKeyPair::generate();
        let public_key_length: usize =
            <sr25519::Public as AsRef<[u8]>>::as_ref(&keypair.public).len();
        assert_eq!(public_key_length, 32);
        assert!(!keypair.private.is_empty());
    }
    #[test]
    fn test_encrypt_decrypt_cold_keypair() {
        println!("Starting test_encrypt_decrypt_cold_keypair");
        let password = "test_password";
        let keypair = ColdKeyPair::generate();

        println!("Generated ColdKeyPair");
        println!("Original private key length: {}", keypair.private_key.len());

        // Encrypt the keypair
        let encrypted_keypair = match keypair.encrypt(password) {
            Ok(enc) => {
                println!("Encryption successful");
                println!("Encrypted data length: {}", enc.private_key.len());
                enc
            }
            Err(e) => {
                println!("Encryption failed: {:?}", e);
                panic!("Encryption failed: {:?}", e);
            }
        };

        // Attempt to decrypt
        let decryption_result = encrypted_keypair.decrypt(password, &encrypted_keypair.private_key);

        match decryption_result {
            Ok(decrypted) => {
                println!("Decryption successful");
                println!("Decrypted data length: {}", decrypted.len());
                assert_ne!(
                    encrypted_keypair.private_key, decrypted,
                    "Encrypted and decrypted data should not be the same"
                );
                assert_eq!(
                    keypair.private_key.len(),
                    decrypted.len(),
                    "Original and decrypted data should have the same length"
                );
                assert_eq!(
                    keypair.private_key, decrypted,
                    "Decrypted data should match the original private key"
                );
                println!("All assertions passed");
            }
            Err(e) => {
                println!("Decryption failed: {:?}", e);
                panic!("Decryption failed: {:?}", e);
            }
        }
        println!("Test completed successfully");
    }

    #[test]
    fn test_decrypt_cold_keypair_wrong_password() {
        let (keypair, _) = create_test_cold_keypair();
        let result = keypair.decrypt("wrong_password", &keypair.private_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_sign_cold_keypair() {
        // Generate a new ColdKeyPair
        let keypair = ColdKeyPair::generate();

        // Sign a message with the unencrypted keypair
        let message = b"test message";
        let signature = keypair.sign(message).expect("Signing should succeed");
        let signature_length = <sr25519::Signature as AsRef<[u8]>>::as_ref(&signature).len();
        assert_eq!(signature_length, 64);

        // Verify the signature
        assert!(sr25519::Pair::verify(&signature, message, &keypair.public));

        // Encrypt the keypair
        let password = "test_password";
        let encrypted_keypair = keypair
            .encrypt(password)
            .expect("Encryption should succeed");

        // Sign a message with the encrypted keypair
        let encrypted_signature = encrypted_keypair
            .sign_encrypted(message, password)
            .expect("Signing with encrypted keypair should succeed");
        let encrypted_signature_length =
            <sr25519::Signature as AsRef<[u8]>>::as_ref(&encrypted_signature).len();
        assert_eq!(encrypted_signature_length, 64);

        // Verify the signature from the encrypted keypair
        assert!(sr25519::Pair::verify(
            &encrypted_signature,
            message,
            &encrypted_keypair.public
        ));

        // Test signing with wrong password
        assert!(encrypted_keypair
            .sign_encrypted(message, "wrong_password")
            .is_err());

        // Test signing with unencrypted keypair using sign_encrypted
        assert!(keypair.sign_encrypted(message, password).is_err());

        // Test signing with encrypted keypair using sign
        let result = encrypted_keypair.sign(message);
        assert!(matches!(result, Err(WalletError::EncryptedKeyError(_))));
    }

    #[test]
    fn test_sign_hot_keypair() {
        let keypair = HotKeyPair::generate();
        let message = b"test message";
        let signature = keypair.sign(message);
        let signature_length: usize = <sr25519::Signature as AsRef<[u8]>>::as_ref(
            &signature.expect("Signature should be valid"),
        )
        .len();
        assert_eq!(signature_length, 64);
    }

    #[test]
    fn test_to_mnemonic_hot_keypair() {
        let keypair = HotKeyPair::generate();
        let mnemonic = keypair.to_mnemonic();
        assert!(!mnemonic.is_empty());
        let words: Vec<&str> = mnemonic.split_whitespace().collect();
        assert!(words.len() == 12 || words.len() == 24);
    }

    #[test]
    fn test_to_mnemonic_cold_keypair() {
        let keypair = ColdKeyPair::generate();
        let result = keypair.to_mnemonic();
        assert_eq!(result, "Getting mnemonic from ColdKeyPair is not allowed");
    }

    #[test]
    fn test_to_seed_hot_keypair() {
        let keypair = HotKeyPair::generate();
        let seed = keypair.to_seed();
        assert_eq!(seed, keypair.private);
    }

    #[test]
    fn test_to_seed_cold_keypair() {
        let keypair = ColdKeyPair::generate();
        let result = keypair.to_seed();
        assert!(result.is_empty());
    }

    #[test]
    fn test_cold_keypair_clone() {
        let keypair = ColdKeyPair::generate();
        let cloned_keypair = keypair.clone();
        assert_eq!(keypair.public, cloned_keypair.public);
        assert_eq!(keypair.private_key, cloned_keypair.private_key);
    }

    #[test]
    fn test_hot_keypair_clone() {
        let keypair = HotKeyPair::generate();
        let cloned_keypair = keypair.clone();
        assert_eq!(keypair.public, cloned_keypair.public);
        assert_eq!(keypair.private, cloned_keypair.private);
    }

    #[test]
    fn test_key_derivation_function_parameters() {
        let password = "test_password";
        let salt = SaltString::generate(&mut rand::thread_rng());

        // Test with default parameters
        let start = Instant::now();
        let argon2 = Argon2::default();
        let _ = argon2.hash_password(password.as_bytes(), &salt).unwrap();
        let default_duration = start.elapsed();

        // Test with custom parameters (increase memory and iterations)
        let custom_argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::new(65536, 10, 4, None).unwrap(),
        );
        let start = Instant::now();
        let _ = custom_argon2
            .hash_password(password.as_bytes(), &salt)
            .unwrap();
        let custom_duration = start.elapsed();

        // Custom parameters should take longer
        assert!(custom_duration > default_duration);
    }

    #[test]
    fn test_sign_various_message_types() {
        let (encrypted_cold_keypair, password) = create_test_cold_keypair();
        let unencrypted_cold_keypair = ColdKeyPair::generate();
        let hot_keypair = HotKeyPair::generate();

        let string_message = b"Hello, world!";
        let int_message = 42u64.to_le_bytes();

        #[derive(Default, Serialize, Deserialize)]
        struct TestStruct {
            a: u32,
            b: [u8; 10],
        }
        let struct_message = TestStruct::default();
        let struct_bytes = bincode::serialize(&struct_message).unwrap();

        // Sign with encrypted cold keypair
        let encrypted_cold_string_sig =
            encrypted_cold_keypair.sign_encrypted(string_message, &password);
        let encrypted_cold_int_sig = encrypted_cold_keypair.sign_encrypted(&int_message, &password);
        let encrypted_cold_struct_sig =
            encrypted_cold_keypair.sign_encrypted(&struct_bytes, &password);

        // Sign with unencrypted cold keypair
        let unencrypted_cold_string_sig = unencrypted_cold_keypair.sign(string_message);
        let unencrypted_cold_int_sig = unencrypted_cold_keypair.sign(&int_message);
        let unencrypted_cold_struct_sig = unencrypted_cold_keypair.sign(&struct_bytes);

        // Sign with hot keypair
        let hot_string_sig = hot_keypair.sign(string_message);
        let hot_int_sig = hot_keypair.sign(&int_message);
        let hot_struct_sig = hot_keypair.sign(&struct_bytes);

        let assert_signature_length = |sig: &sr25519::Signature| {
            let signature_length: usize = <sr25519::Signature as AsRef<[u8]>>::as_ref(sig).len();
            assert_eq!(signature_length, 64);
        };

        // Assert for encrypted cold keypair signatures
        assert_signature_length(
            &encrypted_cold_string_sig.expect("Encrypted cold string signature failed"),
        );
        assert_signature_length(
            &encrypted_cold_int_sig.expect("Encrypted cold int signature failed"),
        );
        assert_signature_length(
            &encrypted_cold_struct_sig.expect("Encrypted cold struct signature failed"),
        );

        // Assert for unencrypted cold keypair signatures
        assert_signature_length(
            &unencrypted_cold_string_sig.expect("Unencrypted cold string signature failed"),
        );
        assert_signature_length(
            &unencrypted_cold_int_sig.expect("Unencrypted cold int signature failed"),
        );
        assert_signature_length(
            &unencrypted_cold_struct_sig.expect("Unencrypted cold struct signature failed"),
        );

        // Assert for hot keypair signatures
        assert_signature_length(&hot_string_sig.expect("Hot string signature failed"));
        assert_signature_length(&hot_int_sig.expect("Hot int signature failed"));
        assert_signature_length(&hot_struct_sig.expect("Hot struct signature failed"));
    }

    #[test]
    fn test_from_mnemonic() {
        // Enable debug logging for this test
        let _ = env_logger::builder()
            .filter_level(log::LevelFilter::Debug)
            .try_init();

        // Test case 1: Valid mnemonic without password
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let result = ColdKeyPair::from_mnemonic(mnemonic, None);
        assert!(
            result.is_ok(),
            "Failed to create ColdKeyPair from valid mnemonic without password: {:?}",
            result.err()
        );

        // Test case 2: Valid mnemonic with password
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let password = Some("secure_password");
        let result = ColdKeyPair::from_mnemonic(mnemonic, password);
        assert!(result.is_ok());

        // Test case 3: Invalid mnemonic
        let invalid_mnemonic = "invalid mnemonic phrase";
        let result = ColdKeyPair::from_mnemonic(invalid_mnemonic, None);
        assert!(matches!(result, Err(WalletError::InvalidMnemonic)));

        // Test case 4: Valid 24-word mnemonic
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
        let result = ColdKeyPair::from_mnemonic(mnemonic, None);
        assert!(result.is_ok());

        // Test case 5: Mnemonic with extra whitespace
        let mnemonic = "  abandon  abandon  abandon  abandon  abandon  abandon  abandon  abandon  abandon  abandon  abandon  about  ";
        let result = ColdKeyPair::from_mnemonic(mnemonic, None);
        assert!(result.is_ok());

        // Test case 6: Consistency check - same mnemonic should produce same keypair
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let keypair1 = ColdKeyPair::from_mnemonic(mnemonic, None).unwrap();
        let keypair2 = ColdKeyPair::from_mnemonic(mnemonic, None).unwrap();
        assert_eq!(keypair1.public, keypair2.public);

        // Test case 7: Different passwords should produce different encrypted private keys
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let keypair1 = ColdKeyPair::from_mnemonic(mnemonic, Some("password1")).unwrap();
        let keypair2 = ColdKeyPair::from_mnemonic(mnemonic, Some("password2")).unwrap();
        assert_ne!(keypair1.private_key, keypair2.private_key);
    }
}
