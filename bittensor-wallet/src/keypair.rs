use crate::errors::WalletError;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};

use bip39::Mnemonic;
use serde::{Deserialize, Serialize};
use sp_core::{sr25519, Pair};
use sp_runtime::traits::IdentifyAccount;

use argon2::{password_hash::SaltString, Argon2, PasswordHasher};

// use errors::WalletError;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ColdKeyPair {
    pub public: sr25519::Public,
    encrypted_private: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HotKeyPair {
    pub public: sr25519::Public,
    pub private: Vec<u8>,
}

pub trait KeyPair {
    fn public(&self) -> &sr25519::Public;
    fn sign(&self, message: &[u8]) -> sr25519::Signature;
    fn to_mnemonic(&self) -> String;
    fn to_seed(&self) -> Vec<u8>;
}

impl KeyPair for ColdKeyPair {
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
    /// * `Result<sr25519::Signature, WalletError>` - The signature if successful, or a WalletError if not.
    ///

    fn sign(&self, message: &[u8]) -> sr25519::Signature {
        // TODO: Implement a secure way to retrieve the private key without requiring a password parameter
        // This might involve using a keyring or secure enclave
        let private_key = self.encrypted_private.clone();
        let pair = sr25519::Pair::from_seed_slice(&private_key)
            .expect("Valid encrypted private key should always produce a valid pair");
        pair.sign(message)
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
    fn public(&self) -> &sr25519::Public {
        &self.public
    }

    fn sign(&self, message: &[u8]) -> sr25519::Signature {
        let pair = sr25519::Pair::from_seed_slice(&self.private)
            .expect("Valid keypair should always produce a valid pair");
        pair.sign(message)
    }

    fn to_mnemonic(&self) -> String {
        let mnemonic = Mnemonic::from_entropy(&self.private)
            .expect("Valid private key should always produce a valid mnemonic");
        mnemonic.to_string()
    }

    fn to_seed(&self) -> Vec<u8> {
        self.private.clone()
    }
}

impl ColdKeyPair {
    pub fn new(public: sr25519::Public, encrypted_private: Vec<u8>) -> Self {
        Self {
            public,
            encrypted_private,
        }
    }

    pub fn generate() -> Self {
        let (pair, _) = sr25519::Pair::generate();
        let public = pair.public();
        let private = pair.to_raw_vec();
        Self {
            public,
            encrypted_private: private,
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
    /// # Examples
    ///
    /// ```
    /// use bittensor_wallet::ColdKeyPair;
    ///
    /// let mnemonic = "word1 word2 word3 ... word24";
    /// let password = Some("optional_password");
    /// let cold_key_pair = ColdKeyPair::from_mnemonic(mnemonic, password).unwrap();
    /// ```
    pub fn from_mnemonic(mnemonic: &str, password: Option<&str>) -> Result<Self, WalletError> {
        // Parse the mnemonic phrase
        let mnemonic = Mnemonic::parse(mnemonic).map_err(|_| WalletError::InvalidMnemonic)?;

        // Generate the seed from the mnemonic
        let seed = mnemonic.to_seed(password.unwrap_or(""));

        // Generate the sr25519 keypair from the seed
        let pair = sr25519::Pair::from_seed_slice(&seed[..32])
            .map_err(|_| WalletError::KeyDerivationError)?;

        let public = pair.public();
        let private = pair.to_raw_vec();

        // If a password is provided, encrypt the private key
        let encrypted_private = if let Some(pwd) = password {
            Self::new(public, private).encrypt(pwd)?
        } else {
            private
        };

        Ok(Self {
            public,
            encrypted_private,
        })
    }

    pub fn encrypt(&self, password: &str) -> Result<Vec<u8>, WalletError> {
        // Generate a random salt for key derivation
        let salt = SaltString::generate(&mut rand::thread_rng());

        // Derive a 32-byte key from the password using Argon2
        let argon2: Argon2<'_> = Argon2::default();
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|_| WalletError::EncryptionError)?;

        let derived_key: [u8; 32] = password_hash
            .hash
            .ok_or(WalletError::EncryptionError)?
            .as_bytes()
            .try_into()
            .map_err(|_| WalletError::EncryptionError)?;

        // Create a new AES-GCM cipher instance
        let cipher =
            Aes256Gcm::new_from_slice(&derived_key).map_err(|_| WalletError::EncryptionError)?;

        // Generate a random nonce
        let nonce_bytes: [u8; 12] = rand::random();
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt the private key
        let ciphertext = cipher
            .encrypt(nonce, self.encrypted_private.as_ref())
            .map_err(|_| WalletError::EncryptionError)?;

        // Pre-allocate the exact size for the encrypted data
        let salt_bytes = salt.as_str().as_bytes();
        let mut encrypted_data =
            Vec::with_capacity(salt_bytes.len() + nonce_bytes.len() + ciphertext.len());

        // Combine salt, nonce, and ciphertext into a single Vec<u8> using extend_from_slice
        encrypted_data.extend_from_slice(salt_bytes);
        encrypted_data.extend_from_slice(&nonce_bytes);
        encrypted_data.extend_from_slice(&ciphertext);

        Ok(encrypted_data)
    }

    pub fn decrypt(&self, password: &str) -> Result<Vec<u8>, WalletError> {
        if self.encrypted_private.len() < 28 {
            return Err(WalletError::DecryptionError(
                "Encrypted data too short".to_string(),
            ));
        }

        let salt = &self.encrypted_private[..16];
        let nonce = &self.encrypted_private[16..28];
        let ciphertext = &self.encrypted_private[28..];

        // Derive the key from the password using Argon2
        let argon2: Argon2<'_> = Argon2::default();
        let salt_string = SaltString::encode_b64(salt)
            .map_err(|e| WalletError::DecryptionError(e.to_string()))?;
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt_string)
            .map_err(|e| WalletError::DecryptionError(e.to_string()))?;

        let derived_key: [u8; 32] = password_hash
            .hash
            .ok_or_else(|| WalletError::DecryptionError("Failed to derive key".to_string()))?
            .as_bytes()
            .try_into()
            .map_err(|_| {
                WalletError::DecryptionError("Failed to convert derived key".to_string())
            })?;

        // Create a new AES-GCM cipher instance
        let cipher = Aes256Gcm::new_from_slice(&derived_key)
            .map_err(|e| WalletError::DecryptionError(e.to_string()))?;

        // Decrypt the private key
        let plaintext = cipher
            .decrypt(Nonce::from_slice(nonce), ciphertext)
            .map_err(|e| WalletError::DecryptionError(e.to_string()))?;

        Ok(plaintext)
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
    use sp_core::Pair as TraitPair;
    use std::time::Instant;

    // Helper function to create a test cold keypair
    fn create_test_cold_keypair() -> (ColdKeyPair, String) {
        let password = "test_password";
        let keypair = ColdKeyPair::generate();
        let encrypted = keypair.encrypt(password).unwrap();
        (
            ColdKeyPair::new(keypair.public, encrypted),
            password.to_string(),
        )
    }

    #[test]
    fn test_generate_cold_keypair() {
        let keypair = ColdKeyPair::generate();
        let public_key_length: usize =
            <sr25519::Public as AsRef<[u8]>>::as_ref(&keypair.public).len();
        assert_eq!(public_key_length, 32);
        assert!(!keypair.encrypted_private.is_empty());
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
        let (keypair, password) = create_test_cold_keypair();
        let encrypted = keypair.encrypt(&password).unwrap();
        let decrypted = keypair.decrypt(&password).unwrap();
        assert_ne!(encrypted, decrypted);
    }

    #[test]
    fn test_decrypt_cold_keypair_wrong_password() {
        let (keypair, _) = create_test_cold_keypair();
        let result = keypair.decrypt("wrong_password");
        assert!(result.is_err());
    }

    #[test]
    fn test_sign_cold_keypair() {
        let (keypair, _password) = create_test_cold_keypair();
        let message: &[u8] = b"test message";
        let signature: sr25519::Signature = keypair.sign(message);
        let signature_length: usize = <sr25519::Signature as AsRef<[u8]>>::as_ref(&signature).len();
        assert_eq!(signature_length, 64);
    }

    #[test]
    fn test_sign_hot_keypair() {
        let keypair = HotKeyPair::generate();
        let message = b"test message";
        let signature = keypair.sign(message);
        let signature_length: usize = <sr25519::Signature as AsRef<[u8]>>::as_ref(&signature).len();
        assert_eq!(signature_length, 64);
    }

    #[test]
    fn test_to_mnemonic_hot_keypair() {
        let keypair = HotKeyPair::generate();
        let mnemonic = keypair.to_mnemonic();
        assert_eq!(mnemonic.split_whitespace().count(), 24);
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
        assert_eq!(keypair.encrypted_private, cloned_keypair.encrypted_private);
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
        let (cold_keypair, _password) = create_test_cold_keypair();
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

        let cold_string_sig = cold_keypair.sign(string_message);
        let cold_int_sig = cold_keypair.sign(&int_message);
        let cold_struct_sig = cold_keypair.sign(&struct_bytes);

        let hot_string_sig = hot_keypair.sign(string_message);
        let hot_int_sig = hot_keypair.sign(&int_message);
        let hot_struct_sig = hot_keypair.sign(&struct_bytes);

        let assert_signature_length = |sig: &sr25519::Signature| {
            let signature_length: usize = <sr25519::Signature as AsRef<[u8]>>::as_ref(sig).len();
            assert_eq!(signature_length, 64);
        };

        assert_signature_length(&cold_string_sig);
        assert_signature_length(&cold_int_sig);
        assert_signature_length(&cold_struct_sig);
        assert_signature_length(&hot_string_sig);
        assert_signature_length(&hot_int_sig);
        assert_signature_length(&hot_struct_sig);
    }

    #[test]
    fn test_from_mnemonic() {
        // Test case 1: Valid mnemonic without password
        let mnemonic = "word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12";
        let result = ColdKeyPair::from_mnemonic(mnemonic, None);
        assert!(result.is_ok());

        // Test case 2: Valid mnemonic with password
        let mnemonic = "word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12";
        let password = Some("secure_password");
        let result = ColdKeyPair::from_mnemonic(mnemonic, password);
        assert!(result.is_ok());

        // Test case 3: Invalid mnemonic
        let invalid_mnemonic = "invalid mnemonic phrase";
        let result = ColdKeyPair::from_mnemonic(invalid_mnemonic, None);
        assert!(matches!(result, Err(WalletError::InvalidMnemonic)));

        // Test case 4: Valid 24-word mnemonic
        let mnemonic = "word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12 word13 word14 word15 word16 word17 word18 word19 word20 word21 word22 word23 word24";
        let result = ColdKeyPair::from_mnemonic(mnemonic, None);
        assert!(result.is_ok());

        // Test case 5: Mnemonic with extra whitespace
        let mnemonic = "  word1  word2  word3  word4  word5  word6  word7  word8  word9  word10  word11  word12  ";
        let result = ColdKeyPair::from_mnemonic(mnemonic, None);
        assert!(result.is_ok());

        // Test case 6: Mnemonic in different language (Spanish)
        let spanish_mnemonic =
            "ábaco bello carga dedo éxito forro ganar hígado isla júpiter kilo lápiz";
        let result = ColdKeyPair::from_mnemonic(spanish_mnemonic, None);
        assert!(result.is_ok());

        // Test case 7: Consistency check - same mnemonic should produce same keypair
        let mnemonic = "word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12";
        let keypair1 = ColdKeyPair::from_mnemonic(mnemonic, None).unwrap();
        let keypair2 = ColdKeyPair::from_mnemonic(mnemonic, None).unwrap();
        assert_eq!(keypair1.public, keypair2.public);

        // Test case 8: Different passwords should produce different encrypted private keys
        let mnemonic = "word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12";
        let keypair1 = ColdKeyPair::from_mnemonic(mnemonic, Some("password1")).unwrap();
        let keypair2 = ColdKeyPair::from_mnemonic(mnemonic, Some("password2")).unwrap();
        assert_ne!(keypair1.encrypted_private, keypair2.encrypted_private);
    }
}
