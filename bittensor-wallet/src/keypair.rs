use crate::errors::WalletError;
use secrets::SecretBox;
use serde::ser::SerializeStruct;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::{password_hash::SaltString, Argon2, PasswordHasher};

use bip39::Mnemonic;
use once_cell;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sp_core::ByteArray;
use sp_core::{sr25519, Pair};
use sp_runtime::traits::IdentifyAccount;

// #[derive(Clone, Debug)]
// pub struct ColdKeyPair {
//     pub public: Vec<u8>,
//     pub private_key: SecretBox<[u8; 32]>,
//     is_encrypted: bool,
// }

// impl Serialize for ColdKeyPair {
//     fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
//     where
//         S: Serializer,
//     {
//         let mut state = serializer.serialize_struct("ColdKeyPair", 3)?;
//         state.serialize_field("public", &self.public)?;
//         state.serialize_field("private_key", &*self.private_key.borrow())?;
//         state.serialize_field("is_encrypted", &self.is_encrypted)?;
//         state.end()
//     }
// }

// impl<'de> Deserialize<'de> for ColdKeyPair {
//     fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
//     where
//         D: Deserializer<'de>,
//     {
//         /// Helper struct for deserialization
//         #[derive(Deserialize)]
//         struct ColdKeyPairHelper {
//             public: Vec<u8>,
//             private_key: [u8; 32],
//             is_encrypted: bool,
//         }

//         // Deserialize into the helper struct
//         let helper: ColdKeyPairHelper = ColdKeyPairHelper::deserialize(deserializer)?;

//         // Construct and return the ColdKeyPair
//         Ok(ColdKeyPair {
//             public: helper.public,
//             private_key: SecretBox::new(|private_key| *private_key = helper.private_key),
//             is_encrypted: helper.is_encrypted,
//         })
//     }
// }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ColdKeyPair {
    pub public: Vec<u8>,
    #[serde(with = "secret_box_serde")]
    pub private_key: SecretBox<[u8; 32]>,
    pub is_encrypted: bool,
}

mod secret_box_serde {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(secret_box: &SecretBox<[u8; 32]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes: [u8; 32] = *secret_box.borrow();
        bytes.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<SecretBox<[u8; 32]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: [u8; 32] = Deserialize::deserialize(deserializer)?;
        Ok(SecretBox::new(|secret| *secret = bytes))
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
    ///
    /// # Example
    ///
    /// ```
    /// # use bittensor_wallet::{ColdKeyPair, KeyPair};
    /// # let cold_key_pair = ColdKeyPair::new(); // Assume this is a valid ColdKeyPair
    /// let public_key: &sr25519::Public = cold_key_pair.public();
    /// println!("Public key: {:?}", public_key);
    /// ```
    fn public(&self) -> &sr25519::Public {
        // Convert the Vec<u8> to sr25519::Public and store it
        static PUBLIC_KEY: once_cell::sync::OnceCell<sr25519::Public> =
            once_cell::sync::OnceCell::new();
        PUBLIC_KEY.get_or_init(|| {
            sr25519::Public::from_slice(&self.public).expect("Public key should always be valid")
        })
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

        let pair = sr25519::Pair::from_seed_slice(self.private_key.borrow().as_ref())
            .map_err(|_| WalletError::InvalidPrivateKey)?;

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
    /// Creates a new ColdKeyPair instance with the given public key and private key.
    ///
    /// # Arguments
    ///
    /// * `public` - The public key of type `sr25519::Public`.
    /// * `private_key` - The private key as a 32-byte array.
    /// * `is_encrypted` - A boolean indicating whether the private key is encrypted.
    ///
    /// # Returns
    ///
    /// A new `ColdKeyPair` instance.
    ///
    /// # Example
    ///
    /// ```
    /// use bittensor_wallet::{ColdKeyPair, sr25519};
    ///
    /// let public = sr25519::Public::from_raw([0u8; 32]);
    /// let private_key = [0u8; 32];
    /// let is_encrypted = false;
    ///
    /// let cold_key_pair = ColdKeyPair::new(public, private_key, is_encrypted);
    /// ```
    pub fn new(public: sr25519::Public, private_key: [u8; 32], is_encrypted: bool) -> Self {
        Self {
            public: public.to_vec(),
            private_key: SecretBox::new(|key| *key = private_key),
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
            public: public.to_vec(),
            private_key: SecretBox::new(|key: &mut [u8; 32]| key.copy_from_slice(&private[..32])),
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
            public: public.to_vec(),
            private_key: SecretBox::new(|key: &mut [u8; 32]| key.copy_from_slice(&private[..32])),
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

        let salt = SaltString::generate(&mut rand::thread_rng());
        let argon2 = Argon2::default();
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| WalletError::EncryptionError(format!("Failed to hash password: {}", e)))?;
        let derived_key = password_hash.hash.unwrap();

        let cipher = Aes256Gcm::new_from_slice(derived_key.as_bytes()).map_err(|e| {
            WalletError::EncryptionError(format!("Failed to create AES-GCM cipher: {}", e))
        })?;

        let nonce_bytes = rand::random::<[u8; 12]>();
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, self.private_key.borrow().as_ref())
            .map_err(|e| {
                WalletError::EncryptionError(format!("AES-GCM encryption failed: {}", e))
            })?;

        let mut encrypted_data = salt.as_str().as_bytes().to_vec();
        encrypted_data.extend_from_slice(nonce.as_slice());
        encrypted_data.extend_from_slice(&ciphertext);

        Ok(Self {
            public: self.public.clone(),
            private_key: SecretBox::new(|key: &mut [u8; 32]| key.copy_from_slice(&encrypted_data)),
            is_encrypted: true,
        })
    }

    /// Signs a message using the encrypted private key.
    ///
    /// This function decrypts the private key using the provided password,
    /// then uses it to sign the given message.
    ///
    /// # Arguments
    ///
    /// * `message` - A byte slice containing the message to be signed.
    /// * `password` - A string slice that holds the password for decryption.
    ///
    /// # Returns
    ///
    /// * `Result<sr25519::Signature, WalletError>` - The signature if successful, or a WalletError if signing fails.
    ///
    /// # Examples
    ///
    /// ```
    /// # use your_crate::{KeyPair, WalletError};
    /// # fn main() -> Result<(), WalletError> {
    /// # let keypair = KeyPair::new()?;
    /// # let encrypted_keypair = keypair.encrypt("password123")?;
    /// let message: &[u8] = b"Hello, world!";
    /// let signature = encrypted_keypair.sign_encrypted(message, "password123")?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn sign_encrypted(
        &self,
        message: &[u8],
        password: &str,
    ) -> Result<sr25519::Signature, WalletError> {
        // Ensure the KeyPair is encrypted before attempting to sign
        if !self.is_encrypted {
            return Err(WalletError::DecryptionError(
                "KeyPair is not encrypted".to_string(),
            ));
        }

        // Decrypt the private key using the provided password
        let decrypted_private_key: Vec<u8> = self.decrypt(password)?;

        // Create a new sr25519::Pair from the decrypted private key
        let pair: sr25519::Pair = sr25519::Pair::from_seed_slice(&decrypted_private_key)
            .map_err(|_| WalletError::KeyDerivationError)?;

        // Sign the message using the pair and return the signature
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
    // pub fn decrypt(&self, password: &str, encrypted_data: &[u8]) -> Result<Vec<u8>, WalletError> {
    //     log::debug!("Starting decryption process");
    //     log::debug!("Encrypted data length: {}", encrypted_data.len());

    //     if encrypted_data.len() < 34 {
    //         // 22 (salt) + 12 (nonce)
    //         log::debug!("Encrypted data too short: {}", encrypted_data.len());
    //         return Err(WalletError::DecryptionError(
    //             "Encrypted data too short".to_string(),
    //         ));
    //     }

    //     let salt =
    //         SaltString::from_b64(std::str::from_utf8(&encrypted_data[..22]).map_err(|e| {
    //             log::debug!("Invalid salt UTF-8: {:?}", e);
    //             WalletError::DecryptionError(format!("Invalid salt UTF-8: {}", e))
    //         })?)
    //         .map_err(|e| {
    //             log::debug!("Invalid salt: {:?}", e);
    //             WalletError::DecryptionError(format!("Invalid salt: {}", e))
    //         })?;
    //     let nonce = Nonce::from_slice(&encrypted_data[22..34]);
    //     let ciphertext = &encrypted_data[34..];

    //     log::debug!("Salt: {}", salt.as_str());
    //     log::debug!("Nonce: {:?}", nonce);
    //     log::debug!("Ciphertext length: {}", ciphertext.len());

    //     // Derive the key from the password using Argon2
    //     let argon2 = Argon2::default();
    //     log::debug!("Argon2 parameters: {:?}", argon2.params());
    //     let password_hash = argon2
    //         .hash_password(password.as_bytes(), &salt)
    //         .map_err(|e| {
    //             log::debug!("Failed to hash password: {:?}", e);
    //             WalletError::DecryptionError(format!("Failed to hash password: {}", e))
    //         })?;
    //     let derived_key = password_hash.hash.unwrap();
    //     log::debug!("Password hashed successfully");
    //     log::debug!(
    //         "Derived key (first 4 bytes): {:?}",
    //         &derived_key.as_bytes()[..4]
    //     );

    //     // Create a new AES-GCM cipher instance
    //     let cipher = Aes256Gcm::new_from_slice(derived_key.as_bytes()).map_err(|e| {
    //         log::debug!("Failed to create AES-GCM cipher: {:?}", e);
    //         WalletError::DecryptionError(format!("Failed to create AES-GCM cipher: {}", e))
    //     })?;
    //     log::debug!("AES-GCM cipher created successfully");

    //     // Decrypt the private key
    //     let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|e| {
    //         log::debug!("Decryption failed: {:?}", e);
    //         WalletError::DecryptionError(format!("Decryption failed: {}", e))
    //     })?;
    //     log::debug!(
    //         "Decryption successful. Plaintext length: {}",
    //         plaintext.len()
    //     );

    //     Ok(plaintext)
    // }
    pub fn decrypt(&self, password: &str) -> Result<Vec<u8>, WalletError> {
        if !self.is_encrypted {
            return Err(WalletError::DecryptionError(
                "KeyPair is not encrypted".to_string(),
            ));
        }

        let encrypted_data = self.private_key.borrow();

        if encrypted_data.len() < 34 {
            return Err(WalletError::DecryptionError(
                "Encrypted data too short".to_string(),
            ));
        }

        let salt = SaltString::from_b64(
            std::str::from_utf8(&encrypted_data[..22])
                .map_err(|e| WalletError::DecryptionError(format!("Invalid salt UTF-8: {}", e)))?,
        )
        .map_err(|e| WalletError::DecryptionError(format!("Invalid salt: {}", e)))?;

        let nonce = Nonce::from_slice(&encrypted_data[22..34]);
        let ciphertext = &encrypted_data[34..];

        let argon2 = Argon2::default();
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| WalletError::DecryptionError(format!("Failed to hash password: {}", e)))?;
        let derived_key = password_hash.hash.unwrap();

        let cipher = Aes256Gcm::new_from_slice(derived_key.as_bytes()).map_err(|e| {
            WalletError::DecryptionError(format!("Failed to create AES-GCM cipher: {}", e))
        })?;

        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| WalletError::DecryptionError(format!("Decryption failed: {}", e)))
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
        let decrypted_private_key = self.decrypt(old_password)?;

        // Convert Vec<u8> to sr25519::Public
        let public =
            sr25519::Public::from_slice(&self.public).map_err(|_| WalletError::InvalidPublicKey)?;

        // Convert Vec<u8> to [u8; 32]
        let private_key: [u8; 32] = decrypted_private_key
            .try_into()
            .map_err(|_| WalletError::InvalidPrivateKey)?;

        // Create a new ColdKeyPair with the converted types
        let new_keypair = ColdKeyPair::new(public, private_key, false);

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

    /// Changes the password used to encrypt the private key.
    ///
    /// # Arguments
    ///
    /// * `old_password` - A string slice that holds the current password.
    /// * `new_password` - A string slice that holds the new password to be set.
    ///
    /// # Returns
    ///
    /// * `Result<(), WalletError>` - Ok(()) if successful, or a WalletError if an error occurred.
    ///
    /// # Errors
    ///
    /// Returns a `WalletError::NotEncrypted` if the key is not currently encrypted.
    /// Returns a `WalletError::DecryptionError` if the old password is incorrect.
    /// Returns a `WalletError::EncryptionError` if there's an issue with the new encryption.
    ///
    /// # Example
    ///
    /// ```
    /// # use bittensor_wallet::ColdKeyPair;
    /// # let mut keypair = ColdKeyPair::generate();
    /// # keypair.encrypt("old_password").unwrap();
    /// let result = keypair.change_password("old_password", "new_password");
    /// assert!(result.is_ok());
    /// ```
    pub fn change_password(
        &mut self,
        old_password: &str,
        new_password: &str,
    ) -> Result<(), WalletError> {
        // Check if the keypair is encrypted
        if !self.is_encrypted {
            return Err(WalletError::NotEncrypted);
        }

        // Decrypt the private key with the old password
        let decrypted_private_key: Vec<u8> = self.decrypt(old_password)?;

        // Re-encrypt with the new password
        let new_encrypted: SecretBox<[u8; 32]> =
            self.encrypt_private_key(&decrypted_private_key, new_password)?;

        // Update the private key and maintain encrypted state
        self.private_key = new_encrypted;
        Ok(())
    }

    // fn re_encrypt_private_key(
    //     &self,
    //     old_password: &str,
    //     new_password: &str,
    // ) -> Result<Vec<u8>, WalletError> {
    //     // Decrypt the entire private key with the old password
    //     let decrypted_data = self.decrypt(old_password, &self.private_key)?;

    //     // Generate a new salt for the new encryption
    //     let new_salt = SaltString::generate(&mut rand::thread_rng());

    //     // Derive a new key from the new password using Argon2
    //     let argon2 = Argon2::default();
    //     let password_hash = argon2
    //         .hash_password(new_password.as_bytes(), &new_salt)
    //         .map_err(|e| WalletError::EncryptionError(format!("Failed to hash password: {}", e)))?;
    //     let new_derived_key = password_hash.hash.unwrap();

    //     // Create a new AES-GCM cipher instance with the new key
    //     let cipher = Aes256Gcm::new_from_slice(new_derived_key.as_bytes()).map_err(|e| {
    //         WalletError::EncryptionError(format!("Failed to create AES-GCM cipher: {}", e))
    //     })?;

    //     // Generate a new nonce
    //     let new_nonce_bytes = rand::random::<[u8; 12]>();
    //     let new_nonce = Nonce::from_slice(&new_nonce_bytes);

    //     // Encrypt the data with the new key and nonce
    //     let new_ciphertext = cipher
    //         .encrypt(new_nonce, decrypted_data.as_ref())
    //         .map_err(|e| {
    //             WalletError::EncryptionError(format!("AES-GCM encryption failed: {}", e))
    //         })?;

    //     // Combine new salt, new nonce, and new ciphertext
    //     let mut new_encrypted_data = new_salt.as_str().as_bytes().to_vec();
    //     new_encrypted_data.extend_from_slice(&new_nonce_bytes);
    //     new_encrypted_data.extend_from_slice(&new_ciphertext);

    //     Ok(new_encrypted_data)
    // }

    /// Verifies if the provided password is correct for this keypair.
    ///
    /// This function attempts to decrypt a small portion of the encrypted private key
    /// to verify if the provided password is correct.
    ///
    /// # Arguments
    ///
    /// * `password` - A string slice that holds the password to verify.
    ///
    /// # Returns
    ///
    /// * `Result<(), WalletError>` - Ok(()) if the password is correct, otherwise an error.
    ///
    /// # Errors
    ///
    /// Returns a `WalletError` if the decryption fails, indicating an incorrect password.
    ///
    // fn verify_password(&self, password: &str) -> Result<(), WalletError> {
    //     // Attempt to decrypt a small portion of the encrypted data
    //     // If decryption succeeds, the password is correct
    //     let test_data: &[u8] = &self.private_key[..34]; // Use the first 34 bytes (salt + nonce)
    //     self.decrypt(password, test_data)?;
    //     Ok(())
    // }

    /// Encrypts a private key using the provided password.
    ///
    /// # Arguments
    ///
    /// * `private_key` - The private key to encrypt.
    /// * `password` - The password to use for encryption.
    ///
    /// # Returns
    ///
    /// * `Result<SecretBox<[u8; 32]>, Error>` - The encrypted private key in a SecretBox.
    ///
    /// # Errors
    ///
    /// Returns an error if encryption fails or if the private key is not 32 bytes long.
    fn encrypt_private_key(
        &self,
        private_key: &[u8],
        password: &str,
    ) -> Result<SecretBox<[u8; 32]>, WalletError> {
        // Ensure the private key is 32 bytes long
        if private_key.len() != 32 {
            return Err(WalletError::InvalidPrivateKey);
        }

        let salt = SaltString::generate(&mut rand::thread_rng());
        let argon2 = Argon2::default();
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| WalletError::EncryptionError(format!("Failed to hash password: {}", e)))?;
        let derived_key = password_hash.hash.unwrap();

        // Create a new SecretBox with the encrypted private key
        let secret_box = SecretBox::new(|secret: &mut [u8; 32]| {
            let cipher = match Aes256Gcm::new_from_slice(derived_key.as_bytes()) {
                Ok(c) => c,
                Err(e) => {
                    log::error!("Failed to create AES-GCM cipher: {}", e);
                    return;
                }
            };

            // Create a longer-lived value for the random bytes
            let nonce_bytes = rand::random::<[u8; 12]>();
            let nonce = Nonce::from_slice(&nonce_bytes);

            let encrypted = match cipher.encrypt(nonce, private_key.as_ref()) {
                Ok(e) => e,
                Err(e) => {
                    log::error!("AES-GCM encryption failed: {}", e);
                    return;
                }
            };

            // Combine salt, nonce, and ciphertext
            let mut result = salt.as_str().as_bytes().to_vec();
            result.extend_from_slice(nonce.as_slice());
            result.extend_from_slice(&encrypted);

            // Copy the result into the secret
            secret.copy_from_slice(&result[..32]);
        });

        Ok(secret_box)
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
        // We need to convert the public key to a 32-byte array first
        let public_bytes: [u8; 32] = self
            .public
            .try_into()
            .expect("Public key should be 32 bytes long");
        sp_runtime::AccountId32::new(public_bytes)
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
        let public_bytes: [u8; 32] = self
            .public
            .try_into()
            .expect("Public key should be 32 bytes long");
        sp_runtime::AccountId32::new(public_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sp_core::crypto::Ss58Codec;
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
        // Generate a new ColdKeyPair
        let keypair: ColdKeyPair = ColdKeyPair::generate();

        // Check the length of the public key
        let public_key_length: usize = <Vec<u8> as AsRef<[u8]>>::as_ref(&keypair.public).len();
        assert_eq!(public_key_length, 32, "Public key should be 32 bytes long");

        // Check that the private key is not empty
        assert!(!keypair.private_key.borrow().iter().all(|&byte| byte == 0),);

        // TODO: Consider adding more robust checks for the private key,
        // such as verifying its length or structure
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
        // SecretBox doesn't have a len() method, so we'll use a different approach
        println!("Original private key is present");

        // Encrypt the keypair
        let encrypted_keypair = match keypair.encrypt(password) {
            Ok(enc) => {
                println!("Encryption successful");
                println!("Encrypted data is present");
                enc
            }
            Err(e) => {
                println!("Encryption failed: {:?}", e);
                panic!("Encryption failed: {:?}", e);
            }
        };

        // Attempt to decrypt the encrypted keypair using the provided password
        let decryption_result: Result<Vec<u8>, WalletError> = encrypted_keypair.decrypt(password);

        match decryption_result {
            Ok(decrypted) => {
                println!("Decryption successful");
                println!("Decrypted data length: {}", decrypted.len());
                assert_ne!(
                    encrypted_keypair.private_key.borrow().as_ref(),
                    decrypted.as_slice(),
                    "Encrypted and decrypted data should not be the same"
                );
                assert_eq!(
                    keypair.private_key.borrow().len(),
                    decrypted.len(),
                    "Original and decrypted data should have the same length"
                );
                assert_eq!(
                    keypair.private_key.borrow().as_ref(),
                    decrypted.as_slice(),
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
        let result: Result<Vec<u8>, WalletError> = keypair.decrypt("wrong_password");
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
        assert!(sr25519::Pair::verify(
            &signature,
            message,
            &sr25519::Public::from_slice(&keypair.public).expect("Invalid public key")
        ));

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
            &sr25519::Public::from_slice(&encrypted_keypair.public).expect("Invalid public key")
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

    #[test]
    fn test_cold_keypair_secret_box() {
        // Generate a new ColdKeyPair
        let cold_keypair = ColdKeyPair::generate();

        // Test that we can access the private key
        {
            let private_key = cold_keypair.private_key.borrow();
            assert_eq!(private_key.len(), 32);
        } // private_key is dropped here, releasing the borrow

        // Test that we can sign a message
        let message = b"test message";
        let signature = cold_keypair.sign(message).expect("Signing should succeed");
        assert!(sr25519::Pair::verify(
            &signature,
            message,
            &sr25519::Public::from_slice(&cold_keypair.public).expect("Invalid public key")
        ));

        // Test that the private key is not directly accessible
        // This line should not compile, so we'll comment it out
        // let _compile_error = cold_keypair.private_key;

        // Test encryption and decryption
        let password = "test_password";
        let encrypted_keypair = cold_keypair
            .encrypt(password)
            .expect("Encryption should succeed");

        // Ensure the encrypted keypair's private key is different
        assert_ne!(
            cold_keypair.private_key.borrow(),
            encrypted_keypair.private_key.borrow()
        );

        // Test signing with encrypted keypair
        let encrypted_signature = encrypted_keypair
            .sign_encrypted(message, password)
            .expect("Signing with encrypted keypair should succeed");
        assert!(sr25519::Pair::verify(
            &encrypted_signature,
            message,
            &sr25519::Public::from_slice(&encrypted_keypair.public).expect("Invalid public key")
        ));

        // Test that signing fails with wrong password
        assert!(encrypted_keypair
            .sign_encrypted(message, "wrong_password")
            .is_err());
    }

    use sp_core::Pair as PairTrait;

    #[test]
    fn test_cold_keypair_serialization() {
        // Enable debug logging for this test
        let _ = env_logger::builder()
            .filter_level(log::LevelFilter::Debug)
            .try_init();

        let cold_keypair = ColdKeyPair::generate();
        log::debug!("Original public key: {:?}", cold_keypair.public);

        // Test signing with original keypair
        let message = b"test message";
        let original_signature = cold_keypair
            .sign(message)
            .expect("Original signing should succeed");
        log::debug!("Original signature: {:?}", original_signature);

        // Serialize the ColdKeyPair
        let serialized =
            serde_json::to_string(&cold_keypair).expect("Serialization should succeed");
        log::debug!("Serialized keypair: {}", serialized);

        // Deserialize the ColdKeyPair
        let deserialized: ColdKeyPair =
            serde_json::from_str(&serialized).expect("Deserialization should succeed");
        log::debug!("Deserialized public key: {:?}", deserialized.public);

        // Check that the public keys match
        assert_eq!(
            cold_keypair.public, deserialized.public,
            "Public keys should match"
        );

        // Check that the private keys match
        assert_eq!(
            *cold_keypair.private_key.borrow(),
            *deserialized.private_key.borrow(),
            "Private keys should match"
        );

        // Test signing with deserialized keypair
        let deserialized_signature = deserialized
            .sign(message)
            .expect("Deserialized signing should succeed");
        log::debug!("Deserialized signature: {:?}", deserialized_signature);

        // Verify both signatures
        let public = sr25519::Public::from_slice(&cold_keypair.public).expect("Invalid public key");
        assert!(
            sr25519::Pair::verify(&original_signature, message, &public),
            "Original signature verification failed"
        );
        assert!(
            sr25519::Pair::verify(&deserialized_signature, message, &public),
            "Deserialized signature verification failed"
        );

        // Compare signatures
        assert_eq!(
            original_signature, deserialized_signature,
            "Signatures should match"
        );
    }

    #[test]
    fn test_cold_keypair_ss58_address() {
        let cold_keypair = ColdKeyPair::generate();
        let public_key =
            sr25519::Public::from_slice(&cold_keypair.public).expect("Invalid public key");
        let ss58_address = public_key.to_ss58check();

        // Ensure the SS58 address is a valid string
        assert!(!ss58_address.is_empty());

        // Verify that we can recover the public key from the SS58 address
        let recovered_public =
            sr25519::Public::from_ss58check(&ss58_address).expect("Invalid SS58 address");
        assert_eq!(public_key, recovered_public);
    }
}
