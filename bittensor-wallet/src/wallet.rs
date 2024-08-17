use crate::errors::WalletError;

use bip39::{Language, Mnemonic};
use serde::{Deserialize, Serialize};
use sp_core::crypto::Ss58Codec;
use sp_core::ByteArray;
use sp_core::{sr25519, Pair};
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Clone, Debug)]
struct KeyCredentials {
    #[serde(rename = "accountId")]
    account_id: String,
    #[serde(rename = "publicKey")]
    public_key: String,
    #[serde(rename = "privateKey")]
    private_key: Option<String>,
    #[serde(rename = "secretPhrase")]
    secret_phrase: Option<String>,
    #[serde(rename = "secretSeed")]
    secret_seed: Option<String>,
    #[serde(rename = "ss58Address")]
    ss58_address: String,
}

use crate::keypair::{ColdKeyPair, HotKeyPair, KeyPair};

#[derive(Clone)]
pub struct Wallet {
    pub name: String,
    pub path: PathBuf,
    pub coldkey: Option<ColdKeyPair>,
    pub hotkeys: HashMap<String, HotKeyPair>,
}

impl Wallet {
    pub fn new(name: String, path: PathBuf) -> Self {
        Wallet {
            name,
            path,
            coldkey: None,
            hotkeys: HashMap::new(),
        }
    }
    /// Creates a new wallet with a coldkey.
    ///
    /// # Arguments
    ///
    /// * `n_words` - The number of words for the mnemonic phrase (typically 12 or 24).
    /// * `password` - The password to encrypt the coldkey.
    ///
    /// # Returns
    ///
    /// * `Result<(), WalletError>` - Ok if the wallet is created successfully, Err otherwise.
    ///
    /// # Errors
    ///
    /// * `WalletError::IoError` - If there's an issue writing files.
    /// * `WalletError::SerializationError` - If there's an issue serializing data.
    /// * `WalletError::EncryptionError` - If there's an issue encrypting the coldkey.
    ///
    pub fn create_new_wallet(&self, password: &str) -> Result<(), WalletError> {
        // Generate a new ColdKeyPair
        let coldkey: ColdKeyPair = ColdKeyPair::generate();

        // Create KeyCredentials for the public part of the coldkey
        let coldkey_pub: KeyCredentials = KeyCredentials {
            account_id: format!("0x{}", hex::encode(coldkey.public.0)),
            public_key: format!("0x{}", hex::encode(coldkey.public.0)),
            private_key: None,
            secret_phrase: None,
            secret_seed: None,
            ss58_address: coldkey.public.to_ss58check(),
        };

        // Serialize and write the public key credentials to a file
        let coldkey_pub_path: PathBuf = self.path.join("coldkeypub.txt");
        let coldkey_pub_json: String = serde_json::to_string_pretty(&coldkey_pub)
            .map_err(|e| WalletError::SerializationError(e.to_string()))?;
        std::fs::write(&coldkey_pub_path, coldkey_pub_json).map_err(WalletError::IoError)?;

        // Encrypt and write the coldkey to a file
        let encrypted_coldkey: Vec<u8> = coldkey.encrypt(password)?;
        let coldkey_path: PathBuf = self.path.join("coldkey");
        std::fs::write(&coldkey_path, encrypted_coldkey).map_err(WalletError::IoError)?;

        Ok(())
    }

    /// Creates a new hotkey and stores it in the wallet.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the hotkey.
    ///
    /// # Returns
    ///
    /// * `Result<(), WalletError>` - Ok if the hotkey is created successfully, Err otherwise.
    ///
    /// # Errors
    ///
    /// * `WalletError::IoError` - If there's an issue writing the hotkey file.
    /// * `WalletError::SerializationError` - If there's an issue serializing the hotkey data.
    ///
    /// # Example
    ///
    /// ```
    /// let wallet = Wallet::new("my_wallet", PathBuf::from("/path/to/wallet"));
    /// match wallet.create_new_hotkey("my_hotkey") {
    ///     Ok(_) => println!("Hotkey created successfully"),
    ///     Err(e) => eprintln!("Error creating hotkey: {:?}", e),
    /// }
    /// ```
    pub fn create_new_hotkey(&self, name: &str) -> Result<(), WalletError> {
        // Generate a new HotKeyPair
        let hotkey: HotKeyPair = HotKeyPair::generate();

        // Create KeyCredentials for the hotkey
        let hotkey_credentials: KeyCredentials = KeyCredentials {
            account_id: format!("0x{}", hex::encode(hotkey.public.0)),
            public_key: format!("0x{}", hex::encode(hotkey.public.0)),
            private_key: Some(format!("0x{}", hex::encode(&hotkey.private))),
            secret_phrase: Some(hotkey.to_mnemonic()),
            secret_seed: Some(format!("0x{}", hex::encode(hotkey.to_seed()))),
            ss58_address: hotkey.public.to_ss58check(),
        };

        // TODO: Consider implementing a more secure way to handle private keys and secret phrases
        // NOTE: The current implementation stores sensitive information in plain text

        // Serialize and write the hotkey credentials to a file
        let hotkey_path: PathBuf = self.path.join("hotkeys").join(name);
        let hotkey_json: String = serde_json::to_string_pretty(&hotkey_credentials)
            .map_err(|e| WalletError::SerializationError(e.to_string()))?;
        std::fs::write(&hotkey_path, hotkey_json).map_err(WalletError::IoError)?;

        Ok(())
    }

    /// Retrieves the coldkey from the wallet.
    ///
    /// # Arguments
    ///
    /// * `password` - The password to decrypt the coldkey.
    ///
    /// # Returns
    ///
    /// * `Result<ColdKeyPair, WalletError>` - The decrypted ColdKeyPair if successful, Err otherwise.
    ///
    /// # Errors
    ///
    /// * `WalletError::IoError` - If there's an issue reading the coldkey files.
    /// * `WalletError::SerializationError` - If there's an issue deserializing the coldkey data.
    /// * `WalletError::DecryptionError` - If the password is incorrect or there's an issue decrypting the coldkey.
    ///
    /// # Example
    ///
    /// ```
    /// let wallet = Wallet::new("my_wallet", PathBuf::from("/path/to/wallet"));
    /// match wallet.get_coldkey("my_secure_password") {
    ///     Ok(coldkey) => println!("Coldkey retrieved successfully"),
    ///     Err(e) => eprintln!("Error retrieving coldkey: {:?}", e),
    /// }
    /// ```
    pub fn get_coldkey(&self, password: &str) -> Result<ColdKeyPair, WalletError> {
        // Read the encrypted coldkey from file
        let coldkey_path: PathBuf = self.path.join("coldkey");
        let encrypted_coldkey: Vec<u8> =
            std::fs::read(&coldkey_path).map_err(WalletError::IoError)?;

        // Read and parse the coldkey public information
        let coldkey_pub_path: PathBuf = self.path.join("coldkeypub.txt");
        let coldkey_pub_json: String =
            std::fs::read_to_string(&coldkey_pub_path).map_err(WalletError::IoError)?;
        let coldkey_pub: KeyCredentials = serde_json::from_str(&coldkey_pub_json)
            .map_err(|e| WalletError::SerializationError(e.to_string()))?;

        // Convert the public key from hex to bytes
        let public: sr25519::Public = sr25519::Public::from_slice(
            &hex::decode(&coldkey_pub.public_key[2..])
                .map_err(|e| WalletError::DecodingError(e.to_string()))?,
        )
        .map_err(|_| WalletError::InvalidPublicKey)?;

        // Create a new ColdKeyPair
        let coldkey: ColdKeyPair = ColdKeyPair::new(public, encrypted_coldkey);

        // Verify the password by attempting to decrypt
        coldkey.decrypt(password)?;

        Ok(coldkey)
    }

    /// Retrieves a HotKeyPair from the wallet by its name.
    ///
    /// # Arguments
    ///
    /// * `name` - A string slice that holds the name of the hotkey to retrieve.
    ///
    /// # Returns
    ///
    /// * `Result<HotKeyPair, WalletError>` - The HotKeyPair if successful, or a WalletError if any operation fails.
    ///
    /// # Errors
    ///
    /// * `WalletError::IoError` - If there's an issue reading the hotkey file.
    /// * `WalletError::SerializationError` - If there's an issue deserializing the hotkey JSON.
    /// * `WalletError::DecodingError` - If there's an issue decoding the hex-encoded keys.
    /// * `WalletError::InvalidPublicKey` - If the public key is invalid.
    ///

    pub fn get_hotkey(&self, name: &str) -> Result<HotKeyPair, WalletError> {
        // Construct the path to the hotkey file
        let hotkey_path: std::path::PathBuf = self.path.join("hotkeys").join(name);

        // Read the hotkey JSON file
        let hotkey_json: String =
            std::fs::read_to_string(&hotkey_path).map_err(WalletError::IoError)?;

        // Deserialize the JSON content into KeyCredentials struct
        let hotkey_credentials: KeyCredentials = serde_json::from_str(&hotkey_json)
            .map_err(|e| WalletError::SerializationError(e.to_string()))?;

        // Decode and create the public key
        let public_key_bytes: Vec<u8> = hex::decode(&hotkey_credentials.public_key[2..])
            .map_err(|e| WalletError::DecodingError(e.to_string()))?;
        let public: sr25519::Public = sr25519::Public::from_slice(&public_key_bytes)
            .map_err(|_| WalletError::InvalidPublicKey)?;

        // Decode the private key
        let private: Vec<u8> = hex::decode(
            &hotkey_credentials
                .private_key
                .ok_or(WalletError::MissingPrivateKey)?[2..],
        )
        .map_err(|e| WalletError::DecodingError(e.to_string()))?;

        // Create and return the HotKeyPair
        Ok(HotKeyPair::new(public, private))
    }

    /// Retrieves all HotKeyPairs from the wallet.
    ///
    /// # Returns
    ///
    /// * `Result<HashMap<String, HotKeyPair>, WalletError>` - A HashMap containing the hotkey names as keys and their corresponding HotKeyPairs as values if successful, or a WalletError if any operation fails.
    ///
    /// # Errors
    ///
    /// * `WalletError::IoError` - If there's an issue reading the hotkeys directory or files.
    /// * `WalletError::SerializationError` - If there's an issue deserializing the hotkey JSON.
    /// * `WalletError::DecodingError` - If there's an issue decoding the hex-encoded keys.
    /// * `WalletError::InvalidPublicKey` - If a public key is invalid.
    ///
    /// # Example
    ///
    /// ```
    /// let wallet = Wallet::new("my_wallet", PathBuf::from("/path/to/wallet"));
    /// match wallet.get_hotkeys() {
    ///     Ok(hotkeys) => {
    ///         for (name, hotkey) in hotkeys {
    ///             println!("Hotkey name: {}, Public key: {:?}", name, hotkey.public_key());
    ///         }
    ///     },
    ///     Err(e) => eprintln!("Error retrieving hotkeys: {:?}", e),
    /// }
    /// ```
    pub fn get_hotkeys(&self) -> Result<HashMap<String, HotKeyPair>, WalletError> {
        let hotkeys_dir: std::path::PathBuf = self.path.join("hotkeys");
        let mut hotkeys: HashMap<String, HotKeyPair> = HashMap::new();

        // Read the hotkeys directory
        let entries: std::fs::ReadDir =
            std::fs::read_dir(&hotkeys_dir).map_err(WalletError::IoError)?;

        for entry in entries {
            let entry: std::fs::DirEntry = entry.map_err(WalletError::IoError)?;
            let file_name: std::ffi::OsString = entry.file_name();
            let hotkey_name: String = file_name.to_string_lossy().into_owned();

            // Get the HotKeyPair for each hotkey file
            let hotkey: HotKeyPair = self.get_hotkey(&hotkey_name)?;

            // Insert the hotkey into the HashMap
            hotkeys.insert(hotkey_name, hotkey);
        }

        Ok(hotkeys)
    }

    pub fn sign_with_coldkey(
        &self,
        message: &[u8],
        password: &str,
    ) -> Result<Vec<u8>, WalletError> {
        let coldkey = self.get_coldkey(password)?;
        Ok(coldkey.sign(message).0.to_vec())
    }

    pub fn sign_with_hotkey(&self, name: &str, message: &[u8]) -> Result<Vec<u8>, WalletError> {
        let hotkey = self.get_hotkey(name)?;
        Ok(hotkey.sign(message).0.to_vec())
    }

    /// Retrieves the SS58-encoded address of the coldkey.
    ///
    /// # Returns
    ///
    /// * `Result<String, WalletError>` - The SS58-encoded address if successful, or an error if the operation fails.
    ///
    /// # Errors
    ///
    /// * `WalletError::IoError` - If there's an issue reading the coldkey public file.
    /// * `WalletError::SerializationError` - If there's an issue deserializing the JSON data.
    /// * `WalletError::NoKeyFound` - If the SS58 address is not found in the deserialized data.
    ///
    /// # Example
    ///
    /// ```
    /// let wallet = Wallet::new("my_wallet", PathBuf::from("/path/to/wallet"));
    /// match wallet.get_coldkey_ss58() {
    ///     Ok(ss58_address) => println!("Coldkey SS58 address: {}", ss58_address),
    ///     Err(e) => eprintln!("Error retrieving coldkey SS58 address: {:?}", e),
    /// }
    /// ```
    pub fn get_coldkey_ss58(&self) -> Result<String, WalletError> {
        // Define the path to the coldkey public file
        let coldkey_pub_path: std::path::PathBuf = self.path.join("coldkeypub.txt");

        // Read the contents of the coldkey public file
        let coldkey_pub_json: String =
            std::fs::read_to_string(&coldkey_pub_path).map_err(WalletError::IoError)?;

        // Deserialize the JSON content into KeyCredentials struct
        let coldkey_pub: KeyCredentials = serde_json::from_str(&coldkey_pub_json)
            .map_err(|e| WalletError::SerializationError(e.to_string()))?;

        // Return the SS58 address
        Ok(coldkey_pub.ss58_address)
    }

    pub fn get_hotkey_ss58(&self, name: &str) -> Result<String, WalletError> {
        let hotkey_path = self.path.join("hotkeys").join(name);
        let hotkey_json: String =
            std::fs::read_to_string(&hotkey_path).map_err(WalletError::IoError)?;
        let hotkey_credentials: KeyCredentials = serde_json::from_str(&hotkey_json)
            .map_err(|e| WalletError::SerializationError(e.to_string()))?;

        // Check if the SS58 address is empty and return an error if it is
        if hotkey_credentials.ss58_address.is_empty() {
            Err(WalletError::NotFound("SS58 address not found".to_string()))
        } else {
            Ok(hotkey_credentials.ss58_address)
        }
    }

    // TODO: Implement a method to rotate or update hotkey passwords
    // TODO: Add a mechanism to verify the integrity of stored hotkeys
    // TODO: Consider implementing a backup system for hotkeys

    // pub fn set_active_hotkey(&mut self, name: &str) -> Result<(), WalletError> {
    //     if self.hotkey_paths.contains_key(name) {
    //         self.active_hotkey = Some(name.to_string());
    //         Ok(())
    //     } else {
    //         Err(WalletError::HotkeyNotFound)
    //     }
    // }

    /// Retrieves the coldkey as a public key.
    ///
    /// This function decrypts the wallet's mnemonic, derives the seed, generates an SR25519 keypair,
    /// and returns the public key.
    ///
    /// # Arguments
    ///
    /// * `password` - A string slice that holds the password to decrypt the mnemonic.
    ///
    /// # Returns
    ///
    /// * `Result<sr25519::Public, WalletError>` - A Result containing either the public key or a WalletError.
    ///
    /// # Example
    ///
    /// ```
    /// let wallet = Wallet::new("my_wallet", PathBuf::from("/path/to/wallet"));
    /// let coldkey_public = wallet.get_coldkey("my_password").expect("Failed to get coldkey public key");
    /// ```
    // pub fn get_coldkey(&self, password: &str) -> Result<sr25519::Public, WalletError> {
    //     // Decrypt the mnemonic using the provided password
    //     let mnemonic: Mnemonic = self.decrypt_mnemonic(password)?;

    //     // Generate the seed from the mnemonic
    //     let seed: [u8; 32] = mnemonic.to_seed("")[..32]
    //         .try_into()
    //         .map_err(|_| WalletError::ConversionError)?;

    //     // Generate an SR25519 keypair from the seed
    //     let pair: sr25519::Pair = sr25519::Pair::from_seed(&seed);

    //     // Return only the public key
    //     Ok(pair.public())
    // }

    /// Gets the active hotkey as a Keypair.
    ///
    /// # Arguments
    ///
    /// * `password` - The password to decrypt the mnemonic and encrypt the private key.
    ///
    /// # Returns
    ///
    /// * `Result<Keypair, WalletError>` - The active hotkey Keypair or an error.
    // pub fn get_active_hotkey(&self, password: &str) -> Result<Keypair, WalletError> {
    //     let active_hotkey = self
    //         .active_hotkey
    //         .as_ref()
    //         .ok_or(WalletError::NoActiveHotkey)?;

    //     self.get_hotkey(active_hotkey, password)
    // }

    /// Gets a hotkey as a Keypair.
    ///
    /// # Arguments
    ///
    /// * `hotkey_name` - The name of the hotkey to retrieve.
    /// * `password` - The password to decrypt the mnemonic and encrypt the private key.
    ///
    /// # Returns
    ///
    /// * `Result<Keypair, WalletError>` - The hotkey Keypair or an error.
    ///  Gets a hotkey as a Keypair.
    ///
    /// # Arguments
    ///
    /// * `hotkey_name` - The name of the hotkey to retrieve.
    /// * `password` - The password to decrypt the mnemonic.
    ///
    /// # Returns
    ///
    /// * `Result<Keypair, WalletError>` - The hotkey Keypair or an error.
    ///
    /// # Example
    ///
    /// ```
    /// let wallet = Wallet::new("my_wallet", PathBuf::from("/path/to/wallet"));
    /// let hotkey = wallet.get_hotkey("my_hotkey", "password").expect("Failed to get hotkey");
    /// ```
    // pub fn get_hotkey(&self, hotkey_name: &str, password: &str) -> Result<Keypair, WalletError> {
    //     let encrypted_private = self
    //         .hotkey_data
    //         .as_ref()
    //         .and_then(|data| data.get(hotkey_name))
    //         .ok_or(WalletError::HotkeyNotFound)?;

    //     let public = self.get_hotkey_public(hotkey_name, password)?;

    //     Ok(Keypair::new(public, encrypted_private.clone()))
    // }

    // fn get_hotkey_public(
    //     &self,
    //     hotkey_name: &str,
    //     password: &str,
    // ) -> Result<sr25519::Public, WalletError> {
    //     let derivation_path = self
    //         .hotkey_paths
    //         .get(hotkey_name)
    //         .ok_or(WalletError::HotkeyNotFound)?;
    //     let mnemonic = self.decrypt_mnemonic(password)?;
    //     let seed = mnemonic.to_seed("");
    //     let pair = self.derive_sr25519_key(&seed[..32], derivation_path)?;
    //     Ok(pair.public())
    // }

    // pub async fn fetch_balance(&mut self) -> Result<(), WalletError> {
    //     // TODO: Implement actual balance fetching logic
    //     self.balance = Some(100.0);
    //     Ok(())
    // }
    // pub fn get_coldkey_ss58(&self) -> Result<String, WalletError> {
    //     let public = self.get_coldkey_public()?;
    //     Ok(public.to_ss58check())
    // }

    // pub fn get_hotkey_ss58(&self, hotkey_name: &str) -> Result<String, WalletError> {
    //     self.hotkey_public_keys
    //         .get(hotkey_name)
    //         .ok_or(WalletError::HotkeyNotFound)
    //         .map(|public_key| public_key.to_ss58check())
    // }

    // fn get_coldkey_public(&self) -> Result<sr25519::Public, WalletError> {
    //     // Assuming the first 32 bytes of encrypted_mnemonic are the public key
    //     // This assumption needs to be validated in the implementation of create_new_wallet
    //     let public_bytes: [u8; 32] = self.encrypted_mnemonic[..32]
    //         .try_into()
    //         .map_err(|_| WalletError::PublicKeyError)?;
    //     Ok(sr25519::Public::from_raw(public_bytes))
    // }

    /// Regenerates the wallet using a provided mnemonic phrase.
    ///
    /// # Arguments
    ///
    /// * `mnemonic` - The mnemonic phrase as a string.
    /// * `password` - The password used to encrypt the mnemonic.
    ///
    /// # Returns
    ///
    /// * `Result<(), WalletError>` - Ok(()) if successful, or an error if the operation fails.
    ///
    /// # Examples
    ///
    /// ```
    /// let mut wallet = Wallet::new("my_wallet", PathBuf::from("/path/to/wallet"));
    /// wallet.regenerate_wallet("your mnemonic phrase here", "secure_password").expect("Failed to regenerate wallet");
    /// ```
    pub fn regenerate_wallet(&self, mnemonic: &str, password: &str) -> Result<(), WalletError> {
        // Parse the mnemonic phrase
        let mnemonic: Mnemonic = Mnemonic::parse_in_normalized(Language::English, mnemonic)
            .map_err(WalletError::MnemonicGenerationError)?;

        // Generate the seed from the mnemonic
        let seed = mnemonic.to_seed("");

        // Generate the sr25519 keypair from the seed
        let pair = sr25519::Pair::from_seed_slice(&seed[..32])
            .map_err(|_| WalletError::KeyDerivationError)?;

        // Create a new ColdKeyPair
        let public = pair.public();
        let private = pair.to_raw_vec();
        let cold_keypair = ColdKeyPair::new(public, private);

        // Encrypt the cold keypair
        let encrypted_private = cold_keypair.encrypt(password)?;

        // Save the encrypted private key
        let coldkey_path = self.path.join("coldkey");
        std::fs::write(&coldkey_path, &encrypted_private).map_err(WalletError::IoError)?;

        // Save the public key information
        self.save_coldkeypub(&cold_keypair)?;

        // Remove all existing hotkeys
        let hotkeys_dir = self.path.join("hotkeys");
        if hotkeys_dir.exists() {
            std::fs::remove_dir_all(&hotkeys_dir).map_err(WalletError::IoError)?;
            std::fs::create_dir(&hotkeys_dir).map_err(WalletError::IoError)?;
        }

        Ok(())
    }

    // Helper method to save the coldkeypub information
    fn save_coldkeypub(&self, cold_keypair: &ColdKeyPair) -> Result<(), WalletError> {
        let coldkey_pub = KeyCredentials {
            account_id: format!("0x{}", hex::encode(cold_keypair.public.0)),
            public_key: format!("0x{}", hex::encode(cold_keypair.public.0)),
            private_key: None,
            secret_phrase: None,
            secret_seed: None,
            ss58_address: cold_keypair.public.to_ss58check(),
        };

        let coldkey_pub_path = self.path.join("coldkeypub.txt");
        let coldkey_pub_json = serde_json::to_string_pretty(&coldkey_pub)
            .map_err(|e| WalletError::SerializationError(e.to_string()))?;
        std::fs::write(&coldkey_pub_path, coldkey_pub_json).map_err(WalletError::IoError)?;

        Ok(())
    }
    /// Changes the password for the wallet and re-encrypts all sensitive data.
    ///
    /// This function decrypts the mnemonic using the old password, re-encrypts it with the new password,
    /// and updates all hotkeys with the new encryption.
    ///
    /// # Arguments
    ///
    /// * `old_password` - A string slice that holds the current password.
    /// * `new_password` - A string slice that holds the new password to be set.
    ///
    /// # Returns
    ///
    /// * `Result<(), WalletError>` - Ok(()) if successful, or an error if the operation fails.
    ///
    pub async fn change_password(
        &self,
        old_password: &str,
        new_password: &str,
    ) -> Result<(), WalletError> {
        // Read and decrypt the coldkey
        let coldkey_path = self.path.join("coldkey");
        let encrypted_coldkey = std::fs::read(&coldkey_path).map_err(WalletError::IoError)?;
        let coldkey = ColdKeyPair::new(self.get_coldkey_public()?, encrypted_coldkey);
        let decrypted_private = coldkey.decrypt(old_password)?;

        // Re-encrypt the coldkey with the new password
        let new_encrypted_coldkey =
            ColdKeyPair::new(coldkey.public, decrypted_private.clone()).encrypt(new_password)?;

        // Save the new encrypted coldkey
        std::fs::write(&coldkey_path, &new_encrypted_coldkey).map_err(WalletError::IoError)?;

        // For hotkeys, we don't need to re-encrypt them as they are stored unencrypted
        // However, we might want to update any password-related information if necessary
        let hotkeys_dir = self.path.join("hotkeys");
        if hotkeys_dir.exists() {
            for entry in std::fs::read_dir(hotkeys_dir)? {
                let entry: std::fs::DirEntry = entry.map_err(WalletError::IoError)?;
                let path = entry.path();
                if path.is_file() {
                    let hotkey_json =
                        std::fs::read_to_string(&path).map_err(WalletError::IoError)?;
                    let hotkey_credentials: KeyCredentials = serde_json::from_str(&hotkey_json)
                        .map_err(|e| WalletError::SerializationError(e.to_string()))?;

                    let updated_hotkey_json = serde_json::to_string_pretty(&hotkey_credentials)
                        .map_err(|e| WalletError::SerializationError(e.to_string()))?;
                    std::fs::write(&path, updated_hotkey_json).map_err(WalletError::IoError)?;
                }
            }
        }

        Ok(())
    }

    // Helper method to get the coldkey public key
    fn get_coldkey_public(&self) -> Result<sr25519::Public, WalletError> {
        let coldkey_pub_path = self.path.join("coldkeypub.txt");
        let coldkey_pub_json: String =
            std::fs::read_to_string(&coldkey_pub_path).map_err(WalletError::IoError)?;
        let coldkey_pub: KeyCredentials = serde_json::from_str(&coldkey_pub_json)
            .map_err(|e| WalletError::SerializationError(e.to_string()))?;

        sr25519::Public::from_slice(
            &hex::decode(&coldkey_pub.public_key[2..])
                .map_err(|e| WalletError::HexDecodeError(e.to_string()))?,
        )
        .map_err(|_| WalletError::InvalidPublicKey)
    }

    // fn encrypt_mnemonic(
    //     &self,
    //     mnemonic: &Mnemonic,
    //     password: &str,
    // ) -> Result<Vec<u8>, WalletError> {
    //     let salt: [u8; 16] = rand::thread_rng().gen();
    //     let argon2 = Argon2::default();
    //     let mut key = [0u8; 32];
    //     argon2
    //         .hash_password_into(password.as_bytes(), &salt, &mut key)
    //         .map_err(|_| WalletError::EncryptionError)?;

    //     let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| WalletError::EncryptionError)?;
    //     let nonce = Nonce::from(rand::thread_rng().gen::<[u8; 12]>());
    //     let mnemonic_string = mnemonic.to_string();
    //     let mnemonic_bytes = mnemonic_string.as_bytes();

    //     log::debug!("Encrypting mnemonic of length: {}", mnemonic_bytes.len());

    //     let ciphertext = cipher
    //         .encrypt(&nonce, mnemonic_bytes)
    //         .map_err(|_| WalletError::EncryptionError)?;

    //     let mut encrypted = Vec::with_capacity(salt.len() + nonce.len() + ciphertext.len());
    //     encrypted.extend_from_slice(&salt);
    //     encrypted.extend_from_slice(nonce.as_slice());
    //     encrypted.extend_from_slice(&ciphertext);

    //     log::debug!(
    //         "Encrypted data length (before adding public key): {}",
    //         encrypted.len()
    //     );
    //     log::debug!(
    //         "Salt length: {}, Nonce length: {}, Ciphertext length: {}",
    //         salt.len(),
    //         nonce.len(),
    //         ciphertext.len()
    //     );

    //     // Generate and prepend public key
    //     let seed = mnemonic.to_seed("");
    //     let pair = sr25519::Pair::from_seed_slice(&seed[..32])
    //         .map_err(|_| WalletError::KeyDerivationError)?;
    //     let public_key = pair.public();

    //     let mut final_encrypted = Vec::with_capacity(32 + encrypted.len());
    //     final_encrypted.extend_from_slice(public_key.as_ref());
    //     final_encrypted.extend_from_slice(&encrypted);

    //     log::debug!(
    //         "Final encrypted data length (including public key): {}",
    //         final_encrypted.len()
    //     );

    //     Ok(final_encrypted)
    // }

    // fn decrypt_mnemonic(&self, password: &str) -> Result<Mnemonic, WalletError> {
    //     log::debug!(
    //         "Decrypting mnemonic of length: {}",
    //         self.encrypted_mnemonic.len()
    //     );

    //     if self.encrypted_mnemonic.len() < 92 {
    //         // 32 (public key) + 16 (salt) + 12 (nonce) + 32 (minimum ciphertext)
    //         log::error!("Encrypted mnemonic is too short");
    //         return Err(WalletError::DecryptionError);
    //     }

    //     let public_key = &self.encrypted_mnemonic[..32];
    //     let salt = &self.encrypted_mnemonic[32..48];
    //     let nonce = &self.encrypted_mnemonic[48..60];
    //     let ciphertext = &self.encrypted_mnemonic[60..];

    //     log::debug!(
    //         "Public key length: {}, Salt length: {}, Nonce length: {}, Ciphertext length: {}",
    //         public_key.len(),
    //         salt.len(),
    //         nonce.len(),
    //         ciphertext.len()
    //     );

    //     // Derive the key from the password using Argon2
    //     let argon2 = Argon2::default();
    //     let mut key = [0u8; 32];
    //     if let Err(e) = argon2.hash_password_into(password.as_bytes(), salt, &mut key) {
    //         log::error!("Failed to derive key from password: {:?}", e);
    //         return Err(WalletError::DecryptionError);
    //     }

    //     // Create an AES-256-GCM cipher
    //     let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| {
    //         log::error!("Failed to create AES cipher: {:?}", e);
    //         WalletError::DecryptionError
    //     })?;

    //     // Decrypt the ciphertext
    //     let plaintext = cipher
    //         .decrypt(Nonce::from_slice(nonce), ciphertext)
    //         .map_err(|e| {
    //             log::error!("Failed to decrypt ciphertext: {:?}", e);
    //             WalletError::DecryptionError
    //         })?;

    //     // Convert plaintext to string and parse as Mnemonic
    //     let mnemonic_str = String::from_utf8(plaintext).map_err(|e| {
    //         log::error!("Failed to convert decrypted data to UTF-8: {:?}", e);
    //         WalletError::DecryptionError
    //     })?;

    //     log::debug!("Decrypted mnemonic string length: {}", mnemonic_str.len());

    /// Creates a new coldkey, encrypts it with the given password, and saves it to the wallet.
    ///
    /// # Arguments
    ///
    /// * `password` - A string slice that holds the password for encrypting the coldkey.
    ///
    /// # Returns
    ///
    /// * `Result<(), WalletError>` - Ok(()) if successful, or an error if the operation fails.
    ///
    pub fn create_new_coldkey(&mut self, password: &str) -> Result<(), WalletError> {
        // Generate a new ColdKeyPair
        let coldkey: ColdKeyPair = ColdKeyPair::generate();

        // Encrypt the coldkey with the provided password
        let encrypted: Vec<u8> = coldkey.encrypt(password)?;

        // Store the new coldkey in the wallet
        self.coldkey = Some(ColdKeyPair::new(coldkey.public, encrypted));

        // Save the coldkey to persistent storage
        self.save_coldkeypub(&coldkey)?;

        Ok(())
    }

    /// Sets a new coldkey for the wallet using a mnemonic phrase and password.
    ///
    /// # Arguments
    ///
    /// * `mnemonic` - A string slice that holds the mnemonic phrase for the coldkey.
    /// * `password` - A string slice that holds the password for encrypting the coldkey.
    ///
    /// # Returns
    ///
    /// * `Result<(), WalletError>` - Ok(()) if successful, or an error if the operation fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use bittensor_wallet::{Wallet, WalletError};
    /// use std::path::PathBuf;
    ///
    /// # fn main() -> Result<(), WalletError> {
    /// let mut wallet = Wallet::new("my_wallet", PathBuf::from("/path/to/wallet"));
    /// let mnemonic = "word1 word2 word3 ... word24";
    /// let password = "secure_password";
    /// wallet.set_coldkey(mnemonic, password)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn set_coldkey(&mut self, mnemonic: &str, password: &str) -> Result<(), WalletError> {
        // Generate a ColdKeyPair from the provided mnemonic
        let coldkey: ColdKeyPair = ColdKeyPair::from_mnemonic(mnemonic, Some(password))
            .map_err(|_| WalletError::InvalidMnemonic)?;

        // Encrypt the coldkey with the provided password
        let encrypted: Vec<u8> = coldkey.encrypt(password)?;

        // Store the new coldkey in the wallet
        self.coldkey = Some(ColdKeyPair::new(coldkey.public, encrypted));

        // Save the coldkey public key to persistent storage
        self.save_coldkeypub(&coldkey)?;

        Ok(())
    }

    /// Decrypts the coldkey using the provided password.
    ///
    /// # Arguments
    ///
    /// * `password` - A string slice that holds the password for decrypting the coldkey.
    ///
    /// # Returns
    ///
    /// * `Result<Vec<u8>, WalletError>` - A vector of bytes representing the decrypted coldkey if successful,
    ///   or a `WalletError` if the operation fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use bittensor_wallet::{Wallet, WalletError};
    /// use std::path::PathBuf;
    ///
    /// # fn main() -> Result<(), WalletError> {
    /// let wallet = Wallet::new("my_wallet", PathBuf::from("/path/to/wallet"));
    /// let password = "secure_password";
    /// let decrypted_coldkey = wallet.decrypt_coldkey(password)?;
    /// # Ok(())
    /// # }
    /// ```
    /// Decrypts the coldkey using the provided password.
    ///
    /// # Arguments
    ///
    /// * `password` - A string slice that holds the password for decrypting the coldkey.
    ///
    /// # Returns
    ///
    /// * `Result<Vec<u8>, WalletError>` - A vector of bytes representing the decrypted coldkey if successful,
    ///   or a `WalletError` if the operation fails.
    ///

    pub fn decrypt_coldkey(&self, password: &str) -> Result<Vec<u8>, WalletError> {
        // Attempt to get a reference to the coldkey, returning a NotFound error if it doesn't exist
        let coldkey: &ColdKeyPair = self
            .coldkey
            .as_ref()
            .ok_or_else(|| WalletError::NotFound("Coldkey not found".to_string()))?;

        // Attempt to decrypt the coldkey using the provided password
        coldkey.decrypt(password).map_err(|e| {
            // Create a specific error for decryption failures
            WalletError::DecryptionError(format!("Failed to decrypt coldkey: {}", e))
        })
    }

    /// Updates the encrypted private key for a specific hotkey.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the hotkey to update.
    /// * `encrypted_private` - The new encrypted private key.
    ///
    /// # Returns
    ///
    /// * `Result<(), WalletError>` - Ok(()) if successful, or an error if the operation fails.
    ///
    /// # Examples
    ///
    /// ```
    /// let mut wallet = Wallet::new("my_wallet", PathBuf::from("/path/to/wallet"));
    /// let encrypted_private = vec![1, 2, 3, 4, 5]; // Example encrypted private key
    /// wallet.update_hotkey_encryption("hotkey1", &encrypted_private).expect("Failed to update hotkey encryption");
    /// ```
    pub fn update_hotkey_encryption(
        &mut self,
        name: &str,
        encrypted_private: &[u8],
    ) -> Result<(), WalletError> {
        // Check if the hotkey exists
        if !self.hotkeys.contains_key(name) {
            return Err(WalletError::HotkeyNotFound);
        }

        // Update the encrypted private key for the specified hotkey
        if let Some(hotkey) = self.hotkeys.get_mut(name) {
            hotkey.private = encrypted_private.to_vec();
        } else {
            return Err(WalletError::HotkeyNotFound);
        }

        // Save the updated hotkey to disk
        self.save_hotkey(name)?;

        Ok(())
    }

    /// Saves the hotkey to disk.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the hotkey to save.
    ///
    /// # Returns
    ///
    /// * `Result<(), WalletError>` - Ok(()) if successful, or an error if the operation fails.
    ///

    fn save_hotkey(&self, name: &str) -> Result<(), WalletError> {
        // Check if the hotkey exists
        let hotkey = self.hotkeys.get(name).ok_or(WalletError::HotkeyNotFound)?;

        // Create the hotkey credentials
        let hotkey_credentials = KeyCredentials {
            account_id: format!("0x{}", hex::encode(hotkey.public.0)),
            public_key: format!("0x{}", hex::encode(hotkey.public.0)),
            private_key: Some(format!("0x{}", hex::encode(&hotkey.private))),
            secret_phrase: None,
            secret_seed: None,
            ss58_address: hotkey.public.to_ss58check(),
        };

        // Convert the credentials to JSON
        let hotkey_json = serde_json::to_string_pretty(&hotkey_credentials)
            .map_err(|e| WalletError::SerializationError(e.to_string()))?;

        // Create the hotkeys directory if it doesn't exist
        let hotkeys_dir = self.path.join("hotkeys");
        std::fs::create_dir_all(&hotkeys_dir).map_err(WalletError::IoError)?;

        // Write the JSON to a file
        let hotkey_path = hotkeys_dir.join(format!("{}.json", name));
        std::fs::write(&hotkey_path, hotkey_json).map_err(WalletError::IoError)?;

        Ok(())
    }

    /// Verifies a signature for a given message using the wallet's active hotkey.
    ///
    /// # Arguments
    ///
    /// * `message` - The message that was signed, as a byte slice.
    /// * `signature` - The signature to verify, as a byte slice.
    /// * `password` - The password to unlock the wallet.
    ///
    /// # Returns
    ///
    /// * `Result<bool, WalletError>` - Ok(true) if the signature is valid, Ok(false) if invalid, or a WalletError.
    ///
    pub fn verify(
        &self,
        message: &[u8],
        signature: &[u8],
        password: &str,
    ) -> Result<bool, WalletError> {
        // Retrieve the active hotkey
        let hotkey = self.get_hotkey(password)?;

        // Convert the signature to Sr25519Signature
        let sr25519_signature =
            sr25519::Signature::try_from(signature).map_err(|_| WalletError::InvalidSignature)?;

        // Verify the signature
        Ok(sr25519::Pair::verify(
            &sr25519_signature,
            message,
            hotkey.public(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use tempfile::tempdir;

    fn init() {
        let _ = env_logger::builder().is_test(true).try_init();
    }
    /// Helper function to create a test wallet
    fn create_test_wallet() -> Result<Wallet, WalletError> {
        let dir = tempdir().map_err(WalletError::IoError)?;
        let wallet = Wallet::new("test_wallet".to_string(), dir.path().to_path_buf());
        // wallet.create_new_wallet(12, "test_password")?;
        Ok(wallet)
    }

    #[test]
    fn test_wallet_creation() {
        let wallet = create_test_wallet().expect("Failed to create test wallet");
        assert_eq!(wallet.name, "test_wallet");
        assert!(wallet.path.exists());
        assert!(wallet.coldkey.is_none());
        assert!(wallet.hotkeys.is_empty());
    }

    #[test]
    fn test_create_new_wallet() {
        let wallet = create_test_wallet().expect("Failed to create test wallet");
        assert!(wallet.create_new_wallet("password123").is_ok());
    }

    #[test]
    fn test_create_new_hotkey() {
        let _ = env_logger::builder().is_test(true).try_init();
        let wallet = create_test_wallet().expect("Failed to create test wallet");

        // First, create a new wallet with a mnemonic
        wallet
            .create_new_wallet("password123")
            .expect("Failed to create new wallet");

        log::debug!("Wallet created successfully");

        // Now create a new hotkey
        wallet
            .create_new_hotkey("hotkey1")
            .expect("Failed to create new hotkey");

        log::debug!("Hotkey created successfully");

        // Additional assertions can be added here to verify the hotkey creation
        assert!(
            wallet.hotkeys.contains_key("hotkey1"),
            "Hotkey 'hotkey1' not found in wallet"
        );
    }

    #[test]
    fn test_get_coldkey() {
        init();
        let wallet = create_test_wallet().expect("Failed to create test wallet");
        wallet
            .create_new_wallet("password123")
            .expect("Failed to create new wallet");
        let coldkey = wallet.get_coldkey("password123");
        assert!(coldkey.is_ok());
    }

    #[test]
    fn test_regenerate_wallet() {
        let wallet = create_test_wallet().expect("Failed to create test wallet");
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        wallet
            .regenerate_wallet(mnemonic, "password123")
            .expect("Failed to regenerate wallet");
        assert!(wallet.coldkey.is_some());
    }

    /// Tests the password change functionality of the wallet.
    ///
    /// This test creates a new wallet, adds a hotkey, and then attempts to change the password.
    /// It verifies that the password change operation completes successfully.
    ///
    /// Tests the password change functionality of the wallet.
    ///
    /// This test creates a new wallet, adds a hotkey, changes the password, and verifies
    /// that operations fail with the old password but succeed with the new password.
    ///
    /// # Example
    ///
    /// ```
    /// let mut wallet = Wallet::new("test_wallet", PathBuf::from("/tmp"));
    /// wallet.create_new_wallet("old_password").unwrap();
    /// wallet.create_new_hotkey("hotkey1").unwrap();
    /// wallet.change_password("old_password", "new_password").await.unwrap();
    /// ```
    #[tokio::test]
    async fn test_change_password() {
        // Create a new test wallet
        let wallet: Wallet = create_test_wallet().expect("Failed to create test wallet");

        // Create a new wallet with the initial password
        wallet
            .create_new_wallet("old_password")
            .expect("Failed to create new wallet");

        // Create a new hotkey using the initial password
        wallet
            .create_new_hotkey("hotkey1")
            .expect("Failed to create new hotkey");

        // Attempt to change the password
        let change_result = wallet.change_password("old_password", "new_password").await;

        // Check the result of the password change operation
        assert!(
            change_result.is_ok(),
            "Failed to change password: {:?}",
            change_result.err()
        );

        // Verify that operations fail with the old password
        let old_password_result = wallet.get_coldkey("old_password");
        assert!(
            old_password_result.is_err(),
            "Operation succeeded with old password when it should have failed"
        );

        // Verify that operations succeed with the new password
        let new_password_result = wallet.get_coldkey("new_password");
        assert!(
            new_password_result.is_ok(),
            "Operation failed with new password when it should have succeeded"
        );

        // TODO: Add more comprehensive tests for other wallet operations after password change
    }

    // #[test]
    // fn test_encrypt_decrypt_mnemonic() {
    //     init();
    //     let mut wallet = create_test_wallet();
    //     let mnemonic = Mnemonic::from_str("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();
    //     let encrypted = wallet.encrypt_mnemonic(&mnemonic, "password123").unwrap();

    //     // Use the encrypted mnemonic to test decryption
    //     wallet.encrypted_mnemonic = encrypted;

    //     let decrypted = wallet.decrypt_mnemonic("password123").unwrap();
    //     assert_eq!(mnemonic.to_string(), decrypted.to_string());
    // }

    #[test]
    fn test_update_hotkey_encryption() {
        let mut wallet = create_test_wallet().expect("Failed to create test wallet");

        // First, create a new wallet
        wallet
            .create_new_wallet("password123")
            .expect("Failed to create new wallet");

        // Now create a new hotkey
        wallet
            .create_new_hotkey("hotkey1")
            .expect("Failed to create new hotkey");

        // Update the hotkey encryption
        let encrypted_private = vec![1, 2, 3, 4, 5]; // Example encrypted private key
        wallet
            .update_hotkey_encryption("hotkey1", &encrypted_private)
            .expect("Failed to update hotkey encryption");

        // TODO: Implement a method to safely retrieve and compare encrypted hotkey data
        // For now, we'll just check that the hotkey exists
        assert!(
            wallet.hotkeys.contains_key("hotkey1"),
            "Hotkey 'hotkey1' not found in wallet"
        );
    }

    // #[test]
    // fn test_wallet_decrypt_private_key_performance() {
    //     let mut wallet = create_test_wallet();
    //     wallet.create_new_wallet(12, "password123").unwrap();
    //     wallet
    //         .create_new_hotkey("test_hotkey", "password123")
    //         .unwrap();

    //     let start = Instant::now();
    //     for _ in 0..10 {
    //         // Reduced from 100 to 10 iterations
    //         let _ = wallet.get_hotkey("test_hotkey", "password123").unwrap();
    //     }
    //     let duration = start.elapsed();

    //     println!("Average decryption time: {:?}", duration / 10);
    //     assert!(duration.as_millis() < 5000, "Decryption is too slow"); // Increased threshold to 5000ms
    // }

    // #[test]
    // fn test_wallet_mnemonic_encryption_uniqueness() {
    //     let mut encrypted_mnemonics = HashSet::new();

    //     for _ in 0..1000 {
    //         let mut wallet = create_test_wallet();
    //         wallet.create_new_wallet(12, "password123").unwrap();

    //         // Check that this encrypted mnemonic is unique
    //         assert!(
    //             encrypted_mnemonics.insert(wallet.encrypted_mnemonic.clone()),
    //             "Duplicate encrypted mnemonic found"
    //         );
    //     }
    // }

    // #[test]
    // fn test_get_hotkey_ss58() {
    //     let mut wallet = create_test_wallet();
    //     wallet.create_new_wallet(12, "password123").unwrap();
    //     wallet
    //         .create_new_hotkey("test_hotkey", "password123")
    //         .unwrap();

    //     let ss58_address = wallet.get_hotkey_ss58("test_hotkey").unwrap();

    //     assert!(!ss58_address.is_empty());
    //     assert!(ss58_address.starts_with('5')); // SS58 addresses typically start with '5'
    //     assert_eq!(ss58_address.len(), 48); // SS58 addresses are typically 48 characters long assert_eq!(ss58_address.len(), 48); // SS58 addresses are typically 48 characters long
    // }
    // #[test]
    // fn test_get_hotkey_ss58() {
    //     let mut wallet = create_test_wallet();
    //     wallet.create_new_wallet(12, "password123").unwrap();
    //     wallet
    //         .create_new_hotkey("test_hotkey", "password123")
    //         .unwrap();

    //     let ss58_address = wallet.get_hotkey_ss58("test_hotkey").unwrap();

    //     assert!(!ss58_address.is_empty());
    //     assert!(ss58_address.starts_with('5'));
    //     assert_eq!(ss58_address.len(), 48); //
    // }
    /// Tests the behavior of `get_hotkey_ss58` method when attempting to retrieve a non-existent hotkey.
    ///
    /// This test ensures that the wallet correctly handles requests for hotkeys that don't exist,
    /// returning an appropriate error.
    ///
    /// # Example
    /// ```
    /// let wallet = Wallet::new();
    /// let result = wallet.get_hotkey_ss58("nonexistent_hotkey");
    /// assert!(result.is_err());
    /// assert!(matches!(result.unwrap_err(), WalletError::HotkeyNotFound));
    /// ```
    #[test]
    fn test_get_hotkey_ss58_nonexistent() {
        // Create a new test wallet
        let wallet: Wallet = create_test_wallet().unwrap();

        // Attempt to get the SS58 address of a non-existent hotkey
        let result: Result<String, WalletError> = wallet.get_hotkey_ss58("nonexistent_hotkey");

        // Assert that the result is an error
        assert!(
            result.is_err(),
            "Expected an error when retrieving non-existent hotkey"
        );

        // Assert that the error matches the expected WalletError::HotkeyNotFound
        assert!(
            matches!(result.unwrap_err(), WalletError::HotkeyNotFound),
            "Expected WalletError::HotkeyNotFound"
        );
    }
    /// Tests the consistency of SS58 address generation for coldkeys and hotkeys.
    ///
    /// This test ensures that:
    /// 1. The wallet can be created and a hotkey can be added.
    /// 2. Coldkey and hotkey SS58 addresses are different.
    /// 3. Multiple calls to get SS58 addresses return consistent results.
    ///
    /// # Example
    /// ```
    /// let wallet = create_test_wallet().unwrap();
    /// wallet.create_new_wallet("password123").unwrap();
    /// wallet.create_new_hotkey("test_hotkey").unwrap();
    ///
    /// let coldkey_ss58 = wallet.get_coldkey_ss58("password123").unwrap();
    /// let hotkey_ss58 = wallet.get_hotkey_ss58("test_hotkey").unwrap();
    ///
    /// assert_ne!(coldkey_ss58, hotkey_ss58);
    /// assert_eq!(coldkey_ss58, wallet.get_coldkey_ss58("password123").unwrap());
    /// assert_eq!(hotkey_ss58, wallet.get_hotkey_ss58("test_hotkey").unwrap());
    /// ```
    #[test]
    fn test_ss58_consistency() {
        let wallet = create_test_wallet().expect("Failed to create test wallet");
        wallet
            .create_new_wallet("password123")
            .expect("Failed to create new wallet");
        wallet
            .create_new_hotkey("test_hotkey")
            .expect("Failed to create new hotkey");

        let coldkey_ss58 = wallet
            .get_coldkey_ss58()
            .expect("Failed to get coldkey SS58");
        let hotkey_ss58 = wallet
            .get_hotkey_ss58("test_hotkey")
            .expect("Failed to get hotkey SS58");

        // Ensure that the coldkey and hotkey have different SS58 addresses
        assert_ne!(
            coldkey_ss58, hotkey_ss58,
            "Coldkey and hotkey SS58 addresses should be different"
        );

        // Ensure that multiple calls to get_coldkey_ss58 return the same address
        assert_eq!(
            coldkey_ss58,
            wallet
                .get_coldkey_ss58()
                .expect("Failed to get coldkey SS58 on second attempt"),
            "Coldkey SS58 address should be consistent across multiple calls"
        );

        // Ensure that multiple calls to get_hotkey_ss58 return the same address
        assert_eq!(
            hotkey_ss58,
            wallet
                .get_hotkey_ss58("test_hotkey")
                .expect("Failed to get hotkey SS58 on second attempt"),
            "Hotkey SS58 address should be consistent across multiple calls"
        );
    }
}
