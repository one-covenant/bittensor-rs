use pyo3::prelude::*;
use pyo3::types::PyBytes;
use std::path::PathBuf;

use crate::errors::WalletError;
use crate::keypair::{ColdKeyPair, HotKeyPair, KeyPair};
use crate::wallet::Wallet;
use pyo3::exceptions::{PyException, PyValueError};
use sp_core::crypto::Ss58Codec;
use sp_core::sr25519;
use sp_core::ByteArray;

/// A Python module implemented in Rust.
#[pymodule]
fn bittensor_wallet(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<PyWallet>()?;
    m.add_class::<PyColdKeyPair>()?;
    m.add_class::<PyHotKeyPair>()?;
    Ok(())
}

/// Python wrapper for the Wallet struct
#[pyclass]
struct PyWallet {
    wallet: Wallet,
}

#[pymethods]
impl PyWallet {
    #[new]
    fn new(name: &str, path: &str) -> Self {
        PyWallet {
            wallet: Wallet::new(name.to_string(), PathBuf::from(path))
                .expect("Failed to create wallet"),
        }
    }

    /// Creates a new wallet with the specified password.
    fn create_new_wallet(&mut self, password: &str) -> PyResult<()> {
        self.wallet
            .create_new_wallet(password)
            .map_err(wallet_error_to_pyerr)
    }

    /// Creates a new hotkey with the specified name.
    fn create_new_hotkey(&mut self, name: &str) -> PyResult<()> {
        self.wallet
            .create_new_hotkey(name)
            .map_err(wallet_error_to_pyerr)
    }

    /// Retrieves the coldkey's public key.
    fn get_coldkey<'py>(&self, py: Python<'py>, password: &str) -> PyResult<&'py PyBytes> {
        match self.wallet.get_coldkey(password) {
            Ok(coldkey) => {
                let key_bytes = coldkey.public.to_vec();
                Ok(PyBytes::new(py, &key_bytes))
            }
            Err(error) => Err(PyValueError::new_err(error.to_string())),
        }
    }

    /// Retrieves a hotkey.
    fn get_hotkey<'py>(&self, py: Python<'py>, name: &str) -> PyResult<&'py PyBytes> {
        match self.wallet.get_hotkey(name) {
            Ok(hotkey) => {
                let key_bytes = hotkey.public.to_vec();
                Ok(PyBytes::new(py, &key_bytes))
            }
            Err(error) => Err(PyValueError::new_err(error.to_string())),
        }
    }

    /// Regenerates the wallet from a mnemonic phrase.
    fn regenerate_wallet(&mut self, mnemonic: &str, password: &str) -> PyResult<()> {
        self.wallet
            .regenerate_wallet(mnemonic, password)
            .map_err(wallet_error_to_pyerr)
    }

    /// Changes the password of the wallet.
    ///
    /// # Arguments
    ///
    /// * `py` - The Python interpreter.
    /// * `old_password` - The current password of the wallet.
    /// * `new_password` - The new password to set for the wallet.
    ///
    /// # Returns
    ///
    /// * `PyResult<&'py PyAny>` - A Python future representing the asynchronous operation.
    ///
    /// # Example
    ///
    /// ```python
    /// wallet = PyWallet("my_wallet", "/path/to/wallet")
    /// await wallet.change_password("old_password", "new_password")
    /// ```
    #[pyo3(name = "change_password")]
    fn py_change_password<'py>(
        &mut self,
        py: Python<'py>,
        old_password: &str,
        new_password: &str,
    ) -> PyResult<&'py PyAny> {
        // Clone the wallet to move it into the async closure
        let mut wallet = self.wallet.clone();

        // Convert passwords to owned String to move into the async closure
        let old_password: String = old_password.to_string();
        let new_password: String = new_password.to_string();

        // Convert the Rust Future into a Python Future
        pyo3_asyncio::tokio::future_into_py(py, async move {
            // Execute the change_password operation and handle the result
            match wallet.change_password(&old_password, &new_password) {
                Ok(_) => Ok(()),
                Err(e) => Err(wallet_error_to_pyerr(e)),
            }
        })
    }

    /// Retrieves the coldkey's SS58 address.
    fn get_coldkey_ss58(&self) -> PyResult<String> {
        self.wallet
            .get_coldkey_ss58()
            .map_err(wallet_error_to_pyerr)
    }

    /// Retrieves a hotkey's SS58 address.
    fn get_hotkey_ss58(&self, hotkey_name: &str) -> PyResult<String> {
        self.wallet
            .get_hotkey_ss58(hotkey_name)
            .map_err(wallet_error_to_pyerr)
    }

    /// Signs a message with the coldkey
    ///
    /// # Arguments
    ///
    /// * `py` - Python interpreter state
    /// * `message` - The message to sign as a byte slice
    /// * `password` - The password to decrypt the coldkey
    ///
    /// # Returns
    ///
    /// * `PyResult<&'py PyBytes>` - The signature as Python bytes if successful, or a Python error
    ///
    fn sign_with_coldkey<'py>(
        &self,
        py: Python<'py>,
        message: &[u8],
        password: &str,
    ) -> PyResult<&'py PyBytes> {
        match self.wallet.sign_with_coldkey(message, password) {
            Ok(signature) => Ok(PyBytes::new(py, &signature)),
            Err(error) => Err(PyValueError::new_err(error.to_string())),
        }
    }

    /// Signs a message with a hotkey
    ///
    /// # Arguments
    ///
    /// * `py` - Python interpreter state
    /// * `name` - The name of the hotkey to use for signing
    /// * `message` - The message to sign as a byte slice
    ///
    /// # Returns
    ///
    /// * `PyResult<&'py PyBytes>` - The signature as Python bytes if successful, or a Python error
    ///
    /// # Example
    ///
    /// ```python
    /// wallet = PyWallet("my_wallet", "/path/to/wallet")
    /// signature = wallet.sign_with_hotkey("my_hotkey", b"message to sign")
    /// ```
    fn sign_with_hotkey<'py>(
        &self,
        py: Python<'py>,
        name: &str,
        message: &[u8],
    ) -> PyResult<&'py PyBytes> {
        match self.wallet.sign_with_hotkey(name, message) {
            Ok(signature) => Ok(PyBytes::new(py, &signature)),
            Err(error) => Err(PyValueError::new_err(error.to_string())),
        }
    }
}

/// Python wrapper for the ColdKeyPair struct
#[pyclass]
struct PyColdKeyPair {
    coldkeypair: ColdKeyPair,
}

#[pymethods]
impl PyColdKeyPair {
    /// Creates a new PyColdKeyPair instance.
    ///
    /// # Arguments
    ///
    /// * `public` - A vector of bytes representing the public key.
    /// * `encrypted_private` - A vector of bytes representing the encrypted private key.
    ///
    /// # Returns
    ///
    /// * `PyResult<Self>` - A new PyColdKeyPair instance if successful, or a PyValueError if the public key is invalid.
    ///
    /// # Examples
    ///
    /// ```python
    /// public_key = b'\x12\x34\x56...'  # 32 bytes
    /// encrypted_private = b'\x78\x90\xAB...'  # Encrypted private key
    /// cold_key_pair = PyColdKeyPair(public_key, encrypted_private)
    /// ```
    /// Creates a new PyColdKeyPair instance.
    ///
    /// # Arguments
    ///
    /// * `public` - A vector of bytes representing the public key.
    /// * `encrypted_private` - A vector of bytes representing the encrypted private key.
    ///
    /// # Returns
    ///
    /// * `PyResult<Self>` - A new PyColdKeyPair instance if successful, or a PyValueError if the public key is invalid.
    ///
    /// # Examples
    ///
    /// ```python
    /// public_key = b'\x12\x34\x56...'  # 32 bytes
    /// encrypted_private = b'\x78\x90\xAB...'  # Encrypted private key
    /// cold_key_pair = PyColdKeyPair(public_key, encrypted_private)
    /// ```
    #[new]
    fn new(public: Vec<u8>, encrypted_private: Vec<u8>) -> PyResult<Self> {
        // Convert the public key bytes to a fixed-size array
        let public_key_array: [u8; 32] = public
            .try_into()
            .map_err(|_| PyValueError::new_err("Invalid public key length"))?;

        // Create the sr25519::Public key from the fixed-size array
        let public_key = sp_core::sr25519::Public::from_raw(public_key_array);

        // Create and return the PyColdKeyPair instance
        Ok(PyColdKeyPair {
            coldkeypair: ColdKeyPair::new(
                sr25519::Public::from_slice(&public_key)
                    .map_err(|_| PyValueError::new_err("Invalid public key"))?,
                encrypted_private
                    .try_into()
                    .map_err(|_| PyValueError::new_err("Private key should be 32 bytes"))?,
                true,
            ),
        })
    }

    #[staticmethod]
    fn generate() -> Self {
        PyColdKeyPair {
            coldkeypair: ColdKeyPair::generate(),
        }
    }

    #[staticmethod]
    fn from_mnemonic(mnemonic: &str, password: Option<&str>) -> PyResult<Self> {
        ColdKeyPair::from_mnemonic(mnemonic, password)
            .map(|coldkeypair| PyColdKeyPair { coldkeypair })
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }

    /// Encrypts the private key using the provided password.
    ///
    /// # Arguments
    ///
    /// * `password` - A string slice that holds the password for encryption.
    ///
    /// # Returns
    ///
    /// * `PyResult<Self>` - A Result containing a new PyColdKeyPair with the encrypted private key if successful,
    ///   or a PyValueError if encryption fails.
    ///
    /// # Examples
    ///
    /// ```python
    /// password = "my_secure_password"
    /// encrypted_cold_key_pair = cold_key_pair.encrypt(password)
    /// ```
    fn encrypt(&self, password: &str) -> PyResult<Self> {
        self.coldkeypair
            .encrypt(password)
            .map(|encrypted_keypair| PyColdKeyPair {
                coldkeypair: encrypted_keypair,
            })
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }

    /// Decrypts the private key using the provided password.
    ///
    /// # Arguments
    ///
    /// * `password` - A string slice that holds the password for decryption.
    ///
    /// # Returns
    ///
    /// * `PyResult<Vec<u8>>` - A Result containing the decrypted private key as a vector of bytes if successful,
    ///   or a PyValueError if decryption fails.
    ///
    /// # Examples
    ///
    /// ```python
    /// password = "my_secure_password"
    /// decrypted_private_key = cold_key_pair.decrypt(password)
    /// ```
    fn decrypt(&self, password: &str) -> PyResult<Vec<u8>> {
        self.coldkeypair
            .decrypt(password)
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }

    fn public_key(&self) -> Vec<u8> {
        self.coldkeypair.public.to_vec()
    }

    fn ss58_address(&self) -> String {
        sr25519::Public::from_slice(&self.coldkeypair.public)
            .expect("Invalid public key")
            .to_ss58check()
    }
}

/// Python wrapper for the HotKeyPair struct
#[pyclass]
struct PyHotKeyPair {
    hotkeypair: HotKeyPair,
}

#[pymethods]
impl PyHotKeyPair {
    #[new]
    fn new(public: Vec<u8>, private: Vec<u8>) -> PyResult<Self> {
        let public_key = sp_core::sr25519::Public::try_from(&public[..])
            .map_err(|_| PyValueError::new_err("Invalid public key"))?;
        Ok(PyHotKeyPair {
            hotkeypair: HotKeyPair::new(public_key, private),
        })
    }

    #[staticmethod]
    fn generate() -> Self {
        PyHotKeyPair {
            hotkeypair: HotKeyPair::generate(),
        }
    }

    fn public_key(&self) -> Vec<u8> {
        self.hotkeypair.public.to_vec()
    }

    fn ss58_address(&self) -> String {
        self.hotkeypair.public.to_ss58check()
    }

    fn sign<'py>(&self, py: Python<'py>, message: &[u8]) -> PyResult<&'py PyBytes> {
        let signature = self
            .hotkeypair
            .sign(message)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        Ok(PyBytes::new(py, &signature))
    }

    fn to_mnemonic(&self) -> String {
        self.hotkeypair.to_mnemonic()
    }

    fn to_seed(&self) -> Vec<u8> {
        self.hotkeypair.to_seed()
    }
}

fn wallet_error_to_pyerr(error: WalletError) -> PyErr {
    PyException::new_err(error.to_string())
}
