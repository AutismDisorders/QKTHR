use crate::module::Module;
use crate::response::Response;
use p12_keystore::KeyStore;
use std::fs;
use std::path::Path;

/// Keystore password cracking module for testing password-protected keystores (e.g., PKCS#12)
pub struct KeystoreModule {
    /// Path to the keystore file
    keystore_path: String,
    /// Timeout in seconds
    timeout: u64,
}

impl KeystoreModule {
    /// Create a new Keystore module with default settings
    pub fn new() -> Self {
        Self {
            keystore_path: String::new(),
            timeout: 10,
        }
    }

    /// Set the keystore file path
    pub fn keystore_path(mut self, path: &str) -> Self {
        self.keystore_path = path.to_string();
        self
    }

    /// Set the timeout in seconds
    pub fn timeout(mut self, timeout: u64) -> Self {
        self.timeout = timeout;
        self
    }
}

impl Module for KeystoreModule {
    /// Create a new instance of the module
    fn new() -> Self
    where
        Self: Sized,
    {
        Self::new()
    }

    /// Initialize the module before starting the fuzzing process
    fn initialize(&mut self) {
        if self.keystore_path.is_empty() {
            panic!("Keystore file path must be set for Keystore module");
        }
        if !Path::new(&self.keystore_path).exists() {
            panic!("Keystore file does not exist: {}", self.keystore_path);
        }
    }

    /// Perform an attack with the given payload
    ///
    /// Returns a Response containing the result of the attack, or an error message.
    fn attack(&self, payload: String) -> Result<Response, String> {
        // Format payload as password
        let password = payload.trim();
        if password.is_empty() {
            return Err("Empty payload".to_string());
        }

        // Read the keystore file
        let data = fs::read(&self.keystore_path)
            .map_err(|e| format!("Failed to read keystore file: {}", e))?;

        // Try to parse the PKCS#12 keystore with the provided password
        // KeyStore::from_pkcs12 takes (data, password, policy) and returns Result<KeyStore, Error>
        let _keystore =
            KeyStore::from_pkcs12(&data, password, p12_keystore::Pkcs12ImportPolicy::default())
                .map_err(|e| format!("Failed to parse keystore: {}", e))?;

        // If parsing succeeds, the password is correct
        let body = format!("Keystore opened successfully with password: {}", password);
        Ok(Response::new(Some(200), body.as_bytes().to_vec()))
    }

    /// Finalize the module after the fuzzing process is complete
    fn finalize(&self) {
        // Clean up resources if needed
    }
}
