use crate::module::Module;
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

    fn initialize(&mut self) {
        if self.keystore_path.is_empty() {
            panic!("Keystore file path must be set for Keystore module");
        }
        if !Path::new(&self.keystore_path).exists() {
            panic!("Keystore file does not exist: {}", self.keystore_path);
        }
    }
}
