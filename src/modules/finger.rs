use crate::module::Module;
use crate::response::Response;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// Finger lookup module for performing Finger protocol queries
pub struct FingerModule {
    /// Target host
    host: String,
    /// Target port
    port: u16,
    /// Timeout in seconds
    timeout: u64,
}

impl FingerModule {
    /// Create a new Finger module with default settings
    pub fn new() -> Self {
        Self {
            host: String::new(),
            port: 79,
            timeout: 10,
        }
    }

    /// Set the target host
    pub fn host(mut self, host: &str) -> Self {
        self.host = host.to_string();
        self
    }

    /// Set the target port
    pub fn port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Set the timeout in seconds
    pub fn timeout(mut self, timeout: u64) -> Self {
        self.timeout = timeout;
        self
    }
}

impl Module for FingerModule {
    /// Create a new instance of the module
    fn new() -> Self
    where
        Self: Sized,
    {
        Self::new()
    }

    /// Initialize the module before starting the fuzzing process
    fn initialize(&mut self) {
        // In a real implementation, we might set up connection pools, etc.
        // For now, we'll just ensure the host is set
        if self.host.is_empty() {
            panic!("Host must be set for Finger module");
        }
    }

    /// Perform an attack with the given payload
    ///
    /// Returns a Response containing the result of the attack, or an error message.
    fn attack(&self, payload: String) -> Result<Response, String> {
        // Format payload as username for Finger query
        let username = payload.trim();
        if username.is_empty() {
            return Err("Empty payload".to_string());
        }

        // Simulate Finger connection attempt
        let addr = format!("{}:{}", self.host, self.port);
        match TcpStream::connect_timeout(&addr.parse().unwrap(), Duration::from_secs(self.timeout))
        {
            Ok(mut stream) => {
                // Set stream timeout
                stream
                    .set_read_timeout(Some(Duration::from_secs(self.timeout)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(self.timeout)))
                    .unwrap();

                // Send the username query (Finger protocol expects username followed by CRLF)
                let query = format!("{}\r\n", username);
                let _ = stream.write_all(query.as_bytes());

                // Read response
                let mut buffer = Vec::new();
                let _ = stream.read_to_end(&mut buffer);

                // Finger typically returns user information or error
                let status_code = if !buffer.is_empty() { 200 } else { 404 };
                let body = String::from_utf8_lossy(&buffer).to_string();

                Ok(Response::new(Some(status_code), body.as_bytes().to_vec()))
            }
            Err(e) => Err(format!("Connection failed: {}", e)),
        }
    }

    /// Finalize the module after the fuzzing process is complete
    fn finalize(&self) {
        // Clean up resources if needed
    }
}
