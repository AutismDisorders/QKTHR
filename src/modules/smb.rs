use crate::module::Module;
use crate::response::Response;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// SMB module – performs a real SMB Negotiate Protocol Exchange.
/// If the server returns a valid SMB Negotiate Response, we treat it as success.
pub struct SmbModule {
    /// Target host
    host: String,
    /// Target port (default 445)
    port: u16,
    /// Timeout in seconds
    timeout: u64,
}

impl SmbModule {
    /// Create a new SMB module with default settings
    pub fn new() -> Self {
        Self {
            host: String::new(),
            port: 445,
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

impl Module for SmbModule {
    fn new() -> Self
    where
        Self: Sized,
    {
        Self::new()
    }

    fn initialize(&mut self) {
        // In a real implementation, we might set up connection pools, etc.
        // For now, we just ensure the host is set
        if self.host.is_empty() {
            panic!("Host must be set for SMB module");
        }
    }

    /// Perform an attack with the given payload
    ///
    /// Returns a Response containing the result of the attack, or an error message.
    fn attack(&self, payload: String) -> Result<Response, String> {
        // payload is expected as "username:password" – for a pure SMB Negotiate we ignore it
        let _ = payload; // silence unused warning

        let addr = format!("{}:{}", self.host, self.port);
        match TcpStream::connect_timeout(&addr.parse().unwrap(), Duration::from_secs(self.timeout))
        {
            Ok(mut stream) => {
                stream
                    .set_read_timeout(Some(Duration::from_secs(self.timeout)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(self.timeout)))
                    .unwrap();

                // Build a minimal SMB Negotiate Protocol Request (NetBIOS session service + SMB)
                // This is the same request used in smb_lookup, which is known to elicit a response.
                let negotiate_request = vec![
                    0x00, 0x00, 0x00, 0x52, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x53, 0x4d, 0x42,
                    0x72, 0x00, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x02, 0x00, 0x02, 0x4c, 0x41, 0x4e,
                    0x4d, 0x41, 0x4e, 0x2e, 0x31, 0x2e, 0x30, 0x02, 0x4c, 0x41, 0x4e, 0x4d, 0x41,
                    0x4e, 0x2e, 0x32, 0x2e, 0x30, 0x02, 0x57, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73,
                    0x20, 0x66, 0x6f, 0x72, 0x20, 0x77, 0x6f, 0x72, 0x6b, 0x67, 0x72, 0x6f, 0x70,
                    0x20, 0x33, 0x2e, 0x30, 0x02, 0x53, 0x6d, 0x62, 0x20, 0x32, 0x2e, 0x30, 0x20,
                    0x20, 0x00,
                ];

                let _ = stream.write_all(&negotiate_request);
                let mut buf = Vec::new();
                let _ = stream.read_to_end(&mut buf);

                // Validate that we got at least an SMB header back
                let success = buf.len() >= 4
                    && buf[0] == 0xFF
                    && buf[1] == b'S'
                    && buf[2] == b'M'
                    && buf[3] == b'B';

                let status = if success { 200 } else { 401 };
                let body = if success {
                    b"SMB Negotiate successful".to_vec()
                } else {
                    b"SMB Negotiate failed or no valid SMB response".to_vec()
                };
                Ok(Response::new(Some(status), body))
            }
            Err(e) => Err(format!("Connection failed: {}", e)),
        }
    }

    /// Finalize the module after the fuzzing process is complete
    fn finalize(&self) {
        // Clean up resources if needed
    }
}
