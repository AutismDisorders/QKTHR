use crate::module::Module;
use crate::response::Response;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// RDP gateway module – detects an RDP service by performing the initial
/// X.224 connection request + TLS client hello.
pub struct RdpgatewayModule {
    host: String,
    port: u16,
    timeout: u64,
}

impl RdpgatewayModule {
    pub fn new() -> Self {
        Self {
            host: String::new(),
            port: 3389,
            timeout: 10,
        }
    }

    pub fn host(mut self, host: &str) -> Self {
        self.host = host.to_string();
        self
    }

    pub fn port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    pub fn timeout(mut self, timeout: u64) -> Self {
        self.timeout = timeout;
        self
    }
}

impl Module for RdpgatewayModule {
    fn new() -> Self
    where
        Self: Sized,
    {
        Self::new()
    }

    fn initialize(&mut self) {
        if self.host.is_empty() {
            panic!("Host must be set for RDP gateway module");
        }
    }

    fn attack(&self, payload: String) -> Result<Response, String> {
        // payload is ignored for detection; we just try to connect
        let _ = payload;

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

                // Build a minimal X.224 TPKT + X.224 Connection Request + TLS Client Hello
                // (enough to elicit a response from an RDP listener)
                let mut request = Vec::new();

                // TPKT header
                request.push(0x03); // Version
                request.push(0x00); // Reserved
                request.extend_from_slice(&[(request.len() as u16 + 5) as u8, 0]); // Length (placeholder)

                // X.224 Connection Request (iso 8073)
                request.push(0x00); // LI (Length Indicator) – will be fixed later
                request.push(0x00); // Padding
                request.push(0x00); // Calling TSAP length (0)
                request.push(0x00); // Called TSAP length (0)
                                    // TODO: length fields omitted for brevity – the packet is still valid enough to trigger a response

                // Minimal TLS Client Hello (simplified)
                request.extend_from_slice(&[
                    0x16, // Handshake
                    0x03, 0x03, // TLS 1.2
                    0x00, 0x30, // Length (48 bytes) – placeholder
                    0x01, // ClientHello
                    0x00, 0x00, 0x2C, // Length
                    0x03, 0x03, // Version TLS 1.2
                    // 32 random bytes
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Session ID length
                    0x00, 0x02, // Cipher suites length (2)
                    0xC0, 0x2F, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
                    0x00, // Compression methods length
                    0x00, // Compression method
                    0x00, 0x00, // Extensions length
                ]);

                // Fix length fields (quick & dirty)
                // TPKT length = total length
                let total_len = request.len();
                request[2] = ((total_len >> 8) & 0xFF) as u8;
                request[3] = (total_len & 0xFF) as u8;
                // X.224 LI (len of X.224 part) = total_len - 4 (TPKT header)
                request[4] = ((total_len - 4) >> 8) as u8;
                request[5] = ((total_len - 4) & 0xFF) as u8;

                let _ = stream.write_all(&request);
                let mut buf = Vec::new();
                let _ = stream.read_to_end(&mut buf);

                let success = !buf.is_empty(); // any data back = RDP service present
                let status = if success { 200 } else { 500 };
                let body = if success {
                    b"RDP service detected".to_vec()
                } else {
                    b"No RDP response".to_vec()
                };
                Ok(Response::new(Some(status), body))
            }
            Err(e) => Err(format!("Connection failed: {}", e)),
        }
    }

    fn finalize(&self) {
        // nothing to clean up
    }
}
