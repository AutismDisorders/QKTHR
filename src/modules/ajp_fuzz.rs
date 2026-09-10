use crate::module::Module;
use crate::response::Response;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// AJP fuzz module – sends an AJP CPING request and expects a CPONG.
pub struct AjpFuzzModule {
    host: String,
    port: u16,
    timeout: u64,
}

impl AjpFuzzModule {
    pub fn new() -> Self {
        Self {
            host: String::new(),
            port: 8009, // default AJP port
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

impl Module for AjpFuzzModule {
    fn new() -> Self
    where
        Self: Sized,
    {
        Self::new()
    }

    fn initialize(&mut self) {
        if self.host.is_empty() {
            panic!("Host must be set for AJP fuzz module");
        }
    }

    fn attack(&self, payload: String) -> Result<Response, String> {
        let data = payload.as_bytes();
        if data.is_empty() {
            return Err("Empty payload".to_string());
        }

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

                // Build AJP packet: 0x413A (magic 'A''J') + 2-byte length + request data
                let mut packet = Vec::new();
                packet.push(b'A');
                packet.push(b'J');
                // length placeholder (2 bytes)
                packet.push(0);
                packet.push(0);
                // Request type: CPING = 0x06
                packet.push(0x00);
                packet.push(0x06);
                // request data length (2 bytes)
                packet.push(((data.len() >> 8) & 0xFF) as u8);
                packet.push((data.len() & 0xFF) as u8);
                // request data
                packet.extend_from_slice(data);
                // padding to make length even (AJP requires even length)
                if packet.len() % 2 == 1 {
                    packet.push(0);
                }
                // Now fix the length field (excluding the first 4 bytes)
                let body_len = packet.len() - 4;
                packet[2] = ((body_len >> 8) & 0xFF) as u8;
                packet[3] = (body_len & 0xFF) as u8;

                let _ = stream.write_all(&packet);
                let mut resp = Vec::new();
                let _ = stream.read_to_end(&mut resp);

                // Expect CPONG: magic 'A''J', length, 0x00 0x07 (CPONG), echoed data
                let success = resp.len() >= 6
                    && resp[0] == b'A'
                    && resp[1] == b'J'
                    && ((resp[2] as u16) << 8 | resp[3] as u16) as usize == resp.len() - 4
                    && resp[4] == 0x00
                    && resp[5] == 0x07; // CPONG

                let status = if success { 200 } else { 500 };
                let body = if success {
                    b"AJP CPONG received".to_vec()
                } else {
                    b"No valid AJP response".to_vec()
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
