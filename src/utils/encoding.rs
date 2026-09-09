use base64::{Engine as _, engine::general_purpose};
use md5::{Digest, Md5};
use sha1::{Digest as Sha1Digest, Sha1};
use std::string::FromUtf8Error;
use urlencoding::{decode, encode};

/// Hex encoding - convert bytes to hexadecimal string
pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Hex decoding - convert hexadecimal string to bytes
pub fn hex_decode(hex: &str) -> Result<Vec<u8>, String> {
    if hex.len() % 2 != 0 {
        return Err("Hex string must have even length".to_string());
    }

    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|_| format!("Invalid hex byte at position {}", i))
        })
        .collect()
}

/// Unhex encoding - alias for hex_encode for compatibility
pub fn unhex_encode(bytes: &[u8]) -> String {
    hex_encode(bytes)
}

/// Unhex decoding - alias for hex_decode for compatibility
pub fn unhex_decode(hex: &str) -> Result<Vec<u8>, String> {
    hex_decode(hex)
}

/// Base64 encoding
pub fn base64_encode(bytes: &[u8]) -> String {
    general_purpose::STANDARD.encode(bytes)
}

/// Base64 decoding
pub fn base64_decode(base64: &str) -> Result<Vec<u8>, base64::DecodeError> {
    general_purpose::STANDARD.decode(base64)
}

/// MD5 hashing
pub fn md5_hash(data: &[u8]) -> String {
    let mut hasher = Md5::new();
    hasher.update(data);
    let result = hasher.finalize();
    hex_encode(&result)
}

/// SHA1 hashing
pub fn sha1_hash(data: &[u8]) -> String {
    let mut hasher = Sha1::new();
    hasher.update(data);
    let result = hasher.finalize();
    hex_encode(&result)
}

/// URL encoding
pub fn url_encode(data: &str) -> String {
    encode(data).into_owned()
}

/// URL decoding
pub fn url_decode(data: &str) -> Result<String, FromUtf8Error> {
    decode(data).map(|s| s.into_owned())
}
