#![allow(dead_code)]
use base64::{engine::general_purpose, Engine as _};
use sha1::Sha1;
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

    let mut result = Vec::new();
    for i in (0..hex.len()).step_by(2) {
        let byte = u8::from_str_radix(&hex[i..i + 2], 16).map_err(|_| "Invalid hex string")?;
        result.push(byte);
    }
    Ok(result)
}
