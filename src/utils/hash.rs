#![allow(dead_code)]
use md5;

/// `md5hex`: MD-5 hex digest of raw bytes.
pub fn md5hex(data: &[u8]) -> String {
    let digest = md5::compute(data);
    format!("{:x}", digest)
}
