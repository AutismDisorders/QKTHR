use md5::Digest;
use md5::Md5;
use sha1::Sha1;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// `md5hex`: MD-5 hex digest of raw bytes (upstream `md5hex`).
pub fn md5hex(data: &[u8]) -> String {
    let mut h = Md5::new();
    h.update(data);
    hex(&h.finalize())
}

/// `sha1hex`: SHA-1 hex digest (upstream `sha1hex`).
pub fn sha1hex(data: &[u8]) -> String {
    let mut h = Sha1::new();
    h.update(data);
    hex(&h.finalize())
}

/// `padhex`: even-length lowercase hex padding (upstream `padhex`).
pub fn padhex(d: u64) -> String {
    let x = format!("{:x}", d);
    if x.len() % 2 == 1 {
        format!("0{}", x)
    } else {
        x
    }
}
