#![allow(dead_code)]
use regex::Regex;
use std::time::Duration;

/// Response represents an HTTP-like response from a service.
#[derive(Debug, Clone)]
pub struct Response {
    pub code: Option<u16>, // Status code (e.g., 200, 404)
    pub size: usize,       // Response body size in bytes
    pub time: Duration,    // Response time
    pub mesg: Vec<u8>,     // Response body (raw bytes)
}

impl Response {
    /// Create a new Response with the given values.
    pub fn new(code: Option<u16>, mesg: Vec<u8>) -> Self {
        Response {
            code,
            size: mesg.len(),
            time: std::time::Duration::new(0, 0),
            mesg,
        }
    }

    /// Check if the response matches a given byte slice (exact match).
    pub fn exact_match(&self, pattern: &[u8]) -> bool {
        self.mesg == pattern
    }

    /// Check if the response contains a given byte slice.
    pub fn contains(&self, pattern: &[u8]) -> bool {
        self.mesg
            .windows(pattern.len())
            .any(|window| window == pattern)
    }

    /// Check if the response mesg contains the given fixed string (as UTF-8 lossy).
    pub fn fgrep_match(&self, pattern: &str) -> bool {
        let mesg_str = String::from_utf8_lossy(&self.mesg);
        mesg_str.contains(pattern)
    }

    /// Check if the response mesg matches the given regular expression (as UTF-8 lossy).
    pub fn egrep_match(&self, pattern: &str) -> bool {
        let mesg_str = String::from_utf8_lossy(&self.mesg);
        if let Ok(regex) = Regex::new(pattern) {
            regex.is_match(&mesg_str)
        } else {
            false
        }
    }
}
