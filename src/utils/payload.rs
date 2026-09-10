use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::Path;

/// File payload iterator - reads lines from a file
pub struct FilePayload {
    reader: Option<BufReader<File>>,
    done: bool,
}

impl FilePayload {
    /// Create a new FilePayload iterator from a file path
    pub fn new<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        Ok(Self {
            reader: Some(reader),
            done: false,
        })
    }
}

impl Iterator for FilePayload {
    type Item = io::Result<String>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }

        let reader = match &mut self.reader {
            Some(r) => r,
            None => return None,
        };

        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => {
                self.done = true;
                None
            }
            Ok(_) => {
                // Remove trailing newline and carriage return if they exist
                if line.ends_with("\r\n") {
                    line.truncate(line.len() - 2);
                } else if line.ends_with('\n') {
                    line.pop();
                }
                Some(Ok(line))
            }
            Err(e) => Some(Err(e)),
        }
    }
}

/// Combo payload iterator - combines multiple iterators
pub struct ComboPayload<I> {
    iterators: Vec<I>,
    current: usize,
}

impl<I: Iterator> ComboPayload<I> {
    /// Create a new ComboPayload from a vector of iterators
    pub fn new(iterators: Vec<I>) -> Self {
        Self {
            iterators,
            current: 0,
        }
    }
}

impl<I: Iterator> Iterator for ComboPayload<I> {
    type Item = I::Item;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current >= self.iterators.len() {
            return None;
        }

        let result = self.iterators[self.current].next();
        if result.is_none() {
            self.current += 1;
            if self.current >= self.iterators.len() {
                return None;
            }
            self.iterators[self.current].next()
        } else {
            result
        }
    }
}

/// Glob payload iterator - supports glob patterns over ranges
pub struct GlobPayload {
    base: String,
    pattern: String,
    current: usize,
    done: bool,
}

impl GlobPayload {
    /// Create a new GlobPayload iterator
    pub fn new<S: Into<String>>(base: S, pattern: S) -> Self {
        Self {
            base: base.into(),
            pattern: pattern.into(),
            current: 0,
            done: false,
        }
    }
}

impl Iterator for GlobPayload {
    type Item = String;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }

        // Simple glob implementation - in practice this would use a glob crate
        // For now, we'll generate strings as base + pattern + counter
        let result = format!("{}{}{}", self.base, self.pattern, self.current);
        self.current += 1;

        // For demonstration, we'll stop after 1000 iterations
        if self.current > 1000 {
            self.done = true;
        }

        Some(result)
    }
}

/// Net (CIDR) payload iterator - iterates over IP addresses in CIDR notation
pub struct NetPayload {
    current: u32,
    end: u32,
    done: bool,
}

impl NetPayload {
    /// Create a new NetPayload iterator from a CIDR string
    pub fn new(cidr: &str) -> Result<Self, String> {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return Err("Invalid CIDR format".to_string());
        }

        let ip_str = parts[0];
        let prefix: u32 = parts[1].parse().map_err(|_| "Invalid prefix")?;

        if prefix > 32 {
            return Err("Prefix must be between 0 and 32".to_string());
        }

        let ip_parts: Vec<&str> = ip_str.split('.').collect();
        if ip_parts.len() != 4 {
            return Err("Invalid IP address".to_string());
        }

        let mut ip: u32 = 0;
        for (i, part) in ip_parts.iter().enumerate() {
            let octet: u8 = part.parse().map_err(|_| "Invalid octet")?;
            ip |= (octet as u32) << (24 - i * 8);
        }

        let network_mask = if prefix == 0 {
            0
        } else {
            !0u32.checked_shl(32 - prefix).unwrap_or(0)
        };
        let network = ip & network_mask;
        let host_bits = 32 - prefix;
        let broadcast = if host_bits == 0 {
            network
        } else {
            network | ((1u32 << host_bits) - 1)
        };

        Ok(Self {
            current: network,
            end: broadcast,
            done: false,
        })
    }
}

impl Iterator for NetPayload {
    type Item = String;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done || self.current > self.end {
            self.done = true;
            return None;
        }

        let ip = self.current;
        self.current += 1;

        let octet4 = (ip & 0xFF) as u8;
        let octet3 = ((ip >> 8) & 0xFF) as u8;
        let octet2 = ((ip >> 16) & 0xFF) as u8;
        let octet1 = ((ip >> 24) & 0xFF) as u8;

        Some(format!("{}.{}.{}.{}", octet1, octet2, octet3, octet4))
    }
}

/// Prog payload iterator - yields output from external programs
pub struct ProgPayload {
    reader: Option<BufReader<std::process::ChildStdout>>,
    _child: Option<std::process::Child>,
    done: bool,
}

impl ProgPayload {
    /// Create a new ProgPayload iterator from a program command
    pub fn new<P: AsRef<str>>(program: P) -> io::Result<Self> {
        use std::process::{Command, Stdio};

        let mut child = Command::new("sh")
            .arg("-c")
            .arg(program.as_ref())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .stdin(Stdio::null())
            .spawn()?;

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Failed to capture stdout"))?;
        let reader = BufReader::new(stdout);

        Ok(Self {
            reader: Some(reader),
            _child: Some(child),
            done: false,
        })
    }
}

impl Iterator for ProgPayload {
    type Item = io::Result<String>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }

        let reader = match &mut self.reader {
            Some(r) => r,
            None => return None,
        };

        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => {
                self.done = true;
                None
            }
            Ok(_) => {
                // Remove trailing newline and carriage return
                if line.ends_with('\n') {
                    line.pop();
                }
                if line.ends_with('\r') {
                    line.pop();
                }
                Some(Ok(line))
            }
            Err(e) => Some(Err(e)),
        }
    }
}

/// Mod payload iterator - applies modulus operation to a base iterator
pub struct ModPayload<I> {
    base: I,
    divisor: usize,
    remainder: usize,
}

impl<I: Iterator<Item = String>> ModPayload<I> {
    /// Create a new ModPayload iterator
    pub fn new(base: I, divisor: usize, remainder: usize) -> Self {
        Self {
            base,
            divisor,
            remainder,
        }
    }
}

impl<I: Iterator<Item = String>> Iterator for ModPayload<I> {
    type Item = String;

    fn next(&mut self) -> Option<Self::Item> {
        let mut index = 0;
        while let Some(item) = self.base.next() {
            if index % self.divisor == self.remainder {
                return Some(item);
            }
            index += 1;
        }
        None
    }
}
