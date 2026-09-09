use chrono::{Local, Utc};
use std::time::Duration;

/// `strfutctime`: UTC timestamp, `%Y-%m-%d %H:%M:%S`.
pub fn strfutctime() -> String {
    Utc::now().format("%Y-%m-%d %H:%M:%S").to_string()
}

/// `strflocaltime`: local timestamp, `%Y-%m-%d %H:%M:%S %Z`.
pub fn strflocaltime() -> String {
    Local::now().format("%Y-%m-%d %H:%M:%S %Z").to_string()
}

/// `pprint_seconds`: upstream `fmt % (d,h,m,s)` with `'%dh %dm %ds'`.
pub fn pprint_seconds(seconds: Duration) -> String {
    let total = seconds.as_secs();
    format!("{}h {}m {}s", total / 3600, (total % 3600) / 60, total % 60,)
}

/// `Timing`: wall-clock stopwatch (upstream `Timing` context manager).
pub struct Timing {
    start: std::time::Instant,
    pub(crate) elapsed: Option<Duration>,
}

impl Timing {
    pub fn new() -> Self {
        Self {
            start: std::time::Instant::now(),
            elapsed: None,
        }
    }
    pub fn elapsed(&mut self) -> Duration {
        let e = self.start.elapsed();
        self.elapsed = Some(e);
        e
    }
}

impl Default for Timing {
    fn default() -> Self {
        Self::new()
    }
}
