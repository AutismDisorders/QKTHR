use crate::module::Module;
use crate::response::Response;
use std::time::Duration;

/// Dummy test module for testing the fuzzing framework itself
pub struct DummyTestModule {
    /// Mode of operation: "success", "failure", "timeout", "error"
    mode: String,
    /// Timeout in seconds
    timeout: u64,
}

impl DummyTestModule {
    /// Create a new Dummy test module with default settings
    pub fn new() -> Self {
        Self {
            mode: "success".to_string(),
            timeout: 1,
        }
    }

    /// Set the mode of operation
    pub fn mode(mut self, mode: &str) -> Self {
        self.mode = mode.to_string();
        self
    }

    /// Set the timeout in seconds
    pub fn timeout(mut self, timeout: u64) -> Self {
        self.timeout = timeout;
        self
    }
}

impl Module for DummyTestModule {
    /// Create a new instance of the module
    fn new() -> Self
    where
        Self: Sized,
    {
        Self::new()
    }

    /// Initialize the module before starting the fuzzing process
    fn initialize(&mut self) {
        // Validate mode
        let valid_modes = vec!["success", "failure", "timeout", "error"];
        if !valid_modes.contains(&self.mode.as_str()) {
            panic!(
                "Invalid mode for dummy test module: {}. Valid modes are: {:?}",
                self.mode, valid_modes
            );
        }
    }

    /// Perform an attack with the given payload
    ///
    /// Returns a Response containing the result of the attack, or an error message.
    fn attack(&self, payload: String) -> Result<Response, String> {
        // For dummy test, we ignore the payload and behave according to mode
        match self.mode.as_str() {
            "success" => {
                // Simulate successful authentication
                let status_code = 200;
                let body = format!("Dummy test SUCCESS for payload: {}", payload);
                Ok(Response::new(Some(status_code), body.as_bytes().to_vec()))
            }
            "failure" => {
                // Simulate failed authentication
                let status_code = 401;
                let body = format!("Dummy test FAILURE for payload: {}", payload);
                Ok(Response::new(Some(status_code), body.as_bytes().to_vec()))
            }
            "timeout" => {
                // Simulate timeout by sleeping longer than timeout
                std::thread::sleep(Duration::from_secs(self.timeout + 2));
                // This would normally cause a timeout, but since we're simulating,
                // we'll return a timeout error
                let status_code = 504;
                let body = format!("Dummy test TIMEOUT for payload: {}", payload);
                Ok(Response::new(Some(status_code), body.as_bytes().to_vec()))
            }
            "error" => {
                // Simulate an error condition
                let status_code = 500;
                let body = format!("Dummy test ERROR for payload: {}", payload);
                Ok(Response::new(Some(status_code), body.as_bytes().to_vec()))
            }
            _ => {
                // This shouldn't happen due to initialization check, but just in case
                Err(format!("Unknown mode: {}", self.mode))
            }
        }
    }

    /// Finalize the module after the fuzzing process is complete
    fn finalize(&self) {
        // Clean up resources if needed
    }
}
