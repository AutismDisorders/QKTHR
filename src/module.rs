use crate::response::Response;

/// Trait defining the interface for attack modules.
#[allow(dead_code)]
pub trait Module {
    /// Create a new instance of the module.
    fn new() -> Self
    where
        Self: Sized;

    /// Initialize the module before starting the fuzzing process.
    fn initialize(&mut self) {}

    /// Perform an attack with the given payload.
    ///
    /// Returns a Response containing the result of the attack, or an error message.
    fn attack(&self, payload: String) -> Result<Response, String>;

    /// Finalize the module after the fuzzing process is complete.
    fn finalize(&self) {}
}
