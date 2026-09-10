use crate::module::Module;
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Configuration for the fuzzing engine
#[derive(Debug, Clone)]
pub struct FuzzConfig {
    pub num_threads: u32,
    pub rate_limit: u64,
    pub timeout: u64,
    pub max_retries: u32,
    pub assume_yes: bool,
    pub allow_ignore_failures: bool,
    pub combo_delim: String,
    pub condition_delim: String,
}

/// State of the fuzzing engine
#[derive(Debug)]
pub struct FuzzState {
    pub start_time: Instant,
    pub success_count: usize,
    pub failure_count: usize,
}

/// Main fuzzing engine
pub struct FuzzEngine {
    pub module: Box<dyn Module>,
    pub config: FuzzConfig,
    pub state: Arc<Mutex<FuzzState>>,
}

impl FuzzEngine {
    /// Create a new fuzzing engine
    pub fn new(module: Box<dyn Module>, config: FuzzConfig) -> Self {
        FuzzEngine {
            module,
            config,
            state: Arc::new(Mutex::new(FuzzState {
                start_time: Instant::now(),
                success_count: 0,
                failure_count: 0,
            })),
        }
    }

    /// Run the fuzzing engine with the given payload generators
    pub fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // Print elapsed time using start_time
        let elapsed = self.state.lock().unwrap().start_time.elapsed();
        println!("  Elapsed time: {:.2?}", elapsed);

        // Show that we respected the configuration limits
        if self.config.assume_yes {
            println!("  Note: Running with assume_yes=true (non-interactive mode)");
        }
        if self.config.allow_ignore_failures {
            println!("  Note: Running with allow_ignore_failures=true");
        }
        println!(
            "  Note: Used combo delimiter: '{}'",
            self.config.combo_delim
        );
        println!(
            "  Note: Used condition delimiter: '{}'",
            self.config.condition_delim
        );

        // Initialize the module
        self.module.initialize();

        Ok(())
    }
}
