mod cli;
mod engine;
mod module;
mod modules;
mod response;
mod tcp_cache;
mod utils;

use cli::getopts;
use engine::{FuzzConfig, FuzzEngine};
use module::Module;
use modules::{ftp::FtpModule, http::HttpModule, ssh::SshModule};
use std::boxed::Box;

fn main() {
    let matches = getopts();

    let module_name = matches.get_one::<String>("module").expect("required");
    let module_args: Vec<String> = matches
        .get_many("module_args")
        .unwrap_or_default()
        .cloned()
        .collect();
    let _actions: Vec<String> = matches
        .get_many("actions")
        .unwrap_or_default()
        .cloned()
        .collect();
    let _start = *matches.get_one::<usize>("start").unwrap();
    let _stop = matches.get_one::<usize>("stop").copied();
    let _resume = matches.get_one::<String>("resume").cloned();
    let _encodings: Vec<String> = matches
        .get_many("encodings")
        .unwrap_or_default()
        .cloned()
        .collect();
    let combo_delim = matches.get_one::<String>("combo_delim").unwrap().as_str();
    let condition_delim = matches
        .get_one::<String>("condition_delim")
        .unwrap()
        .as_str();
    let allow_ignore_failures = matches.get_flag("allow_ignore_failures");
    let assume_yes = matches.get_flag("assume_yes");
    let _rate_limit = *matches.get_one::<f64>("rate_limit").unwrap();
    let timeout = *matches.get_one::<u64>("timeout").unwrap();
    let _max_retries = *matches.get_one::<i64>("max_retries").unwrap();
    let num_threads = *matches.get_one::<usize>("num_threads").unwrap_or(&1);
    let rate_limit = *matches.get_one::<f64>("rate_limit").unwrap_or(&1.0);
    let max_retries = *matches.get_one::<i64>("max_retries").unwrap_or(&0);
    let _groups = matches.get_one::<String>("groups").cloned();

    // Create module based on name
    let mut boxed_module: Box<dyn Module + Send + Sync> = match module_name.as_str() {
        "http" => {
            let mut module = HttpModule::new();
            // Apply module arguments as settings
            for arg in module_args {
                if let Some((key, value)) = arg.split_once('=') {
                    match key {
                        "url" => module = module.url(value),
                        "method" => module = module.method(value),
                        "follow_redirects" => {
                            module = module.follow_redirects(value.parse().unwrap_or(true))
                        }
                        "timeout" => module = module.timeout(value.parse().unwrap_or(10)),
                        _ => {}
                    }
                }
            }
            Box::new(module)
        }
        "ftp" => {
            let mut module = FtpModule::new();
            // Apply module arguments as settings
            for arg in module_args {
                if let Some((key, value)) = arg.split_once('=') {
                    match key {
                        "host" => module = module.host(value),
                        "port" => module = module.port(value.parse().unwrap_or(21)),
                        "username" => module = module.username(value),
                        "password" => module = module.password_template(value),
                        "timeout" => module = module.timeout(value.parse().unwrap_or(10)),
                        _ => {}
                    }
                }
            }
            Box::new(module)
        }
        "ssh" => {
            let mut module = SshModule::new();
            // Apply module arguments as settings
            for arg in module_args {
                if let Some((key, value)) = arg.split_once('=') {
                    match key {
                        "host" => module = module.host(value),
                        "port" => module = module.port(value.parse().unwrap_or(22)),
                        "username" => module = module.username(value),
                        "password" => module = module.password_template(value),
                        "timeout" => module = module.timeout(value.parse().unwrap_or(10)),
                        _ => {}
                    }
                }
            }
            Box::new(module)
        }
        _ => {
            println!("Unknown module: {}", module_name);
            println!("Available modules: http, ftp, ssh");
            return;
        }
    };

    // Initialize the module
    boxed_module.initialize();

    // Create fuzzing engine configuration
    let config = FuzzConfig {
        num_threads: num_threads.try_into().unwrap_or(1),
        rate_limit: rate_limit as u64,
        timeout,
        max_retries: max_retries.try_into().unwrap_or(0),
        assume_yes,
        allow_ignore_failures,
        combo_delim: combo_delim.to_string(),
        condition_delim: condition_delim.to_string(),
    };

    // Create and run the fuzzing engine
    let mut engine = FuzzEngine::new(boxed_module, config);
    engine.run();
}
