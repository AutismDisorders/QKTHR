mod cli;
mod utils;

use cli::getopts;

fn main() {
    let matches = getopts();

    let module = matches.get_one::<String>("module").expect("required");
    let module_args: Vec<String> = matches
        .get_many("module_args")
        .unwrap_or_default()
        .cloned()
        .collect();
    let actions: Vec<String> = matches
        .get_many("actions")
        .unwrap_or_default()
        .cloned()
        .collect();
    let start = *matches.get_one::<usize>("start").unwrap();
    let stop = matches.get_one::<usize>("stop").copied();
    let resume = matches.get_one::<String>("resume").cloned();
    let encodings: Vec<String> = matches
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
    let rate_limit = *matches.get_one::<f64>("rate_limit").unwrap();
    let timeout = *matches.get_one::<u64>("timeout").unwrap();
    let max_retries = *matches.get_one::<i64>("max_retries").unwrap();
    let num_threads = *matches.get_one::<usize>("num_threads").unwrap();
    let groups = matches.get_one::<String>("groups").cloned();

    println!("Module: {}", module);
    println!("Module args: {:?}", module_args);
    println!("Actions: {:?}", actions);
    println!("Start: {}", start);
    println!("Stop: {:?}", stop);
    println!("Resume: {:?}", resume);
    println!("Encodings: {:?}", encodings);
    println!("Combo delim: '{}'", combo_delim);
    println!("Condition delim: '{}'", condition_delim);
    println!("Allow ignore failures: {}", allow_ignore_failures);
    println!("Assume yes: {}", assume_yes);
    println!("Rate limit: {}", rate_limit);
    println!("Timeout: {}", timeout);
    println!("Max retries: {}", max_retries);
    println!("Num threads: {}", num_threads);
    println!("Groups: {:?}", groups);
}
