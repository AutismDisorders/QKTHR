mod cli;
mod utils;

use cli::getopts;
use utils::{expand_path, strflocaltime, strfutctime, which};

fn main() {
    let _matches = getopts();
    let path = expand_path("~/Projects/qkthr");
    println!("{path}");
    let utc = strfutctime();
    println!("{}", utc);
    let lt = strflocaltime();
    println!("{}", lt);
    if which("python").is_some() {
        println!("true");
    } else {
        println!("false");
    }
}
