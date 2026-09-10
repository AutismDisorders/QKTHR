use clap::{value_parser, Arg, ArgAction, Command};

pub fn getopts() -> clap::ArgMatches {
    Command::new("qkthr")
        .version("0.1.0")
        .about("A multi-protocol brute-forcer")
        .arg(
            Arg::new("module")
                .help("Module to run")
                .required(true),
        )
        .arg(
            Arg::new("module_args")
                .help("Arguments for the module")
                .last(true)
                .num_args(0..),
        )
        .arg(
            Arg::new("actions")
                .short('x')
                .long("actions")
                .help("actions and conditions, see Syntax below")
                .action(ArgAction::Append),
        )
        .arg(
            Arg::new("start")
                .long("start")
                .help("start from offset N in the product of all payload sets")
                .value_parser(value_parser!(usize))
                .default_value("0"),
        )
        .arg(
            Arg::new("stop")
                .long("stop")
                .help("stop at offset N")
                .value_parser(value_parser!(usize)),
        )
        .arg(
            Arg::new("resume")
                .long("resume")
                .help("resume previous run"),
        )
        .arg(
            Arg::new("encodings")
                .short('e')
                .long("encodings")
                .help("encode everything between two tags, see Syntax below")
                .action(ArgAction::Append),
        )
        .arg(
            Arg::new("combo_delim")
                .short('C')
                .long("combo-delim")
                .help("delimiter string in combo files (default is ':')")
                .default_value(":"),
        )
        .arg(
            Arg::new("condition_delim")
                .short('X')
                .long("condition-delim")
                .help("delimiter string in conditions (default is ',')")
                .default_value(","),
        )
        .arg(
            Arg::new("allow_ignore_failures")
                .long("allow-ignore-failures")
                .help("failures cannot be ignored with -x (this is by design to avoid false negatives) this option overrides this safeguard")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("assume_yes")
                .short('y')
                .long("assume-yes")
                .help("automatically answer yes for all questions")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("rate_limit")
                .long("rate-limit")
                .help("wait N seconds between each attempt (default is 0)")
                .value_parser(value_parser!(f64))
                .default_value("0"),
        )
        .arg(
            Arg::new("timeout")
                .long("timeout")
                .help("wait N seconds for a response before retrying payload (default is 0)")
                .value_parser(value_parser!(u64))
                .default_value("0"),
        )
        .arg(
            Arg::new("max_retries")
                .long("max-retries")
                .help("skip payload after N retries (default is 4) (-1 for unlimited)")
                .value_parser(value_parser!(i64))
                .default_value("4"),
        )
        .arg(
            Arg::new("num_threads")
                .short('t')
                .long("threads")
                .help("number of threads (default is 10)")
                .value_parser(value_parser!(usize))
                .default_value("10"),
        )
        .arg(
            Arg::new("groups")
                .long("groups")
                .help("default is to iterate over the cartesian product of all payload sets, use this option to iterate over sets simultaneously instead (aka pitchfork), see syntax inside (default is '0,1..n')"),
        )
        .get_matches()
}
