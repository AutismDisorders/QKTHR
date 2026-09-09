use clap::{Arg, ArgAction, ArgMatches, Command};
pub fn getopts() -> ArgMatches {
    let matches = Command::new("qkthr")
        .arg(
            Arg::new("version")
                .short('v')
                .long("version")
                .help("Show version number")
                .action(ArgAction::SetTrue),
        )
        .get_matches();
    matches
}
