use std::path::PathBuf;

/// `expand_path`: expand `~` and env vars, like upstream `os.path.expandvars(os.path.expanduser(s))`.
pub fn expand_path(path: &str) -> String {
    shellexpand::full(path)
        .map(|e| e.into_owned())
        .unwrap_or_else(|e| {
            eprintln!("warning: failed to expand {:?}: {e}", path);
            path.to_string()
        })
}

/// `which`: locate an executable in `PATH` (upstream `which`).
pub fn which(program: &str) -> Option<PathBuf> {
    // On Windows, Python appends `.exe` if missing; keep parity.

    let program = program.to_string();
    #[cfg(windows)]
    let program = {
        let s = program;
        if s.len() < 4 || !s.ends_with(".exe") {
            s + ".exe"
        } else {
            s
        }
    };

    let p = std::path::Path::new(&program);
    if p.components().count() > 1 {
        return (p.is_file() && is_executable(p)).then(|| p.to_path_buf());
    }
    which::which(&program).ok()
}

fn is_executable(path: &std::path::Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        path.metadata()
            .map(|m| m.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        path.is_file()
    }
}
