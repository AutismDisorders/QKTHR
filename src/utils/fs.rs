#![allow(dead_code)]
use chrono::Local;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

/// `count_lines`: count lines buffered, without loading the file (upstream `count_lines`).
pub fn count_lines(path: &Path) -> io::Result<u64> {
    use std::io::Read;
    let mut file = fs::File::open(path)?;
    let mut buffer = [0; 8192];
    let mut newline_count = 0;
    let mut has_content = false;
    let mut last_byte_was_newline = false;
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        for &b in &buffer[..n] {
            has_content = true;
            if b == b'\n' {
                newline_count += 1;
                last_byte_was_newline = true;
            } else {
                last_byte_was_newline = false;
            }
        }
    }
    if has_content && !last_byte_was_newline {
        newline_count += 1;
    }
    Ok(newline_count)
}

/// `build_logdir`: upstream `build_logdir(opt_dir, opt_auto, assume_yes)`.
pub fn build_logdir(
    opt_dir: Option<&str>,
    opt_auto: Option<&str>,
    _assume_yes: bool,
) -> io::Result<Option<PathBuf>> {
    if let Some(desc) = opt_auto {
        create_time_dir(opt_dir.unwrap_or("/tmp/patator"), desc).map(Some)
    } else if let Some(dir) = opt_dir {
        // Just return the directory as is, without creating or wiping it.
        Ok(Some(PathBuf::from(dir)))
    } else {
        Ok(None)
    }
}

/// `create_dir`: empty-or-wipe target dir (upstream `create_dir`).
/// Returns Err on sub-directories when wiping (mirrors upstream "safely aborting").
pub fn create_dir(top_path: &str, assume_yes: bool) -> io::Result<PathBuf> {
    let top = fs::canonicalize(top_path)
        .or_else(|_| fs::create_dir_all(top_path).and_then(|_| fs::canonicalize(top_path)))?;
    if fs::read_dir(&top)?.next().is_some() {
        if !assume_yes {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "directory not wiped",
            ));
        }
        for entry in fs::read_dir(&top)? {
            let path = entry?.path();
            if path.is_dir() {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!(
                        "Directory {:?} contains sub-directories, safely aborting...",
                        path
                    ),
                ));
            }
            fs::remove_file(path)?;
        }
    }
    Ok(top)
}

/// `create_time_dir`: upstream `create_time_dir` - `<dir>/<YYYY-mm-dd>/<HHMMSS>_<desc>`.
pub fn create_time_dir(top_path: &str, desc: &str) -> io::Result<PathBuf> {
    let now = Local::now();
    let date = now.format("%Y-%m-%d").to_string();
    let time = now.format("%H%M%S").to_string();
    let top = PathBuf::from(top_path);
    let date_path = top.join(&date);
    let time_path = date_path.join(format!("{time}_{desc}"));
    fs::create_dir_all(&date_path)?;
    fs::create_dir_all(&time_path)?;
    Ok(time_path)
}

/// `mtime_unix`: Unix seconds of a file's mtime (used by resume/hits bookkeeping).
pub fn mtime_unix(path: &Path) -> io::Result<u64> {
    fs::metadata(path)?
        .modified()?
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
}
