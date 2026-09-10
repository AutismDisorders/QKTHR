use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::Path;
use std::process::{Command, Stdio};

/// Chain: concatenated iterators (upstream chain), zero-cost.
pub struct Chain<I> {
    iters: Vec<I>,
    idx: usize,
}

impl<I> Chain<I> {
    pub fn new(iters: Vec<I>) -> Self {
        Self { iters, idx: 0 }
    }
}

impl<I: Iterator> Iterator for Chain<I> {
    type Item = I::Item;
    fn next(&mut self) -> Option<Self::Item> {
        while self.idx < self.iters.len() {
            if let Some(item) = self.iters[self.idx].next() {
                return Some(item);
            }
            self.idx += 1;
        }
        None
    }
}

/// Lazy cartesian product of pools, yielding Vec<T>.
pub struct Product<'a, T> {
    pools: &'a [&'a [T]],
    indices: Vec<usize>,
    started: bool,
}

impl<'a, T> Product<'a, T> {
    pub fn new(pools: &'a [&'a [T]]) -> Self {
        let indices = vec![0; pools.len()];
        Self {
            pools,
            indices,
            started: false,
        }
    }
}

impl<'a, T: Clone> Iterator for Product<'a, T> {
    type Item = Vec<T>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.pools.is_empty() {
            return None;
        }
        if !self.started {
            if self.pools.iter().any(|p| p.is_empty()) {
                return None;
            }
            self.started = true;
            return Some(self.pools.iter().map(|p| p[0].clone()).collect());
        }
        for i in (0..self.indices.len()).rev() {
            if self.indices[i] + 1 < self.pools[i].len() {
                self.indices[i] += 1;
                for j in (i + 1)..self.indices.len() {
                    self.indices[j] = 0;
                }
                return Some(
                    self.pools
                        .iter()
                        .enumerate()
                        .map(|(k, p)| p[self.indices[k]].clone())
                        .collect(),
                );
            }
        }
        None
    }
}

/// FileIter: line iterator over a file, dropping trailing CR and LF.
pub struct FileIter {
    reader: Box<dyn BufRead>,
    done: bool,
}

impl FileIter {
    pub fn open(path: &Path) -> io::Result<Self> {
        let file = File::open(path)?;
        let reader = Box::new(BufReader::new(file));
        Ok(Self {
            reader,
            done: false,
        })
    }
}

impl Iterator for FileIter {
    type Item = io::Result<Vec<u8>>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let mut buf = Vec::new();
        match self.reader.read_until(b'\n', &mut buf) {
            Ok(0) => {
                self.done = true;
                None
            }
            Ok(_) => {
                if buf.ends_with(b"\n") {
                    buf.pop();
                }
                if buf.ends_with(b"\r") {
                    buf.pop();
                }
                Some(Ok(buf))
            }
            Err(e) => Some(Err(e)),
        }
    }
}

/// ProgIter: yield a line from a program's stdout (spawns sh -c).
pub struct ProgIter {
    reader: Option<Box<dyn BufRead>>,
    _child: Option<std::process::Child>,
}

impl ProgIter {
    pub fn spawn(program: &str) -> io::Result<Self> {
        let mut child = Command::new("sh")
            .arg("-c")
            .arg(program)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "no stdout"))?;
        let reader = Box::new(BufReader::new(stdout));
        Ok(Self {
            reader: Some(reader),
            _child: Some(child),
        })
    }
}

impl Iterator for ProgIter {
    type Item = io::Result<Vec<u8>>;
    fn next(&mut self) -> Option<Self::Item> {
        let mut buf = Vec::new();
        match self.reader.as_mut()?.read_until(b'\n', &mut buf) {
            Ok(0) => None,
            Ok(_) => {
                if buf.ends_with(b"\n") {
                    buf.pop();
                }
                if buf.ends_with(b"\r") {
                    buf.pop();
                }
                Some(Ok(buf))
            }
            Err(e) => Some(Err(e)),
        }
    }
}
