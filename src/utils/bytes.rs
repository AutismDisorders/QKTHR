#![allow(dead_code)]
/// Byte/text coercion helpers mirroring upstream `b`/`B` (ISO-8859-1 lossy).
///
/// Python's `bytes.encode('ISO-8859-1', errors='ignore')` drops unencodable
/// bytes; `str.decode('ISO-8859-1', errors='ignore')` drops invalid sequences.

pub fn b<T: AsRef<[u8]>>(x: T) -> Vec<u8> {
    x.as_ref().to_vec()
}

/// ISO-8859-1 <-> UTF-8 round trip, like Python's latin-1 decode.
pub fn b_to_str(x: &[u8]) -> String {
    x.iter().map(|&c| c as char).collect()
}

/// `ppstr`: normalize a value to a printable string, stripping trailing CR/LF.
pub fn ppstr<S: AsRef<[u8]>>(s: S) -> String {
    let mut v = s.as_ref();
    while v.ends_with(b"\r") || v.ends_with(b"\n") {
        v = &v[..v.len() - 1];
    }
    b_to_str(v)
}

/// `flatten`: upstream controller turns each produced row into strings.
pub fn flatten<I, T>(row: I) -> Vec<String>
where
    I: IntoIterator<Item = T>,
    T: AsRef<[u8]>,
{
    row.into_iter().map(ppstr).collect()
}

/// `repr23`: printable ASCII stays as-is; otherwise mimic Python `repr(bytes)`.
pub fn repr23(s: &[u8]) -> String {
    if s.iter()
        .all(|&c| (0x20..=0x7e).contains(&c) && c != b'\\' && c != b'\'')
    {
        String::from_utf8_lossy(s).into_owned()
    } else {
        let mut out = String::new();
        for &c in s {
            match c {
                b'\n' => out.push_str("\\n"),
                b'\r' => out.push_str("\\r"),
                b'\t' => out.push_str("\\t"),
                b'\\' => out.push_str("\\\\"),
                b'\'' => out.push_str("\\'"),
                c if c < 0x20 || c == 0x7f || c >= 0x80 => out.push_str(&format!("\\x{:02x}", c)),
                c => out.push(c as char),
            }
        }
        out
    }
}
