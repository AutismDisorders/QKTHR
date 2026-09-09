/// `parse_query`: like Python's `urllib.parse.parse_qsl` but WITHOUT replacing `+` with space.
/// Splits on both `&` and `;`, keeps blank values optionally, decodes percent-escapes.
pub fn parse_query(qs: &str, keep_blank_values: bool) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for pair in qs.split(['&', ';']) {
        if pair.is_empty() {
            continue;
        }
        let mut it = pair.splitn(2, '=');
        let name = it.next().unwrap_or("");
        let value = it.next().unwrap_or("");
        if value.is_empty() && !keep_blank_values {
            continue;
        }
        out.push((percent_decode(name), percent_decode(value)));
    }
    out
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let h = unhex(bytes[i + 1]);
                let l = unhex(bytes[i + 2]);
                if let (Some(h), Some(l)) = (unhex(bytes[i + 1]), unhex(bytes[i + 2])) {
                    out.push(h * 16 + l);
                    i += 3;
                } else {
                    out.push(b'%');
                    i += 1;
                }
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn unhex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}
