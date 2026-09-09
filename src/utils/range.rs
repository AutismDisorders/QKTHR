use rand::Rng;

/// Range types accepted by upstream's `RANGE` keyword.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RangeType {
    Hex,
    Int,
    Float,
    Letters,
    Lower,
    Upper,
}

impl RangeType {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "hex" => Self::Hex,
            "int" => Self::Int,
            "float" => Self::Float,
            "letters" => Self::Letters,
            "lower" | "lowercase" => Self::Lower,
            "upper" | "uppercase" => Self::Upper,
            _ => return None,
        })
    }
}

/// Mirrors upstream `RangeIter`: deterministic `start..stop` (step follows sign),
/// letter ranges (`aa-ac`), and optional random mode (size becomes unbounded).
pub enum RangeIter {
    Numeric {
        typ: RangeType,
        start: i64,
        stop: i64,
        step: i64,
        cur: i64,
        done: bool,
        random: bool,
        fmt: NumericFmt,
    },
    Letters {
        charset: &'static str,
        first: Option<String>,
        last: String,
        cur: u64,
        done: bool,
    },
}

enum NumericFmt {
    Dec,
    Hex,
    Float(usize),
}

impl NumericFmt {
    fn render(&self, v: i64) -> String {
        match self {
            Self::Dec => v.to_string(),
            Self::Hex => padhex(v as u64),
            Self::Float(prec) => format!("{:.*}", prec, v as f64 / 10f64.powi(*prec as i32)),
        }
    }
}

fn padhex(d: u64) -> String {
    let x = format!("{:x}", d);
    if x.len() % 2 == 1 { format!("0{x}") } else { x }
}

/// 1-based order number of a letter string (upstream's `count`).
fn letter_count(s: &str, charset: &str) -> u64 {
    let mut total: u64 = 0;
    let mut pow: u64 = 1;
    for c in s.chars().rev() {
        let z = charset
            .chars()
            .position(|x| x == c)
            .map(|i| i + 1)
            .unwrap_or(0) as u64;
        total += z * pow;
        pow *= charset.chars().count() as u64;
    }
    total + 1
}

/// Render the nth (0-based) letter string in `charset` enumeration order.
fn letter_at(mut n: u64, charset: &str) -> String {
    let base = charset.chars().count() as u64;
    let mut out = String::new();
    while n > 0 {
        n -= 1;
        let idx = (n % base) as usize;
        out.insert(0, charset.chars().nth(idx).unwrap());
        n /= base;
    }
    if out.is_empty() {
        out.push(charset.chars().next().unwrap());
    }
    out
}

impl RangeIter {
    pub fn parse(typ: RangeType, rng: &str, random: bool) -> Result<Self, String> {
        match typ {
            RangeType::Hex | RangeType::Int | RangeType::Float => {
                let (mn, mx) = rng
                    .rsplit_once('-')
                    .ok_or_else(|| format!("Unsupported range {rng:?}"))?;
                if mx.contains('-') {
                    return Err(format!("Unsupported range {rng:?}"));
                }
                let start = parse_num(mn.trim(), &typ)?;
                let stop = parse_num(mx.trim(), &typ)?;
                let step = if start > stop { -1 } else { 1 };
                let precision = if typ == RangeType::Float {
                    let dl = |s: &str| s.split('.').nth(1).map(str::len).unwrap_or(0);
                    dl(mn.trim()).max(dl(mx.trim()))
                } else {
                    0
                };
                let fmt = match typ {
                    RangeType::Hex => NumericFmt::Hex,
                    RangeType::Float => NumericFmt::Float(precision),
                    _ => NumericFmt::Dec,
                };
                Ok(Self::Numeric {
                    typ,
                    start,
                    stop,
                    step,
                    cur: start,
                    done: false,
                    random,
                    fmt,
                })
            }
            RangeType::Letters | RangeType::Lower | RangeType::Upper => {
                let charset: &'static str = match typ {
                    RangeType::Letters => "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
                    RangeType::Lower => "abcdefghijklmnopqrstuvwxyz",
                    RangeType::Upper => "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
                    _ => unreachable!(),
                };
                let (first, last) = rng
                    .split_once('-')
                    .ok_or_else(|| format!("Unsupported range {rng:?}"))?;
                if last.is_empty() {
                    return Err(format!("Unsupported range {rng:?}"));
                }
                let first = if first.is_empty() {
                    None
                } else {
                    Some(first.to_string())
                };
                let cur = match &first {
                    Some(f) => letter_count(f, charset).saturating_sub(1),
                    None => 0,
                };
                Ok(Self::Letters {
                    charset,
                    first,
                    last: last.to_string(),
                    cur,
                    done: false,
                })
            }
        }
    }

    pub fn len(&self) -> u64 {
        match self {
            Self::Numeric {
                start,
                stop,
                random,
                ..
            } => {
                if *random {
                    u64::MAX
                } else {
                    (stop - start).abs() as u64 + 1
                }
            }
            Self::Letters {
                first,
                last,
                charset,
                ..
            } => {
                let last_c = letter_count(last, charset);
                let first_c = first.as_ref().map_or(1, |f| letter_count(f, charset));
                last_c.saturating_sub(first_c.saturating_sub(1))
            }
        }
    }
}

impl Iterator for RangeIter {
    type Item = String;
    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Numeric {
                stop,
                step,
                cur,
                done,
                random,
                fmt,
                ..
            } => {
                if *done {
                    return None;
                }
                if !*random && (*step > 0 && *cur > *stop || *step < 0 && *cur < *stop) {
                    *done = true;
                    return None;
                }
                let out = fmt.render(*cur);
                if *random {
                    let hi: i64 = 1_000_000_000;
                    *cur = rand::rng().random_range(0..=hi);
                } else {
                    *cur += *step;
                    if *step > 0 && *cur > *stop {
                        *done = true;
                    }
                    if *step < 0 && *cur < *stop {
                        *done = true;
                    }
                }
                Some(out)
            }
            Self::Letters {
                charset,
                first,
                last,
                cur,
                done,
                ..
            } => {
                if *done {
                    return None;
                }
                let out = letter_at(*cur, charset);
                *cur += 1;
                if let Some(f) = first {
                    if !f.is_empty() && out < *f {
                        // still before the start of the range; skip
                        if letter_count(&out, charset) >= letter_count(last, charset) {
                            *done = true;
                        }
                        return self.next();
                    }
                }
                if letter_count(&out, charset) >= letter_count(last, charset) {
                    *done = true;
                }
                Some(out)
            }
        }
    }
}

fn parse_num(s: &str, typ: &RangeType) -> Result<i64, String> {
    let radix = if s.starts_with("0x") || s.starts_with("0X") || *typ == RangeType::Hex {
        16
    } else {
        10
    };
    let digits = if radix == 16 {
        s.trim_start_matches("0x").trim_start_matches("0X")
    } else {
        s
    };
    i64::from_str_radix(digits, radix).map_err(|_| format!("Unsupported range value {s:?}"))
}
