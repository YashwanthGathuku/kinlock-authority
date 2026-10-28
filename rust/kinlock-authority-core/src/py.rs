//! Small pieces of Python's behaviour that the rules depend on.
//!
//! The Python implementation is the reference. Messages, digests and decisions
//! must match it byte for byte, so the exact formatting of numbers, `str()`,
//! `repr()`, `casefold()` and whitespace splitting is reproduced here.

use serde_json::Value;

use crate::Error;

/// `str.isspace()` for one character.
pub fn is_space(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

/// `str.strip()`.
pub fn strip(s: &str) -> &str {
    s.trim_matches(is_space)
}

/// `" ".join(s.split())`.
pub fn join_words(s: &str) -> String {
    s.split(is_space)
        .filter(|w| !w.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

/// `str.casefold()`: lower case plus the full case folds that differ from it.
pub fn casefold(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            'ß' | 'ẞ' => out.push_str("ss"),
            'ſ' => out.push('s'),
            'ς' => out.push('σ'),
            'ϐ' => out.push('β'),
            'ϑ' => out.push('θ'),
            'ϕ' => out.push('φ'),
            'ϖ' => out.push('π'),
            'ϰ' => out.push('κ'),
            'ϱ' => out.push('ρ'),
            'ϵ' => out.push('ε'),
            'ẛ' => out.push('ṡ'),
            'ﬀ' => out.push_str("ff"),
            'ﬁ' => out.push_str("fi"),
            'ﬂ' => out.push_str("fl"),
            'ﬃ' => out.push_str("ffi"),
            'ﬄ' => out.push_str("ffl"),
            'ﬅ' | 'ﬆ' => out.push_str("st"),
            'ŉ' => out.push_str("\u{2bc}n"),
            'ǰ' => out.push_str("j\u{30c}"),
            'ΐ' => out.push_str("\u{3b9}\u{308}\u{301}"),
            'ΰ' => out.push_str("\u{3c5}\u{308}\u{301}"),
            'և' => out.push_str("\u{565}\u{582}"),
            'ẖ' => out.push_str("h\u{331}"),
            'ẗ' => out.push_str("t\u{308}"),
            'ẘ' => out.push_str("w\u{30a}"),
            'ẙ' => out.push_str("y\u{30a}"),
            'ẚ' => out.push_str("a\u{2be}"),
            'Ꭰ'..='Ᏽ' => out.push(c),
            'ᏸ'..='ᏽ' => out.extend(char::from_u32(c as u32 - 8)),
            'ꭰ'..='ꮿ' => out.extend(char::from_u32(c as u32 - 0xab70 + 0x13a0)),
            _ => out.extend(c.to_lowercase()),
        }
    }
    out
}

/// `" ".join(str(s).casefold().split())`: how names, shops and targets are compared.
pub fn norm(s: &str) -> String {
    join_words(&casefold(s))
}

/// `str.capitalize()`.
pub fn capitalize(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        None => String::new(),
        Some(first) => first
            .to_uppercase()
            .chain(chars.flat_map(char::to_lowercase))
            .collect(),
    }
}

/// `s[0].upper() + s[1:]`.
pub fn upper_first(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        None => String::new(),
        Some(first) => first.to_uppercase().chain(chars).collect(),
    }
}

/// `repr(float)`: the shortest digits that round-trip, in Python's layout.
pub fn float_repr(x: f64) -> String {
    if x.is_nan() {
        return "NaN".into();
    }
    if x.is_infinite() {
        return if x > 0.0 {
            "Infinity".into()
        } else {
            "-Infinity".into()
        };
    }
    let sci = format!("{x:e}");
    let (mantissa, exp) = sci.split_once('e').unwrap_or((&sci, "0"));
    let exp: i32 = exp.parse().unwrap_or(0);
    let (neg, mantissa) = match mantissa.strip_prefix('-') {
        Some(m) => (true, m),
        None => (false, mantissa),
    };
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    let sign = if neg { "-" } else { "" };
    if (-4..16).contains(&exp) {
        if exp >= 0 {
            let point = exp as usize + 1;
            let (int, frac) = if digits.len() > point {
                (digits[..point].to_string(), digits[point..].to_string())
            } else {
                (
                    format!("{digits}{}", "0".repeat(point - digits.len())),
                    "0".to_string(),
                )
            };
            format!("{sign}{int}.{frac}")
        } else {
            format!("{sign}0.{}{digits}", "0".repeat((-exp - 1) as usize))
        }
    } else {
        let rest = if digits.len() > 1 {
            format!(".{}", &digits[1..])
        } else {
            String::new()
        };
        let esign = if exp < 0 { '-' } else { '+' };
        format!("{sign}{}{rest}e{esign}{:02}", &digits[..1], exp.abs())
    }
}

/// `format(x, "g")`.
pub fn format_g(x: f64) -> String {
    if x == 0.0 {
        return if x.is_sign_negative() {
            "-0".into()
        } else {
            "0".into()
        };
    }
    if !x.is_finite() {
        return if x.is_nan() {
            "nan".into()
        } else if x > 0.0 {
            "inf".into()
        } else {
            "-inf".into()
        };
    }
    let sci = format!("{x:.5e}");
    let (mantissa, exp) = sci.split_once('e').unwrap_or((&sci, "0"));
    let exp: i32 = exp.parse().unwrap_or(0);
    if (-4..6).contains(&exp) {
        let decimals = (5 - exp).max(0) as usize;
        let fixed = format!("{x:.decimals$}");
        if fixed.contains('.') {
            fixed
                .trim_end_matches('0')
                .trim_end_matches('.')
                .to_string()
        } else {
            fixed
        }
    } else {
        let m = if mantissa.contains('.') {
            mantissa.trim_end_matches('0').trim_end_matches('.')
        } else {
            mantissa
        };
        let esign = if exp < 0 { '-' } else { '+' };
        format!("{m}e{esign}{:02}", exp.abs())
    }
}

/// Characters `str.isprintable()` rejects, close enough for the messages here.
fn printable(c: char) -> bool {
    if c == ' ' {
        return true;
    }
    !(c.is_control()
        || is_space(c)
        || matches!(c, '\u{ad}' | '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2060}'..='\u{2064}' | '\u{feff}' | '\u{fff9}'..='\u{fffb}' | '\u{e000}'..='\u{f8ff}'))
}

/// `repr(str)`.
pub fn repr_str(s: &str) -> String {
    let quote = if s.contains('\'') && !s.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::with_capacity(s.len() + 2);
    out.push(quote);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if printable(c) => out.push(c),
            c if (c as u32) < 0x100 => out.push_str(&format!("\\x{:02x}", c as u32)),
            c if (c as u32) < 0x10000 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push_str(&format!("\\U{:08x}", c as u32)),
        }
    }
    out.push(quote);
    out
}

fn number_str(n: &serde_json::Number) -> String {
    if n.is_f64() {
        float_repr(n.as_f64().unwrap_or(f64::NAN))
    } else {
        n.to_string()
    }
}

/// `repr()` of a JSON value as Python holds it.
pub fn repr(v: &Value) -> String {
    match v {
        Value::String(s) => repr_str(s),
        Value::Array(a) => format!("[{}]", a.iter().map(repr).collect::<Vec<_>>().join(", ")),
        Value::Object(o) => format!(
            "{{{}}}",
            o.iter()
                .map(|(k, v)| format!("{}: {}", repr_str(k), repr(v)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        other => to_str(other),
    }
}

/// `str()` of a JSON value as Python holds it.
pub fn to_str(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => "None".into(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::Number(n) => number_str(n),
        other => repr(other),
    }
}

/// `bool()` of a JSON value.
pub fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|x| x != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// `int()` of a JSON value.
pub fn to_int(v: &Value) -> Result<i64, Error> {
    match v {
        Value::Bool(b) => Ok(i64::from(*b)),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(i)
            } else if let Some(u) = n.as_u64() {
                i64::try_from(u).map_err(|_| Error::Invalid(format!("integer out of range: {u}")))
            } else {
                let f = n.as_f64().unwrap_or(f64::NAN);
                if f.is_finite() && f.abs() < 9.2e18 {
                    Ok(f.trunc() as i64)
                } else {
                    Err(Error::Invalid(format!(
                        "cannot convert float {} to integer",
                        float_repr(f)
                    )))
                }
            }
        }
        Value::String(s) => {
            let t = strip(s).replace('_', "");
            t.parse::<i64>().map_err(|_| {
                Error::Invalid(format!(
                    "invalid literal for int() with base 10: {}",
                    repr_str(s)
                ))
            })
        }
        other => Err(Error::Invalid(format!(
            "int() argument must be a string or a number, not {}",
            type_name(other)
        ))),
    }
}

/// A JSON number as a float, for clock times.
pub fn to_float(v: &Value) -> Result<f64, Error> {
    match v {
        Value::Number(n) => n
            .as_f64()
            .ok_or_else(|| Error::Invalid("not a number".into())),
        Value::Bool(b) => Ok(f64::from(u8::from(*b))),
        other => Err(Error::Invalid(format!(
            "expected a number, not {}",
            type_name(other)
        ))),
    }
}

/// Python's `==` between a JSON value and an integer (`True == 1`, `1.0 == 1`).
pub fn eq_int(v: &Value, i: i64) -> bool {
    match v {
        Value::Bool(b) => i64::from(*b) == i,
        Value::Number(n) => n
            .as_i64()
            .map_or_else(|| n.as_f64() == Some(i as f64), |x| x == i),
        _ => false,
    }
}

pub fn type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "NoneType",
        Value::Bool(_) => "bool",
        Value::Number(n) if n.is_f64() => "float",
        Value::Number(_) => "int",
        Value::String(_) => "str",
        Value::Array(_) => "list",
        Value::Object(_) => "dict",
    }
}

/// `"$1,234.50"`, as the pages and messages show money.
pub fn money(cents: i64) -> String {
    let sign = if cents < 0 { "-" } else { "" };
    let c = cents.unsigned_abs();
    let (dollars, rest) = (c / 100, c % 100);
    let digits = dollars.to_string();
    let mut grouped = String::new();
    for (i, ch) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i) % 3 == 0 {
            grouped.push(',');
        }
        grouped.push(ch);
    }
    if rest > 0 {
        format!("{sign}${grouped}.{rest:02}")
    } else {
        format!("{sign}${grouped}")
    }
}

/// `hmac.compare_digest` for two strings: constant time over equal lengths.
pub fn ct_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn floats_print_like_python() {
        for (x, s) in [
            (1.5, "1.5"),
            (0.1, "0.1"),
            (1e-7, "1e-07"),
            (1e16, "1e+16"),
            (1e15, "1000000000000000.0"),
            (-0.0, "-0.0"),
            (1000.0, "1000.0"),
            (0.0001, "0.0001"),
            (123456789.125, "123456789.125"),
            (1.5e-5, "1.5e-05"),
            (2.5e300, "2.5e+300"),
        ] {
            assert_eq!(float_repr(x), s, "{x}");
        }
    }

    #[test]
    fn g_format_like_python() {
        for (x, s) in [
            (24.0, "24"),
            (1.5, "1.5"),
            (0.5, "0.5"),
            (1.0 / 3.0, "0.333333"),
            (1e6, "1e+06"),
            (123456.0, "123456"),
            (0.0, "0"),
            (1e-5, "1e-05"),
        ] {
            assert_eq!(format_g(x), s, "{x}");
        }
    }

    #[test]
    fn money_like_python() {
        assert_eq!(money(123456789), "$1,234,567.89");
        assert_eq!(money(-150), "-$1.50");
        assert_eq!(money(100000), "$1,000");
        assert_eq!(money(5), "$0.05");
    }

    #[test]
    fn repr_like_python() {
        assert_eq!(repr_str("gift card"), "'gift card'");
        assert_eq!(repr_str("it's"), "\"it's\"");
        assert_eq!(repr_str("a\u{a0}b"), "'a\\xa0b'");
        assert_eq!(casefold("Straße"), "strasse");
    }
}
