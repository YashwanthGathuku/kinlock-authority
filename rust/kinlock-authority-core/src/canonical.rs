//! Canonical JSON and digests, byte-identical to the Python reference:
//! `json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`.

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::py::float_repr;

fn write_str(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

fn write(out: &mut String, v: &Value) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            if n.is_f64() {
                out.push_str(&float_repr(n.as_f64().unwrap_or(f64::NAN)));
            } else {
                out.push_str(&n.to_string());
            }
        }
        Value::String(s) => write_str(out, s),
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write(out, x);
            }
            out.push(']');
        }
        Value::Object(o) => {
            // Python sorts str keys by code point; Rust orders String by UTF-8 bytes, which is the same order.
            let mut keys: Vec<&String> = o.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_str(out, k);
                out.push(':');
                write(out, &o[k]);
            }
            out.push('}');
        }
    }
}

/// One string per value: sorted keys, no whitespace, UTF-8, Python's escapes and float layout.
pub fn canonical(v: &Value) -> String {
    let mut out = String::new();
    write(&mut out, v);
    out
}

/// SHA-256 of the canonical bytes, as lowercase hex.
pub fn digest(v: &Value) -> String {
    hex(&Sha256::digest(canonical(v).as_bytes()))
}

pub fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 15) as usize] as char);
    }
    s
}

/// Lowercase or uppercase hex to bytes, as `bytes.fromhex` (spaces between bytes allowed).
pub fn unhex(s: &str) -> Option<Vec<u8>> {
    let clean: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if clean.len() % 2 != 0 {
        return None;
    }
    clean
        .chunks(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).ok()?, 16).ok())
        .collect()
}
