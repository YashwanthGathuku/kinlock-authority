//! Verifying append-only, hash-chained receipts. A port of `ReceiptChain.verify`
//! in `kinlock_authority/receipts.py`; appending (a file write) stays in Python.

use serde_json::{json, Map, Value};

use crate::approvals::hmac_hex;
use crate::canonical::digest;
use crate::py::{ct_eq, strip, to_str, truthy};
use crate::Error;

pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const FIELDS: &[&str] = &["seq", "ts", "kind", "data", "prev", "hash", "sig"];

pub fn sign_hash(key: &[u8], h: &str) -> String {
    hmac_hex(key, format!("kinlock-receipt:{h}").as_bytes())
}

/// Python's `==` between two JSON values (`1 == 1.0 == True`).
pub fn py_eq(a: &Value, b: &Value) -> bool {
    let num = |v: &Value| match v {
        Value::Bool(x) => Some(f64::from(u8::from(*x))),
        Value::Number(n) => n.as_f64(),
        _ => None,
    };
    match (a, b) {
        (Value::Number(x), Value::Number(y)) if x.is_f64() || y.is_f64() => num(a) == num(b),
        (Value::Number(x), Value::Number(y)) => x == y,
        (Value::Bool(_) | Value::Number(_), Value::Bool(_) | Value::Number(_)) => num(a) == num(b),
        (Value::Array(x), Value::Array(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(p, q)| py_eq(p, q))
        }
        (Value::Object(x), Value::Object(y)) => {
            x.len() == y.len() && x.iter().all(|(k, v)| y.get(k).is_some_and(|w| py_eq(v, w)))
        }
        _ => a == b,
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ChainReport {
    pub ok: bool,
    pub receipts: i64,
    pub head: String,
    pub broken_at: Option<Value>,
    pub reason: Option<String>,
}

impl ChainReport {
    pub fn to_value(&self) -> Value {
        json!({"ok": self.ok, "receipts": self.receipts, "head": self.head, "broken_at": self.broken_at, "reason": self.reason})
    }
}

fn parse(line: &str) -> Result<Map<String, Value>, String> {
    let v: Value = serde_json::from_str(line).map_err(|e| e.to_string())?;
    let Value::Object(o) = v else {
        return Err("a receipt must be a JSON object".into());
    };
    if let Some(k) = o.keys().find(|k| !FIELDS.contains(&k.as_str())) {
        return Err(format!("unexpected field {k:?}"));
    }
    if let Some(k) = FIELDS[..6].iter().find(|k| !o.contains_key(**k)) {
        return Err(format!("missing field {k:?}"));
    }
    Ok(o)
}

/// Verify a chain given its lines (as the file holds them). `key` makes signatures required.
pub fn verify(lines: &[String], key: Option<&[u8]>) -> Result<ChainReport, Error> {
    if key.is_some_and(|k| k.len() < 32) {
        return Err(Error::Invalid(
            "receipt signing key must be at least 32 bytes".into(),
        ));
    }
    let mut prev = GENESIS.to_string();
    let mut n: i64 = 0;
    let unreadable = |n: i64, prev: &str, e: String| ChainReport {
        ok: false,
        receipts: n,
        head: prev.to_string(),
        broken_at: Some(json!(n)),
        reason: Some(format!("unreadable receipt: {e}")),
    };
    // The file is read line by line, so a line that itself holds a newline is two lines.
    // Python opens it in text mode, where "\r\n" and a lone "\r" also end a line.
    let joined: String = lines
        .iter()
        .map(|l| format!("{l}\n"))
        .collect::<String>()
        .replace("\r\n", "\n")
        .replace('\r', "\n");
    for raw in joined.split_inclusive('\n') {
        let line = strip(raw);
        if line.is_empty() {
            continue;
        }
        let r = match parse(line) {
            Ok(r) => r,
            Err(e) => return Ok(unreadable(n, &prev, e)),
        };
        n += 1;
        let seq = &r["seq"];
        let broken = |reason: String, prev: &str| ChainReport {
            ok: false,
            receipts: n,
            head: prev.to_string(),
            broken_at: Some(seq.clone()),
            reason: Some(reason),
        };
        if !py_eq(seq, &json!(n - 1)) {
            return Ok(broken(
                format!("sequence gap: expected {}, found {}", n - 1, to_str(seq)),
                &prev,
            ));
        }
        if !py_eq(&r["prev"], &Value::String(prev.clone())) {
            return Ok(broken(
                "prev hash does not match the receipt before it".into(),
                &prev,
            ));
        }
        let body = json!({"seq": seq, "ts": r["ts"], "kind": r["kind"], "data": r["data"], "prev": r["prev"]});
        if !py_eq(&Value::String(digest(&body)), &r["hash"]) {
            return Ok(broken(
                "receipt content does not match its hash".into(),
                &prev,
            ));
        }
        let hash = r["hash"].as_str().unwrap_or_default().to_string();
        if let Some(key) = key {
            let sig = r
                .get("sig")
                .cloned()
                .unwrap_or(Value::String(String::new()));
            if !truthy(&sig) {
                return Ok(broken("receipt is not signed".into(), &prev));
            }
            match sig.as_str() {
                Some(s) if s.is_ascii() => {
                    if !ct_eq(&sign_hash(key, &hash), s) {
                        return Ok(broken("receipt signature is not valid".into(), &prev));
                    }
                }
                _ => {
                    return Ok(unreadable(
                        n,
                        &prev,
                        "the signature is not an ASCII string".into(),
                    ))
                }
            }
        }
        prev = hash;
    }
    Ok(ChainReport {
        ok: true,
        receipts: n,
        head: prev,
        broken_at: None,
        reason: None,
    })
}
