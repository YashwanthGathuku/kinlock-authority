//! Exact-action approval capabilities. A port of `kinlock_authority/approvals.py`.
//!
//! Issuing needs a random nonce and a clock, so it stays with the caller; this
//! module signs a payload and checks a capability, which is what must agree
//! byte for byte with Python.

use hmac::{Hmac, Mac};
use serde_json::{Map, Value};
use sha2::Sha256;

use crate::canonical::{canonical, hex};
use crate::py::ct_eq;
use crate::receipts::py_eq;
use crate::Error;

pub const FIELDS: &[&str] = &[
    "cap_id",
    "request_id",
    "action_digest",
    "approver",
    "role",
    "ceiling_cents",
    "nonce",
    "issued_at",
    "expires_at",
    "sig",
];

pub fn hmac_hex(key: &[u8], message: &[u8]) -> String {
    // HMAC accepts any key length, so this cannot fail.
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key)
        .unwrap_or_else(|_| unreachable!("HMAC takes keys of any length"));
    mac.update(message);
    hex(&mac.finalize().into_bytes())
}

pub struct Signer {
    key: Vec<u8>,
}

impl Signer {
    pub fn new(key: &[u8]) -> Result<Signer, Error> {
        if key.len() < 32 {
            return Err(Error::Invalid(
                "signing key must be at least 32 bytes".into(),
            ));
        }
        Ok(Signer { key: key.to_vec() })
    }

    pub fn sign(&self, payload: &Value) -> String {
        hmac_hex(&self.key, canonical(payload).as_bytes())
    }
}

/// A capability as JSON, with its fields' raw types kept so the signature covers exactly what was signed.
#[derive(Clone, Debug)]
pub struct Capability(pub Map<String, Value>);

impl Capability {
    pub fn from_value(v: &Value) -> Result<Capability, Error> {
        let o = v
            .as_object()
            .ok_or_else(|| Error::Invalid("a capability is an object".into()))?;
        for k in o.keys() {
            if !FIELDS.contains(&k.as_str()) {
                return Err(Error::Invalid(format!("unexpected capability field {k:?}")));
            }
        }
        for k in &FIELDS[..FIELDS.len() - 1] {
            if !o.contains_key(*k) {
                return Err(Error::Invalid(format!("missing capability field {k:?}")));
            }
        }
        Ok(Capability(o.clone()))
    }

    pub fn payload(&self) -> Value {
        let mut p = self.0.clone();
        p.remove("sig");
        Value::Object(p)
    }

    fn field(&self, k: &str) -> &Value {
        self.0.get(k).unwrap_or(&Value::Null)
    }

    pub fn sig(&self) -> &str {
        self.0.get("sig").and_then(Value::as_str).unwrap_or("")
    }
}

fn num(v: &Value) -> Option<f64> {
    match v {
        Value::Bool(b) => Some(f64::from(u8::from(*b))),
        Value::Number(n) => n.as_f64(),
        _ => None,
    }
}

/// Every reason this capability can't release this action. Empty means usable.
pub fn capability_problems(
    signer: &Signer,
    cap: &Capability,
    request_id: &Value,
    current_digest: Option<&str>,
    amount_cents: i64,
    used: &[Value],
    now: f64,
) -> Result<Vec<String>, Error> {
    let mut problems = Vec::new();
    if !ct_eq(&signer.sign(&cap.payload()), cap.sig()) {
        problems.push("The approval's signature is not valid".into());
    }
    if used.iter().any(|u| py_eq(u, cap.field("cap_id"))) {
        problems.push("This approval was already used".into());
    }
    let expires = num(cap.field("expires_at"))
        .ok_or_else(|| Error::Invalid("expires_at must be a number".into()))?;
    if now > expires {
        problems.push("This approval has expired".into());
    }
    if !py_eq(cap.field("request_id"), request_id) {
        problems.push("This approval belongs to a different request".into());
    }
    match current_digest {
        None => problems.push("That request is no longer waiting".into()),
        Some(d) => {
            if !ct_eq(cap.field("action_digest").as_str().unwrap_or(""), d)
                || !cap.field("action_digest").is_string()
            {
                problems.push("The request changed after it was approved".into());
            }
        }
    }
    let ceiling = num(cap.field("ceiling_cents"))
        .ok_or_else(|| Error::Invalid("ceiling_cents must be a number".into()))?;
    if (amount_cents as f64) > ceiling {
        problems.push("The amount is over what the approver may allow".into());
    }
    Ok(problems)
}
