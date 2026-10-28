//! The Rust side of the conformance suite: `run(op, input)` mirrors
//! `conformance/runner.py` and returns the same JSON for every vector.

use serde_json::{json, Value};

use crate::approvals::{capability_problems, Capability, Signer};
use crate::canonical::{canonical, digest, unhex};
use crate::firewall::{
    conflict_of_interest, describe_action, evaluate_action, may_approve_action, release_problems,
    scam_signals, tally, AgentAction, FirewallPolicy, Vote,
};
use crate::policy::{evaluate, may_approve, Action, History, Policy};
use crate::py::{to_float, to_int, to_str, truthy};
use crate::receipts::{sign_hash, verify};
use crate::Error;

fn field<'a>(i: &'a Value, k: &str) -> Result<&'a Value, Error> {
    i.get(k)
        .ok_or_else(|| Error::Invalid(format!("missing input {k:?}")))
}

fn text<'a>(i: &'a Value, k: &str) -> Result<&'a str, Error> {
    field(i, k)?
        .as_str()
        .ok_or_else(|| Error::Invalid(format!("input {k:?} must be a string")))
}

fn key(i: &Value) -> Result<Vec<u8>, Error> {
    unhex(text(i, "key_hex")?)
        .ok_or_else(|| Error::Invalid("non-hexadecimal number found in fromhex() arg".into()))
}

fn frozen(i: &Value) -> bool {
    i.get("frozen").is_some_and(truthy)
}

fn hour(i: &Value) -> Result<i64, Error> {
    i.get("local_hour").map_or(Ok(12), to_int)
}

struct Decided {
    action: AgentAction,
    policy: Policy,
    fw: FirewallPolicy,
    decision: crate::firewall::ActionDecision,
}

fn decide(i: &Value) -> Result<Decided, Error> {
    let action = AgentAction::from_value(field(i, "action")?)?;
    let policy = Policy::from_value(field(i, "policy")?)?;
    let fw = FirewallPolicy::from_value(i.get("firewall"))?;
    let decision = evaluate_action(
        &action,
        &policy,
        text(i, "channel")?,
        frozen(i),
        &History::from_value(i.get("history"))?,
        hour(i)?,
        &fw,
    )?;
    Ok(Decided {
        action,
        policy,
        fw,
        decision,
    })
}

fn votes(i: &Value) -> Vec<Vote> {
    crate::policy::items(i.get("votes"))
        .iter()
        .map(|v| Vote {
            voter: v.get("voter").map_or_else(String::new, to_str),
            choice: v.get("choice").map_or_else(String::new, to_str),
            comment: v.get("comment").map_or_else(String::new, to_str),
        })
        .collect()
}

/// Run one conformance operation. Errors the Python side raises as `ValueError` become `{"error": message}`.
pub fn run(op: &str, input: &Value) -> Value {
    match run_inner(op, input) {
        Ok(v) => v,
        Err(Error::Invalid(msg)) => json!({ "error": msg }),
    }
}

/// The single entry point the WASM build exposes: `{"op": ..., "input": ...}` in, the result out.
pub fn run_request(request: &Value) -> Value {
    match request.get("op").and_then(Value::as_str) {
        Some(op) => run(op, request.get("input").unwrap_or(&Value::Null)),
        None => json!({"error": "request needs an \"op\""}),
    }
}

fn run_inner(op: &str, i: &Value) -> Result<Value, Error> {
    Ok(match op {
        "canonical" => {
            let v = field(i, "value")?;
            json!({"canonical": canonical(v), "digest": digest(v)})
        }
        "action_digest" => {
            let a = AgentAction::from_value(field(i, "action")?)?;
            json!({"canonical": canonical(&a.digest_value()), "digest": a.digest()})
        }
        "legacy_action_digest" => {
            let a = Action::from_value(field(i, "action")?)?;
            json!({"canonical": canonical(&a.to_value()), "digest": a.digest()})
        }
        "evaluate" | "may_approve" => {
            let action = Action::from_value(field(i, "action")?)?;
            let p = Policy::from_value(field(i, "policy")?)?;
            let d = evaluate(
                &action,
                &p,
                text(i, "channel")?,
                frozen(i),
                &History::from_value(i.get("history"))?,
                hour(i)?,
            )?;
            if op == "evaluate" {
                d.to_value()
            } else {
                let amount = field(i, "action")?
                    .get("amount_cents")
                    .map_or(Ok(0), to_int)?;
                let contact = p.contact(i.get("contact_id").and_then(Value::as_str).unwrap_or(""));
                let (ok, why) = may_approve(&d, text(i, "role")?, amount, contact);
                json!({"ok": ok, "why": why})
            }
        }
        "evaluate_action" => decide(i)?.decision.to_value(),
        "may_approve_action" => {
            let d = decide(i)?;
            let contact = d
                .policy
                .contact(i.get("contact_id").and_then(Value::as_str).unwrap_or(""));
            let (ok, why) = may_approve_action(
                &d.decision,
                &d.action,
                text(i, "approver")?,
                text(i, "role")?,
                contact,
                &d.fw,
            );
            json!({"ok": ok, "why": why})
        }
        "tally" => {
            let d = decide(i)?;
            let t = tally(&d.decision, &d.action, &votes(i), &d.fw);
            json!({"state": t.state, "approvals": t.approvals, "problems": t.problems, "comments": t.comments.iter().map(|(a, b)| json!([a, b])).collect::<Vec<_>>()})
        }
        "release_problems" => {
            let d = decide(i)?;
            json!(release_problems(
                &d.decision,
                &d.action,
                &votes(i),
                to_float(field(i, "requested_at")?)?,
                to_float(field(i, "now")?)?,
                &d.fw
            ))
        }
        "conflict_of_interest" => {
            let fw = FirewallPolicy::from_value(i.get("firewall"))?;
            json!(conflict_of_interest(
                &AgentAction::from_value(field(i, "action")?)?,
                text(i, "approver")?,
                &fw
            ))
        }
        "describe_action" => json!(describe_action(&AgentAction::from_value(field(
            i, "action"
        )?)?)),
        "scam_signals" => {
            let fw = match i.get("firewall") {
                Some(f) => Some(FirewallPolicy::from_value(Some(f))?),
                None => None,
            };
            json!(scam_signals(text(i, "text")?, fw.as_ref())?)
        }
        "capability_sign" => json!(Signer::new(&key(i)?)?.sign(field(i, "payload")?)),
        "capability_problems" => {
            let signer = Signer::new(&key(i)?)?;
            let cap = Capability::from_value(field(i, "capability")?)?;
            let current = match i.get("current_digest") {
                None | Some(Value::Null) => None,
                Some(v) => Some(
                    v.as_str()
                        .ok_or_else(|| Error::Invalid("current_digest must be a string".into()))?,
                ),
            };
            let used = crate::policy::items(i.get("used"));
            json!(capability_problems(
                &signer,
                &cap,
                field(i, "request_id")?,
                current,
                to_int(field(i, "amount_cents")?)?,
                &used,
                to_float(field(i, "now")?)?
            )?)
        }
        "receipt_sign_hash" => json!(sign_hash(&key(i)?, text(i, "hash")?)),
        "receipts_verify" => {
            let k = match i.get("key_hex") {
                Some(v) if truthy(v) => Some(key(i)?),
                _ => None,
            };
            let lines: Vec<String> = crate::policy::items(i.get("lines"))
                .iter()
                .map(to_str)
                .collect();
            let mut r = verify(&lines, k.as_deref())?.to_value();
            if let Some(reason) = r.get("reason").and_then(Value::as_str) {
                if reason.starts_with("unreadable receipt:") {
                    r["reason"] = json!("unreadable receipt:");
                }
            }
            r
        }
        other => return Err(Error::Invalid(format!("unknown op {other:?}"))),
    })
}
