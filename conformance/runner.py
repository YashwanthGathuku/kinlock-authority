"""The reference side of the conformance suite.

`run(op, input)` calls the Python implementation and returns plain JSON. The
Rust core (`rust/kinlock-authority-core`, `conformance::run`) and the Go gateway
(through the WASM build) expose the same function with the same JSON, so one
vector file checks all three.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

from kinlock_authority.approvals import Capability, Signer, capability_problems
from kinlock_authority.canonical import canonical, digest
from kinlock_authority.firewall import (
    AgentAction,
    FirewallPolicy,
    Vote,
    conflict_of_interest,
    describe_action,
    evaluate_action,
    may_approve_action,
    release_problems,
    scam_signals,
    tally,
)
from kinlock_authority.policy import Action, History, Policy, evaluate, may_approve
from kinlock_authority.receipts import ReceiptChain, sign_hash


def _history(d: dict[str, Any] | None) -> History:
    d = d or {}
    return History(dict(d.get("spent_cents", {})), dict(d.get("count", {})))


def _decide(i: dict[str, Any]):
    action = AgentAction.from_dict(i["action"])
    policy = Policy.from_dict(i["policy"])
    fw = FirewallPolicy.from_dict(i.get("firewall"))
    d = evaluate_action(action, policy, channel=i["channel"], frozen=bool(i.get("frozen", False)), history=_history(i.get("history")), local_hour=int(i.get("local_hour", 12)), firewall=fw)
    return action, policy, fw, d


def _votes(i: dict[str, Any]) -> list[Vote]:
    return [Vote(str(v["voter"]), str(v["choice"]), str(v.get("comment", ""))) for v in i.get("votes", [])]


FIXTURES_PATH = Path(__file__).resolve().parent / "vectors" / "fixtures.json"


def resolve(i: dict[str, Any], fixtures: dict[str, Any]) -> dict[str, Any]:
    """Replace "@name" values with the shared fixture of that name."""
    return {k: fixtures[v[1:]] if isinstance(v, str) and v.startswith("@") else v for k, v in i.items()}


def run(op: str, i: dict[str, Any]) -> Any:
    try:
        return _run(op, i)
    except ValueError as e:
        return {"error": str(e)}


def _run(op: str, i: dict[str, Any]) -> Any:
    if op == "canonical":
        return {"canonical": canonical(i["value"]).decode("utf-8"), "digest": digest(i["value"])}
    if op == "action_digest":
        a = AgentAction.from_dict(i["action"])
        return {"canonical": canonical({"schema": "kinlock.action/1", **a.to_dict()}).decode("utf-8"), "digest": a.digest()}
    if op == "legacy_action_digest":
        a = Action.from_dict(i["action"])
        return {"canonical": canonical(a.to_dict()).decode("utf-8"), "digest": a.digest()}
    if op == "evaluate":
        d = evaluate(Action.from_dict(i["action"]), Policy.from_dict(i["policy"]), channel=i["channel"], frozen=bool(i.get("frozen", False)), history=_history(i.get("history")), local_hour=int(i.get("local_hour", 12)))
        return d.to_dict()
    if op == "may_approve":
        p = Policy.from_dict(i["policy"])
        d = evaluate(Action.from_dict(i["action"]), p, channel=i["channel"], frozen=bool(i.get("frozen", False)), history=_history(i.get("history")), local_hour=int(i.get("local_hour", 12)))
        ok, why = may_approve(d, role=i["role"], amount_cents=int(i["action"].get("amount_cents", 0)), contact=p.contact(i.get("contact_id", "")))
        return {"ok": ok, "why": why}
    if op == "evaluate_action":
        return _decide(i)[3].to_dict()
    if op == "may_approve_action":
        action, policy, fw, d = _decide(i)
        ok, why = may_approve_action(d, action, approver=i["approver"], role=i["role"], contact=policy.contact(i.get("contact_id", "")), firewall=fw)
        return {"ok": ok, "why": why}
    if op == "tally":
        action, _, fw, d = _decide(i)
        t = tally(d, action, _votes(i), firewall=fw)
        return {"state": t.state, "approvals": list(t.approvals), "problems": list(t.problems), "comments": [list(c) for c in t.comments]}
    if op == "release_problems":
        action, _, fw, d = _decide(i)
        return release_problems(d, action, _votes(i), requested_at=i["requested_at"], now=i["now"], firewall=fw)
    if op == "conflict_of_interest":
        return conflict_of_interest(AgentAction.from_dict(i["action"]), i["approver"], FirewallPolicy.from_dict(i.get("firewall")))
    if op == "describe_action":
        return describe_action(AgentAction.from_dict(i["action"]))
    if op == "scam_signals":
        return sorted(scam_signals(i["text"], FirewallPolicy.from_dict(i["firewall"]) if "firewall" in i else None))
    if op == "capability_sign":
        return Signer(bytes.fromhex(i["key_hex"])).sign(i["payload"])
    if op == "capability_problems":
        signer = Signer(bytes.fromhex(i["key_hex"]))
        return capability_problems(signer, Capability.from_dict(i["capability"]), request_id=i["request_id"], current_digest=i.get("current_digest"), amount_cents=int(i["amount_cents"]), used=set(i.get("used", [])), now=i["now"])
    if op == "receipt_sign_hash":
        return sign_hash(bytes.fromhex(i["key_hex"]), i["hash"])
    if op == "receipts_verify":
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "r.jsonl"
            p.write_text("".join(line + "\n" for line in i["lines"]), encoding="utf-8")
            key = bytes.fromhex(i["key_hex"]) if i.get("key_hex") else None
            r = ReceiptChain(p, key=key).verify()
        reason = r.reason
        # Parser error messages differ between languages; vectors pin only the prefix.
        if reason and reason.startswith("unreadable receipt:"):
            reason = "unreadable receipt:"
        return {"ok": r.ok, "receipts": r.receipts, "head": r.head, "broken_at": r.broken_at, "reason": reason}
    raise KeyError(f"unknown op {op}")


def load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))
