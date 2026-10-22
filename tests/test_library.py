from __future__ import annotations

import json

import pytest

from kinlock_authority import Action, History, Outcome, Policy, ReceiptChain, Signer, authority_direction, capability_problems, evaluate, issue_capability, may_approve

POLICY = Policy.from_dict({
    "owner": "Mary",
    "timezone": "America/New_York",
    "contacts": [{"id": "anna", "name": "Anna", "relation": "daughter", "ceiling_cents": 100000}],
    "known_merchants": ["Fresh Market"],
    "known_payees": ["Anna"],
    "limits": {"groceries": {"per_action_cents": 12000, "daily_cents": 20000, "daily_count": 3}},
    "default_limits": {"per_action_cents": 5000, "daily_cents": 10000, "daily_count": 3},
    "blocked_categories": ["gift cards"],
    "owner_only_above_cents": 150000,
    "night_hours": [0, 5],
})


def decide(action: Action, channel: str = "voice", frozen: bool = False, history: History | None = None, hour: int = 10):
    return evaluate(action, POLICY, channel=channel, frozen=frozen, history=history or History(), local_hour=hour)


def test_direction():
    assert authority_direction(Action("1", "freeze"), POLICY) == "reduce"
    assert authority_direction(Action("1", "unfreeze"), POLICY) == "increase"
    assert authority_direction(Action("1", "purchase", 100, "x", "y"), POLICY) == "spend"
    assert authority_direction(Action("1", "set_limit", setting="groceries.daily_cents", value=100), POLICY) == "reduce"
    assert authority_direction(Action("1", "set_limit", setting="groceries.daily_cents", value=10**6), POLICY) == "increase"
    assert authority_direction(Action("1", "set_limit", setting="nope", value=1), POLICY) == "unknown"


@pytest.mark.parametrize("channel", ["voice", "contact"])
def test_only_the_owner_raises_authority(channel):
    for a in (Action("1", "unfreeze"), Action("2", "add_merchant", counterparty="X"), Action("3", "set_limit", setting="owner_only_above_cents", value=10**9)):
        assert decide(a, channel).outcome == Outcome.DENY
        assert decide(a, "owner").outcome == Outcome.ALLOW


def test_any_channel_lowers_authority():
    for ch in ("voice", "contact", "owner"):
        assert decide(Action("1", "freeze"), ch).outcome == Outcome.ALLOW


def test_spending_outcomes():
    assert decide(Action("1", "purchase", 4620, "Fresh Market", "groceries")).outcome == Outcome.ALLOW
    assert decide(Action("1", "purchase", 84999, "TechZone", "electronics")).outcome == Outcome.HOLD
    assert decide(Action("1", "purchase", 5000, "Shop", "gift cards")).outcome == Outcome.DENY
    assert decide(Action("1", "purchase", 4620, "Fresh Market", "groceries"), frozen=True).outcome == Outcome.DENY
    assert decide(Action("1", "transfer", 1000, "Stranger", "transfer")).outcome == Outcome.OWNER
    assert decide(Action("1", "purchase", 160000, "Fresh Market", "groceries")).outcome == Outcome.OWNER
    assert decide(Action("1", "purchase", 4620, "Fresh Market", "groceries"), hour=2).outcome == Outcome.HOLD


def test_daily_totals_and_counts():
    h = History({"groceries": 19000}, {"groceries": 1})
    assert decide(Action("1", "purchase", 2000, "Fresh Market", "groceries"), history=h).outcome == Outcome.HOLD
    h = History({"groceries": 100}, {"groceries": 3})
    assert decide(Action("1", "purchase", 100, "Fresh Market", "groceries"), history=h).outcome == Outcome.HOLD


def test_may_approve():
    held = decide(Action("1", "purchase", 84999, "TechZone", "electronics"))
    anna = POLICY.contact("anna")
    assert may_approve(held, role="contact", amount_cents=84999, contact=anna)[0]
    assert not may_approve(held, role="contact", amount_cents=120000, contact=anna)[0]
    owner_only = decide(Action("1", "transfer", 1000, "Stranger", "transfer"))
    assert not may_approve(owner_only, role="contact", amount_cents=1000, contact=anna)[0]
    assert may_approve(owner_only, role="owner", amount_cents=1000)[0]
    denied = decide(Action("1", "purchase", 5000, "Shop", "gift cards"))
    assert not may_approve(denied, role="owner", amount_cents=5000)[0]


def test_decisions_are_deterministic():
    a = Action("1", "purchase", 84999, "TechZone", "electronics")
    assert decide(a).to_dict() == decide(a).to_dict()


def test_capability_is_bound_to_the_exact_action():
    s = Signer(b"k" * 32)
    a = Action("r1", "purchase", 84999, "TechZone", "electronics")
    cap = issue_capability(s, request_id="r1", action_digest=a.digest(), approver="contact:anna", role="contact", ceiling_cents=100000, now=1000.0)
    ok = dict(request_id="r1", current_digest=a.digest(), amount_cents=84999, used=set(), now=1001.0)
    assert capability_problems(s, cap, **ok) == []
    changed = Action("r1", "purchase", 850000, "TechZone", "electronics")
    assert "The request changed after it was approved" in capability_problems(s, cap, **{**ok, "current_digest": changed.digest(), "amount_cents": 850000})
    assert "This approval was already used" in capability_problems(s, cap, **{**ok, "used": {cap.cap_id}})
    assert "This approval has expired" in capability_problems(s, cap, **{**ok, "now": 2000.0})
    assert "This approval belongs to a different request" in capability_problems(s, cap, **{**ok, "request_id": "r2"})
    assert "The approval's signature is not valid" in capability_problems(Signer(b"x" * 32), cap, **ok)


def test_receipt_chain_detects_edits(tmp_path):
    chain = ReceiptChain(tmp_path / "r.jsonl")
    for i in range(3):
        chain.append("decided", {"i": i})
    assert chain.verify().ok
    lines = (tmp_path / "r.jsonl").read_text().splitlines()
    r = json.loads(lines[1])
    r["data"]["i"] = 99
    lines[1] = json.dumps(r)
    (tmp_path / "r.jsonl").write_text("\n".join(lines) + "\n")
    rep = chain.verify()
    assert not rep.ok and rep.broken_at == 1
