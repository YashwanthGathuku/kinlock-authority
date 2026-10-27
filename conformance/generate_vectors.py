"""Write conformance/vectors/*.json from the Python reference implementation.

    PYTHONPATH=src python conformance/generate_vectors.py

Every case stores its input and the exact JSON the reference returns. The Rust
core and the Go gateway must reproduce every expected value byte for byte.
Re-run this after any intentional change to the Python rules and commit the
result together with the matching Rust change.
"""

from __future__ import annotations

import itertools
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "src"))

from runner import resolve, run  # noqa: E402

from kinlock_authority.canonical import digest  # noqa: E402
from kinlock_authority.firewall import DEFAULT_REMOTE_TOOLS, VERBS  # noqa: E402
from kinlock_authority.receipts import GENESIS, sign_hash  # noqa: E402

POLICY = {
    "owner": "Mary",
    "timezone": "America/New_York",
    "contacts": [{"id": "anna", "name": "Anna", "relation": "daughter", "ceiling_cents": 50000}],
    "known_merchants": ["Fresh Market", "Corner Pharmacy"],
    "known_payees": ["Landlord"],
    "limits": {"groceries": {"per_action_cents": 15000, "daily_cents": 30000, "daily_count": 3}},
    "default_limits": {"per_action_cents": 5000, "daily_cents": 10000, "daily_count": 3},
    "blocked_categories": ["gift cards"],
    "owner_only_above_cents": 100000,
    "merchant_categories": {"Fresh Market": "groceries"},
    "night_hours": [0, 5],
}
POLICY_WRAP_NIGHT = {**POLICY, "night_hours": [22, 6]}
POLICY_NO_NIGHT = {**POLICY, "night_hours": None}

FW = {
    "people": [
        {"id": "contact:anna", "name": "Anna", "group": "anna-household", "identifiers": ["anna@example.com", "+15550101"]},
        {"id": "supporter:tom", "name": "Tom", "group": "anna-household"},
        {"id": "supporter:raj", "name": "Raj", "identifiers": ["raj@example.com"]},
    ],
    "standing": {"comms": ["send_message", "place_call"], "health": ["refill_prescription"]},
    "known_targets": {"comms": ["Anna", "Dr Patel"], "home": ["Anna", "Rosa (cleaner)"]},
    "remote_access_allowlist": ["contact:anna"],
    "quorum": {"legal": {"required": 2, "members": ["contact:anna", "supporter:tom", "supporter:raj"], "owner_final": True}},
}
FW_QUORUM_NOT_FINAL = {**FW, "quorum": {"legal": {"required": 2, "members": ["contact:anna", "supporter:raj"], "owner_final": False}, "access": {"required": 2, "members": ["contact:anna", "supporter:raj"], "owner_final": False}}}
FW_SHORT_COOLOFF = {**FW, "identity_cooloff_seconds": 5400}
FW_ONE_HOUR = {**FW, "identity_cooloff_seconds": 3600}

FIXTURES = {"policy": POLICY, "policy_wrap_night": POLICY_WRAP_NIGHT, "policy_no_night": POLICY_NO_NIGHT, "fw": FW, "fw_quorum_not_final": FW_QUORUM_NOT_FINAL, "fw_short_cooloff": FW_SHORT_COOLOFF, "fw_one_hour": FW_ONE_HOUR}

CHANNELS = ["voice", "contact", "owner"]
RISKS = [[], ["inbound_call"], ["unsolicited_call"], ["new_device"]]
REQUESTERS = ["", "owner", "contact:anna", "caller:+18885550000"]

suites: dict[str, list[dict]] = {}


def add(op: str, name: str, inp: dict) -> None:
    expected = run(op, inp)
    # Shared policies are stored once in fixtures.json and referenced as "@name".
    ref = {k: next((f"@{fn}" for fn, fv in FIXTURES.items() if fv is v), v) for k, v in inp.items()}
    assert resolve(ref, FIXTURES) == inp
    suites.setdefault(op, []).append({"name": name, "input": ref, "expected": expected})


def act(rid, category, verb, target="", details=None, **kw):
    return {"request_id": rid, "category": category, "verb": verb, "target": target, "details": details or {}, **kw}


# -- canonical JSON and digests ---------------------------------------------------------------
for n, v in enumerate([
    {}, [], "", 0, -1, 2**53, True, False, None, 1.5, 0.1, 1e-7, 1e16, 123456789.125, -0.0, 1000.0,
    {"b": 1, "a": [3, 2, 1], "c": {"z": None, "y": "x"}},
    {"text": "line\nbreak\ttab \"quoted\" back\\slash \u0001 \u001f \u007f"},
    {"unicode": "Mária 東京 😀 é", "é": 1, "e": 2, "Z": 3, "a": 4, "😀": 5, "東": 6},
    {"nested": [{"k": [1, {"j": [True, None, 2.25]}]}]},
    {"emoji_key_order": {"\U0001F600": 1, "\uFFFF": 2, "\u00e9": 3}},
]):
    add("canonical", f"value_{n}", {"value": v})

base_actions = [
    act("req_1", "identity", "change_recovery_email", "Gmail", {"new_email": "helper99@mail.ru"}, risk=["inbound_call"]),
    act("req_2", "money", "purchase", "Fresh Market", {"category": "groceries", "item": "milk"}, amount_cents=1299),
    act("req_3", "access", "install_software", "AnyDesk", {"reason": "Microsoft support", "z": 1, "a": [1, 2], "m": {"x": None}}, requester="caller:1"),
    act("req_4", "home", "unlock_door", "front door", {"visitor": "Rosa (cleaner)"}, reversible=False, beneficiaries=["Rosa"]),
    act(5, " LEGAL ", " Sign_Document ", "Will", {}, risk=["b", "a", "a"]),
    act("req_6", "comms", "send_message", "Anna", {"text": "Ça va? 😀", "n": 2.5}),
]
for n, a in enumerate(base_actions):
    add("action_digest", f"action_{n}", {"action": a})
for n, a in enumerate([
    {"request_id": "p1", "kind": "purchase", "amount_cents": 1299, "counterparty": "Fresh Market", "category": "groceries", "items": ["milk", "eggs"]},
    {"request_id": "p2", "kind": "set_limit", "setting": "groceries.daily_cents", "value": 100},
    {"request_id": 3, "kind": "freeze"},
]):
    add("legacy_action_digest", f"legacy_{n}", {"action": a})

# -- the original purchase/transfer rules --------------------------------------------------------
legacy_actions = {
    "groceries_ok": {"request_id": "l", "kind": "purchase", "amount_cents": 4000, "counterparty": "Fresh Market", "category": "groceries"},
    "groceries_over": {"request_id": "l", "kind": "purchase", "amount_cents": 20000, "counterparty": "Fresh Market", "category": "groceries"},
    "new_shop": {"request_id": "l", "kind": "purchase", "amount_cents": 2500, "counterparty": "Gadget Hut", "category": "electronics"},
    "claimed_blocked": {"request_id": "l", "kind": "purchase", "amount_cents": 2500, "counterparty": "Gadget Hut", "category": "Gift Cards"},
    "known_claims": {"request_id": "l", "kind": "purchase", "amount_cents": 2500, "counterparty": "Corner Pharmacy", "category": "pharmacy"},
    "keyword_items": {"request_id": "l", "kind": "purchase", "amount_cents": 2500, "counterparty": "Fresh Market", "items": ["Steam-Card 50"]},
    "keyword_merchant": {"request_id": "l", "kind": "purchase", "amount_cents": 2500, "counterparty": "Bitcoin ATM"},
    "keyword_glued": {"request_id": "l", "kind": "purchase", "amount_cents": 2500, "counterparty": "Shop", "items": ["giftcard"]},
    "wireless_fine": {"request_id": "l", "kind": "purchase", "amount_cents": 2500, "counterparty": "Fresh Market", "items": ["wireless headphones"]},
    "zero": {"request_id": "l", "kind": "purchase", "amount_cents": 0, "counterparty": "Fresh Market"},
    "no_merchant": {"request_id": "l", "kind": "purchase", "amount_cents": 100, "counterparty": "  "},
    "huge": {"request_id": "l", "kind": "purchase", "amount_cents": 250000, "counterparty": "Fresh Market", "category": "groceries"},
    "transfer_known": {"request_id": "l", "kind": "transfer", "amount_cents": 3000, "counterparty": "Landlord"},
    "transfer_new": {"request_id": "l", "kind": "transfer", "amount_cents": 3000, "counterparty": "Stranger"},
    "freeze": {"request_id": "l", "kind": "freeze"},
    "unfreeze": {"request_id": "l", "kind": "unfreeze"},
    "add_payee": {"request_id": "l", "kind": "add_payee", "counterparty": "X"},
    "lower_limit": {"request_id": "l", "kind": "set_limit", "setting": "groceries.daily_cents", "value": 100},
    "raise_limit": {"request_id": "l", "kind": "set_limit", "setting": "groceries.daily_cents", "value": 10**6},
    "raise_default": {"request_id": "l", "kind": "set_limit", "setting": "toys.per_action_cents", "value": 9000},
    "raise_owner_threshold": {"request_id": "l", "kind": "set_limit", "setting": "owner_only_above_cents", "value": 200000},
    "lower_ceiling": {"request_id": "l", "kind": "set_limit", "setting": "contact:anna.ceiling_cents", "value": 100},
    "unknown_contact": {"request_id": "l", "kind": "set_limit", "setting": "contact:zed.ceiling_cents", "value": 100},
    "negative_limit": {"request_id": "l", "kind": "set_limit", "setting": "groceries.daily_cents", "value": -5},
    "bad_setting": {"request_id": "l", "kind": "set_limit", "setting": "nope", "value": 1},
    "mystery": {"request_id": "l", "kind": "launch_rockets"},
}
histories = [None, {"spent_cents": {"groceries": 28000}, "count": {"groceries": 3}}, {"spent_cents": {"other": 9000}, "count": {"other": 1}}]
for (name, a), ch, frozen, (pn, pol), hour, (hn, h) in itertools.product(
    legacy_actions.items(), CHANNELS, [False, True], [("night", POLICY), ("wrap", POLICY_WRAP_NIGHT), ("none", POLICY_NO_NIGHT)], [3, 12, 23], enumerate(histories)
):
    if pn != "night" and name not in ("groceries_ok", "new_shop"):
        continue
    if hn and name not in ("groceries_ok", "groceries_over", "new_shop", "transfer_known"):
        continue
    add("evaluate", f"{name}/{ch}/frozen={frozen}/{pn}/h{hour}/hist{hn}", {"action": a, "policy": pol, "channel": ch, "frozen": frozen, "history": h, "local_hour": hour})
add("evaluate", "unknown_channel", {"action": legacy_actions["freeze"], "policy": POLICY, "channel": "sms"})
for name, role, cid in [("groceries_over", "contact", "anna"), ("groceries_over", "owner", ""), ("groceries_over", "stranger", ""), ("transfer_new", "contact", "anna"), ("huge", "contact", "anna"), ("groceries_ok", "contact", "anna"), ("unfreeze", "owner", ""), ("new_shop", "contact", "zed")]:
    add("may_approve", f"{name}/{role}/{cid}", {"action": legacy_actions[name], "policy": POLICY, "channel": "voice", "local_hour": 12, "role": role, "contact_id": cid})
pricey = {**legacy_actions["groceries_over"], "amount_cents": 60000}
add("may_approve", "over_ceiling", {"action": pricey, "policy": POLICY, "channel": "voice", "local_hour": 12, "role": "contact", "contact_id": "anna"})

# -- every category and verb, on every channel, with every risk signal ---------------------------
targets = {"money": "Fresh Market", "access": "Notepad", "identity": "Gmail", "data": "tax return", "health": "Corner Pharmacy", "home": "front door", "legal": "Will", "comms": "Anna"}
cats = list(VERBS) + ["unmapped", "astrology"]
for cat in cats:
    verbs = list(VERBS.get(cat, {})) + ["teleport"]
    for verb, ch, risk, frozen, req in itertools.product(verbs, CHANNELS, RISKS, [False, True], REQUESTERS):
        if req not in ("", "caller:+18885550000") and risk not in ([], ["inbound_call"]):
            continue
        a = act("sweep", cat, verb, targets.get(cat, "thing"), {"category": "groceries"} if cat == "money" else {}, risk=risk, requester=req, amount_cents=4000 if cat == "money" else 0)
        add("evaluate_action", f"sweep/{cat}/{verb}/{ch}/{'+'.join(risk) or '-'}/frozen={frozen}/req={req or '-'}", {"action": a, "policy": POLICY, "firewall": FW, "channel": ch, "frozen": frozen})

scenarios = {
    "anydesk_microsoft": act("s", "access", "install_software", "AnyDesk", {"reason": "Microsoft support says my computer has a virus"}, requester="caller:+18885550000"),
    "anydesk_allowlisted": act("s", "access", "install_software", "AnyDesk", requester="contact:anna"),
    "anydesk_allowlisted_on_call": act("s", "access", "install_software", "AnyDesk", risk=["inbound_call"], requester="contact:anna"),
    "teamviewer_in_details": act("s", "access", "install_software", "helper.exe", {"note": "it's the teamviewer installer"}, requester="contact:anna"),
    "quick_assist_hyphen": act("s", "access", "install_software", "Quick-Assist", requester="contact:anna"),
    "screen_control_no_tool": act("s", "access", "grant_screen_control", "Bob", requester="caller:9"),
    "notepad": act("s", "access", "install_software", "Notepad++", requester="owner"),
    "refund_scam_text": act("s", "data", "share_pii", "Refund Dept", {"note": "they sent you too much, act now"}),
    "irs": act("s", "money", "transfer", "Landlord", {"note": "IRS says pay immediately"}, amount_cents=3000),
    "money_on_call": act("s", "money", "purchase", "Fresh Market", {"category": "groceries"}, risk=["inbound_call"], amount_cents=1000),
    "money_keyword": act("s", "money", "purchase", "Fresh Market", {"category": "groceries", "item": "Google Play card"}, amount_cents=1000),
    "visitor_known": act("s", "home", "unlock_door", "front door", {"visitor": "Rosa (cleaner)"}),
    "visitor_unknown": act("s", "home", "unlock_door", "front door", {"visitor": "Steve"}),
    "visitor_target": act("s", "home", "unlock_door", "Anna"),
    "message_known": act("s", "comms", "send_message", "anna", {"text": "hi"}),
    "message_unknown": act("s", "comms", "send_message", "Stranger", {"text": "hi"}),
    "message_urgent": act("s", "comms", "send_message", "Anna", {"text": "urgent: don't tell anyone"}),
    "refill": act("s", "health", "refill_prescription", "Corner Pharmacy"),
    "book_no_standing": act("s", "health", "book_appointment", "Dr Patel"),
    "recovery_email": act("s", "identity", "change_recovery_email", "Gmail", {"new_email": "anna@example.com"}),
    "poa": act("s", "legal", "grant_power_of_attorney", "Raj", beneficiaries=["supporter:raj"]),
    "beneficiary": act("s", "legal", "change_beneficiary", "Elder Law Partners", requester="contact:anna"),
    "irreversible_claim": act("s", "comms", "add_contact", "Bob", reversible=False),
    "details_types": act("s", "data", "share_document", "x", {"flag": True, "none": None, "n": 3, "f": 2.5, "l": ["a", 1], "d": {"k": "v"}}),
    "unicode_target": act("s", "comms", "send_message", "Dr  PATEL", {"text": "Grüße"}),
}
for (name, a), ch in itertools.product(scenarios.items(), CHANNELS):
    for fwn, fw in [("fw", FW), ("not_final", FW_QUORUM_NOT_FINAL), ("short", FW_SHORT_COOLOFF), ("hour", FW_ONE_HOUR), ("empty", None)]:
        if fwn not in ("fw", "empty") and a["category"] not in ("legal", "identity", "access"):
            continue
        add("evaluate_action", f"scenario/{name}/{ch}/{fwn}", {"action": a, "policy": POLICY, "firewall": fw, "channel": ch, "frozen": False})
add("evaluate_action", "unknown_channel", {"action": scenarios["refill"], "policy": POLICY, "firewall": FW, "channel": "sms"})

# -- approvals ---------------------------------------------------------------------------------
approvers = [("owner", "owner", ""), ("contact:anna", "contact", "anna"), ("supporter:raj", "contact", ""), ("supporter:tom", "contact", ""), ("caller:1", "contact", ""), ("contact:anna", "stranger", "anna")]
for (name, a), (who, role, cid), fwn in itertools.product(scenarios.items(), approvers, ["fw", "not_final"]):
    if fwn == "not_final" and a["category"] not in ("legal", "access"):
        continue
    fw = FW if fwn == "fw" else FW_QUORUM_NOT_FINAL
    add("may_approve_action", f"{name}/{who}/{role}/{fwn}", {"action": a, "policy": POLICY, "firewall": fw, "channel": "voice", "approver": who, "role": role, "contact_id": cid})
for (name, a), (who, _, _) in itertools.product(scenarios.items(), approvers):
    add("conflict_of_interest", f"{name}/{who}", {"action": a, "approver": who, "firewall": FW})

V = lambda voter, choice, comment="": {"voter": voter, "choice": choice, "comment": comment}  # noqa: E731
vote_sets = {
    "none": [],
    "owner": [V("owner", "approve")],
    "anna": [V("contact:anna", "approve")],
    "anna_raj": [V("contact:anna", "approve"), V("supporter:raj", "approve")],
    "anna_tom_collude": [V("contact:anna", "approve"), V("supporter:tom", "approve")],
    "anna_owner": [V("contact:anna", "approve"), V("owner", "approve")],
    "anna_twice": [V("contact:anna", "approve"), V("contact:anna", "approve")],
    "outsider": [V("caller:1", "approve"), V("owner", "approve")],
    "pause": [V("supporter:raj", "pause", "Wait, let me call her"), V("contact:anna", "approve"), V("owner", "approve")],
    "pause_resume": [V("supporter:raj", "pause"), V("supporter:raj", "resume"), V("contact:anna", "approve"), V("owner", "approve")],
    "owner_resume": [V("supporter:raj", "pause"), V("contact:anna", "pause"), V("owner", "resume"), V("owner", "approve"), V("supporter:raj", "approve")],
    "decline_then": [V("contact:anna", "approve"), V("contact:anna", "decline"), V("supporter:raj", "approve"), V("owner", "approve")],
    "owner_decline": [V("contact:anna", "approve"), V("supporter:raj", "approve"), V("owner", "decline")],
    "weird_choice": [V("contact:anna", "maybe"), V("owner", "approve", "fine by me")],
    "raj_conflict": [V("supporter:raj", "approve"), V("owner", "approve")],
}
for (name, a), (vn, votes), fwn in itertools.product(scenarios.items(), vote_sets.items(), ["fw", "not_final"]):
    if fwn == "not_final" and a["category"] not in ("legal", "access"):
        continue
    fw = FW if fwn == "fw" else FW_QUORUM_NOT_FINAL
    add("tally", f"{name}/{vn}/{fwn}", {"action": a, "policy": POLICY, "firewall": fw, "channel": "voice", "votes": votes})
for name, vn, (tn, req, now) in itertools.product(
    ["recovery_email", "poa", "beneficiary", "visitor_known", "message_unknown", "anydesk_microsoft", "refill"], ["none", "owner", "anna", "anna_owner", "pause"], [("early", 1000.0, 1000.5), ("mid", 1000.0, 80000.25), ("after", 1000, 87400), ("way_after", 1000.0, 10**7)]
):
    add("release_problems", f"{name}/{vn}/{tn}", {"action": scenarios[name], "policy": POLICY, "firewall": FW, "channel": "voice", "votes": vote_sets[vn], "requested_at": req, "now": now})

# -- words and scam signals ----------------------------------------------------------------------
for name, a in list(scenarios.items()) + [(f"verb/{v}", act("w", c, v, "")) for c, vs in VERBS.items() for v in vs] + [(f"verb_t/{v}", act("w", c, v, "X")) for c, vs in VERBS.items() for v in vs] + [("money_amount", act("w", "money", "purchase", "Shop", amount_cents=123456789)), ("home_visitor_wrong_cat", act("w", "comms", "send_message", "Anna", {"visitor": "Steve"})), ("negative", act("w", "money", "transfer", "X", amount_cents=-150))]:
    add("describe_action", name, {"action": a})
for n, t in enumerate([
    "", "Hello Anna", "Microsoft Support called", "tech-support line", "TECHNICAL SUPPORT", "my computer has viruses", "hacked!", "pop up warning",
    "security alert", "firewall expired", "refund", "overpaid you", "reimbursement", "they sent you too much", "Your Bank fraud", "the IRS called",
    "SSA", "urgently", "do it right now", "act now", "or your account will close", "dont tell", "keep this secret", "Amazon customer service",
    "virusscan", "techsupport", "bank\nsupport", "Ünïcödé support", "geek squad technician", "police", "policeman",
]):
    add("scam_signals", f"text_{n}", {"text": t})
add("scam_signals", "custom_patterns", {"text": "send the code please", "firewall": {"scam_patterns": {"otp": [r"\bcode\b"], "none": []}}})

for tool in DEFAULT_REMOTE_TOOLS:
    add("evaluate_action", f"remote_tool/{tool}", {"action": act("t", "access", "install_software", tool.title(), requester="contact:anna"), "policy": POLICY, "firewall": FW, "channel": "voice"})

# -- capabilities -----------------------------------------------------------------------------------
KEY = "6b" * 32
OTHER_KEY = "7c" * 32
cap = {"cap_id": "cap_0123456789abcdef", "request_id": "req_1", "action_digest": "ab" * 32, "approver": "contact:anna", "role": "contact", "ceiling_cents": 50000, "nonce": "00" * 16, "issued_at": 1700000000.25, "expires_at": 1700000120.25}
for n, payload in enumerate([cap, {**cap, "issued_at": 1700000000, "expires_at": 1700000120}, {**cap, "approver": "Mária", "nonce": "é"}]):
    add("capability_sign", f"payload_{n}", {"key_hex": KEY, "payload": payload})
sig = run("capability_sign", {"key_hex": KEY, "payload": cap})
good = {**cap, "sig": sig}
checks = {
    "valid": ({}, {}),
    "bad_sig": ({"sig": "00" * 32}, {}),
    "other_key": ({}, {"key_hex": OTHER_KEY}),
    "tampered_ceiling": ({"ceiling_cents": 5000000}, {"amount_cents": 4000000}),
    "used": ({}, {"used": ["cap_0123456789abcdef"]}),
    "expired": ({}, {"now": 1700000120.5}),
    "at_expiry": ({}, {"now": 1700000120.25}),
    "other_request": ({}, {"request_id": "req_2"}),
    "gone": ({}, {"current_digest": None}),
    "changed": ({}, {"current_digest": "cd" * 32}),
    "over_ceiling": ({}, {"amount_cents": 50001}),
    "everything": ({"sig": "zz"}, {"key_hex": OTHER_KEY, "used": ["cap_0123456789abcdef"], "now": 1800000000, "request_id": "x", "current_digest": "00", "amount_cents": 10**9}),
}
for name, (cap_over, args) in checks.items():
    inp = {"key_hex": KEY, "capability": {**good, **cap_over}, "request_id": "req_1", "current_digest": "ab" * 32, "amount_cents": 4000, "used": [], "now": 1700000060.0, **args}
    add("capability_problems", name, inp)

# -- receipts -----------------------------------------------------------------------------------------
add("receipt_sign_hash", "hash", {"key_hex": KEY, "hash": "ab" * 32})


def chain(n: int, key: str | None):
    rows, prev = [], GENESIS
    for seq in range(n):
        body = {"seq": seq, "ts": f"2026-10-27T12:00:0{seq}.000Z", "kind": "decision", "data": {"request_id": f"r{seq}", "outcome": "HOLD", "amount": 12.5, "who": "Mária"}, "prev": prev}
        h = digest(body)
        row = {**body, "hash": h}
        if key:
            row["sig"] = sign_hash(bytes.fromhex(key), h)
        rows.append(row)
        prev = h
    return rows


def lines(rows):
    return [json.dumps(r, ensure_ascii=False) for r in rows]


for key in [None, KEY]:
    tag = "signed" if key else "unsigned"
    rows = chain(4, key)
    cases = {
        "empty": [],
        "good": lines(rows),
        "blank_lines": ["", *lines(rows[:2]), "   ", *lines(rows[2:])],
        "edited_data": lines(rows[:1] + [{**rows[1], "data": {**rows[1]["data"], "outcome": "ALLOW"}}] + rows[2:]),
        "dropped": lines(rows[:1] + rows[2:]),
        "reordered": lines([rows[1], rows[0], *rows[2:]]),
        "relinked": lines(rows[:2] + [{**rows[2], "prev": GENESIS}] + rows[3:]),
        "bad_json": lines(rows[:2]) + ["{not json"] + lines(rows[2:]),
        "extra_key": lines(rows[:1]) + [json.dumps({**rows[1], "extra": 1})],
        "missing_key": lines(rows[:1]) + [json.dumps({k: v for k, v in rows[1].items() if k != "ts"})],
        "not_object": lines(rows[:1]) + ["[1,2,3]"],
        "seq_string": lines(rows[:1]) + [json.dumps({**rows[1], "seq": "1"})],
    }
    if key:
        recomputed, prev = [], GENESIS
        for r in rows:
            body = {k: r[k] for k in ("seq", "ts", "kind", "data", "prev")} | {"prev": prev}
            if r["seq"] == 1:
                body["data"] = {**body["data"], "outcome": "ALLOW"}
            h = digest(body)
            recomputed.append({**body, "hash": h, "sig": r["sig"]})
            prev = h
        cases |= {
            "recomputed_without_key": lines(recomputed),
            "unsigned_row": lines(rows[:1] + [{k: v for k, v in rows[1].items() if k != "sig"}] + rows[2:]),
            "bad_sig": lines(rows[:2] + [{**rows[2], "sig": "00" * 32}] + rows[3:]),
            "sig_not_string": lines(rows[:1] + [{**rows[1], "sig": 5}]),
            "sig_falsy": lines(rows[:1] + [{**rows[1], "sig": 0}]),
        }
    for name, ls in cases.items():
        add("receipts_verify", f"{tag}/{name}", {"key_hex": key, "lines": ls})
    add("receipts_verify", f"{tag}/read_with_other_key", {"key_hex": OTHER_KEY, "lines": lines(chain(2, KEY))})


def main() -> None:
    out = HERE / "vectors"
    out.mkdir(exist_ok=True)
    for old in out.glob("*.json"):  # includes fixtures.json
        old.unlink()
    (out / "fixtures.json").write_text(json.dumps(FIXTURES, ensure_ascii=False, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    total = 0
    for op, cases in sorted(suites.items()):
        body = ",\n".join(json.dumps(c, ensure_ascii=False, sort_keys=True) for c in cases)
        (out / f"{op}.json").write_text(f'{{"op": "{op}", "cases": [\n{body}\n]}}\n', encoding="utf-8")
        total += len(cases)
        print(f"{op}: {len(cases)}")
    print(f"total: {total}")


if __name__ == "__main__":
    main()
