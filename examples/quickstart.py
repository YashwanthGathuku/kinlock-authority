"""Decide what an assistant may do, approve one exact action, and keep a receipt."""

import tempfile
from pathlib import Path

from kinlock_authority import Action, History, Policy, ReceiptChain, Signer, capability_problems, evaluate, issue_capability

policy = Policy.from_dict({
    "owner": "Mary",
    "timezone": "America/New_York",
    "contacts": [{"id": "anna", "name": "Anna", "relation": "daughter", "ceiling_cents": 100000}],
    "known_merchants": ["Fresh Market"],
    "known_payees": [],
    "limits": {"groceries": {"per_action_cents": 12000, "daily_cents": 20000, "daily_count": 3}},
    "default_limits": {"per_action_cents": 5000, "daily_cents": 10000, "daily_count": 3},
    "blocked_categories": ["gift cards"],
    "owner_only_above_cents": 150000,
})

laptop = Action("req_1", "purchase", 84999, "TechZone", "electronics", ("a laptop",))
d = evaluate(laptop, policy, channel="voice", frozen=False, history=History(), local_hour=10)
print(d.outcome.value, d.reasons)  # HOLD ['TechZone is a new shop', ...]

signer = Signer(b"replace-with-32-random-bytes-....")
cap = issue_capability(signer, request_id="req_1", action_digest=laptop.digest(), approver="contact:anna", role="contact", ceiling_cents=100000, now=0.0)
print(capability_problems(signer, cap, request_id="req_1", current_digest=laptop.digest(), amount_cents=84999, used=set(), now=1.0))  # []

print(evaluate(Action("req_2", "unfreeze"), policy, channel="voice", frozen=True, history=History(), local_hour=10).reasons)
# ["Voice can lower authority but can't raise it; only Mary can, from her own secure page"]

# Write receipts to a throwaway directory so running the example never dirties the repo.
chain = ReceiptChain(str(Path(tempfile.mkdtemp(prefix="kinlock-quickstart-")) / "receipts.jsonl"))
chain.append("decided", {"request_id": "req_1", "decision": d.to_dict()})
print(chain.verify().ok)
