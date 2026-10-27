# kinlock-authority

**Deterministic authority for actions an AI assistant asks to take.** No model in the loop, no dependencies.

By Yashwanth Gathuku. Extracted from [Kinlock](https://github.com/YashwanthGathuku/kinlock), an Alexa+ MCP add-on, so any assistant, agent framework or MCP server can use the same rules.

An assistant turns "order the laptop from TechZone" into a structured `Action`. This library decides whether that action may run, and if a person must approve it, makes sure the approval can only ever release that one exact action.

## Three ideas

**1. Authority direction.** Every action lowers authority (freeze, cancel, lower a limit, remove a shop), raises it (unfreeze, raise a limit, add a shop or contact) or spends. A low-assurance channel such as voice may lower authority freely and can never raise it. Stopping is easy; loosening needs the owner.

| Channel | Lower authority | Spend | Raise authority |
| --- | --- | --- | --- |
| voice | yes | if the rules allow | never |
| trusted contact | yes | approves held actions up to her ceiling | never |
| owner | yes | approves held and owner-only actions | yes |

**2. Exact-action approvals.** A held action is released by a capability: an HMAC-SHA256 signature over the action's canonical digest, the request id, the approver, the approver's ceiling, a nonce and an expiry. `capability_problems()` lists every reason it can't release an action: bad signature, already used, expired, wrong request, the action changed, or over the ceiling.

**3. Hash-chained receipts.** `ReceiptChain` appends JSON receipts whose hash covers the previous one. `verify()` reports exactly where an edit, drop or reorder broke the chain. Pass a secret key, `ReceiptChain(path, key=secret)`, and every receipt also carries `sig`, an HMAC-SHA256 of its hash, so someone who rewrites the file and recomputes every hash is still caught. Without a key the chain is hash-only, exactly as before. A keyed chain requires every receipt to be signed, so a log written before you added the key will not verify under it: start a new log, or keep verifying the old one without a key.

## Decisions

`evaluate(action, policy, channel=..., frozen=..., history=..., local_hour=...)` is a pure function. It returns `ALLOW`, `HOLD` (a trusted contact may approve), `OWNER` (only the owner may) or `DENY` (nothing can release it), with every check and its plain-English reason:

- hard rules: safety lock, blocked categories, scam keywords, valid amount
- owner-only rules: new payees, amounts over the owner's line
- routine rules: known shop, per-action limit, daily total, daily count (so splitting one large order into small ones is caught), late-night hours

### The category comes from the owner, not the caller

An assistant (or whoever is coaching it) could call a gift-card purchase `other` to slip past a blocked category. So `evaluate` never trusts `action.category` on its own:

- `Policy.merchant_categories` maps each merchant to its category, and that mapping wins.
- A merchant in `known_merchants` that has no mapping keeps the category the caller gave. This keeps policies written before the mapping existed working.
- Any other merchant is judged as `other`, with the default limits. The one exception: if the caller names a blocked category itself, that category is used, because a caller may make things stricter but never looser.
- The merchant, item text and claimed category are scanned for `blocked_keywords`: gift cards, crypto and bitcoin, wire transfers, prepaid and money orders by default. Matches are whole words, so "wireless" is not a match. Any match is a `DENY` that no approval can release.

## Use it

```bash
pip install git+https://github.com/YashwanthGathuku/kinlock-authority
python examples/quickstart.py
```

```python
from kinlock_authority import Action, History, Policy, evaluate

d = evaluate(Action("req_1", "purchase", 84999, "TechZone", "electronics"), policy,
             channel="voice", frozen=False, history=History(), local_hour=10)
d.outcome   # Outcome.HOLD
d.reasons   # ['TechZone is a new shop', '$849.99 is over the $50 per-order limit', ...]
```

## Tests

```bash
pip install pytest && python -m pytest -q
```

## License

Apache-2.0.
