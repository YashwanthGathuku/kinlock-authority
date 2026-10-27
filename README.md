# kinlock-authority

[![CI](https://github.com/YashwanthGathuku/kinlock-authority/actions/workflows/ci.yml/badge.svg)](https://github.com/YashwanthGathuku/kinlock-authority/actions/workflows/ci.yml)

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

## Authority firewall (`kinlock_authority.firewall`)

The same idea, beyond payments. `evaluate_action(AgentAction(...), policy, channel=..., frozen=..., firewall=FirewallPolicy)` decides any agent action in eight categories (money, access, identity, data, health, home, legal, comms):

- **Remote access:** refused on an unsolicited call, with scam wording, or for a requester not on the allowlist; otherwise owner-only.
- **Identity and recovery changes:** owner-only after a 24-hour cool-off.
- **Letting someone in:** owner-only unless the visitor is known.
- **Quorum:** per category, people in one group count once, and the owner can be final.
- **Fail-safe:** unknown categories or verbs are held.

Supporting functions:

- `may_approve_action`, `conflict_of_interest`: nobody may approve an action that names them, benefits them, points at their own email or phone, or that they asked for.
- `tally`, `release_problems`: votes, including pause and resume.
- `describe_action`: one plain sentence describing the action.
- `voice_can_only_lower`: an exhaustive check that voice only lowers.

The JSON action format is specified in kinlock's `docs/PROTOCOL.md`. Money actions go through the original `decide`, so the purchase API is unchanged.

| Claim | Tests |
| --- | --- |
| Remote access on a call, with scam wording, or off the allowlist is refused | `tests/test_firewall_guards.py` |
| Identity changes need the owner after a cool-off, even when she asks | `test_identity_changes_need_the_owner_after_a_cooloff` |
| Conflict of interest and collusion are caught; a quorum can't release an owner-level action without her | `tests/test_firewall_approvals.py` |
| Voice never raises authority, over every category, verb and risk combination | `tests/test_firewall_invariants.py` |

## Languages and architecture

- **Python (`src/kinlock_authority`) is the reference.** Every rule is written here first, and the
  Python tests are the spec.
- **Rust (`rust/kinlock-authority-core`) is the trusted core.** It is a port of the deciding code:
  `canonical`/`digest`, `policy.evaluate` and `may_approve`, the firewall (`evaluate_action`,
  `scam_signals`, `conflict_of_interest`, `may_approve_action`, quorum `tally`, `release_problems`,
  `describe_action`, `voice_can_only_lower`), capability signing and `capability_problems`, and
  receipt `sign_hash` and chain verification. It has `#![forbid(unsafe_code)]` and five dependencies
  (serde_json, hmac, sha2, regex, thiserror). A proptest checks that a voice request never allows an
  increase in authority and is never looser than the owner's own channel.
- **`rust/kinlock-authority-wasm`** wraps the core as a wasm32-unknown-unknown module with one JSON
  call (`kinlock_input`, `kinlock_run`, `kinlock_output`). The Go gateway in the `kinlock` repo
  embeds it. The only `allow(unsafe_code)` is on those three `#[no_mangle]` exports. There are no
  unsafe blocks.
- **Conformance vectors keep them identical.** `conformance/generate_vectors.py` runs the Python
  reference over 7,120 cases (16 operations) and stores the exact JSON it returns. Python
  (`tests/test_conformance.py`), Rust (`rust/kinlock-authority-core/tests/vectors.rs`) and Go must
  reproduce every case byte for byte. CI also checks that the committed vectors are current.

What is not ported, and stays Python-only: `Policy.apply` (policy edits), issuing capabilities
(nonce and clock), appending receipts to a file, approval-state storage, and the CLI. There are no
PyO3 bindings, so Python does not call the Rust core.

Known edges, outside the vectors: Rust `casefold` is a table of Python's special folds on top of
Unicode lowercase, not Python's full table. `isprintable` is an approximation. Scam patterns go
through the Rust `regex` crate, which has no lookaround. Integers beyond 64 bits, and
`NaN`/`Infinity`, are rejected rather than parsed.

## Tests

```bash
pip install pytest && python -m pytest -q
cd rust && cargo test --release   # unit tests, all conformance vectors, voice proptest
```

## License

Apache-2.0.
