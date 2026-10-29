"""The owner's rules and the deterministic decision over one action.

Nothing here calls a model or reads a clock: every input is passed in, so the
same action, rules and history always give the same decision, and tests can
replay any case exactly.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any

from .canonical import digest

# Which way an action moves authority.
REDUCE = "reduce"
INCREASE = "increase"
SPEND = "spend"
UNKNOWN = "unknown"

REDUCING_KINDS = frozenset({"freeze", "cancel_pending", "remove_merchant", "remove_payee", "block_category", "remove_contact"})
INCREASING_KINDS = frozenset({"unfreeze", "add_merchant", "add_payee", "unblock_category", "add_contact"})
SPENDING_KINDS = frozenset({"purchase", "transfer"})
SET_LIMIT = "set_limit"  # direction depends on the new value versus the current one

# Channels, from least to most assurance. Voice is the least: anyone in the
# room can speak, a recording can be played, a caller can coach.
VOICE = "voice"
CONTACT = "contact"
OWNER = "owner"
CHANNELS = (VOICE, CONTACT, OWNER)


# Words that mark a purchase as a scam favourite no matter what category the
# caller claims: gift cards, crypto, wires, prepaid and money-order products.
# Matched as whole words against the merchant, the items and the category, so
# "wireless headphones" is fine and "Bitcoin ATM voucher" is not.
DEFAULT_BLOCKED_KEYWORDS = (
    "gift card", "gift cards", "giftcard", "giftcards", "gift voucher", "steam card", "itunes card", "google play card",
    "crypto", "cryptocurrency", "bitcoin", "btc", "ethereum", "eth", "usdt", "tether", "coinbase", "binance",
    "wire", "wire transfer", "western union", "moneygram", "money order", "prepaid", "prepaid card", "reload card",
)
OTHER = "other"


def _keyword_pattern(words) -> re.Pattern[str]:
    alts = sorted({" ".join(w.casefold().split()) for w in words if w.strip()}, key=len, reverse=True)
    # Allow any run of spaces, hyphens or nothing between the words of a phrase ("gift-card", "giftcard").
    body = "|".join(r"[\s\-_]*".join(re.escape(part) for part in a.split(" ")) for a in alts)
    return re.compile(r"(?<![a-z0-9])(?:" + body + r")(?![a-z0-9])") if alts else re.compile(r"(?!x)x")


class Outcome(str, Enum):
    ALLOW = "ALLOW"  # runs now
    HOLD = "HOLD"  # waits for the trusted contact (or the owner)
    OWNER = "OWNER"  # waits for the owner herself
    DENY = "DENY"  # does not run; no approval can change that


def money(cents: int) -> str:
    sign = "-" if cents < 0 else ""
    cents = abs(int(cents))
    dollars, rest = divmod(cents, 100)
    return f"{sign}${dollars:,}" + (f".{rest:02d}" if rest else "")


@dataclass(frozen=True)
class Action:
    """A structured request. The assistant fills it; it never decides it."""

    request_id: str
    kind: str
    amount_cents: int = 0
    counterparty: str = ""  # merchant for a purchase, payee for a transfer
    category: str = ""
    items: tuple[str, ...] = ()
    setting: str = ""  # for set_limit, e.g. "groceries.daily_cents"
    value: int = 0  # for set_limit, or the subject of add/remove kinds is in counterparty/category

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "kind": self.kind,
            "amount_cents": int(self.amount_cents),
            "counterparty": self.counterparty,
            "category": self.category,
            "items": list(self.items),
            "setting": self.setting,
            "value": int(self.value),
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Action:
        return cls(
            request_id=str(d["request_id"]),
            kind=str(d["kind"]),
            amount_cents=int(d.get("amount_cents", 0)),
            counterparty=str(d.get("counterparty", "")),
            category=str(d.get("category", "")),
            items=tuple(str(i) for i in d.get("items", ())),
            setting=str(d.get("setting", "")),
            value=int(d.get("value", 0)),
        )

    def digest(self) -> str:
        """What an approval is bound to. Change any field and the digest changes."""
        return digest(self.to_dict())


@dataclass(frozen=True)
class Limits:
    per_action_cents: int
    daily_cents: int
    daily_count: int


@dataclass(frozen=True)
class Contact:
    id: str
    name: str
    relation: str
    ceiling_cents: int  # the most this person may approve in one action


@dataclass(frozen=True)
class Policy:
    """Rules the owner set for herself. Only the owner channel may loosen them."""

    owner: str
    timezone: str
    contacts: tuple[Contact, ...]
    known_merchants: frozenset[str]
    known_payees: frozenset[str]
    limits: dict[str, Limits]
    default_limits: Limits
    blocked_categories: frozenset[str]
    owner_only_above_cents: int
    night_hours: tuple[int, int] | None = (0, 5)  # [start, end) local hours that hold spending
    # merchant (normalised) -> category. The category of a purchase comes from
    # here, never from the caller; unknown merchants get OTHER (default limits).
    merchant_categories: dict[str, str] = field(default_factory=dict)
    blocked_keywords: tuple[str, ...] = DEFAULT_BLOCKED_KEYWORDS

    @staticmethod
    def _norm(s: str) -> str:
        return " ".join(s.casefold().split())

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Policy:
        lim = lambda x: Limits(int(x["per_action_cents"]), int(x["daily_cents"]), int(x["daily_count"]))  # noqa: E731
        night = d.get("night_hours", [0, 5])
        return cls(
            owner=str(d["owner"]),
            timezone=str(d.get("timezone", "UTC")),
            contacts=tuple(Contact(str(c["id"]), str(c["name"]), str(c.get("relation", "")), int(c["ceiling_cents"])) for c in d.get("contacts", [])),
            known_merchants=frozenset(cls._norm(m) for m in d.get("known_merchants", [])),
            known_payees=frozenset(cls._norm(p) for p in d.get("known_payees", [])),
            limits={cls._norm(str(k)): lim(v) for k, v in d.get("limits", {}).items()},
            default_limits=lim(d["default_limits"]),
            blocked_categories=frozenset(cls._norm(c) for c in d.get("blocked_categories", [])),
            owner_only_above_cents=int(d["owner_only_above_cents"]),
            night_hours=(int(night[0]), int(night[1])) if night else None,
            merchant_categories={cls._norm(str(k)): cls._norm(str(v)) for k, v in d.get("merchant_categories", {}).items()},
            blocked_keywords=tuple(str(w) for w in d.get("blocked_keywords", DEFAULT_BLOCKED_KEYWORDS)),
        )

    def to_dict(self) -> dict[str, Any]:
        lim = lambda x: {"per_action_cents": x.per_action_cents, "daily_cents": x.daily_cents, "daily_count": x.daily_count}  # noqa: E731
        return {
            "owner": self.owner,
            "timezone": self.timezone,
            "contacts": [{"id": c.id, "name": c.name, "relation": c.relation, "ceiling_cents": c.ceiling_cents} for c in self.contacts],
            "known_merchants": sorted(self.known_merchants),
            "known_payees": sorted(self.known_payees),
            "limits": {k: lim(v) for k, v in sorted(self.limits.items())},
            "default_limits": lim(self.default_limits),
            "blocked_categories": sorted(self.blocked_categories),
            "owner_only_above_cents": self.owner_only_above_cents,
            "night_hours": list(self.night_hours) if self.night_hours else None,
            "merchant_categories": dict(sorted(self.merchant_categories.items())),
            "blocked_keywords": list(self.blocked_keywords),
        }

    def resolve_category(self, action: Action) -> str:
        """The category the rules use for a spending action. The caller's word is never trusted.

        Transfers are always "transfer". A purchase takes its merchant's category
        from the owner's catalog (`merchant_categories`). A merchant the owner
        already trusts (`known_merchants`) but never mapped keeps the claimed
        category, for policies written before the catalog existed. Any other
        merchant is OTHER, with the default limits, unless the caller itself named
        a blocked category: a caller may make things stricter, never looser.
        """
        if action.kind == "transfer":
            return "transfer"
        mapped = self.merchant_categories.get(self._norm(action.counterparty))
        if mapped:
            return mapped
        claimed = self._norm(action.category)
        if claimed in self.blocked_categories:
            return claimed
        if claimed and self._norm(action.counterparty) in self.known_merchants:
            return claimed
        return OTHER

    def blocked_keyword(self, action: Action) -> str | None:
        """The first blocked keyword found in the merchant, items or claimed category, if any."""
        text = " ".join([action.counterparty, action.category, *action.items]).casefold()
        m = _keyword_pattern(self.blocked_keywords).search(text)
        return m.group(0) if m else None

    def limits_for(self, category: str) -> Limits:
        return self.limits.get(self._norm(category), self.default_limits)

    def contact(self, contact_id: str) -> Contact | None:
        return next((c for c in self.contacts if c.id == contact_id), None)

    # -- settings a set_limit action can name ---------------------------------
    def setting_value(self, setting: str) -> int | None:
        """Current value of a numeric setting, or None if the name is unknown."""
        if setting == "owner_only_above_cents":
            return self.owner_only_above_cents
        head, _, tail = setting.rpartition(".")
        if head.startswith("contact:"):
            c = self.contact(head[len("contact:") :])
            return c.ceiling_cents if c and tail == "ceiling_cents" else None
        if tail in ("per_action_cents", "daily_cents", "daily_count") and head:
            return int(getattr(self.limits_for(head), tail))
        return None

    def with_setting(self, setting: str, value: int) -> Policy:
        if setting == "owner_only_above_cents":
            return replace(self, owner_only_above_cents=value)
        head, _, tail = setting.rpartition(".")
        if head.startswith("contact:"):
            cid = head[len("contact:") :]
            return replace(self, contacts=tuple(replace(c, ceiling_cents=value) if c.id == cid else c for c in self.contacts))
        cur = self.limits_for(head)
        limits = dict(self.limits)
        limits[self._norm(head)] = replace(cur, **{tail: value})
        return replace(self, limits=limits)

    def apply(self, action: Action) -> Policy:
        """The policy after an allowed rule-changing action."""
        n = self._norm
        k = action.kind
        if k == SET_LIMIT:
            return self.with_setting(action.setting, action.value)
        if k == "add_merchant":
            return replace(self, known_merchants=self.known_merchants | {n(action.counterparty)})
        if k == "remove_merchant":
            return replace(self, known_merchants=self.known_merchants - {n(action.counterparty)})
        if k == "add_payee":
            return replace(self, known_payees=self.known_payees | {n(action.counterparty)})
        if k == "remove_payee":
            return replace(self, known_payees=self.known_payees - {n(action.counterparty)})
        if k == "block_category":
            return replace(self, blocked_categories=self.blocked_categories | {n(action.category)})
        if k == "unblock_category":
            return replace(self, blocked_categories=self.blocked_categories - {n(action.category)})
        if k == "remove_contact":
            return replace(self, contacts=tuple(c for c in self.contacts if c.id != action.counterparty))
        return self


@dataclass(frozen=True)
class History:
    """What already ran today, in the owner's time zone. Built from receipts."""

    spent_cents: dict[str, int] = field(default_factory=dict)  # category -> cents executed today
    count: dict[str, int] = field(default_factory=dict)  # category -> actions executed today


@dataclass(frozen=True)
class Check:
    code: str
    ok: bool
    text: str


@dataclass(frozen=True)
class Decision:
    outcome: Outcome
    direction: str
    checks: tuple[Check, ...]

    @property
    def reasons(self) -> list[str]:
        return [c.text for c in self.checks if not c.ok]

    def to_dict(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome.value,
            "direction": self.direction,
            "checks": [{"code": c.code, "ok": c.ok, "text": c.text} for c in self.checks],
        }


def authority_direction(action: Action, policy: Policy) -> str:
    if action.kind in REDUCING_KINDS:
        return REDUCE
    if action.kind in INCREASING_KINDS:
        return INCREASE
    if action.kind in SPENDING_KINDS:
        return SPEND
    if action.kind == SET_LIMIT:
        current = policy.setting_value(action.setting)
        if current is None or action.value < 0:
            return UNKNOWN
        return REDUCE if action.value <= current else INCREASE
    return UNKNOWN


def evaluate(action: Action, policy: Policy, *, channel: str, frozen: bool, history: History, local_hour: int) -> Decision:
    """Decide one action. Pure: same inputs, same decision."""
    if channel not in CHANNELS:
        raise ValueError(f"unknown channel {channel!r}")
    direction = authority_direction(action, policy)

    if direction == UNKNOWN:
        return Decision(Outcome.DENY, direction, (Check("known", False, "Kinlock doesn't recognise this action, so it won't run it"),))

    if direction == REDUCE:
        return Decision(Outcome.ALLOW, direction, (Check("direction", True, "This only lowers authority, so any channel may do it"),))

    if direction == INCREASE:
        if channel == OWNER:
            return Decision(Outcome.ALLOW, direction, (Check("direction", True, "The owner raised her own limits"),))
        who = "Voice" if channel == VOICE else "A trusted contact"
        text = f"{who} can lower authority but can't raise it; only {policy.owner} can, from her own secure page"
        return Decision(Outcome.DENY, direction, (Check("direction", False, text),))

    # Spending. Hard rules first: nothing can approve past these.
    checks: list[Check] = []
    amount = int(action.amount_cents)
    category = policy.resolve_category(action)
    who = Policy._norm(action.counterparty)
    checks.append(Check("lock", not frozen, "Safety lock is on" if frozen else "Safety lock is off"))
    blocked = category in policy.blocked_categories
    label = category[0].upper() + category[1:]
    checks.append(Check("category", not blocked, f"{label} are always blocked" if blocked else f"{label} isn't a blocked category"))
    hit = policy.blocked_keyword(action)
    if hit:
        checks.append(Check("keywords", False, f"Requests mentioning {hit!r} are always blocked: gift cards, crypto, wires and prepaid cards are what scammers ask for"))
    if amount <= 0:
        checks.append(Check("amount", False, "The amount must be more than zero"))
    if not who:
        checks.append(Check("counterparty", False, "No merchant or payee was named"))
    if any(not c.ok for c in checks):
        return Decision(Outcome.DENY, direction, tuple(checks))

    # Owner-only rules: a trusted contact can't approve these.
    owner_only = False
    if action.kind == "transfer":
        known = who in policy.known_payees
        checks.append(Check("payee", known, f"{action.counterparty} is a known payee" if known else f"{action.counterparty} is a new payee; only {policy.owner} can approve that"))
        owner_only |= not known
    over = amount > policy.owner_only_above_cents
    checks.append(Check("owner_threshold", not over, f"Over {money(policy.owner_only_above_cents)} needs {policy.owner} herself" if over else f"Under {money(policy.owner_only_above_cents)}"))
    owner_only |= over

    # Routine rules: outside them, the action waits for a person.
    lim = policy.limits_for(category)
    if action.kind == "purchase":
        known = who in policy.known_merchants
        checks.append(Check("merchant", known, f"{action.counterparty} is a usual shop" if known else f"{action.counterparty} is a new shop"))
    within = amount <= lim.per_action_cents
    checks.append(Check("per_action", within, f"{money(amount)} is within the {money(lim.per_action_cents)} per-order limit" if within else f"{money(amount)} is over the {money(lim.per_action_cents)} per-order limit"))
    spent = history.spent_cents.get(category, 0)
    total_ok = spent + amount <= lim.daily_cents
    checks.append(Check("daily_total", total_ok, f"Today's {category} total stays within {money(lim.daily_cents)}" if total_ok else f"Today's {category} total would reach {money(spent + amount)}, over {money(lim.daily_cents)}"))
    n = history.count.get(category, 0)
    count_ok = n + 1 <= lim.daily_count
    checks.append(Check("daily_count", count_ok, f"Order {n + 1} of {lim.daily_count} allowed today" if count_ok else f"That would be order {n + 1} today; the limit is {lim.daily_count}"))
    if policy.night_hours:
        a, b = policy.night_hours
        late = a <= local_hour < b if a <= b else (local_hour >= a or local_hour < b)
        checks.append(Check("hours", not late, f"Late-night request ({a:02d}:00 to {b:02d}:00)" if late else "Normal hours"))

    if owner_only:
        return Decision(Outcome.OWNER, direction, tuple(checks))
    if any(not c.ok for c in checks):
        return Decision(Outcome.HOLD, direction, tuple(checks))
    return Decision(Outcome.ALLOW, direction, tuple(checks))


def may_approve(decision: Decision, *, role: str, amount_cents: int, contact: Contact | None = None) -> tuple[bool, str]:
    """Whether a person in `role` may release an action the rules held."""
    if decision.outcome == Outcome.ALLOW:
        return True, "No approval needed"
    if decision.outcome == Outcome.DENY:
        return False, "The rules block this action; no approval can release it"
    if role == OWNER:
        return True, "The owner approved"
    if role != CONTACT or contact is None:
        return False, "Only the owner or her trusted contact can approve"
    if decision.outcome == Outcome.OWNER:
        return False, "This needs the owner herself; a trusted contact can't approve it"
    if amount_cents > contact.ceiling_cents:
        return False, f"{contact.name} may approve up to {money(contact.ceiling_cents)}; this is {money(amount_cents)}"
    return True, f"{contact.name} approved"
