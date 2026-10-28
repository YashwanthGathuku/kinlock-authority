"""The authority firewall: one decision for every consequential action, not only payments.

An assistant (or an MCP gateway in front of other tools) describes what it wants
to do as an `AgentAction`: a category, a verb, a target, free-form details, risk
signals, who asked and who would benefit. `evaluate_action` returns the same four
outcomes as purchases (ALLOW / HOLD / OWNER / DENY) and keeps the same invariant:
a low-assurance channel such as voice may lower authority freely and may never
raise it on its own.

Built-in guards, all deterministic and pure:

* Remote access. Installing or launching a remote-access tool, or handing over
  screen control, is DENIED when the request comes during or after an inbound
  unsolicited call, when the requester is not on the owner's allowlist, or when
  the text carries scam patterns ("Microsoft support", "refund", "virus").
  Otherwise only the owner can approve it.
* Identity and recovery. Password, recovery email or phone, 2FA, benefits direct
  deposit, mailing address, new devices: always the owner, and only after a
  cool-off (default 24 hours) has passed since the request.
* Conflict of interest. Nobody may approve an action they asked for or that
  targets or benefits them, so a trusted contact can't approve pointing Mary's
  recovery email at their own address.
* Quorum (supported decision-making). The owner can require, say, 2 of 3 people
  for chosen categories. Supporters may pause and comment; where the owner is
  final, supporters can never release an action without her. People in the same
  `group` (for example one household) count once, so two of them can't collude to
  make a quorum.

Money actions keep the original rules exactly: `evaluate_action` hands
purchases and transfers to `policy.evaluate`, so every existing limit, keyword
block and approval ceiling still applies.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable

from .canonical import digest
from .policy import (
    CHANNELS,
    CONTACT,
    INCREASE,
    OWNER,
    REDUCE,
    SPEND,
    UNKNOWN,
    VOICE,
    Action,
    Check,
    Contact,
    History,
    Outcome,
    Policy,
    _keyword_pattern,
    evaluate,
    may_approve,
    money,
)

USE = "use"  # acts within authority the owner already granted (send a message to a known contact)

MONEY, ACCESS, IDENTITY, DATA, HEALTH, HOME, LEGAL, COMMS = "money", "access", "identity", "data", "health", "home", "legal", "comms"
CATEGORIES = (MONEY, ACCESS, IDENTITY, DATA, HEALTH, HOME, LEGAL, COMMS)

# Outcome strictness, for "at least this strict" floors.
RANK = {Outcome.ALLOW: 0, Outcome.HOLD: 1, Outcome.OWNER: 2, Outcome.DENY: 3}

# category -> verb -> (direction, reversible). Reversible means the owner can
# undo it afterwards without anyone else's help; an irreversible change that
# raises authority always needs the owner.
VERBS: dict[str, dict[str, tuple[str, bool]]] = {
    MONEY: {
        "purchase": (SPEND, True),
        "transfer": (SPEND, False),
        "freeze": (REDUCE, True),
        "cancel_pending": (REDUCE, True),
    },
    ACCESS: {
        "install_software": (INCREASE, True),
        "launch_remote_tool": (INCREASE, False),
        "grant_screen_control": (INCREASE, False),
        "share_screen": (INCREASE, False),
        "start_remote_session": (INCREASE, False),
        "add_admin_user": (INCREASE, True),
        "uninstall_software": (REDUCE, True),
        "end_remote_session": (REDUCE, True),
        "stop_screen_share": (REDUCE, True),
        "revoke_access": (REDUCE, True),
    },
    IDENTITY: {
        "change_password": (INCREASE, True),
        "change_recovery_email": (INCREASE, True),
        "change_recovery_phone": (INCREASE, True),
        "change_2fa": (INCREASE, True),
        "disable_2fa": (INCREASE, True),
        "change_direct_deposit": (INCREASE, True),
        "change_address": (INCREASE, True),
        "add_device": (INCREASE, True),
        "add_authorized_user": (INCREASE, True),
        "lock_account": (REDUCE, True),
        "sign_out_everywhere": (REDUCE, True),
        "freeze_credit": (REDUCE, True),
    },
    DATA: {
        "share_document": (INCREASE, False),
        "share_pii": (INCREASE, False),
        "grant_data_access": (INCREASE, True),
        "export_data": (INCREASE, False),
        "revoke_share": (REDUCE, True),
    },
    HEALTH: {
        "refill_prescription": (USE, True),
        "book_appointment": (USE, True),
        "cancel_appointment": (INCREASE, True),
        "share_records": (INCREASE, False),
        "change_medication": (INCREASE, True),
        "grant_health_proxy": (INCREASE, True),
    },
    HOME: {
        "unlock_door": (INCREASE, True),
        "disable_alarm": (INCREASE, True),
        "open_garage": (INCREASE, True),
        "add_access_code": (INCREASE, True),
        "lock_door": (REDUCE, True),
        "arm_alarm": (REDUCE, True),
        "close_garage": (REDUCE, True),
        "remove_access_code": (REDUCE, True),
    },
    LEGAL: {
        "sign_document": (INCREASE, False),
        "grant_power_of_attorney": (INCREASE, False),
        "change_beneficiary": (INCREASE, True),
        "accept_terms": (INCREASE, True),
    },
    COMMS: {
        "send_message": (USE, False),
        "place_call": (USE, True),
        "add_contact": (INCREASE, True),
        "forward_mail": (INCREASE, True),
        "set_call_forwarding": (INCREASE, True),
        "block_sender": (REDUCE, True),
        "mute_contact": (REDUCE, True),
    },
}

# Verbs the identity guard covers: these can hand an account to someone else.
IDENTITY_CHANGES = frozenset(v for v, (d, _) in VERBS[IDENTITY].items() if d == INCREASE)
# Verbs that hand over control of the screen or the machine.
SCREEN_CONTROL = frozenset({"launch_remote_tool", "grant_screen_control", "share_screen", "start_remote_session"})

DEFAULT_REMOTE_TOOLS = (
    "anydesk", "teamviewer", "ultraviewer", "quick assist", "quickassist", "screenconnect", "connectwise", "connectwise control",
    "logmein", "logmein rescue", "gotoassist", "goto resolve", "zoho assist", "rustdesk", "splashtop", "supremo", "ammyy", "ammyy admin",
    "chrome remote desktop", "remote desktop", "remotepc", "aeroadmin", "ultravnc", "tightvnc", "realvnc", "vnc viewer", "bomgar",
    "beyondtrust", "dwservice", "action1", "atera", "iperius remote", "getscreen", "hoptodesk", "remoteutilities", "remote utilities",
)

# Scam patterns, as risk signals. A label maps to regexes over the request text.
DEFAULT_SCAM_PATTERNS: dict[str, tuple[str, ...]] = {
    "tech_support": (
        r"\btech(nical)?[\s-]*support\b", r"\bhelp[\s-]*desk\b", r"\bvirus(es)?\b", r"\bmalware\b", r"\bhack(ed|er|ers)?\b",
        r"\b(infected|compromised)\b", r"\bpop[\s-]*up\b", r"\bsecurity (alert|warning)\b", r"\bfirewall (expired|warning)\b",
    ),
    "refund": (r"\brefunds?\b", r"\boverpa(id|yment)\b", r"\breimburse(ment)?\b", r"\bsent you too much\b"),
    "impersonation": (
        (r"\b(microsoft|windows|apple|icloud|amazon|geek squad|norton|mcafee|paypal|google|meta|facebook|your bank|bank)\s+"
        r"(support|security|team|help|department|technician|agent|fraud|customer service)\b"),
        r"\b(irs|social security|ssa|medicare|fbi|police|sheriff)\b",
    ),
    "urgency": (r"\burgent(ly)?\b", r"\bimmediately\b", r"\bright now\b", r"\bact now\b", r"\bor (your|the) account will\b", r"\bdon'?t tell\b", r"\bkeep (this|it) (secret|between us)\b"),
}

# Risk signals the caller or gateway may attach. "inbound_call" means the request
# comes during, or within the owner's window after, an inbound call she didn't
# place; "unsolicited_call" is the same with the caller not in her contacts.
CALL_SIGNALS = frozenset({"inbound_call", "unsolicited_call"})


@dataclass(frozen=True)
class AgentAction:
    """One consequential action an agent wants to take, in any category."""

    request_id: str
    category: str
    verb: str
    target: str = ""  # the thing acted on: an app, an account field, a door, a recipient
    details: dict[str, Any] = field(default_factory=dict)  # free-form; scanned for risk, bound into the digest
    risk: frozenset[str] = frozenset()  # signals from the caller or gateway, e.g. {"inbound_call"}
    reversible: bool = True  # the caller's claim; the verb table can only make it stricter
    requester: str = ""  # who asked: "owner", "caller:+15550100", "contact:anna"
    beneficiaries: tuple[str, ...] = ()  # people who would gain access or money from this
    amount_cents: int = 0  # money actions only

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "category": self.category,
            "verb": self.verb,
            "target": self.target,
            "details": {str(k): self.details[k] for k in sorted(self.details, key=str)},
            "risk": sorted(self.risk),
            "reversible": bool(self.reversible),
            "requester": self.requester,
            "beneficiaries": list(self.beneficiaries),
            "amount_cents": int(self.amount_cents),
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "AgentAction":
        return cls(
            request_id=str(d["request_id"]),
            category=str(d.get("category", "")).strip().casefold(),
            verb=str(d.get("verb", "")).strip().casefold(),
            target=str(d.get("target", "")),
            details=dict(d.get("details") or {}),
            risk=frozenset(str(r) for r in d.get("risk", ())),
            reversible=bool(d.get("reversible", True)),
            requester=str(d.get("requester", "")),
            beneficiaries=tuple(str(b) for b in d.get("beneficiaries", ())),
            amount_cents=int(d.get("amount_cents", 0)),
        )

    def digest(self) -> str:
        """What an approval is bound to. Change any field, a detail or a risk flag and it changes."""
        return digest({"schema": "kinlock.action/1", **self.to_dict()})

    def text(self) -> str:
        """Everything a person or scammer wrote into the request, for the scanners."""
        parts = [self.verb.replace("_", " "), self.target, *(f"{k} {v}" for k, v in self.details.items())]
        return " ".join(str(p) for p in parts).casefold()

    def legacy(self) -> Action:
        """The purchase/transfer `Action` this money action corresponds to."""
        item = self.details.get("item")
        return Action(
            request_id=self.request_id,
            kind=self.verb,
            amount_cents=int(self.amount_cents),
            counterparty=self.target,
            category=str(self.details.get("category", "")),
            items=(str(item),) if item else (),
        )


@dataclass(frozen=True)
class Person:
    """Someone who may vote on held actions: the owner's supporters and trusted contacts."""

    id: str  # "contact:anna", "supporter:raj"
    name: str
    group: str = ""  # people in one group (a household, a firm) count once toward a quorum
    identifiers: tuple[str, ...] = ()  # their emails, phones, devices: a target naming one is a conflict


@dataclass(frozen=True)
class Quorum:
    required: int  # approvals needed, counting the owner
    members: tuple[str, ...]  # who may vote besides the owner
    owner_final: bool = True  # the owner must be one of the approvals


@dataclass(frozen=True)
class FirewallPolicy:
    """The owner's rules for non-money actions. Loosening them is an owner-channel act."""

    people: tuple[Person, ...] = ()
    standing: dict[str, frozenset[str]] = field(default_factory=dict)  # category -> verbs allowed without asking
    known_targets: dict[str, frozenset[str]] = field(default_factory=dict)  # category -> targets she knows (contacts, visitors)
    remote_access_allowlist: frozenset[str] = frozenset()  # requesters who may ask for remote access at all
    owner_only_categories: frozenset[str] = frozenset({IDENTITY, LEGAL})
    identity_cooloff_seconds: int = 24 * 3600
    quorum: dict[str, Quorum] = field(default_factory=dict)
    remote_tools: tuple[str, ...] = DEFAULT_REMOTE_TOOLS
    scam_patterns: dict[str, tuple[str, ...]] = field(default_factory=lambda: dict(DEFAULT_SCAM_PATTERNS))

    @staticmethod
    def _n(s: str) -> str:
        return " ".join(str(s).casefold().split())

    @classmethod
    def from_dict(cls, d: dict[str, Any] | None) -> "FirewallPolicy":
        d = d or {}
        n = cls._n
        return cls(
            people=tuple(Person(str(p["id"]), str(p.get("name", p["id"])), str(p.get("group", "")), tuple(n(i) for i in p.get("identifiers", ()))) for p in d.get("people", [])),
            standing={n(k): frozenset(n(v) for v in vs) for k, vs in d.get("standing", {}).items()},
            known_targets={n(k): frozenset(n(v) for v in vs) for k, vs in d.get("known_targets", {}).items()},
            remote_access_allowlist=frozenset(str(r) for r in d.get("remote_access_allowlist", ())),
            owner_only_categories=frozenset(n(c) for c in d.get("owner_only_categories", (IDENTITY, LEGAL))),
            identity_cooloff_seconds=int(d.get("identity_cooloff_seconds", 24 * 3600)),
            quorum={n(k): Quorum(int(q["required"]), tuple(str(m) for m in q.get("members", ())), bool(q.get("owner_final", True))) for k, q in d.get("quorum", {}).items()},
            remote_tools=tuple(d.get("remote_tools", DEFAULT_REMOTE_TOOLS)),
            scam_patterns={str(k): tuple(v) for k, v in d.get("scam_patterns", DEFAULT_SCAM_PATTERNS).items()},
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "people": [{"id": p.id, "name": p.name, "group": p.group, "identifiers": list(p.identifiers)} for p in self.people],
            "standing": {k: sorted(v) for k, v in sorted(self.standing.items())},
            "known_targets": {k: sorted(v) for k, v in sorted(self.known_targets.items())},
            "remote_access_allowlist": sorted(self.remote_access_allowlist),
            "owner_only_categories": sorted(self.owner_only_categories),
            "identity_cooloff_seconds": self.identity_cooloff_seconds,
            "quorum": {k: {"required": q.required, "members": list(q.members), "owner_final": q.owner_final} for k, q in sorted(self.quorum.items())},
            "remote_tools": list(self.remote_tools),
            "scam_patterns": {k: list(v) for k, v in self.scam_patterns.items()},
        }

    def person(self, pid: str) -> Person | None:
        return next((p for p in self.people if p.id == pid), None)


def remote_tools_named(action: AgentAction, fw: FirewallPolicy) -> list[str]:
    return sorted({m.group(0) for m in _keyword_pattern(fw.remote_tools).finditer(action.text())})


def scam_signals(text: str, fw: FirewallPolicy | None = None) -> frozenset[str]:
    """Labels of scam patterns found in free text. Pure; used as risk signals, never alone as proof."""
    patterns = (fw.scam_patterns if fw else DEFAULT_SCAM_PATTERNS).items()
    t = text.casefold()
    return frozenset(label for label, regs in patterns if any(re.search(r, t) for r in regs))


def classify(action: AgentAction) -> tuple[str, bool]:
    """(direction, reversible) for an action; UNKNOWN for a category or verb Kinlock doesn't know."""
    entry = VERBS.get(action.category, {}).get(action.verb)
    if entry is None:
        return UNKNOWN, False
    direction, reversible = entry
    return direction, reversible and bool(action.reversible)


@dataclass(frozen=True)
class ActionDecision:
    outcome: Outcome
    direction: str
    checks: tuple[Check, ...]
    category: str
    reversible: bool
    cooloff_seconds: int = 0  # the action may not run until this long after it was requested
    quorum: Quorum | None = None
    signals: frozenset[str] = frozenset()  # every risk signal seen, given and detected

    @property
    def reasons(self) -> list[str]:
        return [c.text for c in self.checks if not c.ok]

    def to_dict(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome.value,
            "direction": self.direction,
            "category": self.category,
            "reversible": self.reversible,
            "cooloff_seconds": self.cooloff_seconds,
            "quorum": {"required": self.quorum.required, "members": list(self.quorum.members), "owner_final": self.quorum.owner_final} if self.quorum else None,
            "signals": sorted(self.signals),
            "checks": [{"code": c.code, "ok": c.ok, "text": c.text} for c in self.checks],
        }


def _stricter(a: Outcome, b: Outcome) -> Outcome:
    return a if RANK[a] >= RANK[b] else b


def evaluate_action(
    action: AgentAction,
    policy: Policy,
    *,
    channel: str,
    frozen: bool,
    history: History | None = None,
    local_hour: int = 12,
    firewall: FirewallPolicy | None = None,
) -> ActionDecision:
    """Decide one action in any category. Pure: same inputs, same decision."""
    if channel not in CHANNELS:
        raise ValueError(f"unknown channel {channel!r}")
    fw = firewall or FirewallPolicy()
    history = history or History()
    direction, reversible = classify(action)
    signals = frozenset(action.risk) | {f"scam:{s}" for s in scam_signals(action.text(), fw)}
    tools = remote_tools_named(action, fw)
    if tools:
        signals |= {f"remote_tool:{t}" for t in tools}
    scams = sorted(s[5:] for s in signals if s.startswith("scam:"))
    on_call = bool(signals & CALL_SIGNALS)
    owner = policy.owner

    def done(outcome: Outcome, checks: list[Check], cooloff: int = 0) -> ActionDecision:
        q = fw.quorum.get(action.category) if outcome in (Outcome.HOLD, Outcome.OWNER) else None
        if q:
            checks.append(Check("quorum", False, f"{q.required} people must agree" + (f", including {owner}" if q.owner_final else "")))
        return ActionDecision(outcome, direction, tuple(checks), action.category, reversible, cooloff, q, signals)

    # Money keeps the original purchase and transfer rules exactly.
    if action.category == MONEY and direction == SPEND:
        legacy = evaluate(action.legacy(), policy, channel=channel, frozen=frozen, history=history, local_hour=local_hour)
        checks = list(legacy.checks)
        outcome = legacy.outcome
        if outcome != Outcome.DENY and (scams or on_call):
            why = ", ".join(scams + (["during or right after an inbound call"] if on_call else []))
            checks.append(Check("risk", False, f"Warning signs ({why}), so only {owner} can approve this"))
            outcome = _stricter(outcome, Outcome.OWNER)
        return done(outcome, checks)

    if direction == UNKNOWN:
        # Fail safe: a person looks at anything Kinlock can't classify. Never ALLOW, never silently drop.
        what = "category" if action.category not in VERBS else "action"
        return done(Outcome.HOLD, [Check("known", False, f"Kinlock doesn't know this {what} ({action.category} {action.verb}), so a person has to approve it")])

    if direction == REDUCE:
        return ActionDecision(Outcome.ALLOW, direction, (Check("direction", True, "This only lowers authority, so any channel may do it"),), action.category, reversible, 0, None, signals)

    checks: list[Check] = [Check("lock", not frozen, "Safety lock is on" if frozen else "Safety lock is off")]
    if frozen:
        return done(Outcome.DENY, checks)

    outcome = Outcome.ALLOW
    cooloff = 0
    n = FirewallPolicy._n
    known_target = n(action.target) in fw.known_targets.get(action.category, frozenset())

    if direction == USE:
        standing = action.verb in fw.standing.get(action.category, frozenset())
        checks.append(Check("standing", standing, f"{owner} lets this happen without asking" if standing else f"{owner} hasn't said this can happen without asking"))
        if action.category in fw.known_targets:
            checks.append(Check("target", known_target, f"{action.target} is someone {owner} knows" if known_target else f"{action.target} is new"))
        if not standing or (action.category in fw.known_targets and not known_target):
            outcome = Outcome.HOLD
    else:  # INCREASE: it gives someone access, control or a lasting change
        if channel == OWNER and not (action.category == IDENTITY and action.verb in IDENTITY_CHANGES):
            checks.append(Check("direction", True, f"{owner} asked for this herself on her secure page"))
        else:
            who = {VOICE: "A voice request", CONTACT: "A trusted contact"}.get(channel, "This channel")
            checks.append(Check("direction", False, f"{who} can't give anyone new access or control on its own"))
            outcome = Outcome.HOLD
            if action.category in fw.owner_only_categories:
                checks.append(Check("owner_category", False, f"{action.category.capitalize()} changes need {owner} herself"))
                outcome = Outcome.OWNER
            if not reversible:
                checks.append(Check("reversible", False, f"This can't be undone, so only {owner} can approve it"))
                outcome = Outcome.OWNER

    # -- Remote-access guard ----------------------------------------------------------------
    remote = action.verb in SCREEN_CONTROL or bool(tools)
    if remote and direction != REDUCE:
        label = ", ".join(tools) if tools else action.verb.replace("_", " ")
        allowed = action.requester in fw.remote_access_allowlist
        if on_call:
            checks.append(Check("remote_access", False, f"Remote access ({label}) asked for during or right after a call {owner} didn't place. That is how tech-support scams work, so Kinlock won't do it"))
            outcome = Outcome.DENY
        elif scams:
            checks.append(Check("remote_access", False, f"Remote access ({label}) with warning signs ({', '.join(scams)}). Kinlock won't do it"))
            outcome = Outcome.DENY
        elif not allowed:
            checks.append(Check("remote_access", False, f"Remote access ({label}) for someone not on {owner}'s list. Kinlock won't do it"))
            outcome = Outcome.DENY
        else:
            checks.append(Check("remote_access", False, f"Remote access ({label}) always needs {owner} herself"))
            outcome = _stricter(outcome, Outcome.OWNER)
    elif scams and direction != REDUCE:
        checks.append(Check("risk", False, f"Warning signs ({', '.join(scams)}), so only {owner} can approve this"))
        outcome = _stricter(outcome, Outcome.OWNER)
    if on_call and not remote and direction == INCREASE:
        checks.append(Check("call", False, f"Asked during or right after an inbound call, so only {owner} can approve this"))
        outcome = _stricter(outcome, Outcome.OWNER)

    # -- Identity and recovery guard --------------------------------------------------------
    if action.category == IDENTITY and action.verb in IDENTITY_CHANGES:
        cooloff = max(0, int(fw.identity_cooloff_seconds))
        hours = cooloff / 3600
        span = f"{hours:g} hours" if hours != 1 else "1 hour"
        checks.append(Check("cooloff", False, f"Account recovery and identity changes wait {span}, then need {owner} to confirm"))
        outcome = _stricter(outcome, Outcome.OWNER)

    # -- Home guard: letting someone in ----------------------------------------------------
    if action.category == HOME and direction == INCREASE and outcome != Outcome.DENY and channel != OWNER:
        visitor = str(action.details.get("visitor", action.target))
        known_visitor = n(visitor) in fw.known_targets.get(HOME, frozenset())
        checks.append(Check("visitor", known_visitor, f"{visitor} is someone {owner} lets in" if known_visitor else f"{visitor} isn't someone {owner} has said to let in, so only she can"))
        if not known_visitor:
            outcome = _stricter(outcome, Outcome.OWNER)

    return done(outcome, checks, cooloff)


# -- Approvals --------------------------------------------------------------------------------


def conflict_of_interest(action: AgentAction, approver: str, fw: FirewallPolicy | None = None) -> str | None:
    """Why `approver` can't approve this action, or None. The owner approving her own action is fine."""
    if approver == OWNER:
        return None
    if approver == action.requester:
        return "You asked for this, so you can't also approve it"
    if approver in action.beneficiaries:
        return "This would benefit you, so someone else has to approve it"
    p = (fw or FirewallPolicy()).person(approver)
    if p and p.name:
        n = FirewallPolicy._n
        if n(p.name) == n(action.target) or n(p.name) in {n(b) for b in action.beneficiaries}:
            return "This is about you, so someone else has to approve it"
    if p and p.identifiers:
        text = action.text()
        hit = next((i for i in p.identifiers if i and i in text), None)
        if hit:
            return f"This points at your own {hit}, so someone else has to approve it"
    return None


def may_approve_action(decision: ActionDecision, action: AgentAction, *, approver: str, role: str, contact: Contact | None = None, firewall: FirewallPolicy | None = None) -> tuple[bool, str]:
    """Whether one person may cast an approving vote for this held action."""
    if decision.outcome == Outcome.ALLOW:
        return True, "No approval needed"
    if decision.outcome == Outcome.DENY:
        return False, "The rules block this action; no approval can release it"
    coi = conflict_of_interest(action, approver, firewall)
    if coi:
        return False, coi
    if role == OWNER:
        return True, "The owner approved"
    if decision.outcome == Outcome.OWNER and not decision.quorum:
        return False, "This needs the owner herself; a trusted contact can't approve it"
    if decision.quorum:
        if approver not in decision.quorum.members:
            return False, "You aren't one of the people who decide this together"
        return True, "Your vote counts toward the quorum"
    if action.category == MONEY and decision.direction == SPEND:
        from .policy import Decision as _D

        return may_approve(_D(decision.outcome, decision.direction, decision.checks), role=role, amount_cents=action.amount_cents, contact=contact)
    if role != CONTACT or contact is None:
        return False, "Only the owner or her trusted contact can approve"
    return True, f"{contact.name} approved"


APPROVE, DECLINE, PAUSE, RESUME = "approve", "decline", "pause", "resume"


@dataclass(frozen=True)
class Vote:
    voter: str  # "owner", "contact:anna", "supporter:raj"
    choice: str  # approve | decline | pause | resume
    comment: str = ""


@dataclass(frozen=True)
class Tally:
    state: str  # "approved" | "waiting" | "paused" | "declined"
    approvals: tuple[str, ...]  # who counted, after dedupe and conflict checks
    problems: tuple[str, ...]  # votes that didn't count, and why
    comments: tuple[tuple[str, str], ...]


def tally(decision: ActionDecision, action: AgentAction, votes: Iterable[Vote], *, firewall: FirewallPolicy | None = None) -> Tally:
    """Count votes on a held action under its quorum (or a single owner/contact approval without one).

    * Each person counts once; people sharing a `group` count once together.
    * Conflicted voters (requester, beneficiary, own identifiers in the target) don't count.
    * Where the owner is final, nothing passes without her approval, however many supporters agree.
    * A supporter's pause holds everything until that supporter or the owner resumes. A supporter's
      decline is a "no" vote, not a veto; the owner's decline ends it.
    """
    fw = firewall or FirewallPolicy()
    q = decision.quorum
    members = set(q.members) if q else {p.id for p in fw.people}
    approvals: dict[str, str] = {}  # group key -> voter
    problems: list[str] = []
    comments: list[tuple[str, str]] = []
    paused_by: set[str] = set()
    owner_approved = owner_declined = False
    if decision.outcome == Outcome.DENY:
        return Tally("declined", (), ("The rules block this action; no vote can release it",), ())
    for v in votes:
        if v.comment:
            comments.append((v.voter, v.comment))
        if v.voter != OWNER and v.voter not in members:
            problems.append(f"{v.voter} isn't one of the people who decide this")
            continue
        if v.choice == PAUSE:
            paused_by.add(v.voter)
            continue
        if v.choice == RESUME:
            paused_by = set() if v.voter == OWNER else paused_by - {v.voter}
            continue
        if v.choice == DECLINE:
            if v.voter == OWNER:
                owner_declined = True
            approvals = {k: who for k, who in approvals.items() if who != v.voter}
            continue
        if v.choice != APPROVE:
            problems.append(f"{v.voter}: unknown vote {v.choice!r}")
            continue
        coi = conflict_of_interest(action, v.voter, fw)
        if coi:
            problems.append(f"{v.voter}: {coi}")
            continue
        if v.voter == OWNER:
            owner_approved = True
            approvals["owner"] = OWNER
            continue
        if not q and decision.outcome == Outcome.OWNER:
            problems.append(f"{v.voter}: this needs the owner herself")
            continue
        p = fw.person(v.voter)
        key = f"group:{p.group}" if p and p.group else v.voter
        if key in approvals and approvals[key] != v.voter:
            problems.append(f"{v.voter} is in the same group as {approvals[key]}, so they count once together")
            continue
        approvals[key] = v.voter
    counted = tuple(sorted(set(approvals.values())))
    if owner_declined:
        return Tally("declined", counted, tuple(problems), tuple(comments))
    if paused_by:
        return Tally("paused", counted, tuple(problems + [f"Paused by {', '.join(sorted(paused_by))}"]), tuple(comments))
    if q:
        # An OWNER-level action (identity, remote access, warning signs) needs her whatever the quorum says.
        owner_needed = q.owner_final or decision.outcome == Outcome.OWNER
        enough = len(counted) >= q.required and (owner_approved or not owner_needed)
    elif decision.outcome == Outcome.OWNER:
        enough = owner_approved
    else:
        enough = bool(counted)
    return Tally("approved" if enough else "waiting", counted, tuple(problems), tuple(comments))


def release_problems(decision: ActionDecision, action: AgentAction, votes: Iterable[Vote], *, requested_at: float, now: float, firewall: FirewallPolicy | None = None) -> list[str]:
    """Every reason this held action may not run yet. Empty = it may run (after capability checks)."""
    problems: list[str] = []
    if decision.outcome == Outcome.DENY:
        return ["The rules block this action; no approval can release it"]
    if decision.outcome == Outcome.ALLOW:
        return []
    ready_at = requested_at + decision.cooloff_seconds
    if now < ready_at:
        left = int(ready_at - now)
        problems.append(f"The cool-off period hasn't passed yet ({left // 3600}h {left % 3600 // 60}m left)")
    t = tally(decision, action, votes, firewall=firewall)
    if t.state != "approved":
        problems.append({"paused": "A supporter paused this", "declined": "It was declined", "waiting": "Not enough of the right people have approved it"}[t.state])
    return problems


# -- Words ------------------------------------------------------------------------------------

_PHRASES = {
    "install_software": "install {target}",
    "launch_remote_tool": "start the remote-access tool {target}",
    "grant_screen_control": "give {target} control of the screen",
    "share_screen": "share the screen with {target}",
    "start_remote_session": "start a remote session with {target}",
    "change_password": "change the password for {target}",
    "change_recovery_email": "change the recovery email for {target}",
    "change_recovery_phone": "change the recovery phone for {target}",
    "change_2fa": "change two-step sign-in for {target}",
    "disable_2fa": "turn off two-step sign-in for {target}",
    "change_direct_deposit": "change where {target} payments are deposited",
    "change_address": "change the mailing address for {target}",
    "add_device": "add a new device to {target}",
    "unlock_door": "unlock the {target}",
    "disable_alarm": "turn off the {target} alarm",
    "lock_door": "lock the {target}",
    "send_message": "send a message to {target}",
    "share_document": "share {target}",
    "share_pii": "share personal details with {target}",
    "sign_document": "sign {target}",
    "purchase": "buy from {target}",
    "transfer": "send money to {target}",
}


def describe_action(action: AgentAction) -> str:
    """A short plain phrase for the action, for pages, pushes and spoken receipts."""
    phrase = _PHRASES.get(action.verb, action.verb.replace("_", " ") + (" {target}" if action.target else ""))
    text = phrase.format(target=action.target or "it").strip()
    if action.category == MONEY and action.amount_cents:
        text += f" for {money(action.amount_cents)}"
    visitor = action.details.get("visitor")
    if visitor and action.category == HOME:
        text += f" for {visitor}"
    return text


def voice_can_only_lower(decision: ActionDecision, channel: str) -> bool:
    """The invariant, as a predicate: a voice request never ALLOWs an increase of authority."""
    return not (channel == VOICE and decision.outcome == Outcome.ALLOW and decision.direction == INCREASE)
