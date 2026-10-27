"""Property-style checks over every category, verb, channel, lock state and risk combination.

No randomness: the space is small enough to enumerate exhaustively, so a failure names
the exact case.
"""

from __future__ import annotations

import itertools

import pytest
from fw_common import FW, POLICY

from kinlock_authority import VERBS, AgentAction, Outcome, evaluate_action
from kinlock_authority.firewall import INCREASE, RANK, REDUCE, voice_can_only_lower

RISKS = [frozenset(), frozenset({"inbound_call"}), frozenset({"unsolicited_call"})]
TEXTS = ["", "Microsoft support says there is a virus", "a refund is waiting"]
TARGETS = ["Anna", "AnyDesk", "front door", "Gmail", "a stranger"]
REQUESTERS = ["", "owner", "contact:anna", "caller:+15550000"]
CHANNELS = ["voice", "contact", "owner"]


def every_action():
    i = 0
    for category, verbs in VERBS.items():
        for verb in verbs:
            for target, text, risk, requester in itertools.product(TARGETS, TEXTS, RISKS, REQUESTERS):
                i += 1
                details = {"note": text} if text else {}
                amount = 4000 if category == "money" else 0
                yield AgentAction(f"r{i}", category, verb, target, details, risk=risk, requester=requester, amount_cents=amount)


ACTIONS = list(every_action())


def test_the_space_is_large():
    assert len(ACTIONS) > 10_000


@pytest.mark.parametrize("channel", ["voice", "contact"])
def test_voice_and_contacts_never_allow_an_increase(channel):
    for a in ACTIONS:
        d = evaluate_action(a, POLICY, channel=channel, frozen=False, firewall=FW)
        assert voice_can_only_lower(d, "voice"), a
        if d.direction == INCREASE:
            assert d.outcome != Outcome.ALLOW, a


def test_reductions_are_always_allowed_from_any_channel_even_when_frozen():
    for a in ACTIONS:
        for channel, frozen in itertools.product(CHANNELS, (False, True)):
            d = evaluate_action(a, POLICY, channel=channel, frozen=frozen, firewall=FW)
            if d.direction == REDUCE:
                assert d.outcome == Outcome.ALLOW, (a, channel, frozen)


def test_safety_lock_allows_only_reductions():
    for a in ACTIONS:
        for channel in CHANNELS:
            d = evaluate_action(a, POLICY, channel=channel, frozen=True, firewall=FW)
            if d.outcome == Outcome.ALLOW:
                assert d.direction == REDUCE, (a, channel)


def test_a_lower_assurance_channel_is_never_less_strict():
    for a in ACTIONS:
        ranks = [RANK[evaluate_action(a, POLICY, channel=c, frozen=False, firewall=FW).outcome] for c in ("owner", "contact", "voice")]
        assert ranks[0] <= ranks[1] <= ranks[2] or ranks[1] == ranks[2], (a, ranks)
        assert ranks[0] <= ranks[2], (a, ranks)


def test_adding_a_risk_signal_never_makes_a_decision_less_strict():
    for a in ACTIONS:
        if a.risk:
            continue
        base = RANK[evaluate_action(a, POLICY, channel="voice", frozen=False, firewall=FW).outcome]
        for r in RISKS[1:]:
            riskier = AgentAction(a.request_id, a.category, a.verb, a.target, a.details, risk=r, requester=a.requester, amount_cents=a.amount_cents)
            assert RANK[evaluate_action(riskier, POLICY, channel="voice", frozen=False, firewall=FW).outcome] >= base, (a, r)


def test_marking_an_action_irreversible_never_makes_it_less_strict():
    for a in ACTIONS[::7]:
        stricter = AgentAction(a.request_id, a.category, a.verb, a.target, a.details, a.risk, False, a.requester, a.beneficiaries, a.amount_cents)
        for c in CHANNELS:
            assert RANK[evaluate_action(stricter, POLICY, channel=c, frozen=False, firewall=FW).outcome] >= RANK[evaluate_action(a, POLICY, channel=c, frozen=False, firewall=FW).outcome]


def test_decisions_are_deterministic():
    for a in ACTIONS[::11]:
        assert evaluate_action(a, POLICY, channel="voice", frozen=False, firewall=FW) == evaluate_action(a, POLICY, channel="voice", frozen=False, firewall=FW)
