"""Approvals for non-money actions: conflict of interest, quorum, pauses, cool-off, capabilities, receipts."""

from __future__ import annotations

from fw_common import FW, POLICY

from kinlock_authority import (
    AgentAction,
    Outcome,
    ReceiptChain,
    Signer,
    Vote,
    capability_problems,
    evaluate_action,
    issue_capability,
    may_approve_action,
    release_problems,
    tally,
)
from kinlock_authority.firewall import conflict_of_interest

ANNA = POLICY.contacts[0]
DAY = 24 * 3600


def decide(a, channel="voice"):
    return evaluate_action(a, POLICY, channel=channel, frozen=False, firewall=FW)


def recovery_email(to: str) -> AgentAction:
    return AgentAction("r-id", "identity", "change_recovery_email", "Gmail", {"new_email": to})


# -- conflict of interest --------------------------------------------------------------------


def test_contact_cannot_approve_pointing_recovery_at_their_own_email():
    a = recovery_email("anna@example.com")
    assert conflict_of_interest(a, "contact:anna", FW)
    ok, why = may_approve_action(decide(a), a, approver="contact:anna", role="contact", contact=ANNA, firewall=FW)
    assert not ok and "your own" in why


def test_nobody_approves_their_own_request_or_their_own_benefit():
    a = AgentAction("r", "home", "unlock_door", "front door", {"visitor": "Anna"}, requester="contact:anna")
    assert not may_approve_action(decide(a), a, approver="contact:anna", role="contact", contact=ANNA, firewall=FW)[0]
    b = AgentAction("r", "legal", "change_beneficiary", "life policy", beneficiaries=("supporter:raj",))
    assert "benefit you" in conflict_of_interest(b, "supporter:raj", FW)
    assert conflict_of_interest(b, "owner", FW) is None


def test_contact_alone_can_never_release_an_identity_change():
    a = recovery_email("mary.new@example.com")
    d = decide(a)
    assert not may_approve_action(d, a, approver="contact:anna", role="contact", contact=ANNA, firewall=FW)[0]
    t = tally(d, a, [Vote("contact:anna", "approve"), Vote("supporter:raj", "approve")], firewall=FW)
    assert t.state == "waiting" and t.approvals == ()
    assert release_problems(d, a, [Vote("contact:anna", "approve")], requested_at=0, now=2 * DAY, firewall=FW)


def test_identity_change_needs_the_cooloff_and_the_owner():
    a = recovery_email("mary.new@example.com")
    d = decide(a)
    early = release_problems(d, a, [Vote("owner", "approve")], requested_at=1000, now=1000 + DAY - 60, firewall=FW)
    assert len(early) == 1 and "cool-off" in early[0]
    assert release_problems(d, a, [Vote("owner", "approve")], requested_at=1000, now=1000 + DAY, firewall=FW) == []
    assert release_problems(d, a, [], requested_at=1000, now=1000 + 2 * DAY, firewall=FW) == ["Not enough of the right people have approved it"]


# -- quorum ----------------------------------------------------------------------------------


def poa():
    return AgentAction("r-poa", "legal", "grant_power_of_attorney", "Tom")


def test_quorum_two_of_three_with_the_owner_final():
    a = poa()
    d = decide(a)
    assert d.quorum and d.quorum.required == 2
    assert tally(d, a, [Vote("owner", "approve")], firewall=FW).state == "waiting"
    assert tally(d, a, [Vote("owner", "approve"), Vote("supporter:raj", "approve")], firewall=FW).state == "approved"


def test_supporters_cannot_release_without_the_owner_when_she_is_final():
    a = poa()
    t = tally(decide(a), a, [Vote("contact:anna", "approve"), Vote("supporter:raj", "approve")], firewall=FW)
    assert t.state == "waiting" and len(t.approvals) == 2


def test_same_household_counts_once_so_two_cannot_collude():
    a = AgentAction("r-poa2", "legal", "grant_power_of_attorney", "Elder Law Partners")
    # Anna and Tom share a group: with the owner that's 2 heads, but Anna+Tom alone count as one.
    t = tally(decide(a), a, [Vote("contact:anna", "approve"), Vote("supporter:tom", "approve")], firewall=FW)
    assert t.approvals == ("contact:anna",) and any("same group" in p for p in t.problems)


def test_power_of_attorney_to_a_supporter_cannot_be_approved_by_them():
    a = poa()  # to Tom
    t = tally(decide(a), a, [Vote("supporter:tom", "approve"), Vote("supporter:raj", "approve")], firewall=FW)
    assert "supporter:tom" not in t.approvals and t.state != "approved"


def test_repeat_votes_count_once():
    a = poa()
    t = tally(decide(a), a, [Vote("owner", "approve"), Vote("owner", "approve")], firewall=FW)
    assert t.state == "waiting" and t.approvals == ("owner",)


def test_outsiders_cannot_vote():
    a = poa()
    t = tally(decide(a), a, [Vote("owner", "approve"), Vote("stranger:eve", "approve")], firewall=FW)
    assert t.state == "waiting" and "stranger:eve isn't one of the people" in t.problems[0]


def test_conflicted_voter_is_not_counted_in_a_quorum():
    a = AgentAction("r-poa", "legal", "grant_power_of_attorney", "Raj", beneficiaries=("supporter:raj",))
    t = tally(decide(a), a, [Vote("owner", "approve"), Vote("supporter:raj", "approve")], firewall=FW)
    assert t.state == "waiting" and t.approvals == ("owner",)


def test_supporter_can_pause_and_comment_until_resumed():
    a = poa()
    votes = [Vote("supporter:raj", "pause", "Mary, did Tom explain what this lets him do?"), Vote("owner", "approve"), Vote("contact:anna", "approve")]
    t = tally(decide(a), a, votes, firewall=FW)
    assert t.state == "paused" and t.comments[0][0] == "supporter:raj"
    assert tally(decide(a), a, [*votes, Vote("supporter:raj", "resume")], firewall=FW).state == "approved"
    assert tally(decide(a), a, [*votes, Vote("owner", "resume")], firewall=FW).state == "approved"


def test_supporter_decline_is_a_no_vote_but_the_owner_decline_ends_it():
    a = poa()
    d = decide(a)
    assert tally(d, a, [Vote("contact:anna", "approve"), Vote("contact:anna", "decline"), Vote("owner", "approve")], firewall=FW).state == "waiting"
    assert tally(d, a, [Vote("owner", "decline"), Vote("contact:anna", "approve"), Vote("supporter:raj", "approve")], firewall=FW).state == "declined"


def test_owner_level_action_needs_her_even_under_a_quorum_that_is_not_owner_final():
    from kinlock_authority import FirewallPolicy

    fw = FirewallPolicy.from_dict({**FW.to_dict(), "quorum": {"identity": {"required": 2, "members": ["contact:anna", "supporter:raj"], "owner_final": False}}})
    a = recovery_email("mary.new@example.com")
    d = evaluate_action(a, POLICY, channel="voice", frozen=False, firewall=fw)
    assert tally(d, a, [Vote("contact:anna", "approve"), Vote("supporter:raj", "approve")], firewall=fw).state == "waiting"


def test_denied_actions_cannot_be_voted_through():
    a = AgentAction("r", "access", "install_software", "AnyDesk", risk=frozenset({"inbound_call"}))
    d = decide(a)
    assert d.outcome == Outcome.DENY
    assert tally(d, a, [Vote("owner", "approve")], firewall=FW).state == "declined"
    assert release_problems(d, a, [Vote("owner", "approve")], requested_at=0, now=10**9, firewall=FW)


# -- the contact path for ordinary holds -----------------------------------------------------


def test_contact_can_approve_an_ordinary_hold():
    a = AgentAction("r", "home", "unlock_door", "front door", {"visitor": "Rosa (cleaner)"})
    d = decide(a)
    assert d.outcome == Outcome.HOLD
    assert may_approve_action(d, a, approver="contact:anna", role="contact", contact=ANNA, firewall=FW)[0]
    assert release_problems(d, a, [Vote("contact:anna", "approve")], requested_at=0, now=1, firewall=FW) == []


# -- signed approvals and receipts work unchanged on the new schema --------------------------


def test_capability_is_bound_to_the_action_digest_and_single_use():
    signer = Signer(b"k" * 32)
    a = AgentAction("r-door", "home", "unlock_door", "front door", {"visitor": "Rosa (cleaner)"})
    cap = issue_capability(signer, request_id=a.request_id, action_digest=a.digest(), approver="contact:anna", role="contact", ceiling_cents=0, now=0)
    assert capability_problems(signer, cap, request_id=a.request_id, current_digest=a.digest(), amount_cents=0, used=set(), now=1) == []
    swapped = AgentAction("r-door", "home", "unlock_door", "front door", {"visitor": "someone else"})
    assert "The request changed after it was approved" in capability_problems(signer, cap, request_id=a.request_id, current_digest=swapped.digest(), amount_cents=0, used=set(), now=1)
    assert "This approval was already used" in capability_problems(signer, cap, request_id=a.request_id, current_digest=a.digest(), amount_cents=0, used={cap.cap_id}, now=1)


def test_firewall_decisions_go_into_signed_receipts(tmp_path):
    chain = ReceiptChain(tmp_path / "r.jsonl", key=b"s" * 32)
    a = AgentAction("r", "access", "install_software", "AnyDesk", risk=frozenset({"inbound_call"}))
    chain.append("decision", {"action": a.to_dict(), "digest": a.digest(), "decision": decide(a).to_dict()})
    rep = chain.verify()
    assert rep.ok and rep.receipts == 1
    assert list(chain.receipts())[0].data["decision"]["outcome"] == "DENY"


def test_conflict_when_the_action_names_the_approver():
    a = AgentAction("r-b", "legal", "change_beneficiary", "Anna", {})
    assert conflict_of_interest(a, "contact:anna", FW)
    assert conflict_of_interest(a, "supporter:raj", FW) is None
    assert conflict_of_interest(a, "owner", FW) is None
    named = AgentAction("r-c", "legal", "change_beneficiary", "Life policy", {}, beneficiaries=("Anna",))
    assert conflict_of_interest(named, "contact:anna", FW)
