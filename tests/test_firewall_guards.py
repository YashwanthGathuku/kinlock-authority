"""The built-in guards: remote access, identity and recovery, home, scam signals, fail-safe defaults."""

from __future__ import annotations

import pytest
from fw_common import FW, POLICY

from kinlock_authority import AgentAction, FirewallPolicy, Outcome, evaluate_action, scam_signals
from kinlock_authority.firewall import DEFAULT_REMOTE_TOOLS, describe_action


def act(category, verb, target="", details=None, **kw):
    return AgentAction("r1", category, verb, target, details or {}, **kw)


def decide(a, channel="voice", frozen=False, fw=FW):
    return evaluate_action(a, POLICY, channel=channel, frozen=frozen, firewall=fw)


# -- remote access ---------------------------------------------------------------------------


def test_microsoft_support_asking_for_anydesk_is_denied():
    d = decide(act("access", "install_software", "AnyDesk", {"reason": "Microsoft support says my computer has a virus"}, requester="caller:+18885550000"))
    assert d.outcome == Outcome.DENY
    assert {"scam:tech_support", "scam:impersonation", "remote_tool:anydesk"} <= d.signals


@pytest.mark.parametrize("tool", ["AnyDesk", "TeamViewer", "UltraViewer", "Quick Assist", "ScreenConnect", "ConnectWise Control", "LogMeIn", "Zoho Assist", "RustDesk", "Chrome Remote Desktop"])
def test_every_common_remote_tool_is_recognised_and_denied_on_a_call(tool):
    d = decide(act("access", "install_software", tool, risk=frozenset({"inbound_call"}), requester="contact:anna"))
    assert d.outcome == Outcome.DENY and any(s.startswith("remote_tool:") for s in d.signals)


def test_remote_tool_named_only_in_details_is_still_caught():
    d = decide(act("access", "install_software", "helper.exe", {"note": "it's the teamviewer installer"}, requester="contact:anna"))
    assert "remote_tool:teamviewer" in d.signals and d.outcome == Outcome.OWNER


def test_remote_tool_for_a_requester_not_on_the_allowlist_is_denied():
    assert decide(act("access", "launch_remote_tool", "RustDesk", requester="caller:+15559999")).outcome == Outcome.DENY
    assert decide(act("access", "launch_remote_tool", "RustDesk")).outcome == Outcome.DENY  # anonymous


def test_allowlisted_requester_without_warning_signs_still_needs_the_owner():
    d = decide(act("access", "grant_screen_control", "Anna", requester="contact:anna"))
    assert d.outcome == Outcome.OWNER


def test_screen_control_during_a_call_is_denied_even_for_the_allowlist():
    for verb in ("grant_screen_control", "share_screen", "start_remote_session"):
        assert decide(act("access", verb, "Anna", requester="contact:anna", risk=frozenset({"unsolicited_call"}))).outcome == Outcome.DENY


def test_remote_access_is_denied_even_from_the_owner_channel_on_a_scam_call():
    d = decide(act("access", "install_software", "AnyDesk", risk=frozenset({"inbound_call"}), requester="owner"), channel="owner")
    assert d.outcome == Outcome.DENY


def test_ordinary_software_install_waits_for_a_person():
    d = decide(act("access", "install_software", "Large Print Reader"))
    assert d.outcome == Outcome.HOLD
    assert decide(act("access", "install_software", "Large Print Reader", {"why": "the refund department said so"})).outcome == Outcome.OWNER


def test_ending_a_remote_session_is_always_allowed():
    assert decide(act("access", "end_remote_session", "AnyDesk", risk=frozenset({"inbound_call"}))).outcome == Outcome.ALLOW
    assert decide(act("access", "uninstall_software", "AnyDesk"), frozen=True).outcome == Outcome.ALLOW


@pytest.mark.parametrize(
    "text,label",
    [
        ("This is Microsoft Support calling", "impersonation"),
        ("apple security team here", "impersonation"),
        ("Amazon customer service about your order", "impersonation"),
        ("we need to process your refund", "refund"),
        ("you were overpaid by $900", "refund"),
        ("your computer has a virus", "tech_support"),
        ("I'm from tech support", "tech_support"),
        ("do it right now and don't tell your daughter", "urgency"),
    ],
)
def test_scam_patterns(text, label):
    assert label in scam_signals(text)


def test_ordinary_text_has_no_scam_signals():
    assert scam_signals("please call Anna about Sunday lunch") == frozenset()
    assert scam_signals("install the large print reader") == frozenset()


def test_remote_tool_list_is_long_enough():
    assert {"anydesk", "teamviewer", "ultraviewer", "quick assist", "screenconnect", "connectwise", "logmein", "zoho assist", "rustdesk"} <= set(DEFAULT_REMOTE_TOOLS)


# -- identity and recovery -------------------------------------------------------------------


@pytest.mark.parametrize("verb", ["change_password", "change_recovery_email", "change_recovery_phone", "change_2fa", "disable_2fa", "change_direct_deposit", "change_address", "add_device"])
def test_identity_changes_need_the_owner_after_a_cooloff(verb):
    d = decide(act("identity", verb, "Gmail"))
    assert d.outcome == Outcome.OWNER and d.cooloff_seconds == 24 * 3600
    # Even when the owner asks herself, the cool-off and her confirmation still apply.
    d = decide(act("identity", verb, "Gmail", requester="owner"), channel="owner")
    assert d.outcome == Outcome.OWNER and d.cooloff_seconds == 24 * 3600


def test_cooloff_is_configurable():
    fw = FirewallPolicy.from_dict({**FW.to_dict(), "identity_cooloff_seconds": 3600})
    assert decide(act("identity", "change_direct_deposit", "SSA benefits"), fw=fw).cooloff_seconds == 3600


def test_locking_an_account_is_always_allowed():
    for verb in ("lock_account", "sign_out_everywhere", "freeze_credit"):
        assert decide(act("identity", verb, "Gmail"), frozen=True).outcome == Outcome.ALLOW


# -- home ------------------------------------------------------------------------------------


def test_unlocking_the_door_for_an_unknown_visitor_is_owner_only():
    d = decide(act("home", "unlock_door", "front door", {"visitor": "a man saying he's from the gas company"}))
    assert d.outcome == Outcome.OWNER


def test_unlocking_for_a_known_visitor_can_go_to_the_contact():
    assert decide(act("home", "unlock_door", "front door", {"visitor": "Rosa (cleaner)"})).outcome == Outcome.HOLD


def test_locking_up_is_always_allowed():
    assert decide(act("home", "lock_door", "front door"), frozen=True).outcome == Outcome.ALLOW
    assert decide(act("home", "arm_alarm", "house")).outcome == Outcome.ALLOW


# -- standing permissions, irreversibility, fail-safe ----------------------------------------


def test_message_to_a_known_contact_runs_and_to_a_stranger_waits():
    assert decide(act("comms", "send_message", "Anna", {"text": "running late"})).outcome == Outcome.ALLOW
    assert decide(act("comms", "send_message", "+15550199", {"text": "hi"})).outcome == Outcome.HOLD


def test_message_with_scam_words_needs_the_owner():
    assert decide(act("comms", "send_message", "Anna", {"text": "send the code, it's urgent, don't tell anyone"})).outcome == Outcome.OWNER


def test_irreversible_increases_need_the_owner():
    d = decide(act("data", "share_pii", "Acme Benefits", {"fields": "SSN, date of birth"}))
    assert d.outcome == Outcome.OWNER and not d.reversible


def test_caller_can_mark_an_action_less_reversible_but_not_more():
    assert decide(act("data", "grant_data_access", "Dr Patel", reversible=False)).outcome == Outcome.OWNER
    assert decide(act("data", "share_document", "Dr Patel", reversible=True)).reversible is False


def test_legal_is_owner_only():
    assert decide(act("legal", "grant_power_of_attorney", "Tom")).outcome == Outcome.OWNER


@pytest.mark.parametrize("category,verb", [("access", "do_something"), ("teleport", "go"), ("", "")])
def test_unknown_actions_wait_for_a_person(category, verb):
    d = decide(act(category, verb, "x"))
    assert d.outcome == Outcome.HOLD and d.checks[0].code == "known"


def test_safety_lock_denies_every_increase():
    assert decide(act("home", "unlock_door", "front door", {"visitor": "Anna"}), frozen=True).outcome == Outcome.DENY
    assert decide(act("comms", "send_message", "Anna"), frozen=True).outcome == Outcome.DENY


def test_owner_channel_can_do_reversible_ordinary_changes():
    assert decide(act("comms", "add_contact", "Dr Patel"), channel="owner").outcome == Outcome.ALLOW


# -- money keeps the original rules ----------------------------------------------------------


def test_money_actions_use_the_purchase_rules_unchanged():
    ok = act("money", "purchase", "Fresh Market", {"item": "groceries"}, amount_cents=4620)
    assert decide(ok).outcome == Outcome.ALLOW
    gift = act("money", "purchase", "Fresh Market", {"item": "a $200 gift card"}, amount_cents=20000)
    assert decide(gift).outcome == Outcome.DENY
    assert decide(act("money", "transfer", "New Person", amount_cents=90000)).outcome == Outcome.OWNER


def test_money_on_a_call_or_with_scam_words_needs_the_owner():
    a = act("money", "purchase", "Fresh Market", {"item": "groceries"}, amount_cents=4620, risk=frozenset({"inbound_call"}))
    assert decide(a).outcome == Outcome.OWNER
    a = act("money", "transfer", "Landlord", {"note": "the IRS agent said to"}, amount_cents=4000)
    assert decide(a).outcome == Outcome.OWNER


# -- the schema ------------------------------------------------------------------------------


def test_digest_binds_every_field():
    base = act("home", "unlock_door", "front door", {"visitor": "Anna"}, requester="contact:anna")
    variants = [
        act("home", "unlock_door", "back door", {"visitor": "Anna"}, requester="contact:anna"),
        act("home", "unlock_door", "front door", {"visitor": "Bob"}, requester="contact:anna"),
        act("home", "unlock_door", "front door", {"visitor": "Anna"}, requester="contact:tom"),
        act("home", "unlock_door", "front door", {"visitor": "Anna"}, requester="contact:anna", risk=frozenset({"inbound_call"})),
        act("home", "disable_alarm", "front door", {"visitor": "Anna"}, requester="contact:anna"),
    ]
    assert len({base.digest(), *(v.digest() for v in variants)}) == 1 + len(variants)
    assert AgentAction.from_dict(base.to_dict()) == base and AgentAction.from_dict(base.to_dict()).digest() == base.digest()


def test_describe_action_is_plain_words():
    assert describe_action(act("access", "install_software", "AnyDesk")) == "install AnyDesk"
    assert describe_action(act("home", "unlock_door", "front door", {"visitor": "a stranger"})) == "unlock the front door for a stranger"
    assert describe_action(act("money", "purchase", "TechZone", amount_cents=84999)) == "buy from TechZone for $849.99"
