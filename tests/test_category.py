"""The category a purchase is judged under comes from the owner's catalog, not the caller."""

from __future__ import annotations

import pytest

from kinlock_authority import Action, History, Outcome, Policy, evaluate

BASE = {
    "owner": "Mary",
    "timezone": "America/New_York",
    "contacts": [{"id": "anna", "name": "Anna", "relation": "daughter", "ceiling_cents": 100000}],
    "known_merchants": ["Fresh Market", "Target"],
    "known_payees": ["Anna"],
    "limits": {"groceries": {"per_action_cents": 12000, "daily_cents": 20000, "daily_count": 3}},
    "default_limits": {"per_action_cents": 5000, "daily_cents": 10000, "daily_count": 3},
    "blocked_categories": ["gift cards", "crypto"],
    "owner_only_above_cents": 150000,
    "night_hours": None,
    "merchant_categories": {"Fresh Market": "groceries", "Gift Card Outlet": "gift cards", "CryptoCash": "crypto"},
}
POLICY = Policy.from_dict(BASE)


def decide(a: Action, policy: Policy = POLICY):
    return evaluate(a, policy, channel="voice", frozen=False, history=History(), local_hour=10)


def failed(d) -> set[str]:
    return {c.code for c in d.checks if not c.ok}


def test_gift_card_requested_as_other_is_denied():
    d = decide(Action("1", "purchase", 5000, "Target", "other", ("$50 gift card",)))
    assert d.outcome == Outcome.DENY and "keywords" in failed(d)


def test_gift_card_merchant_with_innocent_category_is_denied():
    d = decide(Action("1", "purchase", 2000, "Gift Card Outlet", "groceries", ("groceries",)))
    assert d.outcome == Outcome.DENY and "category" in failed(d)


@pytest.mark.parametrize("item", ["Bitcoin voucher", "crypto top-up", "Prepaid Visa", "GIFT-CARD bundle", "giftcards x5", "wire transfer fee", "Google Play card"])
def test_scam_keywords_in_item_text_are_denied(item):
    d = decide(Action("1", "purchase", 1000, "Fresh Market", "groceries", (item,)))
    assert d.outcome == Outcome.DENY and "keywords" in failed(d), item


def test_keyword_in_merchant_name_is_denied():
    assert decide(Action("1", "purchase", 1000, "Bitcoin Depot", "other", ("voucher",))).outcome == Outcome.DENY


@pytest.mark.parametrize("item", ["wireless headphones", "ethernet cable", "Ethiopian coffee", "giftwrap"])
def test_words_that_merely_contain_a_keyword_are_not_blocked(item):
    assert decide(Action("1", "purchase", 1000, "Fresh Market", "groceries", (item,))).outcome == Outcome.ALLOW, item


def test_caller_cannot_borrow_a_looser_category_at_an_unknown_shop():
    # Groceries allow $120 per order, the default only $50. An unknown shop claiming "groceries" gets the default.
    d = decide(Action("1", "purchase", 10000, "Random Shop", "groceries", ("food",)))
    assert "per_action" in failed(d)
    assert POLICY.resolve_category(Action("1", "purchase", 10000, "Random Shop", "groceries")) == "other"


def test_catalog_category_overrides_the_caller():
    assert POLICY.resolve_category(Action("1", "purchase", 100, "fresh  market", "electronics")) == "groceries"


def test_caller_may_make_it_stricter():
    assert decide(Action("1", "purchase", 100, "Random Shop", "Gift Cards", ("thing",))).outcome == Outcome.DENY


def test_transfers_are_always_the_transfer_category():
    assert POLICY.resolve_category(Action("1", "transfer", 100, "Anna", "groceries")) == "transfer"


def test_policy_round_trips_new_fields():
    again = Policy.from_dict(POLICY.to_dict())
    assert again.merchant_categories == POLICY.merchant_categories and again.blocked_keywords == POLICY.blocked_keywords


def test_owner_can_configure_keywords():
    p = Policy.from_dict({**BASE, "blocked_keywords": ["lottery"]})
    assert decide(Action("1", "purchase", 100, "Fresh Market", "groceries", ("lottery ticket",)), p).outcome == Outcome.DENY
    assert decide(Action("1", "purchase", 100, "Fresh Market", "groceries", ("wire",)), p).outcome == Outcome.ALLOW
