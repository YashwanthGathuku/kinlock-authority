from kinlock_authority import FirewallPolicy, Policy

POLICY = Policy.from_dict(
    {
        "owner": "Mary",
        "contacts": [{"id": "anna", "name": "Anna", "relation": "daughter", "ceiling_cents": 50000}],
        "known_merchants": ["Fresh Market"],
        "known_payees": ["Landlord"],
        "limits": {"groceries": {"per_action_cents": 15000, "daily_cents": 30000, "daily_count": 3}},
        "default_limits": {"per_action_cents": 5000, "daily_cents": 10000, "daily_count": 3},
        "blocked_categories": ["gift cards"],
        "owner_only_above_cents": 100000,
        "merchant_categories": {"Fresh Market": "groceries"},
        "night_hours": None,
    }
)

FW = FirewallPolicy.from_dict(
    {
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
)
