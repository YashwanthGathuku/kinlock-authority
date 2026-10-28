//! Property: a voice request can only lower authority.
//!
//! Whatever the action (any verb, category, target, amount, risk signals), when it arrives
//! by voice the core never ALLOWs anything that increases authority, and voice is never
//! more permissive than the owner's own channel.

use kinlock_authority_core::firewall::VERBS;
use kinlock_authority_core::policy::{History, INCREASE, OWNER, VOICE};
use kinlock_authority_core::{
    evaluate_action, voice_can_only_lower, AgentAction, FirewallPolicy, Outcome, Policy,
};
use proptest::prelude::*;
use serde_json::{json, Value};

fn fixtures() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/vectors/fixtures.json"
    );
    serde_json::from_str(&std::fs::read_to_string(path).expect("fixtures.json"))
        .expect("valid JSON")
}

fn verb_pairs() -> Vec<(String, String)> {
    let mut out = vec![
        ("money".to_string(), "made_up_verb".to_string()),
        ("made_up".to_string(), "purchase".to_string()),
    ];
    for (cat, verbs) in VERBS {
        for (v, _, _) in verbs.iter() {
            out.push((cat.to_string(), v.to_string()));
        }
    }
    out
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]
    #[test]
    fn voice_never_allows_an_increase(
        pair in prop::sample::select(verb_pairs()),
        target in prop::sample::select(vec!["Fresh Market", "AnyDesk", "TeamViewer", "grandson", "bank", "", "unknown caller", "Settings"]),
        amount in prop::option::of(0i64..500_000),
        risk in prop::collection::vec(prop::sample::select(vec!["urgency", "secrecy", "gift_card", "remote_access", "impersonation"]), 0..3),
        frozen in any::<bool>(),
        hour in 0i64..24,
        spent in 0i64..200_000,
        count in 0i64..20,
        requester in prop::sample::select(vec!["", "owner", "caller", "grandson"]),
    ) {
        let fx = fixtures();
        let policy = Policy::from_value(&fx["policy"]).unwrap();
        let fw = FirewallPolicy::from_value(Some(&fx["fw"])).unwrap();
        let mut a = json!({"request_id": "p", "category": pair.0, "verb": pair.1, "target": target,
                           "requester": requester, "risk": risk, "details": {}});
        if let Some(c) = amount { a["amount_cents"] = json!(c); }
        let action = AgentAction::from_value(&a).unwrap();
        let history = History::from_value(Some(&json!({"spent_cents": spent, "count": count}))).unwrap();

        let by_voice = evaluate_action(&action, &policy, VOICE, frozen, &history, hour, &fw).unwrap();
        prop_assert!(voice_can_only_lower(&by_voice, VOICE));
        prop_assert!(!(by_voice.direction == INCREASE && by_voice.outcome == Outcome::Allow));

        let by_owner = evaluate_action(&action, &policy, OWNER, frozen, &history, hour, &fw).unwrap();
        prop_assert!(by_voice.outcome >= by_owner.outcome, "voice {:?} looser than owner {:?}", by_voice.outcome, by_owner.outcome);
    }
}
