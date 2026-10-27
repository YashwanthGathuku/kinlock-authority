//! The authority firewall: one decision for every consequential action.
//! A port of `kinlock_authority/firewall.py`.

use std::collections::{BTreeMap, BTreeSet};

use regex::Regex;
use serde_json::{json, Map, Value};

use crate::canonical::digest;
use crate::policy::{
    self, check_channel, items, object, Action, Check, Contact, History, KeywordMatcher, Outcome,
    Policy, CONTACT, INCREASE, OWNER, REDUCE, SPEND, UNKNOWN, USE, VOICE,
};
use crate::py::{capitalize, casefold, format_g, money, norm, strip, to_int, to_str, truthy};
use crate::Error;

pub const MONEY: &str = "money";
pub const ACCESS: &str = "access";
pub const IDENTITY: &str = "identity";
pub const DATA: &str = "data";
pub const HEALTH: &str = "health";
pub const HOME: &str = "home";
pub const LEGAL: &str = "legal";
pub const COMMS: &str = "comms";
pub const CATEGORIES: &[&str] = &[MONEY, ACCESS, IDENTITY, DATA, HEALTH, HOME, LEGAL, COMMS];

/// category -> verb -> (direction, reversible).
/// One verb: (name, authority direction, reversible).
pub type Verb = (&'static str, &'static str, bool);

/// Verbs by category.
pub const VERBS: &[(&str, &[Verb])] = &[
    (
        MONEY,
        &[
            ("purchase", SPEND, true),
            ("transfer", SPEND, false),
            ("freeze", REDUCE, true),
            ("cancel_pending", REDUCE, true),
        ],
    ),
    (
        ACCESS,
        &[
            ("install_software", INCREASE, true),
            ("launch_remote_tool", INCREASE, false),
            ("grant_screen_control", INCREASE, false),
            ("share_screen", INCREASE, false),
            ("start_remote_session", INCREASE, false),
            ("add_admin_user", INCREASE, true),
            ("uninstall_software", REDUCE, true),
            ("end_remote_session", REDUCE, true),
            ("stop_screen_share", REDUCE, true),
            ("revoke_access", REDUCE, true),
        ],
    ),
    (
        IDENTITY,
        &[
            ("change_password", INCREASE, true),
            ("change_recovery_email", INCREASE, true),
            ("change_recovery_phone", INCREASE, true),
            ("change_2fa", INCREASE, true),
            ("disable_2fa", INCREASE, true),
            ("change_direct_deposit", INCREASE, true),
            ("change_address", INCREASE, true),
            ("add_device", INCREASE, true),
            ("add_authorized_user", INCREASE, true),
            ("lock_account", REDUCE, true),
            ("sign_out_everywhere", REDUCE, true),
            ("freeze_credit", REDUCE, true),
        ],
    ),
    (
        DATA,
        &[
            ("share_document", INCREASE, false),
            ("share_pii", INCREASE, false),
            ("grant_data_access", INCREASE, true),
            ("export_data", INCREASE, false),
            ("revoke_share", REDUCE, true),
        ],
    ),
    (
        HEALTH,
        &[
            ("refill_prescription", USE, true),
            ("book_appointment", USE, true),
            ("cancel_appointment", INCREASE, true),
            ("share_records", INCREASE, false),
            ("change_medication", INCREASE, true),
            ("grant_health_proxy", INCREASE, true),
        ],
    ),
    (
        HOME,
        &[
            ("unlock_door", INCREASE, true),
            ("disable_alarm", INCREASE, true),
            ("open_garage", INCREASE, true),
            ("add_access_code", INCREASE, true),
            ("lock_door", REDUCE, true),
            ("arm_alarm", REDUCE, true),
            ("close_garage", REDUCE, true),
            ("remove_access_code", REDUCE, true),
        ],
    ),
    (
        LEGAL,
        &[
            ("sign_document", INCREASE, false),
            ("grant_power_of_attorney", INCREASE, false),
            ("change_beneficiary", INCREASE, true),
            ("accept_terms", INCREASE, true),
        ],
    ),
    (
        COMMS,
        &[
            ("send_message", USE, false),
            ("place_call", USE, true),
            ("add_contact", INCREASE, true),
            ("forward_mail", INCREASE, true),
            ("set_call_forwarding", INCREASE, true),
            ("block_sender", REDUCE, true),
            ("mute_contact", REDUCE, true),
        ],
    ),
];

pub const SCREEN_CONTROL: &[&str] = &[
    "launch_remote_tool",
    "grant_screen_control",
    "share_screen",
    "start_remote_session",
];
pub const CALL_SIGNALS: &[&str] = &["inbound_call", "unsolicited_call"];

pub const DEFAULT_REMOTE_TOOLS: &[&str] = &[
    "anydesk",
    "teamviewer",
    "ultraviewer",
    "quick assist",
    "quickassist",
    "screenconnect",
    "connectwise",
    "connectwise control",
    "logmein",
    "logmein rescue",
    "gotoassist",
    "goto resolve",
    "zoho assist",
    "rustdesk",
    "splashtop",
    "supremo",
    "ammyy",
    "ammyy admin",
    "chrome remote desktop",
    "remote desktop",
    "remotepc",
    "aeroadmin",
    "ultravnc",
    "tightvnc",
    "realvnc",
    "vnc viewer",
    "bomgar",
    "beyondtrust",
    "dwservice",
    "action1",
    "atera",
    "iperius remote",
    "getscreen",
    "hoptodesk",
    "remoteutilities",
    "remote utilities",
];

pub const DEFAULT_SCAM_PATTERNS: &[(&str, &[&str])] = &[
    (
        "tech_support",
        &[
            r"\btech(nical)?[\s-]*support\b",
            r"\bhelp[\s-]*desk\b",
            r"\bvirus(es)?\b",
            r"\bmalware\b",
            r"\bhack(ed|er|ers)?\b",
            r"\b(infected|compromised)\b",
            r"\bpop[\s-]*up\b",
            r"\bsecurity (alert|warning)\b",
            r"\bfirewall (expired|warning)\b",
        ],
    ),
    (
        "refund",
        &[
            r"\brefunds?\b",
            r"\boverpa(id|yment)\b",
            r"\breimburse(ment)?\b",
            r"\bsent you too much\b",
        ],
    ),
    (
        "impersonation",
        &[
            r"\b(microsoft|windows|apple|icloud|amazon|geek squad|norton|mcafee|paypal|google|meta|facebook|your bank|bank)\s+(support|security|team|help|department|technician|agent|fraud|customer service)\b",
            r"\b(irs|social security|ssa|medicare|fbi|police|sheriff)\b",
        ],
    ),
    (
        "urgency",
        &[
            r"\burgent(ly)?\b",
            r"\bimmediately\b",
            r"\bright now\b",
            r"\bact now\b",
            r"\bor (your|the) account will\b",
            r"\bdon'?t tell\b",
            r"\bkeep (this|it) (secret|between us)\b",
        ],
    ),
];

/// (direction, reversible) from the verb table, or None for an unknown pair.
pub fn verb(category: &str, verb: &str) -> Option<(&'static str, bool)> {
    VERBS
        .iter()
        .find(|(c, _)| *c == category)?
        .1
        .iter()
        .find(|(v, _, _)| *v == verb)
        .map(|(_, d, r)| (*d, *r))
}

fn known_category(category: &str) -> bool {
    VERBS.iter().any(|(c, _)| *c == category)
}

fn is_identity_change(category: &str, v: &str) -> bool {
    category == IDENTITY && verb(IDENTITY, v).is_some_and(|(d, _)| d == INCREASE)
}

/// One consequential action an agent wants to take, in any category.
#[derive(Clone, Debug, PartialEq)]
pub struct AgentAction {
    pub request_id: String,
    pub category: String,
    pub verb: String,
    pub target: String,
    /// Free-form, in the order given (the scanners read them in that order).
    pub details: Map<String, Value>,
    pub risk: BTreeSet<String>,
    pub reversible: bool,
    pub requester: String,
    pub beneficiaries: Vec<String>,
    pub amount_cents: i64,
}

fn opt_str(d: &Map<String, Value>, k: &str) -> String {
    d.get(k).map_or_else(String::new, to_str)
}

impl AgentAction {
    pub fn from_value(v: &Value) -> Result<AgentAction, Error> {
        let d = object(v)?;
        let request_id = to_str(
            d.get("request_id")
                .ok_or_else(|| Error::Invalid("missing field 'request_id'".into()))?,
        );
        let details = match d.get("details") {
            Some(x) if truthy(x) => object(x)?.clone(),
            _ => Map::new(),
        };
        Ok(AgentAction {
            request_id,
            category: casefold(strip(&opt_str(d, "category"))),
            verb: casefold(strip(&opt_str(d, "verb"))),
            target: opt_str(d, "target"),
            details,
            risk: items(d.get("risk")).iter().map(to_str).collect(),
            reversible: d.get("reversible").map_or(true, truthy),
            requester: opt_str(d, "requester"),
            beneficiaries: items(d.get("beneficiaries")).iter().map(to_str).collect(),
            amount_cents: d.get("amount_cents").map_or(Ok(0), to_int)?,
        })
    }

    pub fn to_value(&self) -> Value {
        let mut details = Map::new();
        let mut keys: Vec<&String> = self.details.keys().collect();
        keys.sort();
        for k in keys {
            details.insert(k.clone(), self.details[k].clone());
        }
        json!({
            "request_id": self.request_id,
            "category": self.category,
            "verb": self.verb,
            "target": self.target,
            "details": details,
            "risk": self.risk.iter().collect::<Vec<_>>(),
            "reversible": self.reversible,
            "requester": self.requester,
            "beneficiaries": self.beneficiaries,
            "amount_cents": self.amount_cents,
        })
    }

    /// The value the digest covers: the action plus its schema tag.
    pub fn digest_value(&self) -> Value {
        let mut v = self.to_value();
        if let Value::Object(o) = &mut v {
            o.insert("schema".into(), Value::String("kinlock.action/1".into()));
        }
        v
    }

    /// What an approval is bound to.
    pub fn digest(&self) -> String {
        digest(&self.digest_value())
    }

    /// Everything a person or scammer wrote into the request, for the scanners.
    pub fn text(&self) -> String {
        let mut parts = vec![self.verb.replace('_', " "), self.target.clone()];
        parts.extend(
            self.details
                .iter()
                .map(|(k, v)| format!("{k} {}", to_str(v))),
        );
        casefold(&parts.join(" "))
    }

    /// The purchase or transfer `Action` this money action corresponds to.
    pub fn legacy(&self) -> Action {
        let item = self.details.get("item");
        Action {
            request_id: self.request_id.clone(),
            kind: self.verb.clone(),
            amount_cents: self.amount_cents,
            counterparty: self.target.clone(),
            category: opt_str(&self.details, "category"),
            items: item.filter(|i| truthy(i)).map(to_str).into_iter().collect(),
            setting: String::new(),
            value: 0,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Person {
    pub id: String,
    pub name: String,
    pub group: String,
    pub identifiers: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Quorum {
    pub required: i64,
    pub members: Vec<String>,
    pub owner_final: bool,
}

impl Quorum {
    fn to_value(&self) -> Value {
        json!({"required": self.required, "members": self.members, "owner_final": self.owner_final})
    }
}

/// The owner's rules for non-money actions.
#[derive(Clone, Debug)]
pub struct FirewallPolicy {
    pub people: Vec<Person>,
    pub standing: BTreeMap<String, BTreeSet<String>>,
    pub known_targets: BTreeMap<String, BTreeSet<String>>,
    pub remote_access_allowlist: BTreeSet<String>,
    pub owner_only_categories: BTreeSet<String>,
    pub identity_cooloff_seconds: i64,
    pub quorum: BTreeMap<String, Quorum>,
    pub remote_tools: Vec<String>,
    remote_matcher: KeywordMatcher,
    pub scam_patterns: Vec<(String, Vec<Regex>)>,
}

impl Default for FirewallPolicy {
    fn default() -> Self {
        FirewallPolicy::from_value(None).expect("the default firewall policy is valid")
    }
}

fn compile(pattern: &str) -> Result<Regex, Error> {
    Regex::new(pattern)
        .map_err(|e| Error::Invalid(format!("scam pattern {pattern:?} is not supported: {e}")))
}

fn norm_map(v: Option<&Value>) -> BTreeMap<String, BTreeSet<String>> {
    let mut m = BTreeMap::new();
    if let Some(Value::Object(o)) = v {
        for (k, vs) in o {
            m.insert(
                norm(k),
                items(Some(vs)).iter().map(|x| norm(&to_str(x))).collect(),
            );
        }
    }
    m
}

impl FirewallPolicy {
    pub fn from_value(v: Option<&Value>) -> Result<FirewallPolicy, Error> {
        let empty = Map::new();
        let d = match v {
            Some(x) if truthy(x) => object(x)?,
            _ => &empty,
        };
        let mut people = Vec::new();
        for p in items(d.get("people")) {
            let p = object(&p)?;
            let id = to_str(
                p.get("id")
                    .ok_or_else(|| Error::Invalid("missing field 'id'".into()))?,
            );
            people.push(Person {
                name: p.get("name").map_or_else(|| id.clone(), to_str),
                group: opt_str(p, "group"),
                identifiers: items(p.get("identifiers"))
                    .iter()
                    .map(|i| norm(&to_str(i)))
                    .collect(),
                id,
            });
        }
        let mut quorum = BTreeMap::new();
        if let Some(Value::Object(o)) = d.get("quorum") {
            for (k, q) in o {
                let q = object(q)?;
                quorum.insert(
                    norm(k),
                    Quorum {
                        required: to_int(
                            q.get("required")
                                .ok_or_else(|| Error::Invalid("missing field 'required'".into()))?,
                        )?,
                        members: items(q.get("members")).iter().map(to_str).collect(),
                        owner_final: q.get("owner_final").map_or(true, truthy),
                    },
                );
            }
        }
        let remote_tools: Vec<String> = match d.get("remote_tools") {
            Some(t) => items(Some(t)).iter().map(to_str).collect(),
            None => DEFAULT_REMOTE_TOOLS.iter().map(|s| s.to_string()).collect(),
        };
        let mut scam_patterns = Vec::new();
        match d.get("scam_patterns") {
            Some(Value::Object(o)) => {
                for (k, v) in o {
                    let regs = items(Some(v))
                        .iter()
                        .map(|r| compile(&to_str(r)))
                        .collect::<Result<Vec<_>, _>>()?;
                    scam_patterns.push((k.clone(), regs));
                }
            }
            Some(_) => return Err(Error::Invalid("scam_patterns must be an object".into())),
            None => {
                for (k, regs) in DEFAULT_SCAM_PATTERNS {
                    scam_patterns.push((
                        k.to_string(),
                        regs.iter()
                            .map(|r| compile(r))
                            .collect::<Result<Vec<_>, _>>()?,
                    ));
                }
            }
        }
        Ok(FirewallPolicy {
            people,
            standing: norm_map(d.get("standing")),
            known_targets: norm_map(d.get("known_targets")),
            remote_access_allowlist: items(d.get("remote_access_allowlist"))
                .iter()
                .map(to_str)
                .collect(),
            owner_only_categories: match d.get("owner_only_categories") {
                Some(c) => items(Some(c)).iter().map(|x| norm(&to_str(x))).collect(),
                None => [IDENTITY, LEGAL].iter().map(|s| s.to_string()).collect(),
            },
            identity_cooloff_seconds: d
                .get("identity_cooloff_seconds")
                .map_or(Ok(24 * 3600), to_int)?,
            quorum,
            remote_matcher: KeywordMatcher::new(&remote_tools),
            remote_tools,
            scam_patterns,
        })
    }

    pub fn person(&self, id: &str) -> Option<&Person> {
        self.people.iter().find(|p| p.id == id)
    }
}

pub fn remote_tools_named(action: &AgentAction, fw: &FirewallPolicy) -> Vec<String> {
    fw.remote_matcher
        .find_all(&action.text())
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// Labels of scam patterns found in free text.
pub fn scam_signals(text: &str, fw: Option<&FirewallPolicy>) -> Result<BTreeSet<String>, Error> {
    let default;
    let fw = match fw {
        Some(f) => f,
        None => {
            default = FirewallPolicy::default();
            &default
        }
    };
    let t = casefold(text);
    Ok(fw
        .scam_patterns
        .iter()
        .filter(|(_, regs)| regs.iter().any(|r| r.is_match(&t)))
        .map(|(l, _)| l.clone())
        .collect())
}

/// (direction, reversible) for an action; UNKNOWN for a category or verb Kinlock doesn't know.
pub fn classify(action: &AgentAction) -> (&'static str, bool) {
    match verb(&action.category, &action.verb) {
        None => (UNKNOWN, false),
        Some((d, r)) => (d, r && action.reversible),
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ActionDecision {
    pub outcome: Outcome,
    pub direction: &'static str,
    pub checks: Vec<Check>,
    pub category: String,
    pub reversible: bool,
    pub cooloff_seconds: i64,
    pub quorum: Option<Quorum>,
    pub signals: BTreeSet<String>,
}

impl ActionDecision {
    pub fn reasons(&self) -> Vec<&str> {
        self.checks
            .iter()
            .filter(|c| !c.ok)
            .map(|c| c.text.as_str())
            .collect()
    }

    pub fn to_value(&self) -> Value {
        json!({
            "outcome": self.outcome.as_str(),
            "direction": self.direction,
            "category": self.category,
            "reversible": self.reversible,
            "cooloff_seconds": self.cooloff_seconds,
            "quorum": self.quorum.as_ref().map(Quorum::to_value),
            "signals": self.signals.iter().collect::<Vec<_>>(),
            "checks": self.checks.iter().map(Check::to_value).collect::<Vec<_>>(),
        })
    }
}

/// Decide one action in any category. Pure: same inputs, same decision.
pub fn evaluate_action(
    action: &AgentAction,
    policy: &Policy,
    channel: &str,
    frozen: bool,
    history: &History,
    local_hour: i64,
    fw: &FirewallPolicy,
) -> Result<ActionDecision, Error> {
    check_channel(channel)?;
    let (direction, reversible) = classify(action);
    let mut signals: BTreeSet<String> = action.risk.clone();
    for s in scam_signals(&action.text(), Some(fw))? {
        signals.insert(format!("scam:{s}"));
    }
    let tools = remote_tools_named(action, fw);
    for t in &tools {
        signals.insert(format!("remote_tool:{t}"));
    }
    let scams: Vec<String> = signals
        .iter()
        .filter_map(|s| s.strip_prefix("scam:").map(str::to_string))
        .collect();
    let on_call = signals.iter().any(|s| CALL_SIGNALS.contains(&s.as_str()));
    let owner = policy.owner.as_str();
    let category = action.category.clone();

    let done = |outcome: Outcome, mut checks: Vec<Check>, cooloff: i64| {
        let q = if matches!(outcome, Outcome::Hold | Outcome::Owner) {
            fw.quorum.get(&category).cloned()
        } else {
            None
        };
        if let Some(q) = &q {
            let tail = if q.owner_final {
                format!(", including {owner}")
            } else {
                String::new()
            };
            checks.push(Check::new(
                "quorum",
                false,
                format!("{} people must agree{tail}", q.required),
            ));
        }
        ActionDecision {
            outcome,
            direction,
            checks,
            category: category.clone(),
            reversible,
            cooloff_seconds: cooloff,
            quorum: q,
            signals: signals.clone(),
        }
    };

    if action.category == MONEY && direction == SPEND {
        let legacy = policy::evaluate(
            &action.legacy(),
            policy,
            channel,
            frozen,
            history,
            local_hour,
        )?;
        let mut checks = legacy.checks;
        let mut outcome = legacy.outcome;
        if outcome != Outcome::Deny && (!scams.is_empty() || on_call) {
            let mut why = scams.clone();
            if on_call {
                why.push("during or right after an inbound call".into());
            }
            checks.push(Check::new(
                "risk",
                false,
                format!(
                    "Warning signs ({}), so only {owner} can approve this",
                    why.join(", ")
                ),
            ));
            outcome = outcome.stricter(Outcome::Owner);
        }
        return Ok(done(outcome, checks, 0));
    }

    if direction == UNKNOWN {
        let what = if known_category(&action.category) {
            "action"
        } else {
            "category"
        };
        return Ok(done(
            Outcome::Hold,
            vec![Check::new(
                "known",
                false,
                format!(
                    "Kinlock doesn't know this {what} ({} {}), so a person has to approve it",
                    action.category, action.verb
                ),
            )],
            0,
        ));
    }

    if direction == REDUCE {
        return Ok(ActionDecision {
            outcome: Outcome::Allow,
            direction,
            checks: vec![Check::new(
                "direction",
                true,
                "This only lowers authority, so any channel may do it",
            )],
            category: category.clone(),
            reversible,
            cooloff_seconds: 0,
            quorum: None,
            signals: signals.clone(),
        });
    }

    let mut checks = vec![Check::new(
        "lock",
        !frozen,
        if frozen {
            "Safety lock is on"
        } else {
            "Safety lock is off"
        },
    )];
    if frozen {
        return Ok(done(Outcome::Deny, checks, 0));
    }

    let mut outcome = Outcome::Allow;
    let mut cooloff = 0;
    let targets = fw.known_targets.get(&action.category);
    let known_target = targets.is_some_and(|t| t.contains(&norm(&action.target)));

    if direction == USE {
        let standing = fw
            .standing
            .get(&action.category)
            .is_some_and(|s| s.contains(&action.verb));
        checks.push(Check::new(
            "standing",
            standing,
            if standing {
                format!("{owner} lets this happen without asking")
            } else {
                format!("{owner} hasn't said this can happen without asking")
            },
        ));
        if targets.is_some() {
            checks.push(Check::new(
                "target",
                known_target,
                if known_target {
                    format!("{} is someone {owner} knows", action.target)
                } else {
                    format!("{} is new", action.target)
                },
            ));
        }
        if !standing || (targets.is_some() && !known_target) {
            outcome = Outcome::Hold;
        }
    } else if channel == OWNER && !is_identity_change(&action.category, &action.verb) {
        checks.push(Check::new(
            "direction",
            true,
            format!("{owner} asked for this herself on her secure page"),
        ));
    } else {
        let who = match channel {
            VOICE => "A voice request",
            CONTACT => "A trusted contact",
            _ => "This channel",
        };
        checks.push(Check::new(
            "direction",
            false,
            format!("{who} can't give anyone new access or control on its own"),
        ));
        outcome = Outcome::Hold;
        if fw.owner_only_categories.contains(&action.category) {
            checks.push(Check::new(
                "owner_category",
                false,
                format!(
                    "{} changes need {owner} herself",
                    capitalize(&action.category)
                ),
            ));
            outcome = Outcome::Owner;
        }
        if !reversible {
            checks.push(Check::new(
                "reversible",
                false,
                format!("This can't be undone, so only {owner} can approve it"),
            ));
            outcome = Outcome::Owner;
        }
    }

    let remote = SCREEN_CONTROL.contains(&action.verb.as_str()) || !tools.is_empty();
    if remote && direction != REDUCE {
        let label = if tools.is_empty() {
            action.verb.replace('_', " ")
        } else {
            tools.join(", ")
        };
        let allowed = fw.remote_access_allowlist.contains(&action.requester);
        if on_call {
            checks.push(Check::new("remote_access", false, format!("Remote access ({label}) asked for during or right after a call {owner} didn't place. That is how tech-support scams work, so Kinlock won't do it")));
            outcome = Outcome::Deny;
        } else if !scams.is_empty() {
            checks.push(Check::new(
                "remote_access",
                false,
                format!(
                    "Remote access ({label}) with warning signs ({}). Kinlock won't do it",
                    scams.join(", ")
                ),
            ));
            outcome = Outcome::Deny;
        } else if !allowed {
            checks.push(Check::new("remote_access", false, format!("Remote access ({label}) for someone not on {owner}'s list. Kinlock won't do it")));
            outcome = Outcome::Deny;
        } else {
            checks.push(Check::new(
                "remote_access",
                false,
                format!("Remote access ({label}) always needs {owner} herself"),
            ));
            outcome = outcome.stricter(Outcome::Owner);
        }
    } else if !scams.is_empty() && direction != REDUCE {
        checks.push(Check::new(
            "risk",
            false,
            format!(
                "Warning signs ({}), so only {owner} can approve this",
                scams.join(", ")
            ),
        ));
        outcome = outcome.stricter(Outcome::Owner);
    }
    if on_call && !remote && direction == INCREASE {
        checks.push(Check::new(
            "call",
            false,
            format!(
                "Asked during or right after an inbound call, so only {owner} can approve this"
            ),
        ));
        outcome = outcome.stricter(Outcome::Owner);
    }

    if is_identity_change(&action.category, &action.verb) {
        cooloff = fw.identity_cooloff_seconds.max(0);
        let hours = cooloff as f64 / 3600.0;
        let span = if hours != 1.0 {
            format!("{} hours", format_g(hours))
        } else {
            "1 hour".into()
        };
        checks.push(Check::new(
            "cooloff",
            false,
            format!(
                "Account recovery and identity changes wait {span}, then need {owner} to confirm"
            ),
        ));
        outcome = outcome.stricter(Outcome::Owner);
    }

    if action.category == HOME
        && direction == INCREASE
        && outcome != Outcome::Deny
        && channel != OWNER
    {
        let visitor = action
            .details
            .get("visitor")
            .map_or_else(|| action.target.clone(), to_str);
        let known_visitor = fw
            .known_targets
            .get(HOME)
            .is_some_and(|t| t.contains(&norm(&visitor)));
        checks.push(Check::new(
            "visitor",
            known_visitor,
            if known_visitor {
                format!("{visitor} is someone {owner} lets in")
            } else {
                format!("{visitor} isn't someone {owner} has said to let in, so only she can")
            },
        ));
        if !known_visitor {
            outcome = outcome.stricter(Outcome::Owner);
        }
    }

    Ok(done(outcome, checks, cooloff))
}

/// Why `approver` can't approve this action, or None.
pub fn conflict_of_interest(
    action: &AgentAction,
    approver: &str,
    fw: &FirewallPolicy,
) -> Option<String> {
    if approver == OWNER {
        return None;
    }
    if approver == action.requester {
        return Some("You asked for this, so you can't also approve it".into());
    }
    if action.beneficiaries.iter().any(|b| b == approver) {
        return Some("This would benefit you, so someone else has to approve it".into());
    }
    let p = fw.person(approver)?;
    if !p.name.is_empty() {
        let name = norm(&p.name);
        if name == norm(&action.target) || action.beneficiaries.iter().any(|b| norm(b) == name) {
            return Some("This is about you, so someone else has to approve it".into());
        }
    }
    if !p.identifiers.is_empty() {
        let text = action.text();
        if let Some(hit) = p
            .identifiers
            .iter()
            .find(|i| !i.is_empty() && text.contains(i.as_str()))
        {
            return Some(format!(
                "This points at your own {hit}, so someone else has to approve it"
            ));
        }
    }
    None
}

/// Whether one person may cast an approving vote for this held action.
pub fn may_approve_action(
    decision: &ActionDecision,
    action: &AgentAction,
    approver: &str,
    role: &str,
    contact: Option<&Contact>,
    fw: &FirewallPolicy,
) -> (bool, String) {
    match decision.outcome {
        Outcome::Allow => return (true, "No approval needed".into()),
        Outcome::Deny => {
            return (
                false,
                "The rules block this action; no approval can release it".into(),
            )
        }
        _ => {}
    }
    if let Some(coi) = conflict_of_interest(action, approver, fw) {
        return (false, coi);
    }
    if role == OWNER {
        return (true, "The owner approved".into());
    }
    if let Some(q) = &decision.quorum {
        if !q.members.iter().any(|m| m == approver) {
            return (
                false,
                "You aren't one of the people who decide this together".into(),
            );
        }
        return (true, "Your vote counts toward the quorum".into());
    }
    if decision.outcome == Outcome::Owner {
        return (
            false,
            "This needs the owner herself; a trusted contact can't approve it".into(),
        );
    }
    if action.category == MONEY && decision.direction == SPEND {
        let d = policy::Decision {
            outcome: decision.outcome,
            direction: decision.direction,
            checks: decision.checks.clone(),
        };
        return policy::may_approve(&d, role, action.amount_cents, contact);
    }
    match contact.filter(|_| role == CONTACT) {
        Some(c) => (true, format!("{} approved", c.name)),
        None => (
            false,
            "Only the owner or her trusted contact can approve".into(),
        ),
    }
}

pub const APPROVE: &str = "approve";
pub const DECLINE: &str = "decline";
pub const PAUSE: &str = "pause";
pub const RESUME: &str = "resume";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vote {
    pub voter: String,
    pub choice: String,
    pub comment: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tally {
    pub state: &'static str,
    pub approvals: Vec<String>,
    pub problems: Vec<String>,
    pub comments: Vec<(String, String)>,
}

/// Count votes on a held action under its quorum (or a single approval without one).
pub fn tally(
    decision: &ActionDecision,
    action: &AgentAction,
    votes: &[Vote],
    fw: &FirewallPolicy,
) -> Tally {
    if decision.outcome == Outcome::Deny {
        return Tally {
            state: "declined",
            approvals: vec![],
            problems: vec!["The rules block this action; no vote can release it".into()],
            comments: vec![],
        };
    }
    let q = decision.quorum.as_ref();
    let members: BTreeSet<&str> = match q {
        Some(q) => q.members.iter().map(String::as_str).collect(),
        None => fw.people.iter().map(|p| p.id.as_str()).collect(),
    };
    // group key -> voter, in insertion order like a Python dict.
    let mut approvals: Vec<(String, String)> = Vec::new();
    let mut problems = Vec::new();
    let mut comments = Vec::new();
    let mut paused_by: BTreeSet<String> = BTreeSet::new();
    let (mut owner_approved, mut owner_declined) = (false, false);
    for v in votes {
        if !v.comment.is_empty() {
            comments.push((v.voter.clone(), v.comment.clone()));
        }
        if v.voter != OWNER && !members.contains(v.voter.as_str()) {
            problems.push(format!(
                "{} isn't one of the people who decide this",
                v.voter
            ));
            continue;
        }
        match v.choice.as_str() {
            PAUSE => {
                paused_by.insert(v.voter.clone());
                continue;
            }
            RESUME => {
                if v.voter == OWNER {
                    paused_by.clear();
                } else {
                    paused_by.remove(&v.voter);
                }
                continue;
            }
            DECLINE => {
                if v.voter == OWNER {
                    owner_declined = true;
                }
                approvals.retain(|(_, who)| *who != v.voter);
                continue;
            }
            APPROVE => {}
            other => {
                problems.push(format!(
                    "{}: unknown vote {}",
                    v.voter,
                    crate::py::repr_str(other)
                ));
                continue;
            }
        }
        if let Some(coi) = conflict_of_interest(action, &v.voter, fw) {
            problems.push(format!("{}: {coi}", v.voter));
            continue;
        }
        let set = |approvals: &mut Vec<(String, String)>, key: String, who: String| match approvals
            .iter_mut()
            .find(|(k, _)| *k == key)
        {
            Some(slot) => slot.1 = who,
            None => approvals.push((key, who)),
        };
        if v.voter == OWNER {
            owner_approved = true;
            set(&mut approvals, "owner".into(), OWNER.into());
            continue;
        }
        if q.is_none() && decision.outcome == Outcome::Owner {
            problems.push(format!("{}: this needs the owner herself", v.voter));
            continue;
        }
        let key = match fw.person(&v.voter) {
            Some(p) if !p.group.is_empty() => format!("group:{}", p.group),
            _ => v.voter.clone(),
        };
        if let Some((_, other)) = approvals.iter().find(|(k, _)| *k == key) {
            if *other != v.voter {
                problems.push(format!(
                    "{} is in the same group as {other}, so they count once together",
                    v.voter
                ));
                continue;
            }
        }
        set(&mut approvals, key, v.voter.clone());
    }
    let counted: Vec<String> = approvals
        .iter()
        .map(|(_, w)| w.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    if owner_declined {
        return Tally {
            state: "declined",
            approvals: counted,
            problems,
            comments,
        };
    }
    if !paused_by.is_empty() {
        problems.push(format!(
            "Paused by {}",
            paused_by.iter().cloned().collect::<Vec<_>>().join(", ")
        ));
        return Tally {
            state: "paused",
            approvals: counted,
            problems,
            comments,
        };
    }
    let enough = match q {
        Some(q) => {
            let owner_needed = q.owner_final || decision.outcome == Outcome::Owner;
            counted.len() as i64 >= q.required && (owner_approved || !owner_needed)
        }
        None if decision.outcome == Outcome::Owner => owner_approved,
        None => !counted.is_empty(),
    };
    Tally {
        state: if enough { "approved" } else { "waiting" },
        approvals: counted,
        problems,
        comments,
    }
}

/// Every reason this held action may not run yet. Empty means it may run (after capability checks).
pub fn release_problems(
    decision: &ActionDecision,
    action: &AgentAction,
    votes: &[Vote],
    requested_at: f64,
    now: f64,
    fw: &FirewallPolicy,
) -> Vec<String> {
    match decision.outcome {
        Outcome::Deny => {
            return vec!["The rules block this action; no approval can release it".into()]
        }
        Outcome::Allow => return vec![],
        _ => {}
    }
    let mut problems = Vec::new();
    let ready_at = requested_at + decision.cooloff_seconds as f64;
    if now < ready_at {
        let left = (ready_at - now).trunc() as i64;
        problems.push(format!(
            "The cool-off period hasn't passed yet ({}h {}m left)",
            left / 3600,
            left % 3600 / 60
        ));
    }
    let t = tally(decision, action, votes, fw);
    match t.state {
        "approved" => {}
        "paused" => problems.push("A supporter paused this".into()),
        "declined" => problems.push("It was declined".into()),
        _ => problems.push("Not enough of the right people have approved it".into()),
    }
    problems
}

fn phrase(verb: &str) -> Option<&'static str> {
    Some(match verb {
        "install_software" => "install {target}",
        "launch_remote_tool" => "start the remote-access tool {target}",
        "grant_screen_control" => "give {target} control of the screen",
        "share_screen" => "share the screen with {target}",
        "start_remote_session" => "start a remote session with {target}",
        "change_password" => "change the password for {target}",
        "change_recovery_email" => "change the recovery email for {target}",
        "change_recovery_phone" => "change the recovery phone for {target}",
        "change_2fa" => "change two-step sign-in for {target}",
        "disable_2fa" => "turn off two-step sign-in for {target}",
        "change_direct_deposit" => "change where {target} payments are deposited",
        "change_address" => "change the mailing address for {target}",
        "add_device" => "add a new device to {target}",
        "unlock_door" => "unlock the {target}",
        "disable_alarm" => "turn off the {target} alarm",
        "lock_door" => "lock the {target}",
        "send_message" => "send a message to {target}",
        "share_document" => "share {target}",
        "share_pii" => "share personal details with {target}",
        "sign_document" => "sign {target}",
        "purchase" => "buy from {target}",
        "transfer" => "send money to {target}",
        _ => return None,
    })
}

/// A short plain phrase for the action, for pages, pushes and spoken receipts.
pub fn describe_action(action: &AgentAction) -> String {
    let template = match phrase(&action.verb) {
        Some(p) => p.to_string(),
        None => {
            action.verb.replace('_', " ")
                + if action.target.is_empty() {
                    ""
                } else {
                    " {target}"
                }
        }
    };
    let target = if action.target.is_empty() {
        "it"
    } else {
        action.target.as_str()
    };
    // str.format substitutes once; braces inside the verb itself would be a format error in Python.
    let mut text = strip(&template.replace("{target}", target)).to_string();
    if action.category == MONEY && action.amount_cents != 0 {
        text += &format!(" for {}", money(action.amount_cents));
    }
    if let Some(visitor) = action.details.get("visitor").filter(|v| truthy(v)) {
        if action.category == HOME {
            text += &format!(" for {}", to_str(visitor));
        }
    }
    text
}

/// The invariant, as a predicate: a voice request never ALLOWs an increase of authority.
pub fn voice_can_only_lower(decision: &ActionDecision, channel: &str) -> bool {
    !(channel == VOICE && decision.outcome == Outcome::Allow && decision.direction == INCREASE)
}
