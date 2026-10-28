//! The owner's rules and the deterministic decision over a purchase, a transfer
//! or a rule change. A port of `kinlock_authority/policy.py`.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Map, Value};

use crate::canonical::digest;
use crate::py::{is_space, money, norm, repr_str, to_int, to_str, truthy, upper_first};
use crate::Error;

pub const REDUCE: &str = "reduce";
pub const INCREASE: &str = "increase";
pub const SPEND: &str = "spend";
pub const UNKNOWN: &str = "unknown";
pub const USE: &str = "use";

pub const REDUCING_KINDS: &[&str] = &[
    "freeze",
    "cancel_pending",
    "remove_merchant",
    "remove_payee",
    "block_category",
    "remove_contact",
];
pub const INCREASING_KINDS: &[&str] = &[
    "unfreeze",
    "add_merchant",
    "add_payee",
    "unblock_category",
    "add_contact",
];
pub const SPENDING_KINDS: &[&str] = &["purchase", "transfer"];
pub const SET_LIMIT: &str = "set_limit";

pub const VOICE: &str = "voice";
pub const CONTACT: &str = "contact";
pub const OWNER: &str = "owner";
pub const CHANNELS: &[&str] = &[VOICE, CONTACT, OWNER];
pub const OTHER: &str = "other";

pub const DEFAULT_BLOCKED_KEYWORDS: &[&str] = &[
    "gift card",
    "gift cards",
    "giftcard",
    "giftcards",
    "gift voucher",
    "steam card",
    "itunes card",
    "google play card",
    "crypto",
    "cryptocurrency",
    "bitcoin",
    "btc",
    "ethereum",
    "eth",
    "usdt",
    "tether",
    "coinbase",
    "binance",
    "wire",
    "wire transfer",
    "western union",
    "moneygram",
    "money order",
    "prepaid",
    "prepaid card",
    "reload card",
];

/// The four outcomes, least to most strict.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Outcome {
    Allow,
    Hold,
    Owner,
    Deny,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Allow => "ALLOW",
            Outcome::Hold => "HOLD",
            Outcome::Owner => "OWNER",
            Outcome::Deny => "DENY",
        }
    }

    /// The stricter of two outcomes.
    pub fn stricter(self, other: Outcome) -> Outcome {
        self.max(other)
    }
}

pub fn check_channel(channel: &str) -> Result<(), Error> {
    if CHANNELS.contains(&channel) {
        Ok(())
    } else {
        Err(Error::Invalid(format!(
            "unknown channel {}",
            repr_str(channel)
        )))
    }
}

/// Words that mark a request as a scam favourite, matched as whole words with any
/// run of spaces, hyphens or underscores (or nothing) between the words of a phrase.
/// Behaves exactly like the Python regular expression built by `_keyword_pattern`.
#[derive(Clone, Debug)]
pub struct KeywordMatcher {
    alts: Vec<Vec<Vec<char>>>,
}

fn boundary(c: Option<&char>) -> bool {
    !matches!(c, Some(c) if c.is_ascii_lowercase() || c.is_ascii_digit())
}

fn is_sep(c: char) -> bool {
    is_space(c) || c == '-' || c == '_'
}

impl KeywordMatcher {
    pub fn new<S: AsRef<str>>(words: &[S]) -> KeywordMatcher {
        let set: BTreeSet<String> = words
            .iter()
            .filter(|w| !crate::py::strip(w.as_ref()).is_empty())
            .map(|w| crate::py::join_words(&crate::py::casefold(w.as_ref())))
            .collect();
        let mut alts: Vec<String> = set.into_iter().collect();
        // Longest first, as the Python pattern orders its alternatives (ties broken by text, which Python leaves to set order).
        alts.sort_by(|a, b| {
            b.chars()
                .count()
                .cmp(&a.chars().count())
                .then_with(|| a.cmp(b))
        });
        KeywordMatcher {
            alts: alts
                .iter()
                .map(|a| a.split(' ').map(|p| p.chars().collect()).collect())
                .collect(),
        }
    }

    /// Every end position for `parts` matched at `pos`, in the order the regex engine tries them.
    fn ends(text: &[char], pos: usize, parts: &[Vec<char>], out: &mut Vec<usize>) {
        let Some((first, rest)) = parts.split_first() else {
            out.push(pos);
            return;
        };
        if text.len() < pos + first.len() || text[pos..pos + first.len()] != first[..] {
            return;
        }
        let after = pos + first.len();
        if rest.is_empty() {
            out.push(after);
            return;
        }
        let mut run = after;
        while run < text.len() && is_sep(text[run]) {
            run += 1;
        }
        for start in (after..=run).rev() {
            Self::ends(text, start, rest, out);
        }
    }

    fn match_at(&self, text: &[char], start: usize) -> Option<usize> {
        if !boundary(start.checked_sub(1).and_then(|i| text.get(i))) {
            return None;
        }
        for alt in &self.alts {
            let mut ends = Vec::new();
            Self::ends(text, start, alt, &mut ends);
            if let Some(e) = ends.into_iter().find(|&e| boundary(text.get(e))) {
                return Some(e);
            }
        }
        None
    }

    /// `pattern.finditer(text)`: every non-overlapping match, left to right.
    pub fn find_all(&self, text: &str) -> Vec<String> {
        let chars: Vec<char> = text.chars().collect();
        let mut found = Vec::new();
        let mut i = 0;
        while i <= chars.len() {
            match self.match_at(&chars, i) {
                Some(e) if e > i => {
                    found.push(chars[i..e].iter().collect());
                    i = e;
                }
                _ => i += 1,
            }
        }
        found
    }

    /// `pattern.search(text)`.
    pub fn first(&self, text: &str) -> Option<String> {
        let chars: Vec<char> = text.chars().collect();
        (0..=chars.len()).find_map(|i| {
            self.match_at(&chars, i)
                .filter(|&e| e > i)
                .map(|e| chars[i..e].iter().collect())
        })
    }
}

fn get<'a>(d: &'a Map<String, Value>, k: &str) -> Option<&'a Value> {
    d.get(k)
}

fn req<'a>(d: &'a Map<String, Value>, k: &str) -> Result<&'a Value, Error> {
    d.get(k)
        .ok_or_else(|| Error::Invalid(format!("missing field {}", repr_str(k))))
}

fn str_or(d: &Map<String, Value>, k: &str, default: &str) -> String {
    get(d, k).map_or_else(|| default.to_string(), to_str)
}

fn int_or(d: &Map<String, Value>, k: &str, default: i64) -> Result<i64, Error> {
    get(d, k).map_or(Ok(default), to_int)
}

/// Iterate a JSON value the way Python iterates it in `for x in value`.
pub fn items(v: Option<&Value>) -> Vec<Value> {
    match v {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(a)) => a.clone(),
        Some(Value::String(s)) => s.chars().map(|c| Value::String(c.to_string())).collect(),
        Some(Value::Object(o)) => o.keys().map(|k| Value::String(k.clone())).collect(),
        Some(other) => vec![other.clone()],
    }
}

pub fn object(v: &Value) -> Result<&Map<String, Value>, Error> {
    v.as_object().ok_or_else(|| {
        Error::Invalid(format!(
            "expected an object, not {}",
            crate::py::type_name(v)
        ))
    })
}

/// A purchase, transfer or rule change. The assistant fills it; it never decides it.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Action {
    pub request_id: String,
    pub kind: String,
    pub amount_cents: i64,
    pub counterparty: String,
    pub category: String,
    pub items: Vec<String>,
    pub setting: String,
    pub value: i64,
}

impl Action {
    pub fn from_value(v: &Value) -> Result<Action, Error> {
        let d = object(v)?;
        Ok(Action {
            request_id: to_str(req(d, "request_id")?),
            kind: to_str(req(d, "kind")?),
            amount_cents: int_or(d, "amount_cents", 0)?,
            counterparty: str_or(d, "counterparty", ""),
            category: str_or(d, "category", ""),
            items: items(get(d, "items")).iter().map(to_str).collect(),
            setting: str_or(d, "setting", ""),
            value: int_or(d, "value", 0)?,
        })
    }

    pub fn to_value(&self) -> Value {
        json!({
            "request_id": self.request_id,
            "kind": self.kind,
            "amount_cents": self.amount_cents,
            "counterparty": self.counterparty,
            "category": self.category,
            "items": self.items,
            "setting": self.setting,
            "value": self.value,
        })
    }

    /// What an approval is bound to.
    pub fn digest(&self) -> String {
        digest(&self.to_value())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub per_action_cents: i64,
    pub daily_cents: i64,
    pub daily_count: i64,
}

impl Limits {
    fn from_value(v: &Value) -> Result<Limits, Error> {
        let d = object(v)?;
        Ok(Limits {
            per_action_cents: to_int(req(d, "per_action_cents")?)?,
            daily_cents: to_int(req(d, "daily_cents")?)?,
            daily_count: to_int(req(d, "daily_count")?)?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Contact {
    pub id: String,
    pub name: String,
    pub relation: String,
    pub ceiling_cents: i64,
}

/// Rules the owner set for herself.
#[derive(Clone, Debug)]
pub struct Policy {
    pub owner: String,
    pub timezone: String,
    pub contacts: Vec<Contact>,
    pub known_merchants: BTreeSet<String>,
    pub known_payees: BTreeSet<String>,
    pub limits: BTreeMap<String, Limits>,
    pub default_limits: Limits,
    pub blocked_categories: BTreeSet<String>,
    pub owner_only_above_cents: i64,
    pub night_hours: Option<(i64, i64)>,
    pub merchant_categories: BTreeMap<String, String>,
    pub blocked_keywords: Vec<String>,
    keywords: KeywordMatcher,
}

impl Policy {
    pub fn from_value(v: &Value) -> Result<Policy, Error> {
        let d = object(v)?;
        let night = match get(d, "night_hours") {
            None => Some((0, 5)),
            Some(n) if !truthy(n) => None,
            Some(n) => {
                let it = items(Some(n));
                match (it.first(), it.get(1)) {
                    (Some(a), Some(b)) => Some((to_int(a)?, to_int(b)?)),
                    _ => return Err(Error::Invalid("night_hours needs two hours".into())),
                }
            }
        };
        let mut contacts = Vec::new();
        for c in items(get(d, "contacts")) {
            let c = object(&c)?;
            contacts.push(Contact {
                id: to_str(req(c, "id")?),
                name: to_str(req(c, "name")?),
                relation: str_or(c, "relation", ""),
                ceiling_cents: to_int(req(c, "ceiling_cents")?)?,
            });
        }
        let mut limits = BTreeMap::new();
        if let Some(Value::Object(l)) = get(d, "limits") {
            for (k, v) in l {
                limits.insert(norm(k), Limits::from_value(v)?);
            }
        }
        let mut merchant_categories = BTreeMap::new();
        if let Some(Value::Object(m)) = get(d, "merchant_categories") {
            for (k, v) in m {
                merchant_categories.insert(norm(k), norm(&to_str(v)));
            }
        }
        let blocked_keywords: Vec<String> = match get(d, "blocked_keywords") {
            None => DEFAULT_BLOCKED_KEYWORDS
                .iter()
                .map(|s| s.to_string())
                .collect(),
            Some(v) => items(Some(v)).iter().map(to_str).collect(),
        };
        let set = |k: &str| {
            items(get(d, k))
                .iter()
                .map(|x| norm(&to_str(x)))
                .collect::<BTreeSet<_>>()
        };
        Ok(Policy {
            owner: to_str(req(d, "owner")?),
            timezone: str_or(d, "timezone", "UTC"),
            contacts,
            known_merchants: set("known_merchants"),
            known_payees: set("known_payees"),
            limits,
            default_limits: Limits::from_value(req(d, "default_limits")?)?,
            blocked_categories: set("blocked_categories"),
            owner_only_above_cents: to_int(req(d, "owner_only_above_cents")?)?,
            night_hours: night,
            merchant_categories,
            keywords: KeywordMatcher::new(&blocked_keywords),
            blocked_keywords,
        })
    }

    /// The category the rules use for a spending action. The caller's word is never trusted.
    pub fn resolve_category(&self, action: &Action) -> String {
        if action.kind == "transfer" {
            return "transfer".into();
        }
        if let Some(mapped) = self.merchant_categories.get(&norm(&action.counterparty)) {
            if !mapped.is_empty() {
                return mapped.clone();
            }
        }
        let claimed = norm(&action.category);
        if self.blocked_categories.contains(&claimed) {
            return claimed;
        }
        if !claimed.is_empty() && self.known_merchants.contains(&norm(&action.counterparty)) {
            return claimed;
        }
        OTHER.into()
    }

    pub fn blocked_keyword(&self, action: &Action) -> Option<String> {
        let mut parts = vec![action.counterparty.clone(), action.category.clone()];
        parts.extend(action.items.iter().cloned());
        self.keywords.first(&crate::py::casefold(&parts.join(" ")))
    }

    pub fn limits_for(&self, category: &str) -> Limits {
        *self
            .limits
            .get(&norm(category))
            .unwrap_or(&self.default_limits)
    }

    pub fn contact(&self, id: &str) -> Option<&Contact> {
        self.contacts.iter().find(|c| c.id == id)
    }

    /// Current value of a numeric setting, or None if the name is unknown.
    pub fn setting_value(&self, setting: &str) -> Option<i64> {
        if setting == "owner_only_above_cents" {
            return Some(self.owner_only_above_cents);
        }
        let (head, tail) = setting.rsplit_once('.').unwrap_or(("", setting));
        if let Some(cid) = head.strip_prefix("contact:") {
            return self
                .contact(cid)
                .filter(|_| tail == "ceiling_cents")
                .map(|c| c.ceiling_cents);
        }
        if !head.is_empty() {
            let l = self.limits_for(head);
            return match tail {
                "per_action_cents" => Some(l.per_action_cents),
                "daily_cents" => Some(l.daily_cents),
                "daily_count" => Some(l.daily_count),
                _ => None,
            };
        }
        None
    }
}

/// What already ran today, in the owner's time zone.
#[derive(Clone, Debug, Default)]
pub struct History {
    pub spent_cents: BTreeMap<String, i64>,
    pub count: BTreeMap<String, i64>,
}

impl History {
    pub fn from_value(v: Option<&Value>) -> Result<History, Error> {
        let mut h = History::default();
        if let Some(Value::Object(d)) = v {
            for (field, target) in [("spent_cents", &mut h.spent_cents), ("count", &mut h.count)] {
                if let Some(Value::Object(m)) = d.get(field) {
                    for (k, v) in m {
                        target.insert(k.clone(), to_int(v)?);
                    }
                }
            }
        }
        Ok(h)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Check {
    pub code: String,
    pub ok: bool,
    pub text: String,
}

impl Check {
    pub fn new(code: &str, ok: bool, text: impl Into<String>) -> Check {
        Check {
            code: code.into(),
            ok,
            text: text.into(),
        }
    }

    pub fn to_value(&self) -> Value {
        json!({"code": self.code, "ok": self.ok, "text": self.text})
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decision {
    pub outcome: Outcome,
    pub direction: &'static str,
    pub checks: Vec<Check>,
}

impl Decision {
    pub fn reasons(&self) -> Vec<&str> {
        self.checks
            .iter()
            .filter(|c| !c.ok)
            .map(|c| c.text.as_str())
            .collect()
    }

    pub fn to_value(&self) -> Value {
        json!({"outcome": self.outcome.as_str(), "direction": self.direction, "checks": self.checks.iter().map(Check::to_value).collect::<Vec<_>>()})
    }
}

pub fn authority_direction(action: &Action, policy: &Policy) -> &'static str {
    let k = action.kind.as_str();
    if REDUCING_KINDS.contains(&k) {
        return REDUCE;
    }
    if INCREASING_KINDS.contains(&k) {
        return INCREASE;
    }
    if SPENDING_KINDS.contains(&k) {
        return SPEND;
    }
    if k == SET_LIMIT {
        return match policy.setting_value(&action.setting) {
            Some(current) if action.value >= 0 => {
                if action.value <= current {
                    REDUCE
                } else {
                    INCREASE
                }
            }
            _ => UNKNOWN,
        };
    }
    UNKNOWN
}

/// Decide one action. Pure: same inputs, same decision.
pub fn evaluate(
    action: &Action,
    policy: &Policy,
    channel: &str,
    frozen: bool,
    history: &History,
    local_hour: i64,
) -> Result<Decision, Error> {
    check_channel(channel)?;
    let direction = authority_direction(action, policy);
    let one = |outcome, code, ok, text: String| Decision {
        outcome,
        direction,
        checks: vec![Check::new(code, ok, text)],
    };
    if direction == UNKNOWN {
        return Ok(one(
            Outcome::Deny,
            "known",
            false,
            "Kinlock doesn't recognise this action, so it won't run it".into(),
        ));
    }
    if direction == REDUCE {
        return Ok(one(
            Outcome::Allow,
            "direction",
            true,
            "This only lowers authority, so any channel may do it".into(),
        ));
    }
    if direction == INCREASE {
        if channel == OWNER {
            return Ok(one(
                Outcome::Allow,
                "direction",
                true,
                "The owner raised her own limits".into(),
            ));
        }
        let who = if channel == VOICE {
            "Voice"
        } else {
            "A trusted contact"
        };
        return Ok(one(Outcome::Deny, "direction", false, format!("{who} can lower authority but can't raise it; only {} can, from her own secure page", policy.owner)));
    }

    let mut checks = Vec::new();
    let amount = action.amount_cents;
    let category = policy.resolve_category(action);
    let who = norm(&action.counterparty);
    checks.push(Check::new(
        "lock",
        !frozen,
        if frozen {
            "Safety lock is on"
        } else {
            "Safety lock is off"
        },
    ));
    let blocked = policy.blocked_categories.contains(&category);
    let label = upper_first(&category);
    checks.push(Check::new(
        "category",
        !blocked,
        if blocked {
            format!("{label} are always blocked")
        } else {
            format!("{label} isn't a blocked category")
        },
    ));
    if let Some(hit) = policy.blocked_keyword(action) {
        checks.push(Check::new("keywords", false, format!("Requests mentioning {} are always blocked: gift cards, crypto, wires and prepaid cards are what scammers ask for", repr_str(&hit))));
    }
    if amount <= 0 {
        checks.push(Check::new(
            "amount",
            false,
            "The amount must be more than zero",
        ));
    }
    if who.is_empty() {
        checks.push(Check::new(
            "counterparty",
            false,
            "No merchant or payee was named",
        ));
    }
    if checks.iter().any(|c| !c.ok) {
        return Ok(Decision {
            outcome: Outcome::Deny,
            direction,
            checks,
        });
    }

    let mut owner_only = false;
    if action.kind == "transfer" {
        let known = policy.known_payees.contains(&who);
        let cp = &action.counterparty;
        checks.push(Check::new(
            "payee",
            known,
            if known {
                format!("{cp} is a known payee")
            } else {
                format!(
                    "{cp} is a new payee; only {} can approve that",
                    policy.owner
                )
            },
        ));
        owner_only |= !known;
    }
    let over = amount > policy.owner_only_above_cents;
    let t = money(policy.owner_only_above_cents);
    checks.push(Check::new(
        "owner_threshold",
        !over,
        if over {
            format!("Over {t} needs {} herself", policy.owner)
        } else {
            format!("Under {t}")
        },
    ));
    owner_only |= over;

    let lim = policy.limits_for(&category);
    if action.kind == "purchase" {
        let known = policy.known_merchants.contains(&who);
        let cp = &action.counterparty;
        checks.push(Check::new(
            "merchant",
            known,
            if known {
                format!("{cp} is a usual shop")
            } else {
                format!("{cp} is a new shop")
            },
        ));
    }
    let within = amount <= lim.per_action_cents;
    let (a, l) = (money(amount), money(lim.per_action_cents));
    checks.push(Check::new(
        "per_action",
        within,
        if within {
            format!("{a} is within the {l} per-order limit")
        } else {
            format!("{a} is over the {l} per-order limit")
        },
    ));
    let spent = history.spent_cents.get(&category).copied().unwrap_or(0);
    let total_ok = spent + amount <= lim.daily_cents;
    let d = money(lim.daily_cents);
    checks.push(Check::new(
        "daily_total",
        total_ok,
        if total_ok {
            format!("Today's {category} total stays within {d}")
        } else {
            format!(
                "Today's {category} total would reach {}, over {d}",
                money(spent + amount)
            )
        },
    ));
    let n = history.count.get(&category).copied().unwrap_or(0);
    let count_ok = n < lim.daily_count;
    checks.push(Check::new(
        "daily_count",
        count_ok,
        if count_ok {
            format!("Order {} of {} allowed today", n + 1, lim.daily_count)
        } else {
            format!(
                "That would be order {} today; the limit is {}",
                n + 1,
                lim.daily_count
            )
        },
    ));
    if let Some((a, b)) = policy.night_hours {
        let late = if a <= b {
            a <= local_hour && local_hour < b
        } else {
            local_hour >= a || local_hour < b
        };
        checks.push(Check::new(
            "hours",
            !late,
            if late {
                format!("Late-night request ({a:02}:00 to {b:02}:00)")
            } else {
                "Normal hours".into()
            },
        ));
    }

    let outcome = if owner_only {
        Outcome::Owner
    } else if checks.iter().any(|c| !c.ok) {
        Outcome::Hold
    } else {
        Outcome::Allow
    };
    Ok(Decision {
        outcome,
        direction,
        checks,
    })
}

/// Whether a person in `role` may release an action the rules held.
pub fn may_approve(
    decision: &Decision,
    role: &str,
    amount_cents: i64,
    contact: Option<&Contact>,
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
    if role == OWNER {
        return (true, "The owner approved".into());
    }
    let Some(contact) = contact.filter(|_| role == CONTACT) else {
        return (
            false,
            "Only the owner or her trusted contact can approve".into(),
        );
    };
    if decision.outcome == Outcome::Owner {
        return (
            false,
            "This needs the owner herself; a trusted contact can't approve it".into(),
        );
    }
    if amount_cents > contact.ceiling_cents {
        return (
            false,
            format!(
                "{} may approve up to {}; this is {}",
                contact.name,
                money(contact.ceiling_cents),
                money(amount_cents)
            ),
        );
    }
    (true, format!("{} approved", contact.name))
}
