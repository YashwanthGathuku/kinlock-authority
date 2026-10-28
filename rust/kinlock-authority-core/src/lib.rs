//! The trusted core of Kinlock Authority, in Rust.
//!
//! A port of the pure, security-critical parts of the Python reference
//! (`src/kinlock_authority`): canonical JSON and digests, the purchase rules,
//! the authority firewall, exact-action capabilities and hash-chained receipts.
//! Nothing here reads a clock, the network or a file: every input is passed in.
//!
//! The Python package stays the reference. `conformance/vectors/*.json` are
//! written by Python and this crate must reproduce every one byte for byte
//! (`tests/vectors.rs`).

#![forbid(unsafe_code)]

pub mod approvals;
pub mod canonical;
pub mod conformance;
pub mod firewall;
pub mod policy;
pub mod py;
pub mod receipts;

/// Errors the Python reference raises as `ValueError`, with the same message.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Invalid(String),
}

pub use canonical::{canonical, digest};
pub use firewall::{
    evaluate_action, voice_can_only_lower, ActionDecision, AgentAction, FirewallPolicy,
};
pub use policy::{evaluate, Action, Decision, Outcome, Policy};
