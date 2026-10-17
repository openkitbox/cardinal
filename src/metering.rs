//! Metering (A §5 `metering` ownership): usage evidence → explicit metering
//! facts.
//!
//! This module is deliberately a leaf: protocols, billing and execution all
//! depend on it, and it depends on nothing else in the crate. That is what
//! keeps the dependency graph acyclic (A §15 "dependency direction and low coupling").
//!
//! [`UsageCounts`](crate::protocol::usage::UsageCounts) itself is wire evidence
//! produced by the protocol kernels, so it lives with them in
//! `crate::protocol::usage`. Billing/cost policy (certainty classification,
//! pricing) stays in this crate.

use serde::{Deserialize, Serialize};

/// Which usage facts are known for one attempt. `unknown` must never be treated
/// as zero (A §10.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageCertainty {
    Known,
    Unknown,
    Estimated,
}
