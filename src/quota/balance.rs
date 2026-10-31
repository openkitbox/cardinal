//! Balance-step classification: how one prepaid balance reading relates to
//! the previous recorded one. This is the single rule shared by the balance
//! history store writer and the GUI live refresh, so both agree on what counts
//! as a change, a spend, or a top-up.

/// Readings closer than this (in currency units) are the same balance: the
/// vendors report to the cent, so sub-cent drift is rounding noise.
const TOPUP_EPSILON: f64 = 0.005;

/// How one balance reading relates to the previous recorded one.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum BalanceStep {
    /// Same balance as before (within [`TOPUP_EPSILON`]).
    Unchanged,
    /// The balance went down: spend, or an expired grant.
    Spent,
    /// A new balance segment starts: the first record (`topup: None`), or an
    /// increase (`topup: Some(delta)`) — a top-up or refund. Vendors expose no
    /// top-up events, so an increase is the only signal; when spend happened
    /// in the same probe interval the recorded top-up is a lower bound.
    Opened { topup: Option<f64> },
}

/// Classify the `next` reading against the `previous` recorded amount.
#[must_use]
pub fn classify(previous: Option<f64>, next: f64) -> BalanceStep {
    let Some(previous) = previous else {
        return BalanceStep::Opened { topup: None };
    };
    if (next - previous).abs() <= TOPUP_EPSILON {
        BalanceStep::Unchanged
    } else if next > previous {
        BalanceStep::Opened {
            topup: Some(next - previous),
        }
    } else {
        BalanceStep::Spent
    }
}
