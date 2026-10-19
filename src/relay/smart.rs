//! Smart route ordering: quota-proportional ("surplus") ordering over
//! cardinal's quota snapshots.
//!
//! Pure computation — no I/O, no DB, no async: the dispatcher hands it the
//! route's candidates in stored order plus the keys' quota snapshots and
//! gets back the dispatch order with a per-candidate reason for the feed.
//!
//! The metric is per-window **surplus**: remaining quota percent minus
//! remaining time percent. A key ranks by its tightest window (the min):
//! - surplus > 0: at the current pace the quota outlives the window — it
//!   would expire unused, so this key is spent first;
//! - surplus < 0: quota is burning faster than the window passes — the key
//!   risks a hard mid-stream refusal and sinks behind the others.
//!
//! This replaces both the fixed 90%/98% usage tiers and the renewal-calendar
//! comparison: the proportion does the work, no absolute thresholds.
//!
//! Deliberate choices carried over from the previous design:
//! - Every window of the key's snapshot counts (no model-scoped windows); the
//!   min over windows is the binding constraint, mirroring the old
//!   "max used share" rule.
//! - A window whose reset has passed has renewed: quota and time both read
//!   full, so the window contributes 0.
//! - A window with no reset time has no time anchor and cannot take part; a
//!   key whose every window lacks one is Unknown. `period_minutes` defaults
//!   to a week (snapshots predating `period_minutes`).
//! - A key with no snapshot is Unknown: dispatched after every known key, in
//!   stored order, so a silent key still gets traffic once the known ones
//!   are spent.
//! - Stable sort: full ties keep the route's stored order, keeping the
//!   vendor's prompt cache warm.

use std::cmp::Ordering;
use std::collections::HashMap;

use chrono::{DateTime, Utc};

use super::candidates::Candidate;
use crate::quota::{KeyQuota, QuotaWindow};

/// A window whose reset has passed but that names no period (snapshots
/// predating `period_minutes`) is taken to span a week.
const DEFAULT_PERIOD_MINUTES: i64 = 7 * 1440;
/// Reason for a key without a usable snapshot.
const UNKNOWN_REASON: &str = "未知额度";

/// Per-candidate Smart verdict: the human reason shown in the feed.
#[derive(Clone, Debug, PartialEq)]
pub struct SmartVerdict {
    /// The human reason (short Chinese — it renders inline in the live feed).
    pub reason: String,
}

/// Reorder ready candidates for a Smart route. Input order is the route's
/// stored order; output is the dispatch order, each candidate paired with
/// its verdict. Snapshot lookup is by the candidate's key id; a missing
/// entry reads as Unknown.
pub fn order(
    candidates: Vec<Candidate>,
    snapshots: &HashMap<i64, KeyQuota>,
    now: DateTime<Utc>,
) -> Vec<(Candidate, SmartVerdict)> {
    let mut ranked: Vec<(Candidate, SmartVerdict, Option<f64>)> = candidates
        .into_iter()
        .map(|candidate| {
            let (verdict, surplus) = evaluate(snapshots.get(&candidate.key.id), now);
            (candidate, verdict, surplus)
        })
        .collect();
    // Known keys by surplus descending; Unknown after them; full ties keep
    // the route's stored order (prompt-cache affinity) via the stable sort.
    ranked.sort_by(|(.., a), (.., b)| match (a, b) {
        (Some(x), Some(y)) => y.total_cmp(x),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    });
    ranked
        .into_iter()
        .map(|(candidate, verdict, _)| (candidate, verdict))
        .collect()
}

/// One window's surplus in percentage points, or `None` when the window
/// carries no time anchor. A renewed window (reset in the past) reads 0:
/// quota and time are both full again.
fn window_surplus(window: &QuotaWindow, now: DateTime<Utc>) -> Option<f64> {
    let resets_at = window.resets_at?;
    if resets_at <= now {
        return Some(0.0);
    }
    let period = window.period_minutes.unwrap_or(DEFAULT_PERIOD_MINUTES);
    let remaining_minutes = (resets_at - now).num_seconds() as f64 / 60.0;
    let remaining_time_pct = (remaining_minutes / period as f64 * 100.0).clamp(0.0, 100.0);
    Some(100.0 - window.used_pct - remaining_time_pct)
}

/// The key's verdict and ranking surplus: the min across its windows (the
/// tightest window is the binding constraint), `None` when no window can
/// rank the key.
fn evaluate(snapshot: Option<&KeyQuota>, now: DateTime<Utc>) -> (SmartVerdict, Option<f64>) {
    let windows = snapshot
        .map(|snapshot| snapshot.windows.as_slice())
        .filter(|windows| !windows.is_empty());
    let Some(windows) = windows else {
        return (unknown(), None);
    };
    let mut surplus: Option<f64> = None;
    for window in windows {
        if let Some(value) = window_surplus(window, now) {
            surplus = Some(match surplus {
                Some(tightest) => tightest.min(value),
                None => value,
            });
        }
    }
    let Some(surplus) = surplus else {
        // Every window lacked a time anchor: nothing ranks this key.
        return (unknown(), None);
    };
    (
        SmartVerdict {
            reason: if surplus >= 0.0 {
                format!("富余+{}%", surplus.round() as i64)
            } else {
                format!("超支-{}%", (-surplus).round() as i64)
            },
        },
        Some(surplus),
    )
}

fn unknown() -> SmartVerdict {
    SmartVerdict {
        reason: UNKNOWN_REASON.to_owned(),
    }
}
