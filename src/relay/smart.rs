//! Smart route ordering: a quota-aware strategy over cardinal's quota
//! snapshots.
//! Pure computation — no I/O, no DB, no async: the dispatcher hands it the
//! route's candidates in stored order plus the keys' quota snapshots and
//! gets back the dispatch order with a per-candidate verdict for the feed.
//!
//! Semantics, and cardinal's deliberate choices:
//! - D1 no model-scoped windows: every window of the key's snapshot counts.
//! - D4 RunsOut/Restarts refinements are not carried — cardinal's
//!   snapshots carry no such data. A past/absent reset renews the whole
//!   span from now, the span itself a week when the window names none.
//! - Tier: the MAX used share across the windows — any
//!   window near its cap risks a hard mid-stream refusal, whatever its
//!   span. A window whose reset is SET and past has renewed and reads 0; a
//!   window naming no reset keeps its share.
//! - Renewal: every window's effective reset as a list, largest span
//!   first, ties to the later reset. Smart compares two
//!   keys' lists position by position, each position hour-truncated;
//!   equal → next position; a list exhausted at a position sorts after
//!   (the zero-time rule); equal throughout → stored order, keeping the
//!   vendor's prompt cache warm.
//! - A key with no snapshot (or an empty one) is Unknown: dispatched as
//!   fine, but after every known-fine key, so a silent key still gets
//!   traffic once the known ones are spent.

use std::cmp::Ordering;
use std::collections::HashMap;

use chrono::{DateTime, Local, Utc};

use super::candidates::Candidate;
use crate::quota::{KeyQuota, QuotaWindow};

/// Share of the deciding window past which a key waits for the others
///.
const LOW_SHARE: f64 = 90.0;
/// Share past which a key is all but used up and only tried when nothing
/// else can take the request.
const SPENT_SHARE: f64 = 98.0;
/// A window whose reset has passed but that names no period (snapshots
/// predating `period_minutes`) is taken to renew a week out.
const DEFAULT_PERIOD_MINUTES: i64 = 7 * 1440;
/// Reason for a key without a usable snapshot.
const UNKNOWN_REASON: &str = "未知额度";

/// How a key's quota places it in the Smart order. The tests assert on this
/// as the specification; the wire carries only [`SmartVerdict::reason`], so
/// nothing outside this module branches on it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Tier {
    /// Room to spare: the default dispatch tier.
    Fine,
    /// 90%+ of the deciding window used: held back until the others cannot
    /// take the request.
    Low,
    /// 98%+ used: only tried after every Low key.
    Spent,
    /// No usable snapshot: dispatched as fine, after every known-fine key.
    Unknown,
}

/// Per-candidate Smart verdict: the tier plus the reason shown in the feed.
#[derive(Clone, Debug, PartialEq)]
pub struct SmartVerdict {
    /// Test-only observable (it pins the algorithm's grouping); dispatch reads
    /// [`Self::reason`].
    pub tier: Tier,
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
    let mut ranked: Vec<(Candidate, SmartVerdict, Rank)> = candidates
        .into_iter()
        .map(|candidate| {
            let (verdict, rank) = evaluate(snapshots.get(&candidate.key.id), now);
            (candidate, verdict, rank)
        })
        .collect();
    // Stable: full ties keep the route's stored order (prompt-cache affinity).
    ranked.sort_by(|(.., a), (.., b)| a.cmp_key(b));
    ranked
        .into_iter()
        .map(|(candidate, verdict, _)| (candidate, verdict))
        .collect()
}

/// One window's renewal slot: its effective reset plus the span that sorts
/// it. A future `resets_at` stands; a past (or absent) one renews the
/// window's whole span from `now`, the span
/// defaulted to a week when the window names none.
#[derive(Debug)]
struct Renewal {
    span_minutes: i64,
    reset: DateTime<Utc>,
}

fn normalize(window: &QuotaWindow, now: DateTime<Utc>) -> Renewal {
    let span_minutes = window.period_minutes.unwrap_or(DEFAULT_PERIOD_MINUTES);
    let reset = match window.resets_at {
        Some(resets_at) if resets_at > now => resets_at,
        _ => now + chrono::Duration::minutes(span_minutes),
    };
    Renewal {
        span_minutes,
        reset,
    }
}

/// The key's used share: the MAX used_pct across the windows
/// — any window near its cap risks a hard mid-stream refusal, whatever its
/// span. A window whose reset is SET and past has renewed and reads 0; a
/// window naming no reset keeps its share.
fn used_share(windows: &[QuotaWindow], now: DateTime<Utc>) -> f64 {
    windows
        .iter()
        .map(|window| match window.resets_at {
            Some(resets_at) if resets_at <= now => 0.0,
            _ => window.used_pct,
        })
        .max_by(f64::total_cmp)
        .unwrap_or(0.0)
}

/// The key's renewals as routing ranks them: every
/// window's effective reset, largest span first, ties to the later reset
/// (stable: same span and reset keep the stored window order).
fn renewals(windows: &[QuotaWindow], now: DateTime<Utc>) -> Vec<Renewal> {
    let mut slots: Vec<Renewal> = windows
        .iter()
        .map(|window| normalize(window, now))
        .collect();
    slots.sort_by(|a, b| {
        b.span_minutes
            .cmp(&a.span_minutes)
            .then_with(|| b.reset.cmp(&a.reset))
    });
    slots
}

/// The renewal-list comparator: two lists position by position, each
/// position's reset truncated to the hour: equal → next position; a list
/// exhausted at a position is the zero time and sorts AFTER the one that still
/// has a renewal there — deliberate relief-timing ordering: a key with another
/// nearer renewal gets relief sooner, so it goes first; equal throughout →
/// stored order.
fn cmp_renewals(a: &[Renewal], b: &[Renewal]) -> Ordering {
    for position in 0..a.len().max(b.len()) {
        match (a.get(position), b.get(position)) {
            (Some(x), Some(y)) => match truncated_hour(x.reset).cmp(&truncated_hour(y.reset)) {
                Ordering::Equal => continue,
                ordering => return ordering,
            },
            (Some(_), None) => return Ordering::Less,
            (None, Some(_)) => return Ordering::Greater,
            (None, None) => continue,
        }
    }
    Ordering::Equal
}

/// The full sort key: group first (known Fine → Unknown → Low → Spent),
/// then the in-group value. Compared by [`Rank::cmp_key`]; the stable sort
/// keeps stored order on a full tie.
#[derive(Debug)]
enum Rank {
    /// The key's renewals, largest span first, compared lexicographically
    /// with each reset truncated to the hour — minute-level jitter must not
    /// reorder.
    Fine(Vec<Renewal>),
    /// No usable snapshot: stored order.
    Unknown,
    /// used ascending.
    Low(f64),
    /// used ascending.
    Spent(f64),
}

impl Rank {
    /// Group order — `u8` gives Fine < Unknown < Low < Spent.
    fn group(&self) -> u8 {
        match self {
            Rank::Fine(_) => 0,
            Rank::Unknown => 1,
            Rank::Low(_) => 2,
            Rank::Spent(_) => 3,
        }
    }

    /// Group first, then the in-group value (`total_cmp`: a total order over
    /// the shares, NaN-free by construction — quotas are clamped on parse).
    fn cmp_key(&self, other: &Self) -> Ordering {
        self.group()
            .cmp(&other.group())
            .then_with(|| match (self, other) {
                (Rank::Fine(a), Rank::Fine(b)) => cmp_renewals(a, b),
                (Rank::Low(a), Rank::Low(b)) | (Rank::Spent(a), Rank::Spent(b)) => a.total_cmp(b),
                // group() is 1:1 with the variants: equal groups can't be different variants.
                _ => Ordering::Equal,
            })
    }
}

/// Tier the key by its max window share and name the reason:
/// `已用{N}%` past the low share; `重置{HH:MM}` / `周{一..日} {HH:MM}` below
/// it, naming the renewal list's head (the largest span's reset); 未知额度
/// without a snapshot.
fn evaluate(snapshot: Option<&KeyQuota>, now: DateTime<Utc>) -> (SmartVerdict, Rank) {
    let windows = snapshot
        .map(|snapshot| snapshot.windows.as_slice())
        .filter(|windows| !windows.is_empty());
    let Some(windows) = windows else {
        return (
            SmartVerdict {
                tier: Tier::Unknown,
                reason: UNKNOWN_REASON.to_owned(),
            },
            Rank::Unknown,
        );
    };
    let used_pct = used_share(windows, now);
    if used_pct >= SPENT_SHARE {
        (
            SmartVerdict {
                tier: Tier::Spent,
                reason: used_reason(used_pct),
            },
            Rank::Spent(used_pct),
        )
    } else if used_pct >= LOW_SHARE {
        (
            SmartVerdict {
                tier: Tier::Low,
                reason: used_reason(used_pct),
            },
            Rank::Low(used_pct),
        )
    } else {
        let slots = renewals(windows, now);
        let Some(head) = slots.first().map(|slot| slot.reset) else {
            // Unreachable (the window list is non-empty), kept total without indexing.
            return (
                SmartVerdict {
                    tier: Tier::Unknown,
                    reason: UNKNOWN_REASON.to_owned(),
                },
                Rank::Unknown,
            );
        };
        (
            SmartVerdict {
                tier: Tier::Fine,
                reason: reset_reason(head, now),
            },
            Rank::Fine(slots),
        )
    }
}

/// The renewal truncated to the hour — floor division (`div_euclid`) so
/// pre-epoch instants floor too, never round toward zero.
fn truncated_hour(at: DateTime<Utc>) -> i64 {
    at.timestamp().div_euclid(60 * 60)
}

/// `已用{N}%` — the share rounded to a whole percent.
fn used_reason(used_pct: f64) -> String {
    format!("已用{}%", used_pct.round() as i64)
}

/// A fine key's reason: `重置{HH:MM}` in the machine's local time; past a
/// day out, the date and time (`M月D日 HH:MM`).
fn reset_reason(renewal: DateTime<Utc>, now: DateTime<Utc>) -> String {
    let local = renewal.with_timezone(&Local);
    if renewal - now > chrono::Duration::hours(24) {
        format!(
            "{}月{}日 {}",
            local.format("%-m"),
            local.format("%-d"),
            local.format("%H:%M")
        )
    } else {
        format!("重置{}", local.format("%H:%M"))
    }
}
