//! Two-level dispatch ordering: the route strategy orders ENTRY GROUPS (one
//! group per route entry, identified by [`Candidate::entry_index`]), while the
//! keys inside one provider's group are always ranked by `smart::order`.
//!
//! Pure computation — no I/O, no locks, no cursor ownership. `order_ready`
//! in `relay.rs` is the thin edge: it reads the snapshot cache and hands in
//! the rotation cursor as a closure.
//!
//! Invariants:
//! - candidates are MOVED into their group, never cloned, and the verdict
//!   reason is computed once per candidate (by `smart::order`, the single
//!   quota computation point) and moved alongside it;
//! - `VerdictReasons` is position-aligned with the returned candidates; the
//!   resting tail the dispatcher chains after them has no reason;
//! - an empty snapshot map degrades every strategy to stored order inside
//!   each group (no reasons), so a quota outage never fails a dispatch.

use std::collections::HashMap;

use chrono::{DateTime, Utc};

use super::candidates::Candidate;
use crate::quota::KeyQuota;
use crate::store::RouteStrategy;

/// The Smart verdict reason per candidate, position-aligned with the ordered
/// ready list the dispatch loop walks (the resting tail is chained after it,
/// so a resting candidate lands past the end and reads as "no reason", never
/// as its ready sibling's verdict). Position, not key id, is the identity: a
/// provider may appear in several route entries, one per model, so the same
/// key shows up once per entry — each copy its own candidate with its own
/// verdict.
pub type VerdictReasons = Vec<String>;

/// Order the ready candidates of one dispatch.
///
/// - `Smart`: every ready candidate is ranked globally by quota surplus
///   (groups only matter for the other strategies).
/// - `Ordered`: entry groups keep their stored order; each group is ranked
///   internally by `smart::order`.
/// - `Rotate`: entry groups rotate around the cursor; each group is ranked
///   internally by `smart::order`. `rotate_start` is called with the number of
///   ready groups and returns the rotation offset — it is NOT called when
///   fewer than two groups are ready, so a lone group never consumes a tick.
///
/// `quotas` comes from the in-memory snapshot cache (no PG round-trip); when
/// it is empty the within-group ranking is skipped and the stored key order is
/// kept, with an empty reason list.
pub fn order_groups(
    strategy: RouteStrategy,
    ready: Vec<Candidate>,
    quotas: &HashMap<i64, KeyQuota>,
    rotate_start: impl FnOnce(usize) -> usize,
    now: DateTime<Utc>,
) -> (Vec<Candidate>, VerdictReasons) {
    match strategy {
        RouteStrategy::Smart => {
            if quotas.is_empty() {
                return (ready, VerdictReasons::new());
            }
            // The verdict reason is computed here, at dispatch-prep time, and
            // MOVED alongside the candidate — never cloned, never recomputed.
            super::smart::order(ready, quotas, now)
                .into_iter()
                .map(|(candidate, verdict)| (candidate, verdict.reason))
                .unzip()
        }
        RouteStrategy::Ordered | RouteStrategy::Rotate => {
            let capacity = ready.len();
            let mut groups = group_by_entry(ready);
            if matches!(strategy, RouteStrategy::Rotate) && groups.len() >= 2 {
                // Fewer than 2 ready groups: rotation is a no-op, and advancing
                // the cursor would only cause a skip when another entry's
                // provider comes back.
                let start = rotate_start(groups.len()) % groups.len();
                groups.rotate_left(start);
            }
            let mut ordered = Vec::with_capacity(capacity);
            let mut reasons = VerdictReasons::new();
            for group in groups {
                if quotas.is_empty() {
                    ordered.extend(group);
                    continue;
                }
                for (candidate, verdict) in super::smart::order(group, quotas, now) {
                    ordered.push(candidate);
                    reasons.push(verdict.reason);
                }
            }
            (ordered, reasons)
        }
    }
}

/// Stable partition by `entry_index`, preserving the first-appearance order of
/// the groups and the stored key order inside each group. Candidates are moved
/// out of `ready`; nothing is cloned.
fn group_by_entry(ready: Vec<Candidate>) -> Vec<Vec<Candidate>> {
    let mut groups: Vec<Vec<Candidate>> = Vec::new();
    for candidate in ready {
        let entry_index = candidate.entry_index;
        match groups.iter_mut().find(|group| {
            group
                .first()
                .is_some_and(|first| first.entry_index == entry_index)
        }) {
            Some(group) => group.push(candidate),
            None => groups.push(vec![candidate]),
        }
    }
    groups
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use chrono::Duration;
    use secrecy::SecretString;

    use super::*;
    use crate::quota::QuotaWindow;
    use crate::store::{ProviderKeyRow, ProviderRow};

    /// `now` is fixed so the surplus arithmetic below is exact: one 60-minute
    /// window resetting in 30 minutes leaves 50% of the time, so
    /// `surplus = 50 - used_pct`.
    fn now() -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000, 0).expect("a Unix timestamp is a valid instant")
    }

    fn quota(used_pct: f64) -> KeyQuota {
        KeyQuota {
            windows: vec![QuotaWindow {
                name: "5 小时".to_owned(),
                used_pct,
                resets_at: Some(now() + Duration::minutes(30)),
                period_minutes: Some(60),
                total: None,
            }],
            balance: None,
            details: Vec::new(),
        }
    }

    fn candidate(id: i64, entry_index: usize) -> Candidate {
        Candidate {
            key: ProviderKeyRow {
                id,
                provider_id: 1,
                label: format!("k{id}"),
                api_key: None,
                enabled: true,
                position: 0,
                max_concurrency: None,
                models: None,
                allowed_models: None,
                auth_kind: "static".to_owned(),
                oauth: None,
                archived_at: None,
            },
            secret: SecretString::from(String::new()),
            provider: ProviderRow {
                id: 1,
                name: "p1".to_owned(),
                protocol: "openai_chat".to_owned(),
                base_url: "http://upstream".to_owned(),
                auth_scheme: "bearer".to_owned(),
                enabled: true,
            },
            upstream_model: "m".to_owned(),
            route_alias: None,
            entry_cap: None,
            entry_index,
            supported_efforts: None,
            default_effort: None,
            context_window: None,
        }
    }

    fn ids(candidates: &[Candidate]) -> Vec<i64> {
        candidates
            .iter()
            .map(|candidate| candidate.key.id)
            .collect()
    }

    fn run(
        strategy: RouteStrategy,
        ready: Vec<(i64, usize, f64)>,
    ) -> (Vec<Candidate>, VerdictReasons) {
        let quotas: HashMap<i64, KeyQuota> = ready
            .iter()
            .map(|(id, _, used)| (*id, quota(*used)))
            .collect();
        let candidates: Vec<Candidate> = ready
            .into_iter()
            .map(|(id, entry_index, _)| candidate(id, entry_index))
            .collect();
        order_groups(strategy, candidates, &quotas, |_| 0, now())
    }

    #[test]
    fn ordered_keeps_group_order_and_ranks_keys_inside_each_group() {
        let (ordered, reasons) = run(
            RouteStrategy::Ordered,
            vec![(1, 0, 90.0), (2, 0, 10.0), (3, 1, 0.0)],
        );
        assert_eq!(
            ids(&ordered),
            vec![2, 1, 3],
            "group 0 first with its tightest key last, then group 1"
        );
        assert_eq!(
            reasons,
            vec!["富余+40%", "超支-40%", "富余+50%"],
            "each reason belongs to the key at the same position"
        );
    }

    #[test]
    fn rotate_moves_the_cursor_over_entry_groups_not_candidates() {
        let ready = vec![(1, 0, 0.0), (2, 0, 0.0), (3, 1, 0.0), (4, 2, 0.0)];
        let quotas: HashMap<i64, KeyQuota> = ready
            .iter()
            .map(|(id, _, used)| (*id, quota(*used)))
            .collect();
        let candidates: Vec<Candidate> = ready
            .into_iter()
            .map(|(id, entry_index, _)| candidate(id, entry_index))
            .collect();
        let groups_seen = Cell::new(0);
        let (ordered, _) = order_groups(
            RouteStrategy::Rotate,
            candidates,
            &quotas,
            |groups| {
                groups_seen.set(groups);
                1
            },
            now(),
        );
        assert_eq!(
            ids(&ordered),
            vec![3, 4, 1, 2],
            "start=1 moves whole groups, and group 0's keys stay together"
        );
        assert_eq!(groups_seen.get(), 3, "the cursor counts entry groups");
    }

    #[test]
    fn rotate_with_a_single_ready_group_does_not_consume_the_cursor() {
        let ready = vec![(1, 0, 90.0), (2, 0, 10.0)];
        let (ordered, reasons) = run(RouteStrategy::Rotate, ready);
        assert_eq!(
            ids(&ordered),
            vec![2, 1],
            "a lone group is still ranked internally by surplus"
        );
        assert_eq!(reasons.len(), 2, "reasons stay position-aligned");

        let candidates = vec![candidate(1, 0), candidate(2, 0)];
        let quotas = HashMap::from([(1, quota(90.0)), (2, quota(10.0))]);
        let (ordered, _) = order_groups(
            RouteStrategy::Rotate,
            candidates,
            &quotas,
            |_| panic!("a single ready group must not advance the cursor"),
            now(),
        );
        assert_eq!(ids(&ordered), vec![2, 1], "no rotation with one group");
    }

    #[test]
    fn rotate_start_wraps_around_the_ready_group_count() {
        // The cursor is shared across requests and outgrows the group count;
        // the offset must wrap instead of panicking in `rotate_left`.
        let ready = vec![(1, 0, 0.0), (2, 1, 0.0), (3, 2, 0.0)];
        let quotas: HashMap<i64, KeyQuota> = ready
            .iter()
            .map(|(id, _, used)| (*id, quota(*used)))
            .collect();
        let candidates: Vec<Candidate> = ready
            .into_iter()
            .map(|(id, entry_index, _)| candidate(id, entry_index))
            .collect();
        let (ordered, _) = order_groups(RouteStrategy::Rotate, candidates, &quotas, |_| 7, now());
        assert_eq!(
            ids(&ordered),
            vec![2, 3, 1],
            "start 7 over 3 groups wraps to offset 1"
        );
    }

    #[test]
    fn smart_ranks_all_ready_candidates_globally() {
        let (ordered, reasons) = run(
            RouteStrategy::Smart,
            vec![(1, 0, 90.0), (2, 1, 10.0), (3, 0, 0.0)],
        );
        assert_eq!(
            ids(&ordered),
            vec![3, 2, 1],
            "Smart ignores entry boundaries and ranks by surplus"
        );
        assert_eq!(reasons.len(), 3, "one reason per candidate");
    }

    #[test]
    fn direct_resolution_is_one_group_ranked_by_surplus() {
        let (ordered, reasons) = run(RouteStrategy::Smart, vec![(1, 0, 90.0), (2, 0, 10.0)]);
        assert_eq!(ids(&ordered), vec![2, 1], "direct provider/model is smart");
        assert_eq!(
            reasons,
            vec!["富余+40%", "超支-40%"],
            "each direct key carries its own aligned verdict"
        );
    }

    #[test]
    fn unknown_quota_ranks_after_known_keys_inside_a_group() {
        let candidates = vec![candidate(1, 0), candidate(2, 0), candidate(3, 0)];
        let quotas = HashMap::from([(1, quota(0.0)), (3, quota(90.0))]);
        let (ordered, reasons) =
            order_groups(RouteStrategy::Ordered, candidates, &quotas, |_| 0, now());
        assert_eq!(
            ids(&ordered),
            vec![1, 3, 2],
            "the key without a snapshot is Unknown and goes last"
        );
        assert_eq!(
            reasons[2], "未知额度",
            "the unknown key's reason is aligned"
        );
    }

    #[test]
    fn empty_snapshots_keep_stored_order_without_reasons() {
        for strategy in [RouteStrategy::Ordered, RouteStrategy::Smart] {
            let candidates = vec![candidate(1, 0), candidate(2, 0), candidate(3, 1)];
            let (ordered, reasons) =
                order_groups(strategy, candidates, &HashMap::new(), |_| 0, now());
            assert_eq!(
                ids(&ordered),
                vec![1, 2, 3],
                "no snapshots: stored order survives for {strategy:?}"
            );
            assert!(reasons.is_empty(), "no quota data means no reasons");
        }

        let candidates = vec![candidate(1, 0), candidate(2, 1)];
        let (ordered, reasons) = order_groups(
            RouteStrategy::Rotate,
            candidates,
            &HashMap::new(),
            |_| 1,
            now(),
        );
        assert_eq!(
            ids(&ordered),
            vec![2, 1],
            "rotation is not quota-dependent and still applies"
        );
        assert!(reasons.is_empty(), "stored order inside the rotated groups");
    }
}
