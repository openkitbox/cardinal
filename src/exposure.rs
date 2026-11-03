//! In-flight exposure: one count per user of admitted-but-unsettled requests.
//!
//! Admission ([`crate::billing::admit`]) reads the balance snapshot taken at
//! authentication, while the debit only lands when the batched ledger writer
//! flushes the attempt row (up to `DEFAULT_FLUSH_INTERVAL` later). Without a
//! bound, a user with a small balance can have any number of requests pass
//! admission inside that window and drive the balance as far negative as they
//! like. This module is that bound: it owns the per-user count of requests
//! that are admitted but have not yet queued their charge.
//!
//! It does not own:
//!
//! - whether an identity may spend at all — that is [`crate::billing::admit`];
//! - how many requests may hit one upstream account — that is
//!   `crate::relay::dispatcher`.
//!
//! Why in memory only: the count is read and written on every admitted
//! request, and its only job is to pace a window measured in ledger flush
//! intervals. A row per request would put PG on the admission path (and on
//! its error path); a persisted count would be a second copy of state the
//! process already has. Nothing here survives a restart, which is harmless:
//! the count bounds a transient window, and the durable fact it protects —
//! the user's balance — is untouched by the reset.
//!
//! Both the acquire and the release run inside `DashMap::entry`, so "read the
//! count → compare to the limit → increment" and "decrement → remove at zero"
//! are each one shard-locked step. Holding the count outside the entry (an
//! `Arc` to an atomic handed out by `get`, say) would split it between an
//! entry removed at zero and a fresh one created by the next arrival, and
//! admit more requests than the limit allows.
//!
//! One bound this module does not remove: a slot lives until the request's
//! charge is queued, so a client that stops reading a stream without closing
//! the connection keeps its slot until the connection fails (the pump's idle
//! timeout watches for reads, not for a peer that stopped draining writes).
//! That is the same connection whose dispatcher slot is pinned today; the
//! difference is that the count is now per user, so a handful of half-dead
//! streams can hold a billed user at its cap. There is deliberately no timer to
//! release such a slot early: releasing before the charge is queued would make
//! the count mean something other than what it says.

use std::sync::Arc;

use dashmap::DashMap;
use dashmap::mapref::entry::Entry;

/// Per-user count of admitted requests whose charge is not queued yet.
///
/// All access is through [`Exposure::try_acquire`] and the `Drop` of the
/// returned slot; the counts are plain `usize` values behind the map's own
/// shard locks.
pub struct Exposure {
    users: DashMap<i64, usize>,
}

impl Exposure {
    /// An empty gate: no user has a request in flight.
    #[must_use]
    pub fn new() -> Self {
        Self {
            users: DashMap::new(),
        }
    }

    /// Take one of `user_id`'s `limit` in-flight slots, or `None` when the
    /// user is already at the limit. The slot frees itself on [`Drop`].
    ///
    /// `limit` is `users.max_concurrent`, which the schema guarantees positive
    /// (`CHECK (max_concurrent > 0)`) and the admin API validates. A value that
    /// still cannot be a count means the guard cannot verify its own
    /// precondition, so it refuses rather than dropping the bound: this gate
    /// exists to keep a user's exposure finite, and failing open would be the
    /// one failure that matters.
    pub fn try_acquire(self: &Arc<Self>, user_id: i64, limit: i32) -> Option<ExposureSlot> {
        let limit = match usize::try_from(limit) {
            Ok(limit) => limit,
            Err(error) => {
                tracing::warn!(
                    user_id,
                    limit,
                    %error,
                    "max_concurrent is not a positive count; refusing rather than admitting unbounded"
                );
                return None;
            }
        };
        // The slot is built only after the count moved: it owns the release,
        // so it must never exist for a request that was refused.
        match self.users.entry(user_id) {
            Entry::Occupied(mut entry) => {
                let count = *entry.get();
                if !within_limit(count, limit) {
                    return None;
                }
                // Saturation guards an impossible count against wrapping: a
                // wrapped count would read low and grant slots that do not
                // exist, so the wrong direction is the one to protect.
                *entry.get_mut() = count.saturating_add(1);
            }
            Entry::Vacant(entry) => {
                // Same decision as above, not "a new entry always fits": a
                // limit of zero admits nothing.
                if !within_limit(0, limit) {
                    return None;
                }
                entry.insert(1);
            }
        }
        Some(ExposureSlot {
            owner: Arc::clone(self),
            user_id,
        })
    }

    /// How many requests `user_id` has in flight right now: a diagnostic
    /// reading for the refusal log, not a decision input.
    #[must_use]
    pub fn in_flight(&self, user_id: i64) -> usize {
        self.users.get(&user_id).map_or(0, |count| *count)
    }
}

impl Default for Exposure {
    fn default() -> Self {
        Self::new()
    }
}

/// Whether one more request fits under `limit`. Decision logic stays a pure
/// function so the shard-locked section is only the read and the write.
fn within_limit(count: usize, limit: usize) -> bool {
    count < limit
}

/// One admitted request's claim on its user's in-flight budget.
///
/// Owns an `Arc<Exposure>` so it can be moved into a task that outlives the
/// dispatch call (a streaming request settles in a spawned task). The claim
/// is released exactly once, in [`Drop`]; there is no other release path.
#[must_use = "dropping the slot immediately releases the user's in-flight budget"]
pub struct ExposureSlot {
    owner: Arc<Exposure>,
    user_id: i64,
}

impl Drop for ExposureSlot {
    fn drop(&mut self) {
        let Entry::Occupied(mut entry) = self.owner.users.entry(self.user_id) else {
            // Unreachable: a slot exists only while its count does, and the
            // count is removed only by the release that consumes the last slot.
            tracing::warn!(
                user_id = self.user_id,
                "exposure slot released with no tracked count"
            );
            return;
        };
        let remaining = entry.get().saturating_sub(1);
        if remaining == 0 {
            // Sized by users with an outstanding request, not by all users.
            entry.remove();
        } else {
            *entry.get_mut() = remaining;
        }
    }
}
