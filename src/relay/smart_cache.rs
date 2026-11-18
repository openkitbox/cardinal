//! In-memory quota snapshot cache for Smart route ordering.
//!
//! Snapshots change only when the prober runs (5-minute timer, GUI manual
//! refresh, or any caller of [`crate::admin_ops::probe_all_quotas`]), so the
//! per-request DB read is replaced by a memory lookup. PG remains the
//! persistent store — startup seeds from `gateway_key_quota_snapshots`.
//!
//! Ownership: one instance on `Core`, shared with relay via `DispatchDeps`.
//! The prober writes, relay reads. No ordering logic lives here — this is
//! a dumb store; `smart::order` stays the single computation site.

use std::collections::HashMap;
use std::sync::RwLock;

use crate::quota::KeyQuota;

/// Read-mostly snapshot cache. Written once per probe round, read once per
/// dispatch. The RwLock is never held across an await.
#[derive(Clone, Default)]
pub struct SmartCache {
    inner: std::sync::Arc<RwLock<HashMap<i64, KeyQuota>>>,
}

impl SmartCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace all snapshots wholesale. Called once per probe round — NOT
    /// on the request path.
    ///
    /// Lock poisoning degrades instead of panicking (consistent with the
    /// other caches): a poisoned write keeps the previous snapshots and logs,
    /// since stale-but-present quota data beats crashing the process.
    pub fn refresh(&self, snapshots: HashMap<i64, KeyQuota>) {
        match self.inner.write() {
            Ok(mut guard) => *guard = snapshots,
            Err(_) => {
                tracing::warn!("smart cache lock poisoned on refresh; keeping previous snapshots");
            }
        }
    }

    /// Update one key's snapshot without touching the others. Used by the
    /// single-key admin refresh, where a wholesale [`Self::refresh`] would
    /// erase every other key's reading from Smart's view. `None` removes the
    /// key (no reading), so ordering falls back to stored order for it.
    ///
    /// Lock poisoning degrades like [`Self::refresh`]: keep the old data.
    pub fn refresh_one(&self, key_id: i64, quota: Option<KeyQuota>) {
        match self.inner.write() {
            Ok(mut guard) => match quota {
                Some(quota) => {
                    guard.insert(key_id, quota);
                }
                None => {
                    guard.remove(&key_id);
                }
            },
            Err(_) => {
                tracing::warn!(
                    key_id,
                    "smart cache lock poisoned on refresh_one; keeping previous snapshot"
                );
            }
        }
    }

    /// Run `read` against the current snapshot map under one read lock — a
    /// dispatch's ordering pass borrows the map instead of deep-cloning it.
    /// The lock is a std `RwLock`, so `read` must stay synchronous (it is:
    /// ordering is pure computation).
    ///
    /// A poisoned lock degrades to an empty map, which the caller treats like
    /// "no snapshots yet" — ordering falls back to stored order.
    pub fn with_snapshots<Output>(
        &self,
        read: impl FnOnce(&HashMap<i64, KeyQuota>) -> Output,
    ) -> Output {
        match self.inner.read() {
            Ok(guard) => read(&guard),
            Err(_) => {
                tracing::warn!("smart cache lock poisoned on read; dispatching without quota data");
                read(&HashMap::new())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::SmartCache;
    use crate::quota::KeyQuota;

    fn quota(plan: &str) -> KeyQuota {
        KeyQuota {
            windows: Vec::new(),
            balance: None,
            plan: Some(plan.to_owned()),
            details: Vec::new(),
            codex_resets: None,
        }
    }

    #[test]
    fn refresh_one_updates_only_the_target_snapshot() {
        let cache = SmartCache::new();
        cache.refresh(HashMap::from([
            (1, quota("one")),
            (2, quota("two")),
            (3, quota("three")),
        ]));

        cache.refresh_one(2, Some(quota("two-refreshed")));

        cache.with_snapshots(|snapshots| {
            assert_eq!(snapshots.len(), 3);
            assert_eq!(snapshots[&1].plan.as_deref(), Some("one"));
            assert_eq!(snapshots[&2].plan.as_deref(), Some("two-refreshed"));
            assert_eq!(snapshots[&3].plan.as_deref(), Some("three"));
        });
    }

    #[test]
    fn refresh_one_none_removes_only_the_target_snapshot() {
        let cache = SmartCache::new();
        cache.refresh(HashMap::from([(1, quota("one")), (2, quota("two"))]));

        cache.refresh_one(2, None);

        cache.with_snapshots(|snapshots| {
            assert_eq!(snapshots.len(), 1);
            assert_eq!(snapshots[&1].plan.as_deref(), Some("one"));
            assert!(!snapshots.contains_key(&2));
        });
    }
}
