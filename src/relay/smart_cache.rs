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
