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

    /// Clone the current snapshot map for a dispatch's ordering pass.
    /// One lock acquisition regardless of candidate count.
    ///
    /// A poisoned lock degrades to an empty map, which the caller treats like
    /// "no snapshots yet" — smart ordering falls back to stored route order.
    pub fn snapshots(&self) -> HashMap<i64, KeyQuota> {
        match self.inner.read() {
            Ok(guard) => guard.clone(),
            Err(_) => {
                tracing::warn!("smart cache lock poisoned on read; dispatching without quota data");
                HashMap::new()
            }
        }
    }

    /// Whether any snapshot has been loaded (drives the degradation path
    /// without a PG round-trip).
    ///
    /// A poisoned lock reports empty, routing the dispatch down the same
    /// "no snapshots" fallback as an unloaded cache.
    pub fn is_empty(&self) -> bool {
        match self.inner.read() {
            Ok(guard) => guard.is_empty(),
            Err(_) => {
                tracing::warn!("smart cache lock poisoned on is_empty; treating as empty");
                true
            }
        }
    }
}
