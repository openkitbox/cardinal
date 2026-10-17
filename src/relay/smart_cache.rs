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
    pub fn refresh(&self, snapshots: HashMap<i64, KeyQuota>) {
        *self.inner.write().expect("smart cache lock poisoned") = snapshots;
    }

    /// Clone the current snapshot map for a dispatch's ordering pass.
    /// One lock acquisition regardless of candidate count.
    pub fn snapshots(&self) -> HashMap<i64, KeyQuota> {
        self.inner
            .read()
            .expect("smart cache lock poisoned")
            .clone()
    }

    /// Whether any snapshot has been loaded (drives the degradation path
    /// without a PG round-trip).
    pub fn is_empty(&self) -> bool {
        self.inner
            .read()
            .expect("smart cache lock poisoned")
            .is_empty()
    }
}
