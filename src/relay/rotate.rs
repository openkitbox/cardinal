//! Round-robin cursor for Rotate route ordering.
//!
//! Rotate ignores quota entirely: each dispatch starts from the position
//! after the last one served, cycling through the ready partition. The cursor
//! is a per-alias `AtomicUsize` — one `fetch_add` on the request path, no
//! lock held, no allocation, no deep copy.
//!
//! Ownership: one instance on `Core`, shared with relay via `DispatchDeps`.
//! Unlike `SmartCache` (a read-mostly store refreshed by a background prober),
//! this is a pure request-path counter — writes ARE the reads.

use std::sync::atomic::{AtomicUsize, Ordering};

use dashmap::DashMap;

/// Per-alias round-robin cursors. Aliases are route names (`"deepseek-flash"`),
/// so the map stays small — one entry per rotate route, never per key/model.
#[derive(Clone, Default)]
pub struct RotateCursors {
    inner: std::sync::Arc<DashMap<String, AtomicUsize>>,
}

impl RotateCursors {
    pub fn new() -> Self {
        Self::default()
    }

    /// Advance the cursor for `alias` and return the previous value.
    /// The caller mods by the current ready count, so membership changes
    /// (keys added/removed/rested) can never overflow into a panic.
    pub fn next(&self, alias: &str) -> usize {
        self.inner
            .entry(alias.to_string())
            .or_insert_with(|| AtomicUsize::new(0))
            .fetch_add(1, Ordering::Relaxed)
    }
}
