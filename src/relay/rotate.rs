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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn per_alias_cursors_advance_independently() {
        let cursors = RotateCursors::new();
        assert_eq!(cursors.next("a"), 0);
        assert_eq!(cursors.next("b"), 0);
        assert_eq!(cursors.next("a"), 1);
        assert_eq!(cursors.next("b"), 1);
        assert_eq!(cursors.next("a"), 2);
    }

    #[test]
    fn rotate_left_walks_the_ring() {
        // The dispatch-side math: cursor % len, then rotate_left.
        let cursors = RotateCursors::new();
        let len = 3;
        let order: Vec<usize> = (0..len).collect();
        let mut served = Vec::new();
        for _ in 0..7 {
            let start = cursors.next("r") % len;
            let mut ready = order.clone();
            ready.rotate_left(start);
            served.push(ready[0]);
        }
        assert_eq!(served, vec![0, 1, 2, 0, 1, 2, 0]);
    }

    #[test]
    fn modulo_safe_after_ready_set_shrinks() {
        // Cursor is at 5; ready set shrinks from 3 to 2. 5 % 2 = 1, no overflow.
        let cursors = RotateCursors::new();
        for _ in 0..5 {
            cursors.next("r");
        }
        let len = 2;
        let start = cursors.next("r") % len; // cursor was 5, now 6; 5 % 2 = 1
        assert_eq!(start, 1);
        let mut ready = ["k1", "k2"];
        ready.rotate_left(start);
        assert_eq!(ready[0], "k2");
    }
}
