//! Batch async ledger writer: the request path pushes [`AttemptLog`] batches
//! onto a channel and moves on; a background task buffers them and flushes to
//! PG on a size trigger or a timer. Persistence latency is lifted off the
//! request path (a settled request no longer waits on the INSERT round-trip),
//! and a burst of concurrent requests amortizes into fewer, larger inserts.
//!
//! Each flush writes two things with different guarantees:
//!
//! - **Charges** (`billing_entries` + `users.balance_microus` +
//!   `gateway_keys.spent_microus`): every billed
//!   row (a user, a request id and a positive `charged_microus`) becomes a
//!   [`Charge`], settled first, in chunks of at most [`SETTLE_CHUNK`]
//!   charges, one transaction per chunk ([`crate::store::settle_charges`]).
//!   Committed chunks leave the pending queue; a failed chunk and every
//!   chunk after it stay queued, in order, for the next flush to retry (the
//!   timer flushes even with no new rows). The request-id unique index makes
//!   a retry of an already-committed charge a no-op, so retries never
//!   double-debit. The queue is capped at [`MAX_PENDING_CHARGES`]: beyond
//!   that the oldest charges are dropped and logged (lost revenue, never an
//!   overcharge). Charges whose user no longer exists, or whose arithmetic
//!   would overflow, are dropped with an error.
//! - **Statistics rows** (`gateway_requests`): written best-effort in one
//!   batch (with per-row fallback if rejected), and cleared after the attempt whether or not every insert landed —
//!   the store logs failures, and keeping the rows would re-insert them.
//!
//! Ordering: one mpsc producer order per push, and the buffer preserves push
//! order, so a request's attempts land in PG in the same order the old
//! per-request insert produced (id order == time order is preserved within a
//! batch; [`crate::store::insert_request_logs`] preserves that order).
//!
//! Shutdown: [`LedgerWriterHandle::flush_and_shutdown`] signals the flush
//! task to drain the channel and write a final batch before exiting, so a
//! graceful exit loses no ledger rows while PG is reachable; charges the
//! final settlement cannot write are reported as lost. An ungraceful kill
//! (SIGKILL, panic abort) loses at most one flush interval of buffered rows
//! and charges (plus any pending retries) — the charges are under-collected,
//! never double-collected. Balances therefore lag by up to one flush window,
//! so a user can end slightly negative; that is accepted.

use std::time::Duration;

use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::task::TaskTracker;

use crate::store::AttemptLog;
use crate::store::Charge;

/// Default flush cadence for the production writer.
pub const DEFAULT_FLUSH_INTERVAL: Duration = Duration::from_millis(100);

/// Default early-flush trigger for the production writer.
pub const DEFAULT_BATCH_SIZE: usize = 100;

/// How long a settled charge may still sit in the flush buffer. Reconciliation
/// ignores request rows and ledger entries younger than this fixed grace window,
/// so a charge that has just been queued never reads as uncollected before its
/// first flush attempt.
/// It does not cover the retry queue: after a failed *settlement* the request
/// rows are still written (the flush inserts them whatever the settle did)
/// while their entries wait for the next flush, so reconciliation reports them
/// as uncollected until the retry lands. That is the honest answer — the money
/// is not in the ledger yet — but it means a positive gap after a
/// settlement-only failure (lock timeout, one bad row) is pending, not lost.
pub const SETTLEMENT_GRACE: Duration = Duration::from_secs(60);

/// Most unsettled charges kept for retry while PG is unreachable; beyond
/// this the oldest are dropped so memory stays bounded.
pub const MAX_PENDING_CHARGES: usize = 100_000;

/// Most charges settled in one transaction, so a large retry backlog never
/// holds one long transaction (and its user row locks) open.
const SETTLE_CHUNK: usize = 1000;

/// Which flush is running: a periodic one has a next flush to retry
/// failures; the final one (graceful shutdown or teardown) does not, so its
/// failures are lost and logged at `error!`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FlushKind {
    Periodic,
    Final,
}

/// Buffers attempt logs and flushes them to PG in batches. Cheap to clone
/// (an unbounded channel sender); the write path is non-blocking — requests
/// push their attempt rows and move on.
#[derive(Clone)]
pub struct LedgerWriter {
    tx: mpsc::UnboundedSender<Vec<AttemptLog>>,
    /// Detached accounting tasks that will still [`Self::push`] (a committed
    /// stream's settlement waits for the pump to end). Shutdown waits on them
    /// before the final flush, so a stream that finishes during the drain is
    /// still charged.
    settlements: TaskTracker,
}

impl LedgerWriter {
    /// Create the writer and spawn its background flush task. `flush_interval`
    /// is how often a non-empty buffer is written; the buffer flushes early
    /// once it reaches `batch_size` rows. Returns the writer and the handle a
    /// graceful shutdown flushes through.
    pub fn new(
        pool: sqlx::PgPool,
        activity: crate::activity::ActivitySink,
        flush_interval: Duration,
        batch_size: usize,
    ) -> (Self, LedgerWriterHandle) {
        let (tx, rx) = mpsc::unbounded_channel();
        let (shutdown_tx, shutdown_rx) = mpsc::channel(1);
        let done = tokio::spawn(flush_loop(
            pool,
            activity,
            rx,
            shutdown_rx,
            flush_interval,
            batch_size,
        ));
        (
            Self {
                tx,
                settlements: TaskTracker::new(),
            },
            LedgerWriterHandle {
                shutdown_tx,
                done: Some(done),
            },
        )
    }

    /// Queue one dispatch's attempt rows for batch persistence. Non-blocking:
    /// an unbounded send cannot fail while the flush task lives, and after a
    /// shutdown the rows are dropped with a warning instead of failing the
    /// request (accounting never breaks the request path).
    pub fn push(&self, attempts: Vec<AttemptLog>) {
        if attempts.is_empty() {
            return;
        }
        if self.tx.send(attempts).is_err() {
            tracing::warn!("ledger writer already shut down; attempt rows dropped");
        }
    }

    /// Spawn a detached accounting task that ends in a [`Self::push`]; the
    /// shutdown drain ([`Self::drain_settlements`]) waits for it.
    pub fn spawn_settlement<F>(&self, task: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        self.settlements.spawn(task);
    }

    /// Wait at most `timeout` for every tracked accounting task to finish.
    /// Call during shutdown after the HTTP server has stopped and before
    /// [`LedgerWriterHandle::flush_and_shutdown`]; tasks still running at the
    /// deadline lose their rows and charges (logged).
    pub async fn drain_settlements(&self, timeout: Duration) {
        self.settlements.close();
        if tokio::time::timeout(timeout, self.settlements.wait())
            .await
            .is_err()
        {
            tracing::error!(
                remaining = self.settlements.len(),
                timeout_secs = timeout.as_secs(),
                "accounting drain timed out; unfinished streams lose their ledger rows and charges"
            );
        }
    }
}

/// Handle for graceful shutdown: call [`Self::flush_and_shutdown`] before
/// process exit so the buffered rows land in PG. Must be unique — do not
/// clone: the shutdown channel has capacity 1, and a second handle's `Drop`
/// would race with `flush_and_shutdown`'s send.
pub struct LedgerWriterHandle {
    shutdown_tx: mpsc::Sender<()>,
    /// Awaited to know the flush task has drained and exited. Option so the
    /// graceful path can take it out (the handle also impls Drop).
    done: Option<JoinHandle<()>>,
}

impl LedgerWriterHandle {
    /// Signal the flush task to drain remaining buffered rows and exit, then
    /// await its completion. Call during graceful shutdown, before the PG pool
    /// closes (the final flush still needs a live connection).
    pub async fn flush_and_shutdown(mut self) {
        // send (not try_send): the shutdown channel has capacity 1 and this is
        // the only sender, so it never waits. An error means the flush task is
        // already gone (its own crash) — there is nothing left to wait on.
        if self.shutdown_tx.send(()).await.is_err() {
            tracing::warn!("ledger flush task already gone; skipping the final flush");
        }
        if let Some(done) = self.done.take()
            && let Err(error) = done.await
        {
            tracing::warn!("ledger flush task join failed: {error}");
        }
    }
}

/// Dropping the handle without a graceful shutdown still asks the flush task
/// to drain and exit: the buffered rows must not die with an aborted task
/// (this is what lets test fixtures drop the handle without losing rows).
impl Drop for LedgerWriterHandle {
    fn drop(&mut self) {
        let _ = self.shutdown_tx.try_send(());
    }
}

/// The background flush loop: buffer pushes, flush on the size trigger or
/// the timer, and on shutdown drain the channel (every push already sent is
/// still queued) and write one final batch.
async fn flush_loop(
    pool: sqlx::PgPool,
    activity: crate::activity::ActivitySink,
    mut rx: mpsc::UnboundedReceiver<Vec<AttemptLog>>,
    mut shutdown_rx: mpsc::Receiver<()>,
    flush_interval: Duration,
    batch_size: usize,
) {
    let mut buffer: Vec<AttemptLog> = Vec::new();
    // Charges whose settlement failed, retried on every later flush.
    let mut pending: Vec<Charge> = Vec::new();
    let mut interval = tokio::time::interval(flush_interval);
    // Delay, not the default Burst: a flush that runs past the interval must
    // wait a full interval rather than firing back-to-back flushes.
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
          biased;
          _ = shutdown_rx.recv() => {
            // Graceful shutdown: drain whatever pushers already sent (the
            // unbounded channel holds them), then write the final batch.
            while let Ok(batch) = rx.try_recv() {
              buffer.extend(batch);
            }
            flush(&pool, &activity, &mut buffer, &mut pending, FlushKind::Final).await;
            break;
          }
          batch = rx.recv() => {
            let Some(batch) = batch else {
              // All LedgerWriter clones dropped (process teardown without a
              // shutdown call): flush what we have and exit.
              flush(&pool, &activity, &mut buffer, &mut pending, FlushKind::Final).await;
              break;
            };
            buffer.extend(batch);
            if buffer.len() >= batch_size {
              flush(&pool, &activity, &mut buffer, &mut pending, FlushKind::Periodic).await;
            }
          }
          _ = interval.tick() => {
            flush(&pool, &activity, &mut buffer, &mut pending, FlushKind::Periodic).await;
          }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum PersistedNotification {
    None,
    Persisted,
    Batch,
}

#[derive(Debug, PartialEq, Eq)]
struct FlushPersistence {
    request_rows: usize,
    inserted_rows: usize,
    notification: PersistedNotification,
    clear_request_rows: bool,
}

impl FlushPersistence {
    fn plan(request_rows: usize, inserted_rows: usize) -> Self {
        let notification = if request_rows == 0 {
            PersistedNotification::None
        } else if request_rows == inserted_rows {
            PersistedNotification::Batch
        } else {
            PersistedNotification::Persisted
        };
        Self {
            request_rows,
            inserted_rows,
            notification,
            clear_request_rows: request_rows > 0,
        }
    }
}

/// Settle the batch's charges (with any pending retries), then write the
/// buffered statistics rows, and notify activity listeners (the `Persisted`
/// event fires per flush, not per request). The statistics buffer is cleared
/// even on partial failure — the rows are already logged by the store, and
/// keeping them would re-insert. Unsettled charges stay in `pending`.
/// A [`FlushKind::Final`] flush logs failures at `error!` level — the
/// operator believes the exit was clean.
async fn flush(
    pool: &sqlx::PgPool,
    activity: &crate::activity::ActivitySink,
    buffer: &mut Vec<AttemptLog>,
    pending: &mut Vec<Charge>,
    kind: FlushKind,
) {
    if buffer.is_empty() && pending.is_empty() {
        return;
    }
    pending.extend(buffer.iter().filter_map(charge_of));
    settle(pool, pending, kind).await;
    if !buffer.is_empty() {
        let ids = crate::store::insert_request_logs(pool, buffer).await;
        let persistence = FlushPersistence::plan(buffer.len(), ids.len());
        match persistence.notification {
            PersistedNotification::None => {
                unreachable!("non-empty request buffer has no notification")
            }
            PersistedNotification::Persisted => {
                if kind == FlushKind::Final {
                    tracing::error!(
                        expected = persistence.request_rows,
                        inserted = persistence.inserted_rows,
                        "ledger shutdown flush: rows lost — PG unreachable during final flush"
                    );
                } else {
                    tracing::warn!(
                        expected = persistence.request_rows,
                        inserted = persistence.inserted_rows,
                        "ledger batch flush: some rows failed to insert"
                    );
                }
                // `insert_request_logs` returns only rows that were durably
                // inserted. A short result cannot be paired with the complete
                // in-memory summary, so retain the old unit event and never
                // publish a misleading PersistedBatch containing failed rows.
                activity.persisted();
            }
            PersistedNotification::Batch => {
                let requests = buffer
                    .iter()
                    .map(crate::activity::PersistedRequest::from_attempt)
                    .collect::<Vec<_>>();
                activity.persisted_batch(requests);
            }
        }
        if persistence.clear_request_rows {
            buffer.clear();
        }
    }
}

/// The charge a ledger row carries: a billed user, a request id and a
/// positive amount. A zero charge (free user) writes no billing entry.
fn charge_of(row: &AttemptLog) -> Option<Charge> {
    let user_id = row.user_id?;
    let request_id = row.request_id.as_ref()?;
    let amount_microus = row.charged_microus.filter(|amount| *amount > 0)?;
    Some(Charge {
        user_id,
        request_id: request_id.clone(),
        amount_microus,
        cost_microus: row.cost_usd.and_then(crate::billing::cost_microus),
        rate_bp: row.rate_bp,
        gateway_key_id: row.gateway_key_id,
    })
}

/// Settle `pending` chunk by chunk, oldest first, one transaction per
/// chunk. Committed chunks (including their definitive skips: unknown users,
/// overflows) leave the queue; the first failure stops the pass and keeps
/// that chunk and everything after it, in order, for the next flush, trimmed
/// to [`MAX_PENDING_CHARGES`] by dropping the oldest. A
/// [`FlushKind::Final`] flush has no next flush, so a failure loses what
/// is left.
async fn settle(pool: &sqlx::PgPool, pending: &mut Vec<Charge>, kind: FlushKind) {
    let mut committed = 0;
    let mut failure: Option<sqlx::Error> = None;
    for chunk in pending.chunks(SETTLE_CHUNK) {
        match crate::store::settle_charges(pool, chunk).await {
            Ok(report) => {
                log_report(&report);
                committed += chunk.len();
            }
            Err(error) => {
                failure = Some(error);
                break;
            }
        }
    }
    pending.drain(..committed);
    let Some(error) = failure else {
        return;
    };
    match kind {
        FlushKind::Final => {
            tracing::error!(
                lost = pending.len(),
                "billing shutdown settlement failed: {error}; charges lost (under-collected)"
            );
            pending.clear();
        }
        FlushKind::Periodic => {
            tracing::error!(
                pending = pending.len(),
                "billing settlement failed: {error}; charges kept for retry"
            );
            if pending.len() > MAX_PENDING_CHARGES {
                let excess = pending.len() - MAX_PENDING_CHARGES;
                pending.drain(..excess);
                tracing::error!(
                    dropped = excess,
                    "billing retry queue full: oldest charges dropped (under-collected)"
                );
            }
        }
    }
}

/// Log the definitive skips of one committed settlement chunk.
fn log_report(report: &crate::store::SettleReport) {
    if !report.unknown_users.is_empty() {
        tracing::error!(
            user_ids = ?report.unknown_users,
            charges = report.unknown_charges,
            "billing settlement: charges dropped — their users no longer exist"
        );
    }
    for skipped in &report.overflowed {
        tracing::error!(
            request_id = skipped.request_id.as_str(),
            user_id = skipped.user_id,
            "billing settlement: charge dropped — the amount overflows the balance"
        );
    }
    if report.duplicates > 0 {
        tracing::warn!(
            duplicates = report.duplicates,
            "billing settlement: request ids already charged; skipped"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::{DEFAULT_FLUSH_INTERVAL, FlushPersistence, PersistedNotification};
    use std::time::Duration;

    #[test]
    fn default_flush_interval_is_realtime() {
        assert_eq!(
            DEFAULT_FLUSH_INTERVAL,
            Duration::from_millis(100),
            "ledger activity should reach listeners without a multi-second delay"
        );
    }

    #[test]
    fn complete_request_flush_publishes_batch_and_clears_rows() {
        assert_eq!(
            FlushPersistence::plan(3, 3),
            FlushPersistence {
                request_rows: 3,
                inserted_rows: 3,
                notification: PersistedNotification::Batch,
                clear_request_rows: true,
            },
            "a fully inserted request batch should carry its request summaries and clear the buffer"
        );
    }

    #[test]
    fn partial_request_flush_publishes_unit_event_and_clears_rows() {
        assert_eq!(
            FlushPersistence::plan(3, 2),
            FlushPersistence {
                request_rows: 3,
                inserted_rows: 2,
                notification: PersistedNotification::Persisted,
                clear_request_rows: true,
            },
            "a partial request insert should trigger a corrective reload and clear the buffer"
        );
    }

    #[test]
    fn failed_request_flush_publishes_unit_event_and_clears_rows() {
        assert_eq!(
            FlushPersistence::plan(3, 0),
            FlushPersistence {
                request_rows: 3,
                inserted_rows: 0,
                notification: PersistedNotification::Persisted,
                clear_request_rows: true,
            },
            "a failed request insert should trigger a corrective reload and clear the buffer"
        );
    }

    #[test]
    fn settlement_only_flush_keeps_request_buffer_untouched_and_silent() {
        assert_eq!(
            FlushPersistence::plan(0, 0),
            FlushPersistence {
                request_rows: 0,
                inserted_rows: 0,
                notification: PersistedNotification::None,
                clear_request_rows: false,
            },
            "a charge-only retry must not trigger a request reload or clear request rows"
        );
    }
}
