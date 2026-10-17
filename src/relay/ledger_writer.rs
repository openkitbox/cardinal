//! Batch async ledger writer: the request path pushes [`AttemptLog`] batches
//! onto a channel and moves on; a background task buffers them and flushes to
//! PG on a size trigger or a timer. Persistence latency is lifted off the
//! request path (a settled request no longer waits on the INSERT round-trip),
//! and a burst of concurrent requests amortizes into fewer, larger inserts.
//!
//! Ordering: one mpsc producer order per push, and the buffer preserves push
//! order, so a request's attempts land in PG in the same order the old
//! per-request insert produced (id order == time order is preserved within a
//! batch; [`crate::store::insert_request_logs`] inserts sequentially).
//!
//! Shutdown: [`LedgerWriterHandle::flush_and_shutdown`] signals the flush
//! task to drain the channel and write a final batch before exiting, so a
//! graceful exit loses no ledger rows. An ungraceful kill (SIGKILL, panic
//! abort) loses at most one flush interval of buffered rows — the same class
//! of loss the old design accepted for the streaming post-processing task.

use std::time::Duration;

use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::store::AttemptLog;

/// Default flush cadence for the production writer.
pub const DEFAULT_FLUSH_INTERVAL: Duration = Duration::from_secs(5);

/// Default early-flush trigger for the production writer.
pub const DEFAULT_BATCH_SIZE: usize = 100;

/// Buffers attempt logs and flushes them to PG in batches. Cheap to clone
/// (an unbounded channel sender); the write path is non-blocking — requests
/// push their attempt rows and move on.
#[derive(Clone)]
pub struct LedgerWriter {
    tx: mpsc::UnboundedSender<Vec<AttemptLog>>,
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
            Self { tx },
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
            flush(&pool, &activity, &mut buffer, true).await;
            break;
          }
          batch = rx.recv() => {
            let Some(batch) = batch else {
              // All LedgerWriter clones dropped (process teardown without a
              // shutdown call): flush what we have and exit.
              flush(&pool, &activity, &mut buffer, true).await;
              break;
            };
            buffer.extend(batch);
            if buffer.len() >= batch_size {
              flush(&pool, &activity, &mut buffer, false).await;
            }
          }
          _ = interval.tick() => {
            flush(&pool, &activity, &mut buffer, false).await;
          }
        }
    }
}

/// Write the buffered rows as one batch and notify activity listeners (the
/// `Persisted` event moved here from the request path: it now fires per
/// flush, not per request). Buffer is cleared even on partial failure — the
/// rows are already logged by the store, and keeping them would re-insert.
/// `is_shutdown`: the final flush during graceful shutdown logs failures at
/// `error!` level — the operator believes the exit was clean.
async fn flush(
    pool: &sqlx::PgPool,
    activity: &crate::activity::ActivitySink,
    buffer: &mut Vec<AttemptLog>,
    is_shutdown: bool,
) {
    if buffer.is_empty() {
        return;
    }
    let ids = crate::store::insert_request_logs(pool, buffer).await;
    if ids.len() != buffer.len() {
        if is_shutdown {
            tracing::error!(
                expected = buffer.len(),
                inserted = ids.len(),
                "ledger shutdown flush: rows lost — PG unreachable during final flush"
            );
        } else {
            tracing::warn!(
                expected = buffer.len(),
                inserted = ids.len(),
                "ledger batch flush: some rows failed to insert"
            );
        }
    }
    buffer.clear();
    activity.persisted();
}
