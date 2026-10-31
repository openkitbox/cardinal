use chrono::DateTime;
use chrono::Utc;
use sqlx::PgPool;

use crate::quota;
use crate::quota::Balance;
use crate::quota::BalanceStep;

/// One recorded prepaid balance reading, as the GUI's balance chart reads it.
/// `opens_segment` marks a segment base (first record or a top-up); `topup`
/// is the observed increase, a lower bound when spend shared the interval.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct BalanceHistoryPoint {
    pub key_id: i64,
    pub amount: f64,
    pub opens_segment: bool,
    pub topup: Option<f64>,
    pub probed_at: chrono::DateTime<chrono::Utc>,
}

/// Record one balance reading taken from the vendor at `probed_at` if it
/// differs from the key's latest recorded amount (an unchanged reading
/// writes nothing). An increase or the first record opens a new segment.
/// Non-finite amounts and readings no newer than the latest recorded one
/// (an out-of-order probe) write nothing.
///
/// The admin refresh and the background prober can probe the same key
/// concurrently, so read-classify-write runs in one transaction under a
/// per-key advisory lock (`hashtextextended('gateway_key_balance_history:'
/// || key_id, 0)`, the same text-hash convention as provider identity
/// locks). Without it, two interleaved probes could compare against the
/// same stale latest row and record a false top-up.
///
/// After an insert, rows older than 45 days that belong to PREVIOUS
/// segments are dropped. The current segment is kept whole: its size is
/// bounded because rows are written only when the amount changes.
///
/// Callers log a failure and carry on: balance history is decorative.
pub async fn balance_history_record(
    pool: &PgPool,
    key_id: i64,
    balance: &Balance,
    probed_at: DateTime<Utc>,
) -> anyhow::Result<()> {
    if !balance.amount.is_finite() {
        return Ok(());
    }
    let mut tx = pool.begin().await?;
    sqlx::query(
        "SELECT pg_advisory_xact_lock(hashtextextended('gateway_key_balance_history:' || $1::text, 0))",
    )
    .bind(key_id)
    .execute(&mut *tx)
    .await?;
    let latest: Option<(f64, DateTime<Utc>)> = sqlx::query_as(
        "SELECT amount, probed_at FROM gateway_key_balance_history
         WHERE key_id = $1 ORDER BY probed_at DESC, id DESC LIMIT 1",
    )
    .bind(key_id)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some((_, latest_at)) = latest
        && probed_at <= latest_at
    {
        return Ok(()); // stale reading; the transaction rolls back on drop
    }
    let previous = latest.map(|(amount, _)| amount);
    let (opens_segment, topup) = match quota::classify(previous, balance.amount) {
        BalanceStep::Unchanged => return Ok(()),
        BalanceStep::Spent => (false, None),
        BalanceStep::Opened { topup } => (true, topup),
    };
    sqlx::query(
        "INSERT INTO gateway_key_balance_history (key_id, amount, opens_segment, topup, probed_at)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(key_id)
    .bind(balance.amount)
    .bind(opens_segment)
    .bind(topup)
    .bind(probed_at)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "DELETE FROM gateway_key_balance_history
         WHERE key_id = $1 AND probed_at < now() - interval '45 days'
           AND probed_at < (
               SELECT probed_at FROM gateway_key_balance_history
               WHERE key_id = $1 AND opens_segment
               ORDER BY probed_at DESC, id DESC LIMIT 1
           )",
    )
    .bind(key_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Every key's CURRENT segment (rows from its latest segment-opening row on):
/// the opening row itself, plus the last row of each hour over the last 48
/// hours and of each day before that. The balance moves monotonically down
/// within a segment, so a bucket's last row carries its end value and
/// downsampling loses no shape. Ordered by key, then probe time.
pub async fn list_balance_history(pool: &PgPool) -> anyhow::Result<Vec<BalanceHistoryPoint>> {
    let rows = sqlx::query_as::<_, (i64, f64, bool, Option<f64>, chrono::DateTime<chrono::Utc>)>(
        "WITH base AS (
             SELECT DISTINCT ON (key_id) id, key_id, probed_at
             FROM gateway_key_balance_history
             WHERE opens_segment
             ORDER BY key_id, probed_at DESC, id DESC
         ), segment AS (
             SELECT h.id, h.key_id, h.amount, h.opens_segment, h.topup, h.probed_at
             FROM gateway_key_balance_history h
             JOIN base b ON b.key_id = h.key_id
             WHERE h.probed_at >= b.probed_at
         ), recent AS (
             SELECT DISTINCT ON (key_id, date_trunc('hour', probed_at)) *
             FROM segment
             WHERE probed_at >= now() - interval '48 hours'
             ORDER BY key_id, date_trunc('hour', probed_at), probed_at DESC, id DESC
         ), older AS (
             SELECT DISTINCT ON (key_id, date_trunc('day', probed_at)) *
             FROM segment
             WHERE probed_at < now() - interval '48 hours'
             ORDER BY key_id, date_trunc('day', probed_at), probed_at DESC, id DESC
         ), picked AS (
             SELECT s.* FROM segment s JOIN base b ON b.id = s.id
             UNION
             SELECT * FROM recent
             UNION
             SELECT * FROM older
         )
         SELECT key_id, amount, opens_segment, topup, probed_at
         FROM picked
         ORDER BY key_id, probed_at",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(
            |(key_id, amount, opens_segment, topup, probed_at)| BalanceHistoryPoint {
                key_id,
                amount,
                opens_segment,
                topup,
                probed_at,
            },
        )
        .collect())
}
