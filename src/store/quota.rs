use sqlx::PgPool;

use crate::quota::KeyQuota;

// ---------- quota history (append-only probe samples for the card trend) ----------

/// One recorded probe reading of one window, as the GUI's trend chart reads
/// it. Flat rather than grouped: the chart filters by key and window name.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct QuotaHistoryPoint {
    pub key_id: i64,
    pub window_name: String,
    pub used_pct: f64,
    pub probed_at: chrono::DateTime<chrono::Utc>,
}

// ---------- quota snapshots (decorative GUI card cache, one row per key) ----------

/// Persist one key's quota reading taken from the vendor at `probed_at`.
/// Called by the admin probe fan-out after each successful read; the GUI
/// renders these snapshots instantly on load before re-probing. A reading
/// older than the stored one (a concurrent probe that finished late) is
/// dropped, so the snapshot never regresses behind the balance history.
pub async fn quota_snapshot_upsert(
    pool: &PgPool,
    key_id: i64,
    quota: &KeyQuota,
    probed_at: chrono::DateTime<chrono::Utc>,
) -> anyhow::Result<()> {
    let payload = serde_json::to_value(quota)?;
    sqlx::query(
        "INSERT INTO gateway_key_quota_snapshots (key_id, payload, probed_at) VALUES ($1, $2, $3)
         ON CONFLICT (key_id) DO UPDATE SET payload = EXCLUDED.payload, probed_at = EXCLUDED.probed_at
         WHERE gateway_key_quota_snapshots.probed_at < EXCLUDED.probed_at",
    )
    .bind(key_id)
    .bind(payload)
    .bind(probed_at)
  .execute(pool)
  .await?;
    Ok(())
}

/// Every stored quota snapshot in key order: (key id, reading, probe time).
/// A row whose payload no longer deserializes (schema drift) is skipped with
/// a warning rather than failing the whole list — that key's card simply
/// shows no reading.
pub async fn list_quota_snapshots(
    pool: &PgPool,
) -> anyhow::Result<Vec<(i64, KeyQuota, chrono::DateTime<chrono::Utc>)>> {
    let rows = sqlx::query_as::<_, (i64, serde_json::Value, chrono::DateTime<chrono::Utc>)>(
        "SELECT key_id, payload, probed_at FROM gateway_key_quota_snapshots ORDER BY key_id",
    )
    .fetch_all(pool)
    .await?;
    let mut snapshots = Vec::with_capacity(rows.len());
    for (key_id, payload, probed_at) in rows {
        match serde_json::from_value(payload) {
            Ok(quota) => snapshots.push((key_id, quota, probed_at)),
            Err(error) => {
                tracing::warn!(key_id, %error, "quota snapshot: undecodable payload skipped")
            }
        }
    }
    Ok(snapshots)
}

/// The stored quota snapshots for the given keys only, in key order:
/// (key id, reading). Keys without a snapshot — or whose payload no longer
/// deserializes (schema drift, skipped with a warning, same as
/// [`list_quota_snapshots`]) — are simply absent from the result. Used by
/// smart routing to score candidates without re-probing upstreams.
/// Duplicate ids in `key_ids` are not deduplicated (callers wanting unique
/// rows should dedupe first).
pub async fn list_quota_snapshots_by_keys(
    pool: &PgPool,
    key_ids: &[i64],
) -> anyhow::Result<Vec<(i64, KeyQuota)>> {
    if key_ids.is_empty() {
        return Ok(Vec::new());
    }
    let rows = sqlx::query_as::<_, (i64, serde_json::Value)>(
    "SELECT key_id, payload FROM gateway_key_quota_snapshots WHERE key_id = ANY($1) ORDER BY key_id",
  )
  .bind(key_ids)
  .fetch_all(pool)
  .await?;
    let mut snapshots = Vec::with_capacity(rows.len());
    for (key_id, payload) in rows {
        match serde_json::from_value(payload) {
            Ok(quota) => snapshots.push((key_id, quota)),
            Err(error) => {
                tracing::warn!(key_id, %error, "quota snapshot: undecodable payload skipped")
            }
        }
    }
    Ok(snapshots)
}

/// Append one history row per plan window after a successful probe, as a single
/// statement. Retention is NOT enforced here: a per-key DELETE on every probe
/// was write amplification, so pruning moved to [`quota_history_prune`], which
/// the probe fan-out runs at a low frequency.
///
/// History exists only because the snapshot table keeps the latest reading
/// alone — the card's cumulative trend needs the samples behind it. Callers
/// log a failure and carry on: quota is decorative.
pub async fn quota_history_insert(
    pool: &PgPool,
    key_id: i64,
    quota: &KeyQuota,
) -> anyhow::Result<()> {
    if quota.windows.is_empty() {
        return Ok(()); // nothing to append, and no statement to send
    }
    let mut query = sqlx::QueryBuilder::new(
        "INSERT INTO gateway_key_quota_history (key_id, window_name, used_pct, resets_at) ",
    );
    query.push_values(quota.windows.iter(), |mut row, window| {
        row.push_bind(key_id)
            .push_bind(&window.name)
            .push_bind(window.used_pct)
            .push_bind(window.resets_at);
    });
    // `probed_at` keeps its column default (`now()`): one statement stamps
    // every window of a probe with the same instant.
    query.build().execute(pool).await?;
    Ok(())
}

/// Drop every history row no chart can show — older than 45 days, which is a
/// monthly window (~31 days) plus a fortnight of slack for a probe gap —
/// returning how many were deleted. One statement for all keys: the per-key
/// delete that used to ride along with every probe is gone, so running this is
/// the caller's decision, not the insert's. The cutoff stays the one
/// authoritative rule and the table stays the one place the rows live.
///
/// Index-backed by `idx_gateway_key_quota_history_probed_at`
/// (migrations/0023_pg_load_indexes.sql), so a prune that finds nothing is an
/// index scan rather than a walk over the append-only table.
///
/// Callers log a failure and carry on: quota is decorative.
pub async fn quota_history_prune(pool: &PgPool) -> anyhow::Result<u64> {
    let deleted = sqlx::query(
        "DELETE FROM gateway_key_quota_history WHERE probed_at < now() - interval '45 days'",
    )
    .execute(pool)
    .await?
    .rows_affected();
    Ok(deleted)
}

/// The chart series for every key/window: the LAST probe of each hour over
/// the last 48 hours, and of each day before that (out to 35 days). Window
/// usage is cumulative, so a bucket's last sample carries its end value and
/// downsampling loses no shape — hourly keeps a freshly deployed gateway's
/// curve visible within hours, daily keeps the month-scale shape cheap. The
/// point keeps its real `probed_at`, so the chart maps it to an exact x.
///
/// Rows from a previous window (before its reset) are included here and
/// filtered by the GUI against the current window's start — the gateway does
/// not need to know each window's period to serve the series.
pub async fn list_quota_history(pool: &PgPool) -> anyhow::Result<Vec<QuotaHistoryPoint>> {
    let rows = sqlx::query_as::<_, (i64, String, f64, chrono::DateTime<chrono::Utc>)>(
        "WITH recent AS (
             SELECT DISTINCT ON (key_id, window_name, date_trunc('hour', probed_at))
                    key_id, window_name, used_pct, probed_at
             FROM gateway_key_quota_history
             WHERE probed_at >= now() - interval '48 hours'
             ORDER BY key_id, window_name, date_trunc('hour', probed_at), probed_at DESC
         ), older AS (
             SELECT DISTINCT ON (key_id, window_name, date_trunc('day', probed_at))
                    key_id, window_name, used_pct, probed_at
             FROM gateway_key_quota_history
             WHERE probed_at >= now() - interval '35 days'
               AND probed_at <  now() - interval '48 hours'
             ORDER BY key_id, window_name, date_trunc('day', probed_at), probed_at DESC
         )
         SELECT key_id, window_name, used_pct, probed_at
         FROM recent
         UNION ALL
         SELECT key_id, window_name, used_pct, probed_at
         FROM older
         ORDER BY key_id, window_name, probed_at",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(
            |(key_id, window_name, used_pct, probed_at)| QuotaHistoryPoint {
                key_id,
                window_name,
                used_pct,
                probed_at,
            },
        )
        .collect())
}

#[cfg(test)]
fn history_insert_sql(window_count: usize) -> String {
    let mut sql = String::from(
        "INSERT INTO gateway_key_quota_history (key_id, window_name, used_pct, resets_at) VALUES ",
    );
    for index in 0..window_count {
        if index > 0 {
            sql.push_str(", ");
        }
        let first_bind = index * 4 + 1;
        sql.push_str(&format!(
            "(${0}, ${1}, ${2}, ${3})",
            first_bind,
            first_bind + 1,
            first_bind + 2,
            first_bind + 3
        ));
    }
    sql
}

#[cfg(test)]
mod tests {
    use super::history_insert_sql;

    #[test]
    fn history_insert_uses_one_statement_for_all_windows() {
        assert_eq!(
            history_insert_sql(3),
            "INSERT INTO gateway_key_quota_history (key_id, window_name, used_pct, resets_at) VALUES ($1, $2, $3, $4), ($5, $6, $7, $8), ($9, $10, $11, $12)"
        );
    }
}
