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

// ---------- quota history (append-only probe samples, card trend chart) ----------

/// Append one history row per plan window after a successful probe, then drop
/// this key's rows older than any chart can show (a monthly window is the
/// longest at ~31 days; a fortnight of slack covers a probe gap).
///
/// History exists only because the snapshot table keeps the latest reading
/// alone — the card's cumulative trend needs the samples behind it. Callers
/// log a failure and carry on: quota is decorative.
pub async fn quota_history_insert(
    pool: &PgPool,
    key_id: i64,
    quota: &KeyQuota,
) -> anyhow::Result<()> {
    for window in &quota.windows {
        sqlx::query(
            "INSERT INTO gateway_key_quota_history (key_id, window_name, used_pct, resets_at)
             VALUES ($1, $2, $3, $4)",
        )
        .bind(key_id)
        .bind(&window.name)
        .bind(window.used_pct)
        .bind(window.resets_at)
        .execute(pool)
        .await?;
    }
    sqlx::query(
        "DELETE FROM gateway_key_quota_history
         WHERE key_id = $1 AND probed_at < now() - interval '45 days'",
    )
    .bind(key_id)
    .execute(pool)
    .await?;
    Ok(())
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
