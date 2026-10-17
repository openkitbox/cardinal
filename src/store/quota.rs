use sqlx::PgPool;

use crate::quota::KeyQuota;

// ---------- quota snapshots (decorative GUI card cache, one row per key) ----------

/// Persist one key's probed quota reading, refreshing the probe timestamp.
/// Called by the admin probe fan-out after each successful read; the GUI
/// renders these snapshots instantly on load before re-probing.
pub async fn quota_snapshot_upsert(
    pool: &PgPool,
    key_id: i64,
    quota: &KeyQuota,
) -> anyhow::Result<()> {
    let payload = serde_json::to_value(quota)?;
    sqlx::query(
    "INSERT INTO gateway_key_quota_snapshots (key_id, payload, probed_at) VALUES ($1, $2, now())
         ON CONFLICT (key_id) DO UPDATE SET payload = EXCLUDED.payload, probed_at = now()",
  )
  .bind(key_id)
  .bind(payload)
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
