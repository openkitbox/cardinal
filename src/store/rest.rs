use sqlx::PgPool;

// ---------- failure cooldown (rest), identity = (key, model); model NULL = the whole key ----------

/// One unexpired cooldown row, as the relay's restLast partition reads it.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, sqlx::FromRow)]
pub struct ActiveRestRow {
    pub key_id: i64,
    /// NULL = the whole key rests; a model id cools only that (key, model) pair.
    pub model: Option<String>,
    pub rest_until: chrono::DateTime<chrono::Utc>,
    pub reason: Option<String>,
}

/// One active cooldown, joined with provider/key names so UIs can read them directly.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, sqlx::FromRow)]
pub struct RestRow {
    pub key_id: i64,
    pub provider_id: i64,
    /// NULL = the whole key rests; a model id cools only that (key, model) pair.
    pub model: Option<String>,
    pub rest_until: chrono::DateTime<chrono::Utc>,
    pub reason: Option<String>,
    pub provider_name: String,
    pub key_label: String,
}

/// Rest one key (or one (key, model) pair) until `rest_until` — the caller
/// computes the duration per failure class, see `relay::failover`. A whole-key
/// row (`model: None`) and per-model rows are separate rows: the upsert targets
/// the (key_id, COALESCE(model, '')) unique index.
/// `model = None` rests the whole key; `Some(m)` rests only that (key, model)
/// pair. Note the uniqueness bucket in migration 0006 coalesces NULL and '' —
/// never write an empty-string model (upstream model ids are non-empty by
/// contract: route entries are validated, the direct path rejects an empty
/// suffix with EmptySuffix).
pub async fn insert_rest(
    pool: &PgPool,
    key_id: i64,
    model: Option<&str>,
    rest_until: chrono::DateTime<chrono::Utc>,
    reason: &str,
) -> anyhow::Result<()> {
    sqlx::query(
    "INSERT INTO gateway_key_rests (key_id, model, rest_until, reason) VALUES ($1, $2, $3, $4)
         ON CONFLICT (key_id, (COALESCE(model, ''))) DO UPDATE SET rest_until = EXCLUDED.rest_until, reason = EXCLUDED.reason",
  )
  .bind(key_id)
  .bind(model)
  .bind(rest_until)
  .bind(reason)
  .execute(pool)
  .await?;
    Ok(())
}

/// The currently-unexpired cooldown rows (relay defers matching candidates behind ready ones).
pub async fn active_rest_rows(pool: &PgPool) -> anyhow::Result<Vec<ActiveRestRow>> {
    let rows = sqlx::query_as::<_, ActiveRestRow>(
        "SELECT key_id, model, rest_until, reason FROM gateway_key_rests WHERE rest_until > now()",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Admin "wake the key": delete EVERY rest row of the key (whole-key and per-model).
pub async fn clear_rest(pool: &PgPool, key_id: i64) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM gateway_key_rests WHERE key_id = $1")
        .bind(key_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Relay success path: the key just proved healthy serving `model`, so drop its
/// whole-key row and THIS model's row — other models' rows stand (a success on
/// m2 says nothing about whether the plan serves m1).
pub async fn clear_rest_for_model(pool: &PgPool, key_id: i64, model: &str) -> anyhow::Result<()> {
    sqlx::query(
        "DELETE FROM gateway_key_rests WHERE key_id = $1 AND (model IS NULL OR model = $2)",
    )
    .bind(key_id)
    .bind(model)
    .execute(pool)
    .await?;
    Ok(())
}

/// Clear the cooldowns of every key of one provider (idempotent).
pub async fn clear_provider_rests(pool: &PgPool, provider_id: i64) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM gateway_key_rests WHERE key_id IN (SELECT id FROM gateway_provider_keys WHERE provider_id = $1)")
    .bind(provider_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// The currently active cooldowns, soonest expiry first.
pub async fn list_rests(pool: &PgPool) -> anyhow::Result<Vec<RestRow>> {
    let rows = sqlx::query_as::<_, RestRow>(
        "SELECT r.key_id, r.model, r.rest_until, r.reason,
            k.provider_id, p.name AS provider_name, k.label AS key_label
         FROM gateway_key_rests r
         JOIN gateway_provider_keys k ON k.id = r.key_id
         JOIN gateway_providers p ON p.id = k.provider_id
         WHERE r.rest_until > now()
         ORDER BY r.rest_until",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}
