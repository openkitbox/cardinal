use crate::protocol::ProtocolId;
use sqlx::PgPool;

/// The ledger time and dispatch request id of one request row — the anchor
/// for locating its captured bodies in the hourly payload files
/// (`body_log::BodyLog::get_near` keys captures by `req_{n}`, not row id:
/// the ledger writer batches inserts, so the row id is unknown at capture
/// time).
pub async fn request_row_anchor(
    pool: &PgPool,
    id: i64,
) -> anyhow::Result<Option<(chrono::DateTime<chrono::Utc>, Option<String>)>> {
    let row: Option<(chrono::DateTime<chrono::Utc>, Option<String>)> =
        sqlx::query_as("SELECT ts, request_id FROM gateway_requests WHERE id = $1")
            .bind(id)
            .fetch_optional(pool)
            .await?;
    Ok(row)
}

/// In-memory record of one relay attempt — the write-side shape of a
/// `gateway_requests` row (owned here so the relay module holds no SQL).
#[derive(Clone, Debug)]
pub struct AttemptLog {
    pub protocol: ProtocolId,
    /// The client-facing protocol (None: not recorded — pre-0018 rows keep
    /// NULL; UIs fall back to showing the upstream protocol alone).
    pub client_protocol: Option<ProtocolId>,
    /// The reasoning effort the client asked for (low/medium/high/xhigh/max;
    /// None = no effort named, or a pre-0019 row).
    pub effort: Option<String>,
    /// Route alias on the route path; NULL on the direct `provider/model` path.
    pub alias: Option<String>,
    pub provider_id: i64,
    /// Candidate key actually used.
    pub provider_key_id: i64,
    /// The client-supplied model string (route alias or "provider/model").
    pub model: String,
    /// The upstream model actually requested (self-reported by the upstream when observed).
    pub served_model: Option<String>,
    pub status: u16,
    pub input_tokens: Option<i64>,
    pub output_tokens: Option<i64>,
    pub cached_input_tokens: Option<i64>,
    /// Messages `cache_creation_input_tokens` (the cache write); other
    /// protocols never report one. Priced at cache_write_usd, 1-hour part at
    /// cache_write_1h_usd.
    pub cache_creation_input_tokens: Option<i64>,
    pub total_ms: i32,
    /// Time to first content (text/reasoning/tool-call delta), ms from the
    /// attempt's start. NULL: non-streaming, or died before any content.
    pub ttft_ms: Option<i64>,
    pub cost_usd: Option<f64>,
    pub error: Option<String>,
    /// The caller's identity (the gateway key's label); NULL for a local
    /// unidentified caller or an in-process direct call.
    pub caller_key: Option<String>,
    /// Which client the request's User-Agent named; NULL
    /// when the request carried no User-Agent or was in-process.
    pub agent: Option<String>,
    /// The dispatch request id (`req_{n}`) — correlates the ledger row with
    /// its routing trace (the trace ring and the upstream header share it).
    /// NULL for attempts constructed before a request id exists.
    pub request_id: Option<String>,
}

/// Persist attempt rows to `gateway_requests`, returning the inserted row ids
/// in attempt order. Called by the ledger writer (`relay::ledger_writer`) in
/// batches, not per request. Logging failures are logged, never propagated:
/// accounting must not break the request path. A row whose insert fails
/// produces no id (it is skipped, so the result may be shorter than
/// `attempts`).
pub async fn insert_request_logs(pool: &PgPool, attempts: &[AttemptLog]) -> Vec<i64> {
    let mut ids = Vec::with_capacity(attempts.len());
    for attempt in attempts {
        let result = sqlx::query_scalar::<_, i64>(
      "INSERT INTO gateway_requests (protocol, client_protocol, effort, alias, provider_id, provider_key_id, model,
             served_model, status, input_tokens, output_tokens, cached_input_tokens,
             cache_creation_input_tokens, total_ms, ttft_ms, cost_usd, error, caller_key, agent, request_id)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)
             RETURNING id",
    )
    .bind(attempt.protocol.as_str())
    .bind(attempt.client_protocol.map(|p| p.as_str()))
    .bind(&attempt.effort)
    .bind(&attempt.alias)
    .bind(attempt.provider_id)
    .bind(attempt.provider_key_id)
    .bind(&attempt.model)
    .bind(&attempt.served_model)
    .bind(i32::from(attempt.status))
    .bind(attempt.input_tokens)
    .bind(attempt.output_tokens)
    .bind(attempt.cached_input_tokens)
    .bind(attempt.cache_creation_input_tokens)
    .bind(attempt.total_ms)
    .bind(attempt.ttft_ms)
    .bind(attempt.cost_usd)
    .bind(&attempt.error)
    .bind(&attempt.caller_key)
    .bind(&attempt.agent)
    .bind(&attempt.request_id)
    .fetch_one(pool)
    .await;
        match result {
            Ok(id) => ids.push(id),
            Err(error) => tracing::error!("failed to persist requests row: {error}"),
        }
    }
    ids
}

/// One `gateway_requests` row (the request log).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, sqlx::FromRow)]
pub struct RequestRow {
    pub id: i64,
    pub ts: chrono::DateTime<chrono::Utc>,
    pub protocol: String,
    /// The client-facing protocol (None: rows predating migration 0018).
    pub client_protocol: Option<String>,
    /// The reasoning effort the client asked for (None = none named / pre-0019).
    pub effort: Option<String>,
    pub alias: Option<String>,
    pub provider_id: Option<i64>,
    pub provider_key_id: Option<i64>,
    pub model: Option<String>,
    pub served_model: Option<String>,
    pub status: i32,
    pub input_tokens: Option<i64>,
    pub output_tokens: Option<i64>,
    pub cached_input_tokens: Option<i64>,
    pub cache_creation_input_tokens: Option<i64>,
    pub total_ms: Option<i32>,
    /// Time to first content, ms (0017; NULL = non-streaming / no content).
    pub ttft_ms: Option<i64>,
    pub cost_usd: Option<f64>,
    pub error: Option<String>,
    /// Who called (the gateway key label; None = loopback/in-process caller).
    pub caller_key: Option<String>,
    /// Which client the request's User-Agent named (None = no User-Agent or an
    /// in-process call; rows predating 0014).
    pub agent: Option<String>,
    /// The dispatch request id (`req_{n}`), correlating the row with its
    /// routing trace (0021; None for earlier rows).
    pub request_id: Option<String>,
    /// The serving account's label (LEFT JOIN on provider_key_id; None when the
    /// request had no key — e.g. a pre-candidate failure — or the key is gone).
    pub key_label: Option<String>,
}

/// The most recent requests, newest first. `before_id` paginates: only rows
/// with `id < before_id` are returned (id order == time order), None = first
/// page. A page smaller than `limit` means there is no older data.
pub async fn list_recent_requests(
    pool: &PgPool,
    limit: i64,
    before_id: Option<i64>,
) -> anyhow::Result<Vec<RequestRow>> {
    let rows = sqlx::query_as::<_, RequestRow>(
    "SELECT r.id, r.ts, r.protocol, r.client_protocol, r.effort, r.alias, r.provider_id, r.provider_key_id, r.model, r.served_model, r.status,
            r.input_tokens, r.output_tokens, r.cached_input_tokens, r.cache_creation_input_tokens, r.total_ms, r.ttft_ms, r.cost_usd::float8, r.error, r.caller_key, r.agent,
            r.request_id, k.label AS key_label
         FROM gateway_requests r
         LEFT JOIN gateway_provider_keys k ON k.id = r.provider_key_id
         WHERE ($1::bigint IS NULL OR r.id < $1)
         ORDER BY r.id DESC LIMIT $2",
  )
  .bind(before_id)
  .bind(limit)
  .fetch_all(pool)
  .await?;
    Ok(rows)
}
