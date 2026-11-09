use crate::protocol::ProtocolId;
use sqlx::PgPool;

/// The ledger time and dispatch request id of one request row — the anchor
/// for locating its captured bodies in the hourly payload files
/// (`body_log::BodyLog::get_near` keys captures by `req_<uuid>`, not row id:
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
    /// The caller's identity (the gateway key's label, kept for display and
    /// grouping); NULL for an in-process direct call.
    pub caller_key: Option<String>,
    /// The user owning the caller's gateway key (0013); NULL for an
    /// in-process direct call. Usage scoping and billing key on this.
    pub user_id: Option<i64>,
    /// The caller's gateway key id (0013); NULL for an in-process direct call.
    pub gateway_key_id: Option<i64>,
    /// Which client the request's User-Agent named; NULL
    /// when the request carried no User-Agent or was in-process.
    pub agent: Option<String>,
    /// The dispatch request id (`req_<uuid>`) — correlates the ledger row with
    /// its routing trace (the trace ring and the upstream header share it).
    /// NULL for attempts constructed before a request id exists.
    pub request_id: Option<String>,
    /// Amount to debit for this attempt, micro-USD (0014). Set only on a
    /// successful attempt of a caller with known or estimated usage; None =
    /// not charged (failed attempt, unknown usage, unpriced model or an
    /// in-process call). Estimated usage is derivable from `protocol = kiro`.
    pub charged_microus: Option<i64>,
    /// The caller's effective rate multiplier in basis points at request
    /// time (0014); None for an in-process direct call.
    pub rate_bp: Option<i64>,
}

/// One round trip for the whole batch: 24 parallel arrays, one per column,
/// unzipped by a multi-array `UNNEST` and written in `ordinality` order, so the
/// returned ids follow `attempts`. The column order appears three times (the
/// INSERT target, the SELECT list and the UNNEST alias) and the bind order must
/// match it: a positional `UNNEST` misaligns silently when they disagree.
const REQUEST_LOG_INSERT_SQL: &str = "
INSERT INTO gateway_requests (protocol, client_protocol, effort, alias, provider_id, provider_key_id,
        model, served_model, status, input_tokens, output_tokens, cached_input_tokens,
        cache_creation_input_tokens, total_ms, ttft_ms, cost_usd, error, caller_key, agent, request_id,
        user_id, gateway_key_id, charged_microus, rate_bp)
SELECT protocol, client_protocol, effort, alias, provider_id, provider_key_id,
        model, served_model, status, input_tokens, output_tokens, cached_input_tokens,
        cache_creation_input_tokens, total_ms, ttft_ms, cost_usd, error, caller_key, agent, request_id,
        user_id, gateway_key_id, charged_microus, rate_bp
FROM UNNEST($1::text[], $2::text[], $3::text[], $4::text[],
        $5::bigint[], $6::bigint[], $7::text[], $8::text[], $9::integer[], $10::bigint[],
        $11::bigint[], $12::bigint[], $13::bigint[], $14::integer[], $15::bigint[], $16::float8[],
        $17::text[], $18::text[], $19::text[], $20::text[], $21::bigint[], $22::bigint[],
        $23::bigint[], $24::bigint[])
    WITH ORDINALITY AS batch(protocol, client_protocol, effort, alias, provider_id, provider_key_id,
        model, served_model, status, input_tokens, output_tokens, cached_input_tokens,
        cache_creation_input_tokens, total_ms, ttft_ms, cost_usd, error, caller_key, agent, request_id,
        user_id, gateway_key_id, charged_microus, rate_bp, ordinality)
ORDER BY ordinality
RETURNING id";

#[derive(Debug, PartialEq, Eq)]
enum BatchFailureStage {
    Fetch,
    Commit,
}

#[derive(Debug, PartialEq, Eq)]
enum BatchFailure {
    SafeToFallback,
    Ambiguous,
}

fn classify_batch_failure(stage: BatchFailureStage, rollback_succeeded: bool) -> BatchFailure {
    match (stage, rollback_succeeded) {
        (BatchFailureStage::Fetch, true) => BatchFailure::SafeToFallback,
        (BatchFailureStage::Fetch, false) | (BatchFailureStage::Commit, _) => {
            BatchFailure::Ambiguous
        }
    }
}

struct BatchInsertError {
    error: sqlx::Error,
    fallback_allowed: bool,
}

/// Persist attempt rows to `gateway_requests` in one statement, returning the
/// inserted row ids in attempt order. Called by the ledger writer
/// (`relay::ledger_writer`) in batches, not per request, so the round trip is
/// amortized over the batch. Logging failures are logged, never propagated:
/// accounting must not break the request path. A failed batch is retried one
/// row at a time only after its transaction was successfully rolled back.
pub async fn insert_request_logs(pool: &PgPool, attempts: &[AttemptLog]) -> Vec<i64> {
    if attempts.is_empty() {
        return Vec::new();
    }
    match insert_batch(pool, attempts).await {
        Ok(ids) => ids,
        Err(batch_error) if batch_error.fallback_allowed => {
            tracing::error!(
                rows = attempts.len(),
                error = %batch_error.error,
                "failed to persist request log batch after rollback; retrying its rows one at a time"
            );
            let mut ids = Vec::with_capacity(attempts.len());
            for attempt in attempts {
                match insert_batch(pool, std::slice::from_ref(attempt)).await {
                    Ok(row_ids) => ids.extend(row_ids),
                    Err(error) => {
                        tracing::error!("failed to persist requests row: {}", error.error)
                    }
                }
            }
            ids
        }
        Err(batch_error) => {
            tracing::error!(
                rows = attempts.len(),
                error = %batch_error.error,
                "request log batch outcome is ambiguous; refusing row fallback"
            );
            Vec::new()
        }
    }
}

/// Insert one batch in an explicit transaction and return its new ids in
/// attempt order. A query failure is safe to retry only when rollback succeeds;
/// a failed commit is always ambiguous because the server may have committed.
async fn insert_batch(
    pool: &PgPool,
    attempts: &[AttemptLog],
) -> Result<Vec<i64>, BatchInsertError> {
    let mut transaction = pool.begin().await.map_err(|error| BatchInsertError {
        error,
        fallback_allowed: false,
    })?;
    let query = sqlx::query_scalar::<_, i64>(REQUEST_LOG_INSERT_SQL)
        .bind(column(attempts, |a| a.protocol.as_str()))
        .bind(column(attempts, |a| a.client_protocol.map(|p| p.as_str())))
        .bind(column(attempts, |a| a.effort.as_deref()))
        .bind(column(attempts, |a| a.alias.as_deref()))
        .bind(column(attempts, |a| a.provider_id))
        .bind(column(attempts, |a| a.provider_key_id))
        .bind(column(attempts, |a| a.model.as_str()))
        .bind(column(attempts, |a| a.served_model.as_deref()))
        .bind(column(attempts, |a| i32::from(a.status)))
        .bind(column(attempts, |a| a.input_tokens))
        .bind(column(attempts, |a| a.output_tokens))
        .bind(column(attempts, |a| a.cached_input_tokens))
        .bind(column(attempts, |a| a.cache_creation_input_tokens))
        .bind(column(attempts, |a| a.total_ms))
        .bind(column(attempts, |a| a.ttft_ms))
        .bind(column(attempts, |a| a.cost_usd))
        .bind(column(attempts, |a| a.error.as_deref()))
        .bind(column(attempts, |a| a.caller_key.as_deref()))
        .bind(column(attempts, |a| a.agent.as_deref()))
        .bind(column(attempts, |a| a.request_id.as_deref()))
        .bind(column(attempts, |a| a.user_id))
        .bind(column(attempts, |a| a.gateway_key_id))
        .bind(column(attempts, |a| a.charged_microus))
        .bind(column(attempts, |a| a.rate_bp));
    let ids = match query.fetch_all(&mut *transaction).await {
        Ok(ids) => ids,
        Err(error) => {
            let rollback_succeeded = match transaction.rollback().await {
                Ok(()) => true,
                Err(rollback_error) => {
                    tracing::error!(
                        error = %rollback_error,
                        "failed to roll back ambiguous request log batch"
                    );
                    false
                }
            };
            return Err(BatchInsertError {
                error,
                fallback_allowed: classify_batch_failure(
                    BatchFailureStage::Fetch,
                    rollback_succeeded,
                ) == BatchFailure::SafeToFallback,
            });
        }
    };
    transaction
        .commit()
        .await
        .map_err(|error| BatchInsertError {
            error,
            fallback_allowed: classify_batch_failure(BatchFailureStage::Commit, true)
                == BatchFailure::SafeToFallback,
        })?;
    Ok(ids)
}

/// One bind array per column. Strings are borrowed from `attempts`; only the
/// pointers and the copyable scalar fields are collected.
fn column<'a, T>(attempts: &'a [AttemptLog], map: impl Fn(&'a AttemptLog) -> T) -> Vec<T> {
    attempts.iter().map(map).collect()
}

#[cfg(test)]
mod tests {
    use super::{BatchFailure, BatchFailureStage, REQUEST_LOG_INSERT_SQL, classify_batch_failure};

    #[test]
    fn only_a_successful_rollback_allows_row_fallback() {
        assert_eq!(
            classify_batch_failure(BatchFailureStage::Fetch, true),
            BatchFailure::SafeToFallback
        );
        assert_eq!(
            classify_batch_failure(BatchFailureStage::Fetch, false),
            BatchFailure::Ambiguous
        );
        assert_eq!(
            classify_batch_failure(BatchFailureStage::Commit, true),
            BatchFailure::Ambiguous
        );
    }

    const COLUMNS: &str = "protocol, client_protocol, effort, alias, provider_id, provider_key_id, model, served_model, status, input_tokens, output_tokens, cached_input_tokens, cache_creation_input_tokens, total_ms, ttft_ms, cost_usd, error, caller_key, agent, request_id, user_id, gateway_key_id, charged_microus, rate_bp";

    /// The statement names the column order three times (INSERT target, SELECT
    /// list, UNNEST alias) and a multi-array UNNEST pairs its arrays by
    /// position, so a column added to one list alone would write every value of
    /// the batch into the wrong field.
    #[test]
    fn batch_statement_names_the_same_columns_in_every_list() {
        let sql: String = REQUEST_LOG_INSERT_SQL
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        assert_eq!(sql.matches(COLUMNS).count(), 3, "columns: {COLUMNS}");
        assert_eq!(
            sql.matches('$').count(),
            24,
            "one placeholder per column, in column order: {sql}"
        );
    }
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
    /// Who called (the gateway key label; None = in-process caller or a row
    /// from before loopback access was closed).
    pub caller_key: Option<String>,
    /// Which client the request's User-Agent named (None = no User-Agent or an
    /// in-process call; rows predating 0014).
    pub agent: Option<String>,
    /// The dispatch request id (`req_<uuid>`), correlating the row with its
    /// routing trace (0021; None for earlier rows).
    pub request_id: Option<String>,
    /// The serving account's label (LEFT JOIN on provider_key_id; None when the
    /// request had no key — e.g. a pre-candidate failure — or the key is gone).
    pub key_label: Option<String>,
    /// The user owning the caller's gateway key (0013; None = in-process call
    /// or an unattributed historical row).
    pub user_id: Option<i64>,
    /// That user's login (LEFT JOIN on user_id; None when `user_id` is None).
    pub login: Option<String>,
    /// The caller's gateway key id (0013; None as for `user_id`).
    pub gateway_key_id: Option<i64>,
    /// Amount debited for this attempt, micro-USD (0014; None = not charged).
    pub charged_microus: Option<i64>,
    /// The caller's effective rate at request time, basis points (0014; None
    /// = in-process call or a row predating billing).
    pub rate_bp: Option<i64>,
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
            r.request_id, k.label AS key_label, r.user_id, u.login, r.gateway_key_id, r.charged_microus, r.rate_bp
         FROM gateway_requests r
         LEFT JOIN gateway_provider_keys k ON k.id = r.provider_key_id
         LEFT JOIN users u ON u.id = r.user_id
         WHERE ($1::bigint IS NULL OR r.id < $1)
         ORDER BY r.id DESC LIMIT $2",
  )
  .bind(before_id)
  .bind(limit)
  .fetch_all(pool)
  .await?;
    Ok(rows)
}
