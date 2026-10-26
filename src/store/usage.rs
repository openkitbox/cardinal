use sqlx::PgPool;

// ---------- admin reads: usage / request log / cooldowns ----------
//
// Typed rows shared by the HTTP admin handlers (`admin.rs`) and the
// in-process admin facade (`admin_ops.rs`). The SQL lives here exactly once;
// the HTTP layer only maps rows onto its wire shapes.

/// Caller filter shared by the usage admin reads (`caller` query parameter).
/// `None` = every caller; `Null` = only unidentified callers (caller_key IS
/// NULL, the 本机/in-process rows); `Label` = one gateway key label or a
/// self-named `cardinal-x` caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CallerFilter {
    Null,
    Label,
}

impl CallerFilter {
    /// Wire spelling of the filter kind (the `caller` query parameter's kind
    /// half); `as_str` keeps the SQL bind in lockstep with serde's names.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Null => "null",
            Self::Label => "label",
        }
    }
}

/// One day × alias usage aggregate over `gateway_requests`.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, sqlx::FromRow)]
pub struct UsageRow {
    /// UTC day, `YYYY-MM-DD`.
    pub day: String,
    pub alias: Option<String>,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub cached_input_tokens: i64,
    pub requests: i64,
    pub cost_usd: Option<f64>,
}

/// Usage aggregated by day × alias over the last `days` days (newest day first).
pub async fn usage_by_day(
    pool: &PgPool,
    days: i32,
    caller: Option<(CallerFilter, &str)>,
) -> anyhow::Result<Vec<UsageRow>> {
    let rows = sqlx::query_as::<_, UsageRow>(
        "SELECT to_char((ts AT TIME ZONE 'UTC')::date, 'YYYY-MM-DD') AS day, alias,
            COALESCE(SUM(input_tokens), 0)::bigint AS input_tokens,
            COALESCE(SUM(output_tokens), 0)::bigint AS output_tokens,
            COALESCE(SUM(cached_input_tokens), 0)::bigint AS cached_input_tokens,
            COUNT(*)::bigint AS requests,
            SUM(cost_usd)::float8 AS cost_usd
         FROM gateway_requests
         WHERE ts > now() - make_interval(days => $1)
           AND ($2::text IS NULL
                OR ($2 = 'null' AND caller_key IS NULL)
                OR ($2 = 'label' AND caller_key = $3))
         GROUP BY day, alias
         ORDER BY day DESC, alias",
    )
    .bind(days)
    .bind(caller.map(|(kind, _)| kind.as_str()))
    .bind(caller.map(|(_, label)| label))
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Category dimension of the usage trend chart (the GUI's 拆分维度 switch).
/// The serde names are the wire spelling of the `/api/usage/trend` `split`
/// query parameter.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrendSplit {
    /// Route alias (NULL = a direct `provider/model` call).
    Route,
    /// Upstream-served model id (`served_model`): lowercased so case variants
    /// dedupe, and with a leading vendor namespace stripped (`deepseek/x` → `x`)
    /// so one model under several namespaces is a single category.
    Model,
    /// Provider name (joined from `gateway_providers`).
    Provider,
    /// Client identity: the UA's name (`agent`) wins, the gateway key's
    /// self-name (`cardinal-x` → `x`, else its stored label) falls back — the
    /// same display rule as the requests page (`named_client`). Rows with
    /// neither group as NULL (the GUI renders them as 本机).
    Client,
    /// Caller identity recorded in `caller_key`: authenticated requests use the
    /// gateway key label; loopback requests may use a self-named value or agent;
    /// unrecognized callers are NULL. The GUI displays NULL as 本机.
    User,
}

/// One bucket × category aggregate behind the usage trend chart.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, sqlx::FromRow)]
pub struct TrendRow {
    /// Bucket label in the caller's local wall clock (the GUI passes its
    /// offset; the SQL shifts by it): `YYYY-MM-DD`, or `YYYY-MM-DD HH24:00`
    /// for a sub-day window (hourly buckets).
    pub bucket: String,
    /// Category value; NULL alias/model/provider falls back in the GUI.
    pub category: Option<String>,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub requests: i64,
    /// Attempts that ended in an error (same convention as [`UsageWindow`]).
    pub failed: i64,
    pub cost_usd: Option<f64>,
    /// Output tokens over successful rows — the per-category speed numerator.
    pub timed_output: i64,
    /// Summed wall time of successful rows — the duration card's denominator.
    pub timed_ms: i64,
    /// Decode-window milliseconds over successful rows (total_ms - ttft_ms)
    /// — the per-category speed denominator.
    pub decode_ms: i64,
}

/// A window buckets hourly up to this span, else daily (a local calendar day
/// is 23–25 hours under DST, so a day still reads as hours). Shared by
/// [`usage_trend`]'s SQL and the GUI's bucket grid so the two always agree.
pub fn hourly_buckets(
    since: chrono::DateTime<chrono::Utc>,
    until: chrono::DateTime<chrono::Utc>,
) -> bool {
    until - since <= chrono::Duration::hours(25)
}

/// Usage aggregated by bucket × category for the trend chart over the
/// half-open window `[since, until)`. The bucket and category expressions
/// come from fixed enum arms — no caller input reaches the SQL text. Bucket
/// labels are wall-clock-shifted by `local_offset` (`AT TIME ZONE 'UTC'`
/// drops to the naive UTC reading, the interval shift moves it to local wall
/// clock); the GUI's bucket grid shifts by the same offset, so labels match.
pub async fn usage_trend(
    pool: &PgPool,
    since: chrono::DateTime<chrono::Utc>,
    until: chrono::DateTime<chrono::Utc>,
    split: TrendSplit,
    local_offset: chrono::Duration,
    caller: Option<(CallerFilter, &str)>,
) -> anyhow::Result<Vec<TrendRow>> {
    let bucket = if hourly_buckets(since, until) {
        "to_char(date_trunc('hour', r.ts AT TIME ZONE 'UTC' + $3), 'YYYY-MM-DD HH24:00')"
    } else {
        "to_char(date_trunc('day', r.ts AT TIME ZONE 'UTC' + $3), 'YYYY-MM-DD')"
    };
    let (category, join, filter) = match split {
        TrendSplit::Route => ("r.alias", "", ""),
        // Rows without a served model (rejected/failed attempts) are excluded
        // from the model split entirely — no "unknown" bucket. A leading
        // `namespace/` is a vendor namespace, not part of the model's identity
        // (`deepseek/deepseek-v4.1-flash` is the model `deepseek-v4.1-flash`), so
        // it is stripped before grouping: one series per model, its namespaces
        // merged. A slash-free id passes through untouched.
        TrendSplit::Model => (
            "LOWER(regexp_replace(r.served_model, '^[^/]+/', ''))",
            "",
            " AND r.served_model IS NOT NULL",
        ),
        TrendSplit::Provider => (
            "p.name",
            "LEFT JOIN gateway_providers p ON p.id = r.provider_id",
            "",
        ),
        // `LIKE 'cardinal-_%'` demands at least one character after the prefix, so
        // a bare `cardinal-` (empty self-name) falls back to the raw value — the
        // same rule as the GUI's `client_of`.
        TrendSplit::Client => (
            "COALESCE(r.agent, CASE WHEN r.caller_key LIKE 'cardinal-_%' THEN substring(r.caller_key from 10) ELSE r.caller_key END)",
            "",
            "",
        ),
        TrendSplit::User => ("r.caller_key", "", ""),
    };
    let sql = format!(
    "SELECT {bucket} AS bucket, {category} AS category,
            COALESCE(SUM(r.input_tokens), 0)::bigint AS input_tokens,
            COALESCE(SUM(r.output_tokens), 0)::bigint AS output_tokens,
            COUNT(*)::bigint AS requests,
            COUNT(*) FILTER (WHERE r.error IS NOT NULL)::bigint AS failed,
            SUM(r.cost_usd)::float8 AS cost_usd,
            COALESCE(SUM(r.output_tokens) FILTER (WHERE r.error IS NULL), 0)::bigint AS timed_output,
            COALESCE(SUM(r.total_ms) FILTER (WHERE r.error IS NULL), 0)::bigint AS timed_ms,
            COALESCE(SUM(GREATEST(r.total_ms - COALESCE(r.ttft_ms, 0), 0)) FILTER (WHERE r.error IS NULL), 0)::bigint AS decode_ms
         FROM gateway_requests r {join}
         WHERE r.ts >= $1 AND r.ts < $2
           AND ($4::text IS NULL
                OR ($4 = 'null' AND r.caller_key IS NULL)
                OR ($4 = 'label' AND r.caller_key = $5)){filter}
         GROUP BY 1, 2
         ORDER BY 1"
  );
    // Safe: the only interpolation is from the fixed
    // `bucket`/`category`/`join`/`filter` arms above; caller input goes through
    // bind parameters.
    let rows = sqlx::query_as::<_, TrendRow>(sqlx::AssertSqlSafe(sql))
        .bind(since)
        .bind(until)
        .bind(local_offset)
        .bind(caller.map(|(kind, _)| kind.as_str()))
        .bind(caller.map(|(_, label)| label))
        .fetch_all(pool)
        .await?;
    Ok(rows)
}

/// Whole-window usage aggregates behind the KPI cards (one row; the daily ×
/// alias split stays with [`UsageRow`]). `cached_input_tokens` is already
/// contained in `input_tokens` (crate::protocol::usage contract) — never add it
/// to a total again.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize, sqlx::FromRow)]
pub struct UsageWindow {
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub cached_input_tokens: i64,
    pub requests: i64,
    /// Attempts that ended in an error (the ledger's unit is the attempt).
    pub failed: i64,
    /// Sum over priced rows; None when no row was priced.
    pub cost_usd: Option<f64>,
    /// Successful rows with usage but no known price (not counted in cost).
    pub unpriced: i64,
    /// Output tokens over successful rows — the speed card's numerator.
    pub timed_output: i64,
    /// Total milliseconds over successful rows — the duration card's denominator.
    pub timed_ms: i64,
    /// Decode-window milliseconds over successful rows (total_ms - ttft_ms)
    /// — the speed card's denominator.
    pub decode_ms: i64,
}

/// Aggregate the whole window into one row for the KPI cards.
pub async fn usage_window(
    pool: &PgPool,
    since: chrono::DateTime<chrono::Utc>,
    until: chrono::DateTime<chrono::Utc>,
    caller: Option<(CallerFilter, &str)>,
) -> anyhow::Result<UsageWindow> {
    let window = sqlx::query_as::<_, UsageWindow>(
    "SELECT COALESCE(SUM(input_tokens), 0)::bigint AS input_tokens,
            COALESCE(SUM(output_tokens), 0)::bigint AS output_tokens,
            COALESCE(SUM(cached_input_tokens), 0)::bigint AS cached_input_tokens,
            COUNT(*)::bigint AS requests,
            COUNT(*) FILTER (WHERE error IS NOT NULL)::bigint AS failed,
            SUM(cost_usd)::float8 AS cost_usd,
            COUNT(*) FILTER (WHERE error IS NULL AND input_tokens IS NOT NULL AND cost_usd IS NULL)::bigint AS unpriced,
            COALESCE(SUM(output_tokens) FILTER (WHERE error IS NULL), 0)::bigint AS timed_output,
            COALESCE(SUM(total_ms) FILTER (WHERE error IS NULL), 0)::bigint AS timed_ms,
            COALESCE(SUM(GREATEST(total_ms - COALESCE(ttft_ms, 0), 0)) FILTER (WHERE error IS NULL), 0)::bigint AS decode_ms
         FROM gateway_requests
         WHERE ts >= $1 AND ts < $2
           AND ($3::text IS NULL
                OR ($3 = 'null' AND caller_key IS NULL)
                OR ($3 = 'label' AND caller_key = $4))",
  )
  .bind(since)
  .bind(until)
  .bind(caller.map(|(kind, _)| kind.as_str()))
  .bind(caller.map(|(_, label)| label))
  .fetch_one(pool)
  .await?;
    Ok(window)
}
