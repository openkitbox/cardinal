use crate::store::user::OWNER_LOGIN;
use sqlx::PgPool;

// ---------- admin reads: usage / request log / cooldowns ----------
//
// Typed rows shared by the HTTP admin handlers (`admin.rs`) and the
// in-process admin facade (`admin_ops.rs`). The SQL lives here exactly once;
// the HTTP layer only maps rows onto its wire shapes.

/// Caller filter shared by the usage reads. `None` (no filter) = every
/// caller; `Null` = only unidentified rows (caller_key IS NULL: in-process
/// calls and history from before loopback access was closed); `Key` = one
/// gateway key, by id (labels are only unique per user, so a label cannot
/// name a key); `User` = every key one user owns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallerFilter {
    Null,
    Key(i64),
    User(i64),
}

/// SQL bind values of an optional [`CallerFilter`]: the kind (`NULL` = no
/// filter) and the id it compares against (a key id or a user id).
struct CallerBinds {
    kind: Option<&'static str>,
    id: Option<i64>,
}

impl From<Option<CallerFilter>> for CallerBinds {
    fn from(caller: Option<CallerFilter>) -> Self {
        let (kind, id) = match caller {
            None => (None, None),
            Some(CallerFilter::Null) => (Some("null"), None),
            Some(CallerFilter::Key(key_id)) => (Some("key"), Some(key_id)),
            Some(CallerFilter::User(user_id)) => (Some("user"), Some(user_id)),
        };
        Self { kind, id }
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
    caller: Option<CallerFilter>,
) -> anyhow::Result<Vec<UsageRow>> {
    let binds = CallerBinds::from(caller);
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
                OR ($2 = 'key' AND gateway_key_id = $3)
                OR ($2 = 'user' AND user_id = $3))
         GROUP BY day, alias
         ORDER BY day DESC, alias",
    )
    .bind(days)
    .bind(binds.kind)
    .bind(binds.id)
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
    /// Client identity: the UA's name (`agent`) wins, the gateway key falls
    /// back as `login/label` (labels are only unique per user; a one-user
    /// scope, and the built-in owner's keys, show the bare label). Rows with
    /// neither group as NULL (the GUI renders them as 本机).
    Client,
    /// User identity: the built-in owner's requests are split by caller key
    /// (bare label, one series per key, no agent override), while every real
    /// user's keys aggregate into one series per login (`users.login` joined
    /// on `user_id`). Rows with no owning user stay NULL; the GUI displays
    /// NULL as （未归属）.
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
    pub cached_input_tokens: i64,
    pub requests: i64,
    /// Attempts that ended in an error (same convention as [`UsageWindow`]).
    pub failed: i64,
    pub cost_usd: Option<f64>,
    /// Amount debited to users, micro-USD (sum of `charged_microus`; 0 when
    /// nothing was charged).
    pub charged_microus: i64,
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
    caller: Option<CallerFilter>,
) -> anyhow::Result<Vec<TrendRow>> {
    let bucket = if hourly_buckets(since, until) {
        "to_char(date_trunc('hour', r.ts AT TIME ZONE 'UTC' + $3), 'YYYY-MM-DD HH24:00')"
    } else {
        "to_char(date_trunc('day', r.ts AT TIME ZONE 'UTC' + $3), 'YYYY-MM-DD')"
    };
    // The fourth element is the extra bind an arm's SQL text needs: only the
    // client and user splits reference `$6`. It lives beside the text so the
    // placeholder and its bind cannot drift apart (a missing bind is a Bind-
    // time error, not a compile error).
    let (category, join, filter, owner_login) = match split {
        TrendSplit::Route => ("r.alias", "", "", None),
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
            None,
        ),
        TrendSplit::Provider => (
            "p.name",
            "LEFT JOIN gateway_providers p ON p.id = r.provider_id",
            "",
            None,
        ),
        // Labels are only unique per user, so the label fallback is
        // qualified with the owner's login (`alice/default`) unless the scope
        // is already one user ($4 = 'user'), where the bare label is unique.
        // The built-in owner's keys belong to no real user identity, so they
        // keep the bare label (`default`), as do historical rows with no
        // recorded user.
        TrendSplit::Client => (
            "COALESCE(r.agent,
                      CASE WHEN $4 IS DISTINCT FROM 'user'
                                AND u.login IS DISTINCT FROM $6
                           THEN u.login || '/' || r.caller_key END,
                      r.caller_key)",
            "LEFT JOIN users u ON u.id = r.user_id",
            "",
            Some(OWNER_LOGIN),
        ),
        // Owner rows split per key (bare label) so the owner is not a single
        // aggregate; a real user's keys merge into one login series, because
        // logins are unique, so grouping by the login is grouping by user_id.
        // No agent override here: the agent is client identity, not user
        // identity. Rows with no user stay NULL (GUI: （未归属）). A bare
        // owner key label equal to a real user's login shares that series.
        TrendSplit::User => (
            "CASE WHEN u.login = $6 THEN r.caller_key ELSE u.login END",
            "LEFT JOIN users u ON u.id = r.user_id",
            "",
            Some(OWNER_LOGIN),
        ),
    };
    let sql = format!(
    "SELECT {bucket} AS bucket, {category} AS category,
            COALESCE(SUM(r.input_tokens), 0)::bigint AS input_tokens,
            COALESCE(SUM(r.output_tokens), 0)::bigint AS output_tokens,
            COALESCE(SUM(r.cached_input_tokens), 0)::bigint AS cached_input_tokens,
            COUNT(*)::bigint AS requests,
            COUNT(*) FILTER (WHERE r.error IS NOT NULL)::bigint AS failed,
            SUM(r.cost_usd)::float8 AS cost_usd,
            COALESCE(SUM(r.charged_microus), 0)::bigint AS charged_microus,
            COALESCE(SUM(r.output_tokens) FILTER (WHERE r.error IS NULL), 0)::bigint AS timed_output,
            COALESCE(SUM(r.total_ms) FILTER (WHERE r.error IS NULL), 0)::bigint AS timed_ms,
            COALESCE(SUM(GREATEST(r.total_ms - COALESCE(r.ttft_ms, 0), 0)) FILTER (WHERE r.error IS NULL), 0)::bigint AS decode_ms
         FROM gateway_requests r {join}
         WHERE r.ts >= $1 AND r.ts < $2
           AND ($4::text IS NULL
                OR ($4 = 'null' AND r.caller_key IS NULL)
                OR ($4 = 'key' AND r.gateway_key_id = $5)
                OR ($4 = 'user' AND r.user_id = $5)){filter}
         GROUP BY 1, 2
         ORDER BY 1"
  );
    // Safe: the only interpolation is from the fixed
    // `bucket`/`category`/`join`/`filter` arms above; caller input goes through
    // bind parameters.
    let binds = CallerBinds::from(caller);
    let mut query = sqlx::query_as::<_, TrendRow>(sqlx::AssertSqlSafe(sql))
        .bind(since)
        .bind(until)
        .bind(local_offset)
        .bind(binds.kind)
        .bind(binds.id);
    // Only the client and user arms supply an extra bind, because only their
    // SQL text references `$6`; binding it for a statement without that
    // placeholder makes PostgreSQL reject the parameter at Bind time.
    if let Some(owner_login) = owner_login {
        query = query.bind(owner_login);
    }
    let rows = query.fetch_all(pool).await?;
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
    /// Amount debited to users, micro-USD (sum of `charged_microus`; 0 when
    /// nothing was charged).
    pub charged_microus: i64,
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
    caller: Option<CallerFilter>,
) -> anyhow::Result<UsageWindow> {
    let binds = CallerBinds::from(caller);
    let window = sqlx::query_as::<_, UsageWindow>(
    "SELECT COALESCE(SUM(input_tokens), 0)::bigint AS input_tokens,
            COALESCE(SUM(output_tokens), 0)::bigint AS output_tokens,
            COALESCE(SUM(cached_input_tokens), 0)::bigint AS cached_input_tokens,
            COUNT(*)::bigint AS requests,
            COUNT(*) FILTER (WHERE error IS NOT NULL)::bigint AS failed,
            SUM(cost_usd)::float8 AS cost_usd,
            COALESCE(SUM(charged_microus), 0)::bigint AS charged_microus,
            COUNT(*) FILTER (WHERE error IS NULL AND input_tokens IS NOT NULL AND cost_usd IS NULL)::bigint AS unpriced,
            COALESCE(SUM(output_tokens) FILTER (WHERE error IS NULL), 0)::bigint AS timed_output,
            COALESCE(SUM(total_ms) FILTER (WHERE error IS NULL), 0)::bigint AS timed_ms,
            COALESCE(SUM(GREATEST(total_ms - COALESCE(ttft_ms, 0), 0)) FILTER (WHERE error IS NULL), 0)::bigint AS decode_ms
         FROM gateway_requests
         WHERE ts >= $1 AND ts < $2
           AND ($3::text IS NULL
                OR ($3 = 'null' AND caller_key IS NULL)
                OR ($3 = 'key' AND gateway_key_id = $4)
                OR ($3 = 'user' AND user_id = $4))",
  )
  .bind(since)
  .bind(until)
  .bind(binds.kind)
  .bind(binds.id)
  .fetch_one(pool)
  .await?;
    Ok(window)
}
