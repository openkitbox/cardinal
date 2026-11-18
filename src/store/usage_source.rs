use chrono::{DateTime, Duration, Utc};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SourcePlan {
    Raw,
    Split {
        raw_left: bool,
        cagg: bool,
        raw_right: bool,
    },
}

pub(crate) fn source_plan(
    since: DateTime<Utc>,
    until: DateTime<Utc>,
) -> (SourcePlan, DateTime<Utc>, DateTime<Utc>) {
    let left_end = ceil_hour(since);
    let right_start = floor_hour(until);
    if since >= until || left_end >= right_start {
        return (SourcePlan::Raw, since, until);
    }

    (
        SourcePlan::Split {
            raw_left: since < left_end,
            cagg: true,
            raw_right: right_start < until,
        },
        left_end,
        right_start,
    )
}

pub(crate) fn can_use_cagg_trend(local_offset: Duration) -> bool {
    local_offset.num_seconds().rem_euclid(3_600) == 0
}

fn floor_hour(timestamp: DateTime<Utc>) -> DateTime<Utc> {
    let seconds = timestamp.timestamp().div_euclid(3_600) * 3_600;
    DateTime::from_timestamp(seconds, 0).expect("UTC timestamp remains representable")
}

fn ceil_hour(timestamp: DateTime<Utc>) -> DateTime<Utc> {
    let floor = floor_hour(timestamp);
    if timestamp == floor {
        floor
    } else {
        floor + Duration::hours(1)
    }
}

const RAW_METRICS: &str = "COUNT(*) AS requests,
       COUNT(*) FILTER (WHERE {alias}.error IS NOT NULL) AS failed,
       SUM({alias}.input_tokens) AS input_tokens,
       SUM({alias}.output_tokens) AS output_tokens,
       SUM({alias}.cached_input_tokens) AS cached_input_tokens,
       SUM({alias}.charged_microus) AS charged_microus,
       SUM({alias}.cost_usd) AS cost_usd,
       COUNT(*) FILTER (WHERE {alias}.error IS NULL
                          AND {alias}.input_tokens IS NOT NULL
                          AND {alias}.cost_usd IS NULL) AS unpriced,
       SUM({alias}.output_tokens) FILTER (WHERE {alias}.error IS NULL) AS timed_output,
       SUM({alias}.total_ms) FILTER (WHERE {alias}.error IS NULL) AS timed_ms,
       SUM(GREATEST({alias}.total_ms - COALESCE({alias}.ttft_ms, 0), 0))
           FILTER (WHERE {alias}.error IS NULL) AS decode_ms";

const CAGG_METRICS: &str = "h.requests, h.failed, h.input_tokens, h.output_tokens,
       h.cached_input_tokens, h.charged_microus, h.cost_usd, h.unpriced,
       h.timed_output, h.timed_ms, h.decode_ms";

fn raw_source(predicate: &str, kind: &str, id: &str) -> String {
    format!(
        "SELECT date_trunc('hour', r.ts AT TIME ZONE 'UTC') AT TIME ZONE 'UTC' AS hour,
       r.alias, r.served_model, r.provider_id, r.caller_key, r.gateway_key_id, r.user_id, r.agent,
       {metrics}
  FROM gateway_requests r
 WHERE {predicate}
   AND ({kind}::text IS NULL
        OR ({kind} = 'null' AND r.caller_key IS NULL)
        OR ({kind} = 'key' AND r.gateway_key_id = {id})
        OR ({kind} = 'user' AND r.user_id = {id}))
 GROUP BY 1, 2, 3, 4, 5, 6, 7, 8",
        metrics = RAW_METRICS.replace("{alias}", "r"),
    )
}

fn cagg_source(predicate: &str, kind: &str, id: &str) -> String {
    format!(
        "SELECT h.hour, h.alias, h.served_model, h.provider_id, h.caller_key,
       h.gateway_key_id, h.user_id, h.agent,
       {metrics}
  FROM gateway_usage_hourly h
 WHERE {predicate}
   AND ({kind}::text IS NULL
        OR ({kind} = 'null' AND h.caller_key IS NULL)
        OR ({kind} = 'key' AND h.gateway_key_id = {id})
        OR ({kind} = 'user' AND h.user_id = {id}))",
        metrics = CAGG_METRICS,
    )
}

fn source_with_params(plan: SourcePlan, kind: &str, id: &str, left: &str, right: &str) -> String {
    match plan {
        SourcePlan::Raw => raw_source("r.ts >= $1 AND r.ts < $2", kind, id),
        SourcePlan::Split {
            raw_left,
            cagg,
            raw_right,
        } => {
            let mut branches = Vec::with_capacity(3);
            if raw_left {
                branches.push(raw_source(
                    &format!("r.ts >= $1 AND r.ts < {left}"),
                    kind,
                    id,
                ));
            }
            if cagg {
                branches.push(cagg_source(
                    &format!("h.hour >= {left} AND h.hour < {right}"),
                    kind,
                    id,
                ));
            }
            if raw_right {
                branches.push(raw_source(
                    &format!("r.ts >= {right} AND r.ts < $2"),
                    kind,
                    id,
                ));
            }
            branches.join("\nUNION ALL\n")
        }
    }
}

pub(crate) fn trend_source(plan: SourcePlan) -> String {
    source_with_params(plan, "$4", "$5", "$6", "$7")
}

pub(crate) fn window_source(plan: SourcePlan) -> String {
    source_with_params(plan, "$3", "$4", "$5", "$6")
}

/// Build the daily source with the legacy strict lower boundary. Keeping this
/// predicate in one named helper makes the aligned and non-aligned cases use
/// the same `>` semantics. `first_cagg_hour` is deliberately the next hour
/// after an hour-aligned `since`: the first raw hour must remain raw so a
/// CAGG bucket cannot accidentally include a row exactly at the strict bound.
pub(crate) fn daily_source() -> String {
    let raw_full = raw_source(
        "NOT b.can_split AND r.ts > b.since AND r.ts < b.until",
        "$2",
        "$3",
    )
    .replace(
        "FROM gateway_requests r",
        "FROM gateway_requests r CROSS JOIN bounds b",
    );
    let raw_left = raw_source(daily_raw_left_predicate(), "$2", "$3").replace(
        "FROM gateway_requests r",
        "FROM gateway_requests r CROSS JOIN bounds b",
    );
    let cagg = cagg_source(
        "b.can_split AND h.hour >= b.first_cagg_hour AND h.hour < b.right_start",
        "$2",
        "$3",
    )
    .replace(
        "FROM gateway_usage_hourly h",
        "FROM gateway_usage_hourly h CROSS JOIN bounds b",
    );
    let raw_right = raw_source(
        "b.can_split AND r.ts >= b.right_start AND r.ts < b.until",
        "$2",
        "$3",
    )
    .replace(
        "FROM gateway_requests r",
        "FROM gateway_requests r CROSS JOIN bounds b",
    );

    format!(
        "WITH bounds AS (
    SELECT now() - make_interval(days => $1) AS since,
           now() AS until,
           date_trunc('hour', now() - make_interval(days => $1)) + INTERVAL '1 hour' AS first_cagg_hour,
           date_trunc('hour', now()) AS right_start,
            date_trunc('hour', now() - make_interval(days => $1)) + INTERVAL '1 hour'
                < date_trunc('hour', now()) AS can_split
), source AS (
{raw_full}
UNION ALL
{raw_left}
UNION ALL
{cagg}
UNION ALL
{raw_right}
)"
    )
}

fn daily_raw_left_predicate() -> &'static str {
    "b.can_split AND r.ts > b.since AND r.ts < b.first_cagg_hour"
}
