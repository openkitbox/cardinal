#!/usr/bin/env bash
set -Eeuo pipefail

readonly CAGG='public.gateway_usage_hourly'
readonly REFRESH_STATEMENT_TIMEOUT='30min'
readonly MAX_CHUNK='24 hours'
readonly SERVICE_NAME='cardinal_usage_backfill'

service_file=''
cleanup() {
  if [[ -n "$service_file" ]]; then
    rm -f -- "$service_file"
  fi
}
trap cleanup EXIT

fail() {
  printf 'timescale usage backfill: %s\n' "$1" >&2
  exit 1
}

require_dsn() {
  local dsn=${TS_USAGE_DSN-}
  [[ -n "$dsn" ]] || fail 'TS_USAGE_DSN must be non-empty'
  [[ "$dsn" != *[[:space:][:cntrl:]]* ]] || \
    fail 'TS_USAGE_DSN contains whitespace or control characters'
}

validate_rfc3339() {
  local name=$1
  local value=$2
  [[ "$value" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?(Z|[+-][0-9]{2}:[0-9]{2})$ ]] || \
    fail "$name must be RFC3339 (for example, 2026-11-18T00:00:00Z)"
}

create_service_file() {
  local dsn=${TS_USAGE_DSN-}
  service_file=$(mktemp "${TMPDIR:-/tmp}/cardinal-timescale.XXXXXX") || \
    fail 'could not create a temporary libpq service file'
  chmod 600 "$service_file" || fail 'could not protect the temporary libpq service file'
  TS_USAGE_DSN_VALUE="$dsn" TS_USAGE_SERVICE_FILE="$service_file" python3 - <<'PY'
import os
import sys
from urllib.parse import unquote, urlsplit

path = os.environ['TS_USAGE_SERVICE_FILE']
dsn = os.environ['TS_USAGE_DSN_VALUE']
try:
    parsed = urlsplit(dsn)
    port = parsed.port
except ValueError:
    print('timescale usage backfill: unsupported TS_USAGE_DSN URI', file=sys.stderr)
    sys.exit(1)

if parsed.scheme.lower() not in {'postgres', 'postgresql'}:
    print('timescale usage backfill: TS_USAGE_DSN must use postgres:// or postgresql://', file=sys.stderr)
    sys.exit(1)
if parsed.hostname is None or parsed.path in {'', '/'}:
    print('timescale usage backfill: TS_USAGE_DSN must include a host and database', file=sys.stderr)
    sys.exit(1)
if parsed.query or parsed.fragment:
    print('timescale usage backfill: URI query parameters and fragments are unsupported', file=sys.stderr)
    sys.exit(1)

values = {
    'host': parsed.hostname,
    'dbname': unquote(parsed.path[1:]),
}
if port is not None:
    values['port'] = str(port)
if parsed.username is not None:
    values['user'] = unquote(parsed.username)
if parsed.password is not None:
    values['password'] = unquote(parsed.password)

for key, value in values.items():
    if not value or any(character.isspace() or ord(character) < 32 or ord(character) == 127
                         or character == '\\' for character in value):
        print(f'timescale usage backfill: unsupported value in TS_USAGE_DSN {key}', file=sys.stderr)
        sys.exit(1)

with open(path, 'w', encoding='utf-8') as service:
    service.write('[cardinal_usage_backfill]\n')
    for key, value in values.items():
        service.write(f'{key}={value}\n')
PY
  export PGSERVICEFILE="$service_file"
  export PGSERVICE="$SERVICE_NAME"
  unset TS_USAGE_DSN
}

psql_run() {
  psql -X -v ON_ERROR_STOP=1 "$@"
}

psql_scalar() {
  psql -X -v ON_ERROR_STOP=1 -Atq "$@"
}

require_dsn

if [[ -n ${TS_USAGE_START-} ]]; then
  validate_rfc3339 TS_USAGE_START "$TS_USAGE_START"
fi
if [[ -n ${TS_USAGE_END-} ]]; then
  validate_rfc3339 TS_USAGE_END "$TS_USAGE_END"
fi

create_service_file

preflight_sql=$(cat <<'SQL'
DO $preflight$
DECLARE
  extension_version text;
  extension_major integer;
  extension_minor integer;
  request_owner text;
  hypertable_count integer;
  cagg_count integer;
  cagg_materialized_only boolean;
BEGIN
  SELECT extversion
    INTO extension_version
    FROM pg_extension
   WHERE extname = 'timescaledb';

  IF extension_version IS NULL THEN
    RAISE EXCEPTION 'TimescaleDB extension is not installed';
  END IF;
  IF extension_version !~ '^[0-9]+\.[0-9]+' THEN
    RAISE EXCEPTION 'TimescaleDB version is not parseable: %', extension_version;
  END IF;

  extension_major := split_part(extension_version, '.', 1)::integer;
  extension_minor := split_part(extension_version, '.', 2)::integer;
  IF extension_major < 2
     OR (extension_major = 2 AND extension_minor < 31) THEN
    RAISE EXCEPTION 'TimescaleDB >= 2.31.0 is required (found %)', extension_version;
  END IF;

  SELECT pg_get_userbyid(c.relowner)
    INTO request_owner
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
   WHERE n.nspname = 'public'
     AND c.relname = 'gateway_requests';
  IF request_owner IS NULL THEN
    RAISE EXCEPTION 'table public.gateway_requests does not exist';
  END IF;
  IF request_owner <> current_user THEN
    RAISE EXCEPTION 'current_user % does not own public.gateway_requests (owner is %)',
      current_user, request_owner;
  END IF;

  SELECT count(*)
    INTO hypertable_count
    FROM timescaledb_information.hypertables
   WHERE hypertable_schema = 'public'
     AND hypertable_name = 'gateway_requests';
  IF hypertable_count <> 1 THEN
    RAISE EXCEPTION 'hypertable public.gateway_requests is missing';
  END IF;

  SELECT count(*), bool_and(NOT materialized_only)
    INTO cagg_count, cagg_materialized_only
    FROM timescaledb_information.continuous_aggregates
   WHERE view_schema = 'public'
     AND view_name = 'gateway_usage_hourly';
  IF cagg_count <> 1 THEN
    RAISE EXCEPTION 'continuous aggregate % is missing', 'public.gateway_usage_hourly';
  END IF;
  IF cagg_materialized_only IS DISTINCT FROM TRUE THEN
    RAISE EXCEPTION 'continuous aggregate % must have materialized_only=false',
      'public.gateway_usage_hourly';
  END IF;
END
$preflight$;
SQL
)
psql_run -c "$preflight_sql"

if [[ -n ${TS_USAGE_START-} ]]; then
  refresh_start=$(psql_scalar -v requested_start="$TS_USAGE_START" <<'SQL'
SELECT :'requested_start'::timestamptz;
SQL
  )
else
  refresh_start=$(psql_scalar -c \
    "SELECT date_trunc('hour', min(ts)) FROM public.gateway_requests;")
  [[ -n "$refresh_start" ]] || fail 'gateway_requests has no rows; set TS_USAGE_START and TS_USAGE_END explicitly'
fi

if [[ -n ${TS_USAGE_END-} ]]; then
  refresh_end=$(psql_scalar -v requested_end="$TS_USAGE_END" <<'SQL'
SELECT :'requested_end'::timestamptz;
SQL
  )
else
  refresh_end=$(psql_scalar -c "SELECT date_trunc('hour', now());")
fi

bounds_ok=$(psql_scalar -v refresh_start="$refresh_start" -v refresh_end="$refresh_end" <<'SQL'
SELECT (
     date_trunc('hour', :'refresh_start'::timestamptz) = :'refresh_start'::timestamptz
     AND date_trunc('hour', :'refresh_end'::timestamptz) = :'refresh_end'::timestamptz
     AND :'refresh_start'::timestamptz < :'refresh_end'::timestamptz
     AND :'refresh_end'::timestamptz <= now()
   )::int;
SQL
)
[[ "$bounds_ok" == '1' ]] || fail 'refresh start/end must be hour-aligned and start must be before end'

policy_job_rows=$(psql_scalar -F '|' <<'SQL'
SELECT job_id, scheduled::text
  FROM timescaledb_information.jobs
 WHERE hypertable_schema = 'public'
   AND hypertable_name = 'gateway_usage_hourly'
   AND proc_name = 'policy_refresh_continuous_aggregate'
 ORDER BY job_id;
SQL
)

policy_exists=false
policy_job_id=''
policy_scheduled=''
if [[ -n "$policy_job_rows" ]]; then
  [[ "$policy_job_rows" != *$'\n'* ]] || \
    fail 'multiple refresh policies found for the continuous aggregate'
  IFS='|' read -r policy_job_id policy_scheduled <<< "$policy_job_rows"
  [[ "$policy_job_id" =~ ^[0-9]+$ ]] || fail 'Timescale returned an invalid refresh job id'
  [[ "$policy_scheduled" == 'true' || "$policy_scheduled" == 'false' ]] || \
    fail 'Timescale returned an invalid refresh job schedule state'
  policy_exists=true

  psql_run -v refresh_job_id="$policy_job_id" <<'SQL' >/dev/null
SELECT alter_job(:'refresh_job_id'::integer, scheduled => false);
SQL
  running_jobs=$(psql_scalar -v refresh_job_id="$policy_job_id" <<'SQL'
    SELECT count(*)
      FROM timescaledb_information.job_stats
     WHERE job_id = :'refresh_job_id'::integer
       AND job_status = 'Running';
SQL
  )
  [[ "$running_jobs" == '0' ]] || \
    fail 'the continuous-aggregate refresh job is still running after being stopped'
fi

chunk_start=$refresh_start
while [[ "$chunk_start" != "$refresh_end" ]]; do
  chunk_end=$(psql_scalar -v chunk_start="$chunk_start" -v refresh_end="$refresh_end" <<SQL
SELECT least(:'refresh_end'::timestamptz, :'chunk_start'::timestamptz + interval '$MAX_CHUNK');
SQL
  )
  [[ -n "$chunk_end" && "$chunk_end" != "$chunk_start" ]] || \
    fail 'failed to advance the refresh window'

  printf 'refreshing %s through %s\n' "$chunk_start" "$chunk_end"
  psql_run -v chunk_start="$chunk_start" -v chunk_end="$chunk_end" <<SQL
     SET statement_timeout = '$REFRESH_STATEMENT_TIMEOUT';
     CALL refresh_continuous_aggregate(
       '$CAGG',
       :'chunk_start'::timestamptz,
       :'chunk_end'::timestamptz
     );
SQL
  chunk_start=$chunk_end
done

comparison=$(psql_scalar -v refresh_start="$refresh_start" -v refresh_end="$refresh_end" -F '|' <<'SQL'
 WITH source_totals AS (
   SELECT count(*) AS request_count,
          coalesce(sum(input_tokens), 0) AS input_tokens,
          coalesce(sum(output_tokens), 0) AS output_tokens,
          coalesce(sum(cached_input_tokens), 0) AS cached_input_tokens,
          count(*) FILTER (WHERE error IS NOT NULL) AS failed,
          sum(cost_usd) AS cost_usd,
          coalesce(sum(charged_microus), 0) AS charged_total,
          count(*) FILTER (
            WHERE error IS NULL
              AND input_tokens IS NOT NULL
              AND cost_usd IS NULL
          ) AS null_cost_count,
          coalesce(sum(output_tokens) FILTER (WHERE error IS NULL), 0) AS timed_output,
          coalesce(sum(total_ms) FILTER (WHERE error IS NULL), 0) AS timed_ms,
          coalesce(sum(GREATEST(total_ms - coalesce(ttft_ms, 0), 0))
                   FILTER (WHERE error IS NULL), 0) AS decode_ms
     FROM public.gateway_requests
   WHERE ts >= :'refresh_start'::timestamptz
     AND ts < :'refresh_end'::timestamptz
 ), aggregate_totals AS (
   SELECT coalesce(sum(requests), 0) AS request_count,
          coalesce(sum(input_tokens), 0) AS input_tokens,
          coalesce(sum(output_tokens), 0) AS output_tokens,
          coalesce(sum(cached_input_tokens), 0) AS cached_input_tokens,
          coalesce(sum(failed), 0) AS failed,
          sum(cost_usd) AS cost_usd,
          coalesce(sum(charged_microus), 0) AS charged_total,
          coalesce(sum(unpriced), 0) AS null_cost_count,
          coalesce(sum(timed_output), 0) AS timed_output,
          coalesce(sum(timed_ms), 0) AS timed_ms,
          coalesce(sum(decode_ms), 0) AS decode_ms
    FROM public.gateway_usage_hourly
   WHERE hour >= :'refresh_start'::timestamptz
     AND hour < :'refresh_end'::timestamptz
)
 SELECT source_totals.request_count,
        source_totals.input_tokens,
        source_totals.output_tokens,
        source_totals.cached_input_tokens,
        source_totals.failed,
        source_totals.cost_usd,
        source_totals.charged_total,
        source_totals.null_cost_count,
        source_totals.timed_output,
        source_totals.timed_ms,
        source_totals.decode_ms,
        aggregate_totals.request_count,
        aggregate_totals.input_tokens,
        aggregate_totals.output_tokens,
        aggregate_totals.cached_input_tokens,
        aggregate_totals.failed,
        aggregate_totals.cost_usd,
        aggregate_totals.charged_total,
        aggregate_totals.null_cost_count,
        aggregate_totals.timed_output,
        aggregate_totals.timed_ms,
        aggregate_totals.decode_ms,
        (source_totals.request_count = aggregate_totals.request_count
         AND source_totals.input_tokens = aggregate_totals.input_tokens
         AND source_totals.output_tokens = aggregate_totals.output_tokens
         AND source_totals.cached_input_tokens = aggregate_totals.cached_input_tokens
         AND source_totals.failed = aggregate_totals.failed
         AND source_totals.cost_usd IS NOT DISTINCT FROM aggregate_totals.cost_usd
         AND source_totals.charged_total = aggregate_totals.charged_total
         AND source_totals.null_cost_count = aggregate_totals.null_cost_count
         AND source_totals.timed_output = aggregate_totals.timed_output
         AND source_totals.timed_ms = aggregate_totals.timed_ms
         AND source_totals.decode_ms = aggregate_totals.decode_ms)::int
   FROM source_totals, aggregate_totals;
SQL
)

IFS='|' read -r source_count source_input source_output source_cached source_failed source_cost source_total source_null_cost source_timed_output source_timed_ms source_decode_ms aggregate_count aggregate_input aggregate_output aggregate_cached aggregate_failed aggregate_cost aggregate_total aggregate_null_cost aggregate_timed_output aggregate_timed_ms aggregate_decode_ms comparison_ok <<< "$comparison"
[[ "$comparison_ok" == '1' ]] || fail "aggregate check failed (requests ${source_count}/${aggregate_count}, charged_microus ${source_total}/${aggregate_total}, NULL cost ${source_null_cost}/${aggregate_null_cost})"
printf 'aggregate check passed (requests=%s, charged_microus=%s, NULL cost=%s)\n' \
  "$source_count" "$source_total" "$source_null_cost"

if [[ "$policy_exists" == true ]]; then
  psql_run -v refresh_job_id="$policy_job_id" -v original_scheduled="$policy_scheduled" <<'SQL' >/dev/null
SELECT alter_job(:'refresh_job_id'::integer, scheduled => :'original_scheduled'::boolean);
SQL
  psql_run -v refresh_job_id="$policy_job_id" <<'SQL' >/dev/null
SELECT alter_job(:'refresh_job_id'::integer, max_runtime => INTERVAL '2 minutes');
SQL
  printf 'existing continuous-aggregate refresh policy restored\n'
else
  psql_run <<SQL >/dev/null
  SELECT add_continuous_aggregate_policy(
    '$CAGG',
   start_offset => INTERVAL '3 days',
   end_offset => INTERVAL '1 hour',
     schedule_interval => INTERVAL '5 minutes'
   );
SQL
  new_job_id=$(psql_scalar <<'SQL'
    SELECT job_id
      FROM timescaledb_information.jobs
     WHERE hypertable_schema = 'public'
       AND hypertable_name = 'gateway_usage_hourly'
       AND proc_name = 'policy_refresh_continuous_aggregate';
SQL
  )
  [[ "$new_job_id" =~ ^[0-9]+$ ]] || fail 'could not resolve the newly created refresh job'
  psql_run -v refresh_job_id="$new_job_id" <<'SQL' >/dev/null
SELECT alter_job(:'refresh_job_id'::integer, max_runtime => INTERVAL '2 minutes');
SQL
  printf 'continuous-aggregate refresh policy created\n'
fi
