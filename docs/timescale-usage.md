# Usage aggregate backfill

`scripts/timescale-usage-backfill.sh` fills the `gateway_usage_hourly`
continuous aggregate created by migration 0029 and manages its refresh policy.
It is a maintenance command, not a gateway start-up step: it never drops or
recreates an object, creates a watermark, enables columnstore, or restarts
Cardinal.

## Running it

Run it from a maintenance host with a PostgreSQL connection as the owner of
`public.gateway_requests`:

```bash
TS_USAGE_DSN='postgres://user:password@db.example/cardinal' \
  ./scripts/timescale-usage-backfill.sh
```

`TS_USAGE_DSN` is required and is rejected when empty or containing whitespace
or control characters. The script accepts only a simple `postgres://` or
`postgresql://` URI with host, database, and optional port/user/password; URI
query parameters and fragments are rejected rather than passed through. It
writes the parsed connection values to a mode-0600 temporary libpq service file
and uses `PGSERVICEFILE`/`PGSERVICE`, so the full DSN is not present in the
`psql` argument list. The temporary file is removed on exit and is never
printed.

`TS_USAGE_START` and `TS_USAGE_END` are optional RFC3339 timestamps. Explicit values must be exactly on an hour boundary, must satisfy `start < end`, and
must not end in the future; the script checks all three conditions in SQL before
stopping a policy or refreshing.
If omitted, the range is the whole-hour interval from
`date_trunc('hour', min(gateway_requests.ts))` through the hour immediately
before `now()`. The end is exclusive. The same validated range is used for
chunk refreshes and the source/aggregate comparison.

The script checks TimescaleDB 2.31 or newer, ownership of
`gateway_requests`, the source hypertable, and the real-time (`materialized_only
= false`) continuous aggregate before changing anything. It finds the refresh
policy job through the public `timescaledb_information.jobs` and `job_stats`
views; in that view a continuous-aggregate refresh job is keyed by the
continuous aggregate's public view name (`gateway_usage_hourly`). Unexpected
job IDs, schedule states, multiple matching policies, or a job that remains
running are fatal; the script does not guess that no policy exists.

The requested interval is refreshed in chunks of at most 24 hours. Every chunk
uses an explicit statement timeout; a failed chunk stops the script immediately
and no later chunk is skipped. At the end, source rows and aggregate rows are
compared for request count, `charged_microus`, and the count of successful,
token-observed requests whose `cost_usd` is NULL.

## Policy lifecycle

If a refresh policy already exists, the script records its job ID and original
`schedule` state, stops it through TimescaleDB's public `alter_job` API, and
confirms that that exact job is not running. On any refresh, comparison, or
policy-operation failure, the job remains stopped so operators can investigate.
A successful run restores the existing job's original scheduled state and
normalizes its `max_runtime` to two minutes; it does not replace its offsets or
interval.

If no policy exists, a successful run creates exactly one policy with:

- `start_offset => '3 days'`
- `end_offset => '1 hour'`
- `schedule_interval => '5 minutes'`

For a newly created policy, the script sets the resulting job's
`max_runtime` to two minutes. An existing policy's job settings are preserved;
the script does not silently replace its offsets or runtime budget.

There is no `if_not_exists` masking. A policy creation error is non-zero and
must be investigated. The command is repeatable, but reruns deliberately stop
and restore an existing policy rather than claiming that a mismatched policy
is idempotent.

## Maintenance window and real-time tail

Run the initial backfill during a window with enough database capacity for
scanning `gateway_requests` and materializing the requested history. It does
not stop request ingestion. While the aggregate is `materialized_only = false`,
queries include the raw hypertable's recent, not-yet-materialized rows through
the real-time tail. The installed policy intentionally refreshes only through
one hour ago, so the tail covers the newest hour between policy runs.

Do not interpret a successful refresh as making future historical writes
visible automatically. An INSERT arriving late for a bucket already refreshed
must be followed by a refresh covering that bucket (for example, rerun with an
explicit hour-aligned range that includes the affected hour). The policy
normally handles recent changes inside its three-day start window, but older
late arrivals need an explicit maintenance refresh.

## Failed jobs and recovery

After a failed command, inspect
`timescaledb_information.job_stats` and
`timescaledb_information.job_errors` for the continuous aggregate. A
pre-existing policy is intentionally left stopped after a failed refresh or
comparison. Once the error is understood, rerun the script for the needed
hour-aligned range; a successful rerun restores that policy's original
scheduled state. If no policy existed, a successful rerun creates the target
policy. If policy restoration or creation itself fails, treat the command as
failed and verify the job state before retrying. Unrelated TimescaleDB jobs
should be resolved independently.

## Native policy fallback

On a host where TimescaleDB's background-worker scheduler cannot execute its
own jobs (for example, scheduled jobs repeatedly fail with
`cannot drop portal "" while it is being set up`, including TimescaleDB's
built-in retention job), do not rely on `add_continuous_aggregate_policy` for
the live tail. Keep the continuous aggregate and refresh it with a small
systemd timer instead:

```ini
# /etc/systemd/system/cardinal-cagg-refresh.service
[Service]
Type=oneshot
User=postgres
ExecStart=/usr/bin/psql -X -v ON_ERROR_STOP=1 -d cardinal -c "CALL refresh_continuous_aggregate('public.gateway_usage_hourly', now() - interval '3 days', date_trunc('hour', now()));"
TimeoutStartSec=120
```

```ini
# /etc/systemd/system/cardinal-cagg-refresh.timer
[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
Unit=cardinal-cagg-refresh.service
```

Run the timer as a database role that can execute the refresh procedure; the
example uses local `postgres` peer authentication and therefore needs no DSN in
the unit. Disable a scheduled refresh job with `alter_job(<job_id>,
scheduled => false)` while the timer is authoritative, and re-enable the native
policy only after the scheduler is fixed. The timer is external to the gateway
process, so it adds no per-request database writes.

## Known production issue: native TimescaleDB jobs

Production evidence from 2026-11-18 shows that TimescaleDB background jobs fail
with PostgreSQL SQLSTATE `24000`:

```text
cannot drop portal "" while it is being set up
```

The failure affects both the continuous-aggregate refresh job and TimescaleDB's
own `policy_job_stat_history_retention` job. The retention job is an internal
TimescaleDB job that cleans job statistics/history; it does **not** delete
Cardinal's `gateway_requests` rows. The same error across unrelated TimescaleDB
jobs points to the shared background-worker job execution path, not to the
Cardinal aggregate SQL.

The production combination was PostgreSQL 18.7 with TimescaleDB 2.31.0 and was
later upgraded to TimescaleDB 2.32.0. Increasing `max_worker_processes` from 8
to 32, restarting PostgreSQL, restarting TimescaleDB workers, and upgrading the
extension did not remove the error. A normal foreground session can execute
`CALL refresh_continuous_aggregate(...)` successfully, so the failure is
specific to the native background scheduler path. The exact upstream root cause
is **not yet proven**; the leading hypothesis is a PostgreSQL 18.x and
TimescaleDB scheduler/portal-lifecycle compatibility issue. Do not describe this
as a confirmed upstream bug until the isolated reproduction below succeeds.

Until the root cause is resolved:

- Keep the native CAGG refresh job disabled (`scheduled = false`).
- Keep `cardinal-cagg-refresh.timer` as the production refresh authority.
- Do not re-enable the native policy merely because a PostgreSQL or TimescaleDB
  package was upgraded; first run the verification matrix and observe a
  successful native job execution.
- Continue checking `timescaledb_information.job_errors`; a successful manual
  refresh or timer run does not prove that the native scheduler is fixed.

### Follow-up investigation

1. Reproduce the smallest hypertable + continuous aggregate + refresh policy in
   an isolated database on PostgreSQL 18.7 / TimescaleDB 2.32.0. Include the
   built-in job-history retention job in the observation.
2. Compare the same fixture on PostgreSQL 18.6, PostgreSQL 18.7, and a
   supported PostgreSQL 17 release with the same TimescaleDB package.
3. Verify extension/loader consistency after every upgrade:
   `pg_extension.extversion`, `pg_available_extension_versions`,
   `shared_preload_libraries`, and the installed loader package must agree.
4. Capture the first failing job, `job_errors.err_message`, SQLSTATE, PostgreSQL
   log context, and whether a foreground `CALL refresh_continuous_aggregate`
   succeeds.
5. Only after native jobs succeed repeatedly should the timer be disabled and
   the policy re-enabled. If the issue is confirmed as an upstream compatibility
   defect, record the fixed package/version and retain the timer as the rollback
   path.

## Backup and restore

Include the `gateway_requests` hypertable, its TimescaleDB metadata, and the
`gateway_usage_hourly` continuous aggregate definition/materialization in the
backup plan. Restore the extension and database objects with a supported
TimescaleDB 2.31+ installation before running the script. After a restore,
check that the source hypertable, materialization hypertable, and real-time
setting are present; if the aggregate has no materialized data or the restore
was logical, run this script for the restored history before relying on
aggregate-only reporting. Restore into an isolated database first when
possible and verify counts, charged microunits, and NULL-cost counts against
the source before returning it to service.
