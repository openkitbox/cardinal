-- 0023_pg_load_indexes.sql
--
-- Keep quota history on ordinary PostgreSQL tables.  This migration deliberately
-- does not install TimescaleDB or convert any table to a hypertable: the history
-- table has a foreign key to gateway_provider_keys, and a hypertable conversion
-- would need a separately verified constraint, lock, retention, and rollback
-- design.  gateway_requests is billing/audit data and is outside this boundary.
--
-- list_quota_history() bounds both branches by probed_at (48 hours and 35 days),
-- while the existing key/window index supports their DISTINCT ON ordering.  This
-- time-leading index bounds each branch to its window instead of scanning the
-- whole append-only table as history grows, and also serves age-based cleanup
-- (DELETE ... WHERE probed_at < now() - interval '45 days') without a full scan.
-- Measured on a synthetic 300k-row table: both branches switch from Seq Scan to
-- Index Scan, and the window-scoped cleanup becomes an index scan.
CREATE INDEX IF NOT EXISTS idx_gateway_key_quota_history_probed_at
    ON public.gateway_key_quota_history USING btree (probed_at DESC);

-- PostgreSQL cannot use date_trunc(text, timestamptz) in an expression index:
-- that function depends on the session time zone and is only STABLE.  So do not
-- add a misleading hourly/daily bucket index here; the DISTINCT ON queries still
-- sort by the bucket expression.  Making that sort index-backed would need an
-- immutable UTC bucket expression in both the index and src/store/quota.rs, which
-- is a coordinated read-path change rather than a schema-only one.
