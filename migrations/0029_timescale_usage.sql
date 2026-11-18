-- TimescaleDB-backed request history and usage aggregate.
--
-- This migration deliberately fails on installations without the required
-- TimescaleDB version or ownership/constraint prerequisites.  It does not
-- create the extension, backfill the aggregate, or install a background job.
--
-- The short lock timeout prevents a production startup from waiting forever for
-- a writer. The statement timeout is a bounded maintenance-window budget for
-- the existing-table conversion; both settings are local to this migration
-- transaction and roll back with it on failure.
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30min';

DO $$
DECLARE
    extension_version text;
    extension_major integer;
    extension_minor integer;
    request_owner text;
    request_relkind "char";
    primary_key_count integer;
    foreign_key_count integer;
    incoming_foreign_key_count integer;
    other_unique_index_count integer;
    missing_columns text;
BEGIN
    SELECT extversion
      INTO extension_version
      FROM pg_extension
     WHERE extname = 'timescaledb';

    IF extension_version IS NULL THEN
        RAISE EXCEPTION
            'migration 0029 requires the TimescaleDB extension; it is not installed (CREATE EXTENSION is intentionally not run by migrations)';
    END IF;

    IF extension_version !~ '^[0-9]+\.[0-9]+' THEN
        RAISE EXCEPTION
            'migration 0029 requires a parseable TimescaleDB version, got %', extension_version;
    END IF;

    extension_major := split_part(extension_version, '.', 1)::integer;
    extension_minor := split_part(extension_version, '.', 2)::integer;
    IF extension_major < 2
       OR (extension_major = 2 AND extension_minor < 31) THEN
        RAISE EXCEPTION
            'migration 0029 requires TimescaleDB >= 2.31.0, found %', extension_version;
    END IF;

    IF to_regclass('public.gateway_requests') IS NULL THEN
        RAISE EXCEPTION
            'migration 0029 requires table public.gateway_requests';
    END IF;

    SELECT pg_get_userbyid(c.relowner)
      INTO request_owner
      FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'public'
       AND c.relname = 'gateway_requests';

    IF request_owner <> current_user THEN
        RAISE EXCEPTION
            'migration 0029 requires current_user % to own public.gateway_requests (owner is %)',
            current_user, request_owner;
    END IF;

    SELECT c.relkind
      INTO request_relkind
      FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'public'
       AND c.relname = 'gateway_requests';

    IF request_relkind <> 'r' THEN
        RAISE EXCEPTION
            'migration 0029 requires public.gateway_requests to be a regular table (relkind %)',
            request_relkind;
    END IF;

    IF NOT has_schema_privilege(current_user, 'public', 'CREATE') THEN
        RAISE EXCEPTION
            'migration 0029 requires CREATE privilege on schema public for %', current_user;
    END IF;

    SELECT string_agg(required.column_name, ', ' ORDER BY required.column_name)
      INTO missing_columns
      FROM (VALUES
            ('id'), ('ts'), ('alias'), ('served_model'), ('provider_id'),
            ('caller_key'), ('gateway_key_id'), ('user_id'), ('agent'),
            ('input_tokens'), ('output_tokens'), ('cached_input_tokens'),
            ('charged_microus'), ('cost_usd'), ('error'), ('total_ms'),
            ('ttft_ms')) AS required(column_name)
     WHERE NOT EXISTS (
         SELECT 1
           FROM information_schema.columns c
          WHERE c.table_schema = 'public'
            AND c.table_name = 'gateway_requests'
            AND c.column_name = required.column_name
     );

    IF missing_columns IS NOT NULL THEN
        RAISE EXCEPTION
            'migration 0029 requires columns on public.gateway_requests: %', missing_columns;
    END IF;

    IF NOT EXISTS (
        SELECT 1
          FROM information_schema.columns
         WHERE table_schema = 'public'
           AND table_name = 'gateway_requests'
           AND column_name = 'ts'
           AND data_type = 'timestamp with time zone'
           AND is_nullable = 'NO'
    ) THEN
        RAISE EXCEPTION
            'migration 0029 requires public.gateway_requests.ts to be NOT NULL timestamptz';
    END IF;

    IF NOT EXISTS (
        SELECT 1
          FROM information_schema.columns
         WHERE table_schema = 'public'
           AND table_name = 'gateway_requests'
           AND column_name = 'id'
           AND data_type = 'bigint'
           AND is_nullable = 'NO'
    ) THEN
        RAISE EXCEPTION
            'migration 0029 requires public.gateway_requests.id to be NOT NULL bigint';
    END IF;

    IF EXISTS (
        SELECT 1
          FROM timescaledb_information.hypertables
         WHERE hypertable_schema = 'public'
           AND hypertable_name = 'gateway_requests'
    ) THEN
        RAISE EXCEPTION
            'migration 0029 found public.gateway_requests already converted to a hypertable';
    END IF;

    SELECT count(*)
      INTO primary_key_count
      FROM pg_constraint
     WHERE conrelid = 'public.gateway_requests'::regclass
       AND contype = 'p'
       AND conname = 'gateway_requests_pkey'
       AND pg_get_constraintdef(oid) = 'PRIMARY KEY (id)';

    IF primary_key_count <> 1 THEN
        RAISE EXCEPTION
            'migration 0029 requires the existing primary key gateway_requests_pkey PRIMARY KEY (id), found % matching constraints',
            primary_key_count;
    END IF;

    SELECT count(*)
      INTO foreign_key_count
      FROM pg_constraint
     WHERE conrelid = 'public.gateway_requests'::regclass
       AND contype = 'f';

    SELECT count(*)
      INTO incoming_foreign_key_count
      FROM pg_constraint
     WHERE confrelid = 'public.gateway_requests'::regclass
       AND contype = 'f';

    IF foreign_key_count <> 0 OR incoming_foreign_key_count <> 0 THEN
        RAISE EXCEPTION
            'migration 0029 requires no foreign keys involving public.gateway_requests (outgoing %, incoming %)',
            foreign_key_count, incoming_foreign_key_count;
    END IF;

    SELECT count(*)
      INTO other_unique_index_count
      FROM pg_index i
      JOIN pg_class index_class ON index_class.oid = i.indexrelid
     WHERE i.indrelid = 'public.gateway_requests'::regclass
       AND i.indisunique
       AND index_class.relname <> 'gateway_requests_pkey';

    IF other_unique_index_count <> 0 THEN
        RAISE EXCEPTION
            'migration 0029 requires no unique index other than gateway_requests_pkey before time partitioning (found %)',
            other_unique_index_count;
    END IF;

    IF to_regclass('public.gateway_usage_hourly') IS NOT NULL THEN
        RAISE EXCEPTION
            'migration 0029 cannot create public.gateway_usage_hourly because that object already exists';
    END IF;
END
$$;

ALTER TABLE public.gateway_requests
    DROP CONSTRAINT gateway_requests_pkey;

ALTER TABLE public.gateway_requests
    ADD CONSTRAINT gateway_requests_pkey PRIMARY KEY (id, ts);

SELECT create_hypertable(
    'public.gateway_requests'::regclass,
    by_range('ts', INTERVAL '7 days'),
    migrate_data => TRUE,
    create_default_indexes => FALSE
);

CREATE MATERIALIZED VIEW public.gateway_usage_hourly
WITH (
    timescaledb.continuous,
    timescaledb.materialized_only = FALSE
)
AS
SELECT time_bucket(INTERVAL '1 hour', ts) AS hour,
       alias,
       served_model,
       provider_id,
       caller_key,
       gateway_key_id,
       user_id,
       agent,
       COUNT(*) AS requests,
       COUNT(*) FILTER (WHERE error IS NOT NULL) AS failed,
       SUM(input_tokens) AS input_tokens,
       SUM(output_tokens) AS output_tokens,
       SUM(cached_input_tokens) AS cached_input_tokens,
       SUM(charged_microus) AS charged_microus,
       SUM(cost_usd) AS cost_usd,
       COUNT(*) FILTER (
           WHERE error IS NULL
             AND input_tokens IS NOT NULL
             AND cost_usd IS NULL
       ) AS unpriced,
       SUM(output_tokens) FILTER (WHERE error IS NULL) AS timed_output,
       SUM(total_ms) FILTER (WHERE error IS NULL) AS timed_ms,
       SUM(GREATEST(total_ms - COALESCE(ttft_ms, 0), 0))
           FILTER (WHERE error IS NULL) AS decode_ms
  FROM public.gateway_requests
 GROUP BY 1, 2, 3, 4, 5, 6, 7, 8
WITH NO DATA;
