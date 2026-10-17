-- gateway initial schema (squashed from 0001-0025; all prior migrations consolidated
-- into a single idempotent baseline. Pure DDL — no data rows.)

CREATE TABLE IF NOT EXISTS public.gateway_providers (
    id bigint NOT NULL,
    name text NOT NULL,
    protocol text NOT NULL,
    base_url text NOT NULL,
    auth_scheme text NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT gateway_providers_protocol_check CHECK ((protocol = ANY (ARRAY['anthropic_messages'::text, 'openai_chat'::text, 'openai_responses'::text, 'gemini'::text])))
);
DO $$ BEGIN
    ALTER TABLE public.gateway_providers ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
        SEQUENCE NAME public.gateway_providers_id_seq START WITH 1 INCREMENT BY 1 NO MINVALUE NO MAXVALUE CACHE 1
    );
EXCEPTION WHEN OTHERS THEN NULL;
END $$;

CREATE TABLE IF NOT EXISTS public.gateway_provider_keys (
    id bigint NOT NULL,
    provider_id bigint NOT NULL,
    label text NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    "position" integer NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    max_concurrency integer,
    models jsonb,
    models_probed_at timestamp with time zone,
    allowed_models jsonb,
    api_key text,
    CONSTRAINT gateway_provider_keys_max_concurrency_check CHECK (((max_concurrency IS NULL) OR (max_concurrency > 0)))
);
DO $$ BEGIN
    ALTER TABLE public.gateway_provider_keys ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
        SEQUENCE NAME public.gateway_provider_keys_id_seq START WITH 1 INCREMENT BY 1 NO MINVALUE NO MAXVALUE CACHE 1
    );
EXCEPTION WHEN OTHERS THEN NULL;
END $$;

CREATE TABLE IF NOT EXISTS public.gateway_key_quota_snapshots (
    key_id bigint NOT NULL,
    payload jsonb NOT NULL,
    probed_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE IF NOT EXISTS public.gateway_key_rests (
    key_id bigint NOT NULL,
    rest_until timestamp with time zone NOT NULL,
    reason text,
    model text
);

CREATE TABLE IF NOT EXISTS public.gateway_keys (
    label text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    created_by text,
    last_used_at timestamp with time zone,
    disabled_at timestamp with time zone,
    key_plaintext text NOT NULL,
    id bigint NOT NULL
);
DO $$ BEGIN
    ALTER TABLE public.gateway_keys ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
        SEQUENCE NAME public.gateway_keys_id_seq START WITH 1 INCREMENT BY 1 NO MINVALUE NO MAXVALUE CACHE 1
    );
EXCEPTION WHEN OTHERS THEN NULL;
END $$;

CREATE TABLE IF NOT EXISTS public.gateway_model_prices (
    model text NOT NULL,
    input_usd numeric(12,4) DEFAULT 0 NOT NULL,
    output_usd numeric(12,4) DEFAULT 0 NOT NULL,
    cache_read_usd numeric(12,4) DEFAULT 0 NOT NULL,
    cache_write_usd numeric(12,4) DEFAULT 0 NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    provider_id bigint DEFAULT 0 NOT NULL,
    cache_write_1h_usd numeric(12,4),
    tiers jsonb,
    source text DEFAULT 'manual'::text NOT NULL
);

CREATE TABLE IF NOT EXISTS public.gateway_requests (
    id bigint NOT NULL,
    ts timestamp with time zone DEFAULT now() NOT NULL,
    protocol text NOT NULL,
    alias text,
    provider_id bigint,
    provider_key_id bigint,
    model text,
    served_model text,
    status integer NOT NULL,
    input_tokens bigint,
    output_tokens bigint,
    cached_input_tokens bigint,
    total_ms integer,
    cost_usd numeric(12,6),
    error text,
    caller_key text,
    agent text,
    cache_creation_input_tokens bigint DEFAULT 0,
    ttft_ms bigint,
    client_protocol text,
    effort text,
    request_id text
);
DO $$ BEGIN
    ALTER TABLE public.gateway_requests ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
        SEQUENCE NAME public.gateway_requests_id_seq START WITH 1 INCREMENT BY 1 NO MINVALUE NO MAXVALUE CACHE 1
    );
EXCEPTION WHEN OTHERS THEN NULL;
END $$;

CREATE TABLE IF NOT EXISTS public.gateway_routes (
    alias text CONSTRAINT gateway_combos_alias_not_null NOT NULL,
    entries jsonb CONSTRAINT gateway_combos_entries_not_null NOT NULL,
    context_window bigint,
    strategy text DEFAULT 'ordered'::text NOT NULL,
    CONSTRAINT gateway_combos_context_window_check CHECK (((context_window IS NULL) OR (context_window > 0)))
);

-- primary keys (skip if already present)
DO $$ BEGIN ALTER TABLE ONLY public.gateway_providers ADD CONSTRAINT gateway_providers_pkey PRIMARY KEY (id); EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER TABLE ONLY public.gateway_provider_keys ADD CONSTRAINT gateway_provider_keys_pkey PRIMARY KEY (id); EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER TABLE ONLY public.gateway_key_quota_snapshots ADD CONSTRAINT gateway_key_quota_snapshots_pkey PRIMARY KEY (key_id); EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER TABLE ONLY public.gateway_keys ADD CONSTRAINT gateway_keys_pkey PRIMARY KEY (id); EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER TABLE ONLY public.gateway_model_prices ADD CONSTRAINT gateway_model_prices_pkey PRIMARY KEY (provider_id, model); EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER TABLE ONLY public.gateway_requests ADD CONSTRAINT gateway_requests_pkey PRIMARY KEY (id); EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER TABLE ONLY public.gateway_routes ADD CONSTRAINT gateway_combos_pkey PRIMARY KEY (alias); EXCEPTION WHEN OTHERS THEN NULL; END $$;

-- unique constraints (skip if already present)
DO $$ BEGIN ALTER TABLE ONLY public.gateway_providers ADD CONSTRAINT gateway_providers_name_key UNIQUE (name); EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER TABLE ONLY public.gateway_keys ADD CONSTRAINT gateway_keys_key_plaintext_unique UNIQUE (key_plaintext); EXCEPTION WHEN OTHERS THEN NULL; END $$;

-- indexes
CREATE INDEX IF NOT EXISTS idx_gateway_provider_keys_provider ON public.gateway_provider_keys USING btree (provider_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_gateway_key_rests_key_model ON public.gateway_key_rests USING btree (key_id, COALESCE(model, ''::text));
CREATE INDEX IF NOT EXISTS idx_gateway_requests_ts ON public.gateway_requests USING btree (ts DESC);
CREATE INDEX IF NOT EXISTS idx_gateway_requests_alias_ts ON public.gateway_requests USING btree (alias, ts DESC);

-- foreign keys (skip if already present)
DO $$ BEGIN ALTER TABLE ONLY public.gateway_provider_keys ADD CONSTRAINT gateway_provider_keys_provider_id_fkey FOREIGN KEY (provider_id) REFERENCES public.gateway_providers(id) ON DELETE CASCADE; EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER TABLE ONLY public.gateway_key_quota_snapshots ADD CONSTRAINT gateway_key_quota_snapshots_key_id_fkey FOREIGN KEY (key_id) REFERENCES public.gateway_provider_keys(id) ON DELETE CASCADE; EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER TABLE ONLY public.gateway_key_rests ADD CONSTRAINT gateway_key_rests_key_id_fkey FOREIGN KEY (key_id) REFERENCES public.gateway_provider_keys(id) ON DELETE CASCADE; EXCEPTION WHEN OTHERS THEN NULL; END $$;
