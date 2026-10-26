-- Native Kiro upstream (`kiro` provider protocol, Kiro OIDC key credentials).
--
-- The provider-protocol CHECK constraint is the closed set of upstream
-- dialects a provider row may declare: it is replaced here, exactly like
-- 0003 did for the retrieval API, never extended by omission.
--
-- `gateway_provider_keys` gains the credential shape:
-- - `auth_kind` = how the row authenticates upstream; `static` keeps the
--   existing plaintext `api_key` (the default, so pre-existing rows are
--   unchanged), `kiro_oidc` carries an OAuth bundle in `oauth` instead.
-- - `oauth` = the Kiro OIDC bundle (camelCase JSON, see
--   `kiro::KiroOAuth`).
--
-- The two credential shapes are disjoint, enforced by the CHECK: a static row
-- never carries `oauth`, and an OIDC row never carries an `api_key` and always
-- holds a JSON *object*. That keeps every read path honest — a row cannot hold
-- a second credential the reader would silently ignore — and keeps malformed
-- JSON out of the type that must decode it at dispatch time.
--
-- `api_key` stays nullable and is deliberately not altered: a Kiro key stores
-- its tokens in `oauth`, never in the plaintext API-key column.

ALTER TABLE public.gateway_providers
    DROP CONSTRAINT IF EXISTS gateway_providers_protocol_check;

ALTER TABLE public.gateway_providers
    ADD CONSTRAINT gateway_providers_protocol_check
    CHECK (protocol = ANY (ARRAY[
        'anthropic_messages'::text,
        'openai_chat'::text,
        'openai_responses'::text,
        'gemini'::text,
        'openai_embeddings'::text,
        'kiro'::text
    ]));

ALTER TABLE public.gateway_provider_keys
    ADD COLUMN auth_kind text NOT NULL DEFAULT 'static';

ALTER TABLE public.gateway_provider_keys
    ADD COLUMN oauth jsonb;

ALTER TABLE public.gateway_provider_keys
    ADD CONSTRAINT gateway_provider_keys_auth_kind_check
    CHECK (auth_kind = ANY (ARRAY['static'::text, 'kiro_oidc'::text]));

ALTER TABLE public.gateway_provider_keys
    ADD CONSTRAINT gateway_provider_keys_oauth_check
    CHECK (
        (auth_kind = 'static' AND oauth IS NULL)
        OR (
            auth_kind = 'kiro_oidc'
            AND api_key IS NULL
            AND oauth IS NOT NULL
            AND jsonb_typeof(oauth) = 'object'
        )
    );
