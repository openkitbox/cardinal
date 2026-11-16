-- WorkBuddy account OAuth credentials.
-- The provider protocol CHECK remains unchanged: WorkBuddy reuses the existing
-- OpenAI Chat and Anthropic Messages protocol rows.

ALTER TABLE public.gateway_provider_keys
    DROP CONSTRAINT IF EXISTS gateway_provider_keys_auth_kind_check;

ALTER TABLE public.gateway_provider_keys
    ADD CONSTRAINT gateway_provider_keys_auth_kind_check
    CHECK (auth_kind = ANY (ARRAY[
        'static'::text,
        'kiro_oidc'::text,
        'opencode_oauth'::text,
        'cursor_oauth'::text,
        'openai_oauth'::text,
        'workbuddy_oauth'::text
    ]));

ALTER TABLE public.gateway_provider_keys
    DROP CONSTRAINT IF EXISTS gateway_provider_keys_oauth_check;

ALTER TABLE public.gateway_provider_keys
    ADD CONSTRAINT gateway_provider_keys_oauth_check
    CHECK (
        (auth_kind = 'static' AND oauth IS NULL)
        OR (
            auth_kind IN ('kiro_oidc', 'opencode_oauth')
            AND api_key IS NULL
            AND oauth IS NOT NULL
            AND jsonb_typeof(oauth) = 'object'
        )
        OR (
            auth_kind = 'cursor_oauth'
            AND api_key IS NULL
            AND oauth IS NOT NULL
            AND jsonb_typeof(oauth) = 'object'
            AND oauth ? 'access_token'
            AND oauth ? 'refresh_token'
            AND oauth ? 'expires_at'
        )
        OR (
            auth_kind = 'openai_oauth'
            AND api_key IS NULL
            AND oauth IS NOT NULL
            AND jsonb_typeof(oauth) = 'object'
            AND oauth ? 'access_token'
            AND oauth ? 'refresh_token'
            AND oauth ? 'expires_at'
            AND oauth ? 'account_id'
        )
        OR (
            auth_kind = 'workbuddy_oauth'
            AND api_key IS NULL
            AND oauth IS NOT NULL
            AND jsonb_typeof(oauth) = 'object'
            AND oauth ? 'access_token'
            AND oauth ? 'refresh_token'
            AND oauth ? 'expires_at'
            AND oauth ? 'uid'
        )
    );
