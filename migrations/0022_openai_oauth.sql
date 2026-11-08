-- 0022_openai_oauth.sql
-- 第四种 OAuth 凭证:OpenAI Codex(ChatGPT 订阅)账号登录(auth_kind = 'openai_oauth')。
--
-- OpenAI Codex 不是新协议:它复用既有的 'openai_responses' 上游方言,所以
-- gateway_providers.protocol 的 CHECK 一字不动;区分依据只是 key 行的 auth_kind,
-- 与 'opencode_oauth'(一个账号服务多种协议)同理。
--
-- 与 0017/0021 完全同构,这里只放宽两个封闭集合、不新增列、不改写任何已有行:
--   * auth_kind 增加 'openai_oauth'(与 'static'、'kiro_oidc'、'opencode_oauth'、
--     'cursor_oauth' 并列);
--   * oauth 形态仍由「没有 api_key + JSON 对象」表达,但 openai_oauth 行额外要求
--     四个必有字段存在:access_token / refresh_token / expires_at / account_id
--     (account_id 是每个上游请求都要带的 ChatGPT 工作区 id)。具体是哪一种
--     bundle 只由 auth_kind 决定,绝不靠嗅探 JSON 内容。
--
-- openai_oauth 行的 access_token 会过期、refresh token 会轮换,由 gateway 派发期
-- 刷新并 CAS 写回,因此 token 只能待在 oauth 列,不能塞进 api_key。

ALTER TABLE public.gateway_provider_keys
    DROP CONSTRAINT IF EXISTS gateway_provider_keys_auth_kind_check;

ALTER TABLE public.gateway_provider_keys
    ADD CONSTRAINT gateway_provider_keys_auth_kind_check
    CHECK (auth_kind = ANY (ARRAY[
        'static'::text,
        'kiro_oidc'::text,
        'opencode_oauth'::text,
        'cursor_oauth'::text,
        'openai_oauth'::text
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
    );
