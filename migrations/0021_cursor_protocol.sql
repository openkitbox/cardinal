-- 0021_cursor_protocol.sql
-- Cursor 上游方言(protocol = 'cursor')与第三种 OAuth 凭证(auth_kind = 'cursor_oauth')。
--
-- Cursor 是新增的上游翻译目标(只作出站,不给客户端暴露该路径),因此 provider 的
-- protocol 封闭集合要加一个值;两类账号共用一个 provider:
--   * 'cursor_oauth':一条 cursor.com 浏览器登录得到的 OAuth bundle;
--   * 'static':Cursor 用户 API key,派发期经 /auth/exchange_user_api_key 换成 token。
--
-- 与 0007/0017 完全同构,这里只放宽两个封闭集合、不新增列、不改写任何已有行:
--   * protocol 增加 'cursor'(与 'kiro' 等六个已有值并列);
--   * auth_kind 增加 'cursor_oauth'(与 'static'、'kiro_oidc'、'opencode_oauth' 并列);
--   * oauth 形态仍由「没有 api_key + JSON 对象」表达,但 cursor_oauth 行额外要求
--     三个必有字段存在:access_token / refresh_token / expires_at。具体是哪一种
--     bundle 只由 auth_kind 决定,绝不靠嗅探 JSON 内容。
--
-- cursor_oauth 行的 access_token 会过期(Cursor 响应里没有过期字段,过期时间只能
-- 由 access token 这个 JWT 的 exp 得出),由 gateway 派发期刷新并 CAS 写回;refresh
-- token 在 Cursor 侧不轮换,但要能被后续刷新读到,因此同样只能待在 oauth 列。

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
        'kiro'::text,
        'cursor'::text
    ]));

ALTER TABLE public.gateway_provider_keys
    DROP CONSTRAINT IF EXISTS gateway_provider_keys_auth_kind_check;

ALTER TABLE public.gateway_provider_keys
    ADD CONSTRAINT gateway_provider_keys_auth_kind_check
    CHECK (auth_kind = ANY (ARRAY[
        'static'::text,
        'kiro_oidc'::text,
        'opencode_oauth'::text,
        'cursor_oauth'::text
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
    );
