-- 0017_opencode_oauth.sql
-- 第二种 OAuth 凭证:OpenCode Console 账号登录(auth_kind = 'opencode_oauth')。
--
-- gateway_provider_keys 早就表达"一行只有一种凭证":auth_kind 说明形态,两条 CHECK
-- 保证两种形态互斥(0007)。这里只把两个封闭集合放宽一行,不新增列、不改写任何已有行:
--   * auth_kind 增加 'opencode_oauth'(与 'static'、'kiro_oidc' 并列);
--   * oauth 形态由两种 OAuth kind 共用:没有 api_key,oauth 必须是 JSON 对象
--     (见 opencode::OpencodeOAuth)。具体是哪一种 bundle 只由 auth_kind 决定,
--     绝不靠嗅探 JSON 内容。
--
-- opencode_oauth 行的 access_token 会过期、由 gateway 派发期刷新并 CAS 写回,
-- 因此 token 只能待在 oauth 列,不能塞进 api_key。

ALTER TABLE public.gateway_provider_keys
    DROP CONSTRAINT IF EXISTS gateway_provider_keys_auth_kind_check;

ALTER TABLE public.gateway_provider_keys
    ADD CONSTRAINT gateway_provider_keys_auth_kind_check
    CHECK (auth_kind = ANY (ARRAY[
        'static'::text,
        'kiro_oidc'::text,
        'opencode_oauth'::text
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
    );
