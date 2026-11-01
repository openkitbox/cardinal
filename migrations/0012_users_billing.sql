-- 0012_users_billing.sql
-- 用户体系与计费账本。金额一律整数 micro-USD(1 USD = 1,000,000),倍率一律
-- 整数 basis points(10000 = 1.0×)。

-- 用户组 = 商品:只管定价倍率与路由可见性,不碰上游账号调度。
-- route_aliases 为 NULL 表示全部路由可用,数组表示白名单。
CREATE TABLE IF NOT EXISTS public.user_groups (
    id            bigserial PRIMARY KEY,
    name          text NOT NULL UNIQUE,
    rate_bp       bigint NOT NULL DEFAULT 10000 CHECK (rate_bp >= 0),
    route_aliases text[]
);

-- 用户:gateway key 的归属方。rate_bp 为用户级覆盖,NULL 时沿用所属组的倍率。
-- balance_microus 只能与 billing_entries 同一事务更新,两者之和必须相等。
-- max_concurrent / rpm 先落列,P2 风控才使用。
CREATE TABLE IF NOT EXISTS public.users (
    id              bigserial PRIMARY KEY,
    login           text NOT NULL UNIQUE,
    display_name    text NOT NULL DEFAULT '',
    enabled         boolean NOT NULL DEFAULT true,
    group_id        bigint NOT NULL REFERENCES public.user_groups(id),
    rate_bp         bigint CHECK (rate_bp IS NULL OR rate_bp >= 0),
    balance_microus bigint NOT NULL DEFAULT 0,
    max_concurrent  int NOT NULL DEFAULT 4 CHECK (max_concurrent > 0),
    rpm             int CHECK (rpm IS NULL OR rpm > 0),
    created_at      timestamptz NOT NULL DEFAULT now()
);

-- 余额变动的唯一来源。charge 为负、topup 为正;cost_microus / rate_bp 是
-- 扣费当时的成本与倍率快照,事后改价不影响历史。
CREATE TABLE IF NOT EXISTS public.billing_entries (
    id                    bigserial PRIMARY KEY,
    user_id               bigint NOT NULL REFERENCES public.users(id),
    kind                  text NOT NULL CHECK (kind IN ('charge', 'topup', 'adjust', 'refund')),
    amount_microus        bigint NOT NULL,
    balance_after_microus bigint NOT NULL,
    request_id            text,
    cost_microus          bigint,
    rate_bp               bigint,
    note                  text NOT NULL DEFAULT '',
    operator              text,
    created_at            timestamptz NOT NULL DEFAULT now()
);

-- 同一请求只扣一次:批量结算重复 flush 时由此索引去重。
CREATE UNIQUE INDEX IF NOT EXISTS billing_entries_charge_request
    ON public.billing_entries (request_id) WHERE kind = 'charge';

-- 支撑按用户倒序查账单:list_entries 以 id 做 keyset 分页(id < $2 ORDER BY id DESC)。
CREATE INDEX IF NOT EXISTS idx_billing_entries_user_id_desc
    ON public.billing_entries (user_id, id DESC);

-- 内置组 internal(倍率 0,永不收费)与内置用户 owner:存量 key 与配置种子
-- key 都归属 owner,因此迁移后现有调用方行为不变。
INSERT INTO public.user_groups (name, rate_bp) VALUES ('internal', 0)
    ON CONFLICT (name) DO NOTHING;

INSERT INTO public.users (login, group_id)
SELECT 'owner', g.id FROM public.user_groups g WHERE g.name = 'internal'
    ON CONFLICT (login) DO NOTHING;

-- key 归属用户;先回填存量行再收紧为 NOT NULL。
-- key_plaintext 保持明文与唯一约束不变:key 必须随时可查看、复制。
-- expires_at / quota_microus 先落列,P2 才使用。
ALTER TABLE public.gateway_keys
    ADD COLUMN IF NOT EXISTS user_id bigint REFERENCES public.users(id),
    ADD COLUMN IF NOT EXISTS expires_at timestamptz,
    ADD COLUMN IF NOT EXISTS quota_microus bigint CHECK (quota_microus IS NULL OR quota_microus >= 0);

UPDATE public.gateway_keys
   SET user_id = (SELECT id FROM public.users WHERE login = 'owner')
 WHERE user_id IS NULL;

ALTER TABLE public.gateway_keys ALTER COLUMN user_id SET NOT NULL;

-- 支撑按用户列出名下 key。
CREATE INDEX IF NOT EXISTS idx_gateway_keys_user
    ON public.gateway_keys (user_id);
