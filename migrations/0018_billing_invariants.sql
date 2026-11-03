-- 0018_billing_invariants.sql
-- 把计费的三条不变量从 HTTP 边缘下沉到 schema:倍率上界、charge 行形状、
-- 按组查用户。Rust 侧仍是这些量的所有者,DB 只是兜底——绕过 admin 校验的
-- 写入(手工 SQL、未来新增的写路径、迁移脚本)也不该能造出无法结算的账。

-- 0012 只约束了 rate_bp >= 0,上界一直只活在 admin 的 400 校验里。越界倍率
-- 会让 charge_microus 的乘积饱和到 i64::MAX,结算再把该笔扣费当"溢出"丢弃:
-- 结果不是收贵了,是这笔应收白送。上界 1000000 与 billing::MAX_RATE_BP
-- 同源(即 100×),常量归 Rust 所有,这里只做同一数值的兜底。
-- 按命名规则自动加的旧 CHECK(user_groups_rate_bp_check)先删再换名,
-- 避免两条同义约束并存。
ALTER TABLE public.user_groups DROP CONSTRAINT IF EXISTS user_groups_rate_bp_check;
ALTER TABLE public.user_groups ADD CONSTRAINT user_groups_rate_bp_range
    CHECK (rate_bp BETWEEN 0 AND 1000000);

-- 用户级倍率是对组倍率的覆盖,NULL 表示沿用组倍率,所以没值时不受上界约束;
-- 有值时与组倍率同一个 [0, 1000000] 区间和同一个 MAX_RATE_BP 依据。
ALTER TABLE public.users DROP CONSTRAINT IF EXISTS users_rate_bp_check;
ALTER TABLE public.users ADD CONSTRAINT users_rate_bp_range
    CHECK (rate_bp IS NULL OR rate_bp BETWEEN 0 AND 1000000);

-- charge 行的幂等完全依赖 request_id:部分唯一索引
-- billing_entries_charge_request(0012)以它为键去重。request_id 可空,则一条
-- 无键的 charge 既无法去重、也让"这笔钱对应哪个请求"无从追溯。金额符号同理:
-- charge 必须是负值(0012 表注释),正数 charge 等于凭空发钱。
ALTER TABLE public.billing_entries ADD CONSTRAINT billing_entries_charge_shape
    CHECK (kind <> 'charge' OR (request_id IS NOT NULL AND amount_microus < 0));

-- 账本里的倍率快照是"当时实际用的倍率",超过 MAX_RATE_BP 说明写入方绕过了
-- 校验;这类历史行会让对账算不平,宁可在写入时就拒绝。
ALTER TABLE public.billing_entries ADD CONSTRAINT billing_entries_rate_bp_range
    CHECK (rate_bp IS NULL OR rate_bp BETWEEN 0 AND 1000000);

-- list_groups / get_group 每个组跑一次 COUNT(*) FROM users WHERE group_id = ...,
-- 组的更新/删除又要按同一列做 FK 校验;此前 users 上只有主键与 login 唯一索引,
-- 这两类访问都是全表扫。
CREATE INDEX IF NOT EXISTS idx_users_group_id ON public.users (group_id);
