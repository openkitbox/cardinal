-- 0009_key_groups.sql
-- 账号分组:分组与账号是多对多,成员关系只存在分组一侧(关联表),
-- 账号表不带分组列,因此没有两处数据可以漂移。
-- 删除分组或删除账号都由外键 CASCADE 清掉关系行,互不影响对方本身。
-- 分组名全局唯一;CHECK 是规整后的最后一道防线(去首尾空白、1-32 字符)。
CREATE TABLE IF NOT EXISTS public.gateway_key_groups (
    id   bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name text NOT NULL UNIQUE CHECK (name = btrim(name) AND char_length(name) BETWEEN 1 AND 32)
);

CREATE TABLE IF NOT EXISTS public.gateway_key_group_members (
    group_id bigint NOT NULL REFERENCES public.gateway_key_groups(id) ON DELETE CASCADE,
    key_id   bigint NOT NULL REFERENCES public.gateway_provider_keys(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, key_id)
);

-- 支撑按账号取其全部分组,以及删账号时的级联清理。
CREATE INDEX IF NOT EXISTS idx_gateway_key_group_members_key
    ON public.gateway_key_group_members (key_id);
