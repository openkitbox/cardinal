-- 0013_request_user.sql
-- 账本按 id 关联调用方:user_id = key 的归属用户,gateway_key_id = 调用所用 key。
-- caller_key(key label)保留,只作展示与分组(GUI 的 User 维度),不再作鉴权或计费依据。
-- 不加外键:账本是历史,删除用户或 key 既不级联删除账本,也不应被账本阻塞。
-- 进程内直调(无 HTTP 鉴权)的行两列均为 NULL。
ALTER TABLE public.gateway_requests
    ADD COLUMN IF NOT EXISTS user_id bigint,
    ADD COLUMN IF NOT EXISTS gateway_key_id bigint;

-- 回填历史:label 自 0008 起唯一,caller_key = label 可唯一对应到 key。
-- 匹配不到的行(loopback 匿名、cardinal-xxx 自命名、已改名或已删除的 key)保持 NULL。
UPDATE public.gateway_requests r
   SET user_id = k.user_id, gateway_key_id = k.id
  FROM public.gateway_keys k
 WHERE r.caller_key = k.label
   AND r.gateway_key_id IS NULL;

-- 支撑用户自助用量:按 user_id 汇总名下全部 key 在时间窗内的请求。
CREATE INDEX IF NOT EXISTS idx_gateway_requests_user_ts
    ON public.gateway_requests USING btree (user_id, ts DESC);

-- 支撑 key 列表的 last_used_at(每个 key 取 max(ts)):走索引首行,不扫账本。
CREATE INDEX IF NOT EXISTS idx_gateway_requests_gateway_key_ts
    ON public.gateway_requests USING btree (gateway_key_id, ts DESC);
