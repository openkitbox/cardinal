-- 0008_gateway_key_label_unique.sql
-- gateway_keys.last_used_at 是账本的派生值(max(gateway_requests.ts) 按 caller_key=label),
-- 不再单独持久化,避免每个请求写一次库且与账本漂移。
-- 账本只记 label,所以 label 必须唯一才能对应到单个 key。
ALTER TABLE public.gateway_keys DROP COLUMN IF EXISTS last_used_at;

-- 既有重名:每组保留 id 最小的原名,其余追加 -<id>。
UPDATE public.gateway_keys k
   SET label = k.label || '-' || k.id
 WHERE k.id <> (SELECT min(d.id) FROM public.gateway_keys d WHERE d.label = k.label);

CREATE UNIQUE INDEX IF NOT EXISTS gateway_keys_label_unique
    ON public.gateway_keys USING btree (label);

-- 支撑按 caller 取最近一次请求时间。
CREATE INDEX IF NOT EXISTS idx_gateway_requests_caller_ts
    ON public.gateway_requests USING btree (caller_key, ts DESC);
