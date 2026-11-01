-- 0015_key_terms.sql
-- gateway key 条款:过期时间与额度(0012 已落列)开始生效,label 改为每个用户内唯一。

-- label 只需在同一用户名下唯一:全局唯一会让 A 用户因 B 用户占用了某个 label
-- 而建 key 失败,并可借 409 探测别人的 label。账本按 gateway_key_id 关联 key,
-- caller_key 里的 label 只用于展示。
DROP INDEX IF EXISTS public.gateway_keys_label_unique;
CREATE UNIQUE INDEX IF NOT EXISTS gateway_keys_user_label_unique
    ON public.gateway_keys USING btree (user_id, label);

-- 额度执行用计数列:spent_microus = 该 key 全部 charge 条目金额的绝对值之和,
-- 只与 billing_entries 同一事务更新(与 users.balance_microus 同一种约束)。
-- 鉴权时直接读它,不对账本求和。quota_microus 为累计上限,不按周期重置。
ALTER TABLE public.gateway_keys
    ADD COLUMN IF NOT EXISTS spent_microus bigint NOT NULL DEFAULT 0 CHECK (spent_microus >= 0);

-- charge 条目记录扣费所用的 key,用于核对 spent_microus;其余条目为 NULL。
ALTER TABLE public.billing_entries
    ADD COLUMN IF NOT EXISTS gateway_key_id bigint REFERENCES public.gateway_keys(id);

-- 回填:同一 request_id 的所有 attempt 都用同一个 key,取任意一行即可。
UPDATE public.billing_entries e
   SET gateway_key_id = (SELECT r.gateway_key_id
                           FROM public.gateway_requests r
                          WHERE r.request_id = e.request_id
                            AND r.gateway_key_id IS NOT NULL
                          LIMIT 1)
 WHERE e.kind = 'charge'
   AND e.gateway_key_id IS NULL
   AND e.request_id IS NOT NULL;

-- charge 金额为负,spent 取绝对值。
UPDATE public.gateway_keys k
   SET spent_microus = s.spent
  FROM (SELECT gateway_key_id, -SUM(amount_microus)::bigint AS spent
          FROM public.billing_entries
         WHERE kind = 'charge' AND gateway_key_id IS NOT NULL
         GROUP BY gateway_key_id) s
 WHERE k.id = s.gateway_key_id;
