-- 0010_balance_history.sql
-- 预付费余额历史：只在余额变化时追加一行（探测值不变不写）。
-- 余额上升（充值或退款）开启新的"段"（opens_segment = true，topup 记增量下限）；
-- 首条记录也开段（topup 为 NULL）。GUI 只画当前段：已用比例 = (段首余额 − 当前余额) / 段首余额。
-- 清理只删除早于当前段起点、且超过 45 天的旧段行；当前段整段保留（只在变化时写，行数有界）。
CREATE TABLE IF NOT EXISTS public.gateway_key_balance_history (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    key_id bigint NOT NULL REFERENCES public.gateway_provider_keys(id) ON DELETE CASCADE,
    amount double precision NOT NULL,
    opens_segment boolean NOT NULL,
    topup double precision,
    probed_at timestamp with time zone DEFAULT now() NOT NULL
);

-- 支撑按 key 取最新一行（写入前的比较）与按时间降采样。
CREATE INDEX IF NOT EXISTS idx_gateway_key_balance_history_key
    ON public.gateway_key_balance_history USING btree (key_id, probed_at DESC);

-- 支撑按 key 取当前段的开段行。
CREATE INDEX IF NOT EXISTS idx_gateway_key_balance_history_segment
    ON public.gateway_key_balance_history USING btree (key_id, probed_at DESC)
    WHERE opens_segment;
