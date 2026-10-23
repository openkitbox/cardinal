-- 0005_quota_history.sql
-- 配额探测历史：每次成功探测按窗口追加一行，供账号卡片的累计用量走势图读取。
-- 快照表（gateway_key_quota_snapshots）只有每 key 的最新一行，无法画历史。
CREATE TABLE IF NOT EXISTS public.gateway_key_quota_history (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    key_id bigint NOT NULL REFERENCES public.gateway_provider_keys(id) ON DELETE CASCADE,
    window_name text NOT NULL,
    used_pct double precision NOT NULL,
    resets_at timestamp with time zone,
    probed_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_gateway_key_quota_history_key_window
    ON public.gateway_key_quota_history USING btree (key_id, window_name, probed_at DESC);
