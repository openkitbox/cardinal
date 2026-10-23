-- 0006_quota_overrides.sql
-- 每账号配额覆盖：厂商探测补不出来的字段由用户锚定。当前唯一键：
--   monthly_reset_day — 月度窗口的 UTC 重置日（1-28），如订阅月每月 15 号重置
--   就填 {"monthly_reset_day": 15}；探测在月窗口缺 resets_at 时据此推算。
ALTER TABLE public.gateway_provider_keys ADD COLUMN IF NOT EXISTS quota_overrides jsonb;
