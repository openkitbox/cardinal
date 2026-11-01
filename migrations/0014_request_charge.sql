-- 0014_request_charge.sql
-- 每个 attempt 行记录扣费快照:rate_bp = 请求当时调用方的有效倍率(用户覆盖优先于组),
-- charged_microus = 该 attempt 应扣金额(micro-USD,ceil(cost × rate / 10000))。
-- 两列均可 NULL:
--   - 进程内直调(无调用方)两列均为 NULL;
--   - 有调用方时 rate_bp 总有值;charged_microus 只出现在成功 attempt 上,
--     失败 attempt 或无 usage(certainty 为 unknown)的成功 attempt 为 NULL,表示不扣费。
--   - 倍率为 0 的免费用户成功行 charged_microus = 0。
-- 不另加 estimated 列:usage 是否为本地估算可由 protocol = 'kiro' 推导
-- (protocol 存上游协议,Kiro 的 token 数是本地估算)。
ALTER TABLE public.gateway_requests
    ADD COLUMN IF NOT EXISTS charged_microus bigint,
    ADD COLUMN IF NOT EXISTS rate_bp bigint;
