-- 0020_key_rest_on_429.sql
-- 账号级「429 不冷却」开关:rest_on_429 = FALSE 的账号收到上游 429 短限流
-- (relay::failover::Failure::Rate)时不再写入冷却(rest_cache),改为原地重试该账号;
-- Quota/Credit/Unserved/Other 等其它失败类别的冷却不受影响。
-- 只对 Kiro 账号开放修改(store::patch_provider_key 校验 provider 协议),
-- 默认 TRUE = 既有行为,既有行无需回填。
ALTER TABLE gateway_provider_keys
    ADD COLUMN rest_on_429 BOOLEAN NOT NULL DEFAULT TRUE;
