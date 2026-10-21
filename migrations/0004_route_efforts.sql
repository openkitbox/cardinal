-- 0004_route_efforts.sql
-- 路由层固定对外 effort 档位。NULL = legacy(成员快照交集派生);
-- '[]' = 显式无 reasoning 变体;非空数组 = 固定列表(规范名,升序,展示顺序)。
ALTER TABLE public.gateway_routes ADD COLUMN IF NOT EXISTS efforts jsonb;
