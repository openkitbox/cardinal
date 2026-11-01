-- 0011_key_archive.sql
-- 账号归档:archived_at 为 NULL = 未归档,非 NULL = 归档时间。
-- 归档与 enabled、分组成员关系相互独立:归档不改 enabled,也不动分组关联行。
-- 只由账号 PATCH 写入(归档写 now() 且保留首次归档时间,取消归档写 NULL)。
ALTER TABLE public.gateway_provider_keys ADD COLUMN IF NOT EXISTS archived_at timestamptz;
