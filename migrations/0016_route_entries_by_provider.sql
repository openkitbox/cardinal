-- 0016_route_entries_by_provider.sql
-- 路由条目改为引用 provider 而非单个 key:每个 entries 元素的 key_id 换成该 key 所属的
-- provider_id,调度时一个条目展开为该 provider 的全部可用 key。

-- 重写规则:
--   * 元素的 provider 取它已有的 provider_id;没有才回落到 key_id 所属 key 的 provider_id
--     (已是新格式的元素原样保留,混合数组里两种元素可以并存);
--   * 既没有 provider_id、key_id 也已不存在的元素丢弃(与旧的删 key 级联语义一致);
--   * 同一路由内 (provider_id, model) 重复时只保留数组中第一次出现的元素,
--     连同其 label / max_concurrency / rules / active_window,其余重复元素的这些字段直接丢弃;
--   * 保留元素在数组中的原有顺序(WITH ORDINALITY);
--   * 元素全部丢弃的路由写成 '[]',保留别名以便重新指向。
--   * entries 不是 JSON 数组的路由不参与改写(jsonb_array_elements 对非数组会报错,
--     那会中断网关启动)。
WITH expanded AS (
    SELECT r.alias,
           e.ord,
           COALESCE((e.entry->>'provider_id')::bigint, k.provider_id) AS provider_id,
           (e.entry - 'key_id')
             || jsonb_build_object(
                    'provider_id',
                    COALESCE((e.entry->>'provider_id')::bigint, k.provider_id)
                ) AS entry,
           e.entry->>'model' AS model
      FROM public.gateway_routes r
     CROSS JOIN LATERAL jsonb_array_elements(r.entries) WITH ORDINALITY AS e(entry, ord)
      -- LEFT: an element already carrying provider_id has no key_id to join on,
      -- and must survive the rewrite untouched.
      LEFT JOIN public.gateway_provider_keys k ON k.id = (e.entry->>'key_id')::bigint
     WHERE jsonb_typeof(r.entries) = 'array'
),
resolved AS (
    SELECT alias, ord, provider_id, model, entry
      FROM expanded
     WHERE provider_id IS NOT NULL
),
ranked AS (
    SELECT alias, ord, entry,
           row_number() OVER (PARTITION BY alias, provider_id, model ORDER BY ord) AS rn
      FROM resolved
),
rebuilt AS (
    SELECT alias, jsonb_agg(entry ORDER BY ord) AS entries
      FROM ranked
     WHERE rn = 1
     GROUP BY alias
)
-- 只改写仍含 key_id 元素的路由:已是 '[]' 的路由不动,重复执行也不会误删条目。
UPDATE public.gateway_routes r
   SET entries = COALESCE((SELECT b.entries FROM rebuilt b WHERE b.alias = r.alias), '[]'::jsonb)
 WHERE jsonb_typeof(r.entries) = 'array'
   AND EXISTS (SELECT 1 FROM jsonb_array_elements(r.entries) AS x WHERE x ? 'key_id');
