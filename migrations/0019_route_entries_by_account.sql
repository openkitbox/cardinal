-- 0019_route_entries_by_account.sql
-- 路由条目改回以账号为单位:每个 entries 元素的 provider_id 换成账号 key_id,
-- 一个条目 = 一个账号(gateway_provider_keys 行) × 一个模型,派发不再把一个条目展开成
-- 该 provider 的全部账号。0016 的逆形状改写(注意不是严格的逆变换:0016 按
-- (provider, model) 去重时丢掉的信息无法恢复,这里按 (key_id, model) 重新展开)。

-- 重写规则:
--   * 只改写仍含 provider 形状元素(key_id 不是 JSON number、provider_id 是 JSON number)的
--     路由:已是 {key_id, ...} 的元素原样保留,混合数组里两种元素可以并存,重复执行也
--     不会再改写(改写只会产出数字 key_id,第二次执行就找不到符合条件的元素);
--   * provider 形状的元素展开成该 provider 每个未归档账号(archived_at IS NULL)一条;
--     已归档账号不展开(它们本来就不参与派发),未归档但停用的账号照样展开
--     (停用是可逆状态,随时可能重新启用);
--   * 展开顺序 = 该 provider 的 (position, id);
--   * 每个展开元素 = 原元素去掉 provider_id、加上 key_id,label / max_concurrency /
--     rules / active_window 逐字复制;
--   * 同一路由内 (key_id, model) 重复时只保留数组中第一次出现的元素(原数组位置在前的
--     先出现,同一元素内按账号顺序在前者先出现),其余重复元素连同其字段丢弃;
--   * 保留元素在数组中的相对顺序:先原数组下标(WITH ORDINALITY),再元素内账号顺序;
--   * provider 一个未归档账号都没有时该元素丢弃(等价于「条目解析为零候选」);
--   * 既没有 key_id 也没有 provider_id 的元素原样保留(无法归类的内容不改写);
--   * 元素全部丢弃的路由写成 '[]',保留别名以便重新指向;
--   * entries 不是 JSON 数组的路由不参与改写(jsonb_array_elements 对非数组会报错,
--     那会中断网关启动)。
WITH elements AS (
    SELECT r.alias,
           e.ord,
           e.entry,
           -- 类型判断放在 CASE 里:Postgres 不保证 AND/OR 的求值顺序,
           -- 比较走 numeric,小数或超范围的 id 也不会抛转型错误。
           -- jsonb_typeof 对缺失的键返回 NULL,所以用 IS NOT DISTINCT FROM 'number'
           -- 判成 false,免得 NOT ... 在 NULL 上又变成 NULL 把元素漏掉。
           jsonb_typeof(e.entry->'key_id') IS NOT DISTINCT FROM 'number' AS is_account_entry,
           CASE
               WHEN jsonb_typeof(e.entry->'provider_id') = 'number'
                   THEN (e.entry->>'provider_id')::numeric
           END AS provider_id
      FROM public.gateway_routes r
     CROSS JOIN LATERAL jsonb_array_elements(
             CASE WHEN jsonb_typeof(r.entries) = 'array' THEN r.entries ELSE '[]'::jsonb END
         ) WITH ORDINALITY AS e(entry, ord)
),
expanded AS (
    -- 已是账号形状的元素原样保留,元素内顺序占 0。
    SELECT alias, ord, 0 AS sub, entry
      FROM elements
     WHERE is_account_entry
    UNION ALL
    -- provider 形状的元素展开成它的每个未归档账号。
    SELECT el.alias,
           el.ord,
           row_number() OVER (PARTITION BY el.alias, el.ord ORDER BY k.position, k.id) AS sub,
           (el.entry - 'provider_id') || jsonb_build_object('key_id', k.id) AS entry
      FROM elements el
      JOIN public.gateway_provider_keys k
        ON k.provider_id = el.provider_id
       AND k.archived_at IS NULL
     WHERE NOT el.is_account_entry
       AND el.provider_id IS NOT NULL
    UNION ALL
    -- 两种 id 都没有的元素原样保留。
    SELECT alias, ord, 0, entry
      FROM elements
     WHERE NOT is_account_entry
       AND provider_id IS NULL
),
ranked AS (
    -- 同一路由内 (key_id, model) 去重保首个;没有 key_id 的元素不参与去重。
    SELECT alias, ord, sub, entry,
           CASE
               WHEN entry ? 'key_id'
                   THEN row_number() OVER (
                            PARTITION BY alias, entry->>'key_id', entry->>'model'
                            ORDER BY ord, sub
                        )
               ELSE 1
           END AS rn
      FROM expanded
),
rebuilt AS (
    SELECT alias, jsonb_agg(entry ORDER BY ord, sub) AS entries
      FROM ranked
     WHERE rn = 1
     GROUP BY alias
)
UPDATE public.gateway_routes r
   SET entries = COALESCE((SELECT b.entries FROM rebuilt b WHERE b.alias = r.alias), '[]'::jsonb)
 WHERE CASE WHEN jsonb_typeof(r.entries) = 'array'
            THEN EXISTS (
                    SELECT 1
                      FROM jsonb_array_elements(r.entries) AS x
                     WHERE jsonb_typeof(x->'key_id') IS DISTINCT FROM 'number'
                       AND jsonb_typeof(x->'provider_id') = 'number'
                 )
            ELSE false END;
