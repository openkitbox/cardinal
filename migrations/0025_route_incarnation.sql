-- Stable identity distinguishes a recreated alias even if cache reloads coalesce.
ALTER TABLE gateway_routes ADD COLUMN incarnation bigint GENERATED ALWAYS AS IDENTITY;
