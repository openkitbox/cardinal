-- Route-level display note (备注): a short admin-facing remark shown on the
-- route's header row in the GUI. Pure metadata — the relay resolution path
-- never reads it; it rides the admin bootstrap document only.
ALTER TABLE public.gateway_routes ADD COLUMN IF NOT EXISTS note text;
