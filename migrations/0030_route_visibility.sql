ALTER TABLE public.users
    ADD COLUMN IF NOT EXISTS route_aliases text[];

ALTER TABLE public.gateway_keys
    ADD COLUMN IF NOT EXISTS route_aliases text[];
