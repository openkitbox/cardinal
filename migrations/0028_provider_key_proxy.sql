-- Per-account egress proxy endpoint (https://host:port or socks5://host:port,
-- optionally with credentials). NULL = no proxy, which preserves the existing
-- direct-egress behaviour for every pre-existing row. The URL may carry a
-- password, so it is stored verbatim but never projected onto any API view.
ALTER TABLE gateway_provider_keys
    ADD COLUMN IF NOT EXISTS proxy_url text;
