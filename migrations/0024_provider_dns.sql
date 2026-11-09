ALTER TABLE gateway_providers
    ADD COLUMN IF NOT EXISTS dns text NOT NULL DEFAULT 'overseas';

ALTER TABLE gateway_providers
    DROP CONSTRAINT IF EXISTS gateway_providers_dns_check;
ALTER TABLE gateway_providers
    ADD CONSTRAINT gateway_providers_dns_check CHECK (dns IN ('overseas', 'domestic'));

-- Preserve the historical domestic resolver choice for known domestic vendors.
UPDATE gateway_providers
SET dns = 'domestic'
WHERE substring(base_url from '^https?://([^/:]+)') ~
    '(^|\.)(bigmodel\.cn|deepseek\.com|moonshot\.cn|kimi\.com)$';
