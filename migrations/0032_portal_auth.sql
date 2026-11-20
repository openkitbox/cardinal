-- Portal configuration and external login identities. The database is the
-- source of truth for mail transport and OAuth credentials; provider endpoints
-- stay code constants so the admin surface cannot be turned into an SSRF proxy.

-- Singleton row: `id = true` makes a second configuration row impossible.
CREATE TABLE public.portal_settings (
    id            boolean PRIMARY KEY DEFAULT true CHECK (id),
    mail_transport text NOT NULL DEFAULT 'http' CHECK (mail_transport IN ('http', 'smtp')),
    mail_url       text NOT NULL DEFAULT '',
    mail_token     text NOT NULL DEFAULT '',
    mail_from      text NOT NULL DEFAULT '',
    mail_origin    text NOT NULL DEFAULT '',
    smtp_host      text NOT NULL DEFAULT '',
    smtp_port      int NOT NULL DEFAULT 587 CHECK (smtp_port BETWEEN 1 AND 65535),
    smtp_username  text NOT NULL DEFAULT '',
    smtp_password  text NOT NULL DEFAULT '',
    smtp_tls       text NOT NULL DEFAULT 'starttls' CHECK (smtp_tls IN ('none', 'starttls', 'tls')),
    smtp_from      text NOT NULL DEFAULT '',
    updated_at     timestamptz NOT NULL DEFAULT now()
);
INSERT INTO public.portal_settings (id) VALUES (true) ON CONFLICT DO NOTHING;

-- `extra` holds non-secret, provider-specific settings (for example a dev-only
-- endpoint override); no authorize/token/userinfo URL is stored here.
CREATE TABLE public.auth_providers (
    provider      text PRIMARY KEY CHECK (provider ~ '^[a-z][a-z0-9_-]*$'),
    client_id     text NOT NULL DEFAULT '',
    client_secret text NOT NULL DEFAULT '',
    redirect_uri  text NOT NULL DEFAULT '',
    enabled       boolean NOT NULL DEFAULT false,
    extra         jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(extra) = 'object'),
    updated_at    timestamptz NOT NULL DEFAULT now()
);

-- No FK on provider: deleting a provider removes its login entry but must not
-- invalidate identities users already have.
CREATE TABLE public.account_oauth_identities (
    provider   text NOT NULL CHECK (provider ~ '^[a-z][a-z0-9_-]*$'),
    subject    text NOT NULL CHECK (subject <> ''),
    user_id    bigint NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    email      text NOT NULL CHECK (
        email <> ''
        AND email = btrim(email, E' \t\n\r')
        AND email = lower(email COLLATE "C")
    ),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (provider, subject)
);
CREATE INDEX account_oauth_identities_user ON public.account_oauth_identities (user_id);
