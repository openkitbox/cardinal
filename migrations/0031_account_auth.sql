-- Add portal identity without provisioning credentials for existing billing users.
CREATE TABLE public.account_credentials (
    user_id bigint PRIMARY KEY REFERENCES public.users(id) ON DELETE CASCADE,
    email text NOT NULL UNIQUE CHECK (
        email <> ''
        AND email = btrim(email, E' \t\n\r')
        AND email = lower(email COLLATE "C")
    ),
    password_hash text NOT NULL CHECK (password_hash <> ''),
    password_version bigint NOT NULL DEFAULT 0 CHECK (password_version >= 0)
);

-- A NULL user_id represents registration; resets bind to an existing account.
CREATE TABLE public.account_challenges (
    token_digest bytea PRIMARY KEY CHECK (octet_length(token_digest) = 32),
    email text NOT NULL CHECK (
        email <> ''
        AND email = btrim(email, E' \t\n\r')
        AND email = lower(email COLLATE "C")
    ),
    user_id bigint REFERENCES public.account_credentials(user_id) ON DELETE CASCADE,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz
);
CREATE INDEX account_challenges_user ON public.account_challenges (user_id)
    WHERE user_id IS NOT NULL;

-- A NULL key_id represents account auth, never a deleted Key. Deleting a
-- Key cascades its sessions rather than broadening their scope to the account.
CREATE TABLE public.portal_sessions (
    token_digest bytea PRIMARY KEY CHECK (octet_length(token_digest) = 32),
    user_id bigint NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    key_id bigint REFERENCES public.gateway_keys(id) ON DELETE CASCADE,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz
);
CREATE INDEX portal_sessions_user ON public.portal_sessions (user_id);
CREATE INDEX portal_sessions_key ON public.portal_sessions (key_id)
    WHERE key_id IS NOT NULL;
