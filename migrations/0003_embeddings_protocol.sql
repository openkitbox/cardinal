-- Retrieval API protocol (`openai_embeddings`, served at POST /v1/embeddings).
--
-- The provider-protocol CHECK constraint is the closed set of upstream
-- dialects a provider row may declare. Adding a protocol value is an explicit
-- schema change, exactly like adding a ProtocolId variant is an explicit code
-- change: the constraints in 0001 are replaced, never extended by omission.
--
-- `gateway_requests.protocol` deliberately has no CHECK: it records whatever a
-- row was served with, including values older builds no longer produce.

ALTER TABLE public.gateway_providers
    DROP CONSTRAINT IF EXISTS gateway_providers_protocol_check;

ALTER TABLE public.gateway_providers
    ADD CONSTRAINT gateway_providers_protocol_check
    CHECK (protocol = ANY (ARRAY[
        'anthropic_messages'::text,
        'openai_chat'::text,
        'openai_responses'::text,
        'gemini'::text,
        'openai_embeddings'::text
    ]));
