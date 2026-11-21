-- 0033_payment.sql
-- Online top-up orders and the idempotency ledger for Xiaodou callbacks.
-- Gateway owns the money: the fixed FX snapshot on each order is the only
-- source of the USD micro amount credited to the user's ledger.

CREATE TABLE public.payment_orders (
    id                      bigserial PRIMARY KEY,
    out_trade_no            text NOT NULL UNIQUE CHECK (out_trade_no <> ''),
    user_id                 bigint NOT NULL REFERENCES public.users(id),
    amount_fen              bigint NOT NULL CHECK (amount_fen > 0),
    currency                text NOT NULL DEFAULT 'CNY' CHECK (currency = 'CNY'),
    usd_micros_per_cny_fen  bigint NOT NULL CHECK (usd_micros_per_cny_fen > 0),
    credit_usd_micros       bigint NOT NULL CHECK (credit_usd_micros > 0),
    channel                 text NOT NULL CHECK (channel <> ''),
    status                  text NOT NULL DEFAULT 'CREATED'
        CHECK (status IN ('CREATED', 'PAYING', 'SUCCEEDED', 'CLOSED', 'FAILED', 'UNKNOWN')),
    open_order_id           text,
    pay_url                 text,
    qr_code                 text,
    expire_at               timestamptz,
    fee_projection          jsonb
        CHECK (fee_projection IS NULL OR jsonb_typeof(fee_projection) = 'object'),
    request_id              text NOT NULL CHECK (request_id <> ''),
    created_at              timestamptz NOT NULL DEFAULT now(),
    updated_at              timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX payment_orders_user_id_desc ON public.payment_orders (user_id, id DESC);
CREATE INDEX payment_orders_status ON public.payment_orders (status);

-- eventId is the sole idempotency key. order_id is nullable so a callback
-- arriving before its order row can still be recorded for reconciliation.
CREATE TABLE public.payment_events (
    event_id       text PRIMARY KEY CHECK (event_id <> ''),
    event_type     text NOT NULL CHECK (event_type <> ''),
    payload        jsonb NOT NULL DEFAULT '{}'::jsonb
        CHECK (jsonb_typeof(payload) = 'object'),
    headers_digest text NOT NULL CHECK (headers_digest <> ''),
    order_id       bigint REFERENCES public.payment_orders(id),
    received_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX payment_events_order_id_received ON public.payment_events (order_id, received_at);

CREATE TABLE public.payment_refunds (
    id            bigserial PRIMARY KEY,
    out_refund_no text NOT NULL UNIQUE CHECK (out_refund_no <> ''),
    order_id      bigint NOT NULL REFERENCES public.payment_orders(id),
    amount_fen    bigint NOT NULL CHECK (amount_fen > 0),
    status        text NOT NULL DEFAULT 'PENDING'
        CHECK (status IN ('PENDING', 'SUCCEEDED', 'FAILED')),
    request_id    text NOT NULL CHECK (request_id <> ''),
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX payment_refunds_order_id ON public.payment_refunds (order_id);

-- The charge-only index from 0012 does not protect top-ups or refunds. A
-- payment request id (outTradeNo / outRefundNo) must never move money twice,
-- even if a caller bypasses the event or refund status gate.
CREATE UNIQUE INDEX billing_entries_payment_request
    ON public.billing_entries (request_id)
    WHERE kind IN ('topup', 'refund') AND request_id IS NOT NULL;
