//! Payment persistence: orders, webhook events and refunds.
//!
//! This module owns every SQL statement and row lock in the payment path.
//! Handlers pass typed inputs and receive typed rows; they never write money
//! or status directly. The `*_in_tx` primitives let the orchestration layer
//! put event de-duplication, status promotion, ledger insertion and the
//! balance update in one caller-owned transaction.

use jiff::Timestamp;
use jiff_sqlx::ToSqlx;
use serde_json::Value;
use sqlx::types::Json;
use sqlx::{PgConnection, PgPool};

use super::{CreditError, credit_in_tx};

macro_rules! order_columns {
    () => {
        "id, out_trade_no, user_id, amount_fen, currency, usd_micros_per_cny_fen, \
         credit_usd_micros, channel, status, open_order_id, pay_url, qr_code, expire_at, \
         fee_projection, request_id, created_at, updated_at"
    };
}

macro_rules! refund_columns {
    () => {
        "id, out_refund_no, order_id, amount_fen, status, request_id, created_at, updated_at"
    };
}

/// One payment order. `credit_usd_micros` is the FX snapshot taken at order
/// creation and is the only amount the ledger may credit for this order.
#[derive(Clone)]
pub struct PaymentOrderRow {
    pub id: i64,
    pub out_trade_no: String,
    pub user_id: i64,
    pub amount_fen: i64,
    pub currency: String,
    pub usd_micros_per_cny_fen: i64,
    pub credit_usd_micros: i64,
    pub channel: String,
    pub status: String,
    pub open_order_id: Option<String>,
    pub pay_url: Option<String>,
    pub qr_code: Option<String>,
    pub expire_at: Option<Timestamp>,
    pub fee_projection: Option<Json<Value>>,
    pub request_id: String,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

impl std::fmt::Debug for PaymentOrderRow {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PaymentOrderRow")
            .field("id", &self.id)
            .field("out_trade_no", &self.out_trade_no)
            .field("user_id", &self.user_id)
            .field("amount_fen", &self.amount_fen)
            .field("currency", &self.currency)
            .field("usd_micros_per_cny_fen", &self.usd_micros_per_cny_fen)
            .field("credit_usd_micros", &self.credit_usd_micros)
            .field("channel", &self.channel)
            .field("status", &self.status)
            .field("open_order_id", &self.open_order_id)
            .field("pay_url", &"<redacted>")
            .field("qr_code", &"<redacted>")
            .field("expire_at", &self.expire_at)
            .field("fee_projection", &"<redacted>")
            .field("request_id", &self.request_id)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for PaymentOrderRow {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        use sqlx::Row as _;

        Ok(Self {
            id: row.try_get("id")?,
            out_trade_no: row.try_get("out_trade_no")?,
            user_id: row.try_get("user_id")?,
            amount_fen: row.try_get("amount_fen")?,
            currency: row.try_get("currency")?,
            usd_micros_per_cny_fen: row.try_get("usd_micros_per_cny_fen")?,
            credit_usd_micros: row.try_get("credit_usd_micros")?,
            channel: row.try_get("channel")?,
            status: row.try_get("status")?,
            open_order_id: row.try_get("open_order_id")?,
            pay_url: row.try_get("pay_url")?,
            qr_code: row.try_get("qr_code")?,
            expire_at: row
                .try_get::<Option<jiff_sqlx::Timestamp>, _>("expire_at")?
                .map(|value| value.to_jiff()),
            fee_projection: row.try_get("fee_projection")?,
            request_id: row.try_get("request_id")?,
            created_at: row
                .try_get::<jiff_sqlx::Timestamp, _>("created_at")?
                .to_jiff(),
            updated_at: row
                .try_get::<jiff_sqlx::Timestamp, _>("updated_at")?
                .to_jiff(),
        })
    }
}

/// New order in `CREATED`. `request_id` is the upstream request id kept for
/// retries of the same placement.
#[derive(Debug, Clone, Copy)]
pub struct NewPaymentOrder<'a> {
    pub out_trade_no: &'a str,
    pub user_id: i64,
    pub amount_fen: i64,
    pub usd_micros_per_cny_fen: i64,
    pub credit_usd_micros: i64,
    pub channel: &'a str,
    pub request_id: &'a str,
}

/// Upstream placement response, stored verbatim from the signed response.
#[derive(Clone, Copy)]
pub struct PaymentPlacement<'a> {
    pub open_order_id: &'a str,
    pub pay_url: &'a str,
    pub qr_code: Option<&'a str>,
    pub expire_at: Option<Timestamp>,
    pub fee_projection: &'a Value,
    pub request_id: &'a str,
}

impl std::fmt::Debug for PaymentPlacement<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PaymentPlacement")
            .field("open_order_id", &self.open_order_id)
            .field("pay_url", &"<redacted>")
            .field("qr_code", &"<redacted>")
            .field("expire_at", &self.expire_at)
            .field("fee_projection", &"<redacted>")
            .field("request_id", &self.request_id)
            .finish()
    }
}

/// One raw webhook event. `headers_digest` binds the authenticated header set
/// to the stored payload without keeping signature material.
#[derive(Clone, Copy)]
pub struct NewPaymentEvent<'a> {
    pub event_id: &'a str,
    pub event_type: &'a str,
    pub payload: &'a Value,
    pub headers_digest: &'a str,
    pub out_trade_no: &'a str,
}

impl std::fmt::Debug for NewPaymentEvent<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NewPaymentEvent")
            .field("event_id", &self.event_id)
            .field("event_type", &self.event_type)
            .field("payload", &"<redacted>")
            .field("headers_digest", &self.headers_digest)
            .field("out_trade_no", &self.out_trade_no)
            .finish()
    }
}

/// Stored event, including the resolved local order (if one existed).
#[derive(Clone, sqlx::FromRow)]
pub struct PaymentEventRow {
    pub event_id: String,
    pub event_type: String,
    pub payload: Json<Value>,
    pub headers_digest: String,
    pub order_id: Option<i64>,
    #[sqlx(try_from = "jiff_sqlx::Timestamp")]
    pub received_at: Timestamp,
}

impl std::fmt::Debug for PaymentEventRow {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PaymentEventRow")
            .field("event_id", &self.event_id)
            .field("event_type", &self.event_type)
            .field("payload", &"<redacted>")
            .field("headers_digest", &self.headers_digest)
            .field("order_id", &self.order_id)
            .field("received_at", &self.received_at)
            .finish()
    }
}

/// New refund row. `request_id` is the stable `outRefundNo` request key.
#[derive(Debug, Clone, Copy)]
pub struct NewPaymentRefund<'a> {
    pub out_refund_no: &'a str,
    pub order_id: i64,
    pub amount_fen: i64,
    pub request_id: &'a str,
}

/// One refund attempt.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PaymentRefundRow {
    pub id: i64,
    pub out_refund_no: String,
    pub order_id: i64,
    pub amount_fen: i64,
    pub status: String,
    pub request_id: String,
    #[sqlx(try_from = "jiff_sqlx::Timestamp")]
    pub created_at: Timestamp,
    #[sqlx(try_from = "jiff_sqlx::Timestamp")]
    pub updated_at: Timestamp,
}

/// Everything needed to settle one verified success event. The caller has
/// already verified the signature; this function enforces the storage rules.
#[derive(Clone, Copy)]
pub struct SettlePaymentInput<'a> {
    pub event_id: &'a str,
    pub event_type: &'a str,
    pub payload: &'a Value,
    pub headers_digest: &'a str,
    pub out_trade_no: &'a str,
    pub gross_amount_fen: i64,
    pub note: &'a str,
    pub operator: &'a str,
}

impl std::fmt::Debug for SettlePaymentInput<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SettlePaymentInput")
            .field("event_id", &self.event_id)
            .field("event_type", &self.event_type)
            .field("payload", &"<redacted>")
            .field("headers_digest", &self.headers_digest)
            .field("out_trade_no", &self.out_trade_no)
            .field("gross_amount_fen", &self.gross_amount_fen)
            .field("note", &self.note)
            .field("operator", &self.operator)
            .finish()
    }
}

/// What a success settlement did, as observed inside the caller's transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettleOutcome {
    Credited {
        entry_id: i64,
        balance_after_microus: i64,
    },
    DuplicateEvent,
    AlreadySucceeded,
    AmountMismatch {
        expected_fen: i64,
        received_fen: i64,
    },
    UnknownOrder,
    RefundSettled,
    RefundDuplicateEvent,
    RefundAlreadyTerminal,
    RefundUnknown,
    RefundInvalidStatus,
    RefundAmountMismatch {
        expected_fen: i64,
        received_fen: i64,
    },
}

/// Why a settlement could not be stored.
#[derive(Debug, thiserror::Error)]
pub enum PaymentError {
    #[error("user {0} no longer exists")]
    UnknownUser(i64),
    #[error(transparent)]
    Database(#[from] sqlx::Error),
    #[error(transparent)]
    Credit(#[from] CreditError),
}

/// Insert a `CREATED` order. A taken `out_trade_no` is a database error; the
/// caller must reuse the existing order rather than generate a new one.
pub async fn create_order(
    pool: &PgPool,
    order: NewPaymentOrder<'_>,
) -> Result<PaymentOrderRow, sqlx::Error> {
    sqlx::query_as::<_, PaymentOrderRow>(concat!(
        "INSERT INTO payment_orders
             (out_trade_no, user_id, amount_fen, currency, usd_micros_per_cny_fen,
              credit_usd_micros, channel, status, request_id)
         VALUES ($1, $2, $3, 'CNY', $4, $5, $6, 'CREATED', $7)
         RETURNING ",
        order_columns!()
    ))
    .bind(order.out_trade_no)
    .bind(order.user_id)
    .bind(order.amount_fen)
    .bind(order.usd_micros_per_cny_fen)
    .bind(order.credit_usd_micros)
    .bind(order.channel)
    .bind(order.request_id)
    .fetch_one(pool)
    .await
}

/// One order by id, or `None` when the id is unknown.
pub async fn get_order(pool: &PgPool, id: i64) -> Result<Option<PaymentOrderRow>, sqlx::Error> {
    sqlx::query_as::<_, PaymentOrderRow>(concat!(
        "SELECT ",
        order_columns!(),
        " FROM payment_orders WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(pool)
    .await
}

/// One order by its stable upstream trade number.
pub async fn get_order_by_out_trade_no(
    pool: &PgPool,
    out_trade_no: &str,
) -> Result<Option<PaymentOrderRow>, sqlx::Error> {
    sqlx::query_as::<_, PaymentOrderRow>(concat!(
        "SELECT ",
        order_columns!(),
        " FROM payment_orders WHERE out_trade_no = $1"
    ))
    .bind(out_trade_no)
    .fetch_optional(pool)
    .await
}

impl PaymentOrderRow {
    /// Orders in the closed `from..=to` window, newest id first. Filtering in
    /// SQL keeps a backdated high-id row from hiding an in-window lower-id row.
    pub async fn list_in_window(
        pool: &PgPool,
        from: Timestamp,
        to: Timestamp,
        before_id: Option<i64>,
        limit: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as::<_, Self>(concat!(
            "SELECT ",
            order_columns!(),
            " FROM payment_orders
              WHERE created_at >= $1 AND created_at <= $2
                AND ($3::bigint IS NULL OR id < $3)
              ORDER BY id DESC LIMIT $4"
        ))
        .bind(from.to_sqlx())
        .bind(to.to_sqlx())
        .bind(before_id)
        .bind(limit)
        .fetch_all(pool)
        .await
    }

    async fn get_by_id_in_tx(
        conn: &mut PgConnection,
        id: i64,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as::<_, Self>(concat!(
            "SELECT ",
            order_columns!(),
            " FROM payment_orders WHERE id = $1"
        ))
        .bind(id)
        .fetch_optional(conn)
        .await
    }
}

/// Orders newest first, optionally narrowed to one user and to ids below the
/// cursor. `None` for `user_id` is the admin-wide view.
pub async fn list_orders(
    pool: &PgPool,
    user_id: Option<i64>,
    before_id: Option<i64>,
    limit: i64,
) -> Result<Vec<PaymentOrderRow>, sqlx::Error> {
    sqlx::query_as::<_, PaymentOrderRow>(concat!(
        "SELECT ",
        order_columns!(),
        " FROM payment_orders
          WHERE ($1::bigint IS NULL OR user_id = $1)
            AND ($2::bigint IS NULL OR id < $2)
          ORDER BY id DESC LIMIT $3"
    ))
    .bind(user_id)
    .bind(before_id)
    .bind(limit)
    .fetch_all(pool)
    .await
}

/// Store the placement response and move `CREATED`/`PAYING` to `PAYING`.
/// Returns `false` for an unknown order or one already past `PAYING`.
pub async fn record_placement_in_tx(
    conn: &mut PgConnection,
    out_trade_no: &str,
    placement: PaymentPlacement<'_>,
) -> Result<bool, sqlx::Error> {
    let inserted: Option<i64> = sqlx::query_scalar(
        "UPDATE payment_orders
            SET status = 'PAYING', open_order_id = $2, pay_url = $3, qr_code = $4,
                expire_at = $5, fee_projection = $6, request_id = $7, updated_at = now()
          WHERE out_trade_no = $1 AND status IN ('CREATED', 'PAYING')
          RETURNING id",
    )
    .bind(out_trade_no)
    .bind(placement.open_order_id)
    .bind(placement.pay_url)
    .bind(placement.qr_code)
    .bind(placement.expire_at.map(ToSqlx::to_sqlx))
    .bind(Json(placement.fee_projection))
    .bind(placement.request_id)
    .fetch_optional(conn)
    .await?;
    Ok(inserted.is_some())
}

/// Lock an order row and change its status. The caller owns the state machine;
/// this primitive only guarantees the status read and write are one operation.
pub async fn set_order_status_in_tx(
    conn: &mut PgConnection,
    out_trade_no: &str,
    status: &str,
) -> Result<bool, sqlx::Error> {
    let Some(id) = lock_order_id(conn, out_trade_no).await? else {
        return Ok(false);
    };
    update_order_status(conn, id, status).await?;
    Ok(true)
}

async fn lock_order_id(
    conn: &mut PgConnection,
    out_trade_no: &str,
) -> Result<Option<i64>, sqlx::Error> {
    sqlx::query_scalar("SELECT id FROM payment_orders WHERE out_trade_no = $1 FOR UPDATE")
        .bind(out_trade_no)
        .fetch_optional(conn)
        .await
}

async fn update_order_status(
    conn: &mut PgConnection,
    id: i64,
    status: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE payment_orders SET status = $2, updated_at = now() WHERE id = $1")
        .bind(id)
        .bind(status)
        .execute(conn)
        .await?;
    Ok(())
}

async fn lock_order(
    conn: &mut PgConnection,
    out_trade_no: &str,
) -> Result<Option<PaymentOrderRow>, sqlx::Error> {
    sqlx::query_as::<_, PaymentOrderRow>(concat!(
        "SELECT ",
        order_columns!(),
        " FROM payment_orders WHERE out_trade_no = $1 FOR UPDATE"
    ))
    .bind(out_trade_no)
    .fetch_optional(conn)
    .await
}

/// Insert an event, returning `false` when this `eventId` was already stored.
/// The unique primary key is the de-duplication gate; the insert and any
/// business writes stay in the caller's transaction.
pub async fn record_event_in_tx(
    conn: &mut PgConnection,
    event: &NewPaymentEvent<'_>,
) -> Result<bool, sqlx::Error> {
    let inserted: Option<String> = sqlx::query_scalar(
        "INSERT INTO payment_events
             (event_id, event_type, payload, headers_digest, order_id)
          VALUES ($1, $2, $3::jsonb, $4,
                  (SELECT id FROM payment_orders WHERE out_trade_no = $5))
          ON CONFLICT (event_id) DO NOTHING
          RETURNING event_id",
    )
    .bind(event.event_id)
    .bind(event.event_type)
    .bind(Json(event.payload))
    .bind(event.headers_digest)
    .bind(event.out_trade_no)
    .fetch_optional(conn)
    .await?;
    Ok(inserted.is_some())
}

/// One event by `eventId`, or `None` when it was never received.
pub async fn get_event(
    pool: &PgPool,
    event_id: &str,
) -> Result<Option<PaymentEventRow>, sqlx::Error> {
    sqlx::query_as::<_, PaymentEventRow>(
        "SELECT event_id, event_type, payload, headers_digest, order_id, received_at
           FROM payment_events WHERE event_id = $1",
    )
    .bind(event_id)
    .fetch_optional(pool)
    .await
}

/// Events for one local order, newest first. `None` lists all events.
pub async fn list_events(
    pool: &PgPool,
    order_id: Option<i64>,
    limit: i64,
) -> Result<Vec<PaymentEventRow>, sqlx::Error> {
    sqlx::query_as::<_, PaymentEventRow>(
        "SELECT event_id, event_type, payload, headers_digest, order_id, received_at
           FROM payment_events
          WHERE $1::bigint IS NULL OR order_id = $1
          ORDER BY received_at DESC, event_id DESC LIMIT $2",
    )
    .bind(order_id)
    .bind(limit)
    .fetch_all(pool)
    .await
}

/// Insert a refund row. A taken `out_refund_no` is a database error; the
/// caller must reuse the existing refund instead of retrying with a new one.
pub async fn create_refund_in_tx(
    conn: &mut PgConnection,
    refund: &NewPaymentRefund<'_>,
) -> Result<PaymentRefundRow, sqlx::Error> {
    sqlx::query_as::<_, PaymentRefundRow>(
        "INSERT INTO payment_refunds
             (out_refund_no, order_id, amount_fen, status, request_id)
         VALUES ($1, $2, $3, 'PENDING', $4)
         RETURNING id, out_refund_no, order_id, amount_fen, status, request_id,
                   created_at, updated_at",
    )
    .bind(refund.out_refund_no)
    .bind(refund.order_id)
    .bind(refund.amount_fen)
    .bind(refund.request_id)
    .fetch_one(conn)
    .await
}

/// One refund by its stable number.
pub async fn get_refund(
    pool: &PgPool,
    out_refund_no: &str,
) -> Result<Option<PaymentRefundRow>, sqlx::Error> {
    sqlx::query_as::<_, PaymentRefundRow>(
        "SELECT id, out_refund_no, order_id, amount_fen, status, request_id,
                created_at, updated_at
           FROM payment_refunds WHERE out_refund_no = $1",
    )
    .bind(out_refund_no)
    .fetch_optional(pool)
    .await
}

/// Refunds for one order (or all orders), newest first.
pub async fn list_refunds(
    pool: &PgPool,
    order_id: Option<i64>,
    limit: i64,
) -> Result<Vec<PaymentRefundRow>, sqlx::Error> {
    sqlx::query_as::<_, PaymentRefundRow>(
        "SELECT id, out_refund_no, order_id, amount_fen, status, request_id,
                created_at, updated_at
           FROM payment_refunds
          WHERE $1::bigint IS NULL OR order_id = $1
          ORDER BY id DESC LIMIT $2",
    )
    .bind(order_id)
    .bind(limit)
    .fetch_all(pool)
    .await
}

/// Lock a refund row and store its terminal status.
pub async fn set_refund_status_in_tx(
    conn: &mut PgConnection,
    out_refund_no: &str,
    status: &str,
) -> Result<bool, sqlx::Error> {
    let id: Option<i64> =
        sqlx::query_scalar("SELECT id FROM payment_refunds WHERE out_refund_no = $1 FOR UPDATE")
            .bind(out_refund_no)
            .fetch_optional(&mut *conn)
            .await?;
    let Some(id) = id else {
        return Ok(false);
    };
    sqlx::query("UPDATE payment_refunds SET status = $2, updated_at = now() WHERE id = $1")
        .bind(id)
        .bind(status)
        .execute(conn)
        .await?;
    Ok(true)
}

impl PaymentRefundRow {
    async fn lock_in_tx(
        conn: &mut PgConnection,
        out_refund_no: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as::<_, Self>(concat!(
            "SELECT ",
            refund_columns!(),
            " FROM payment_refunds WHERE out_refund_no = $1 FOR UPDATE"
        ))
        .bind(out_refund_no)
        .fetch_optional(conn)
        .await
    }

    /// Claim one stable refund number in the caller's transaction. A racing
    /// request waits on the unique index and then reads the winner's row, so
    /// neither request can create a second refund number.
    pub async fn ensure_in_tx(
        conn: &mut PgConnection,
        refund: &NewPaymentRefund<'_>,
    ) -> Result<(Self, bool), sqlx::Error> {
        let inserted: Option<Self> = sqlx::query_as::<_, Self>(concat!(
            "INSERT INTO payment_refunds
                 (out_refund_no, order_id, amount_fen, status, request_id)
             VALUES ($1, $2, $3, 'PENDING', $4)
             ON CONFLICT (out_refund_no) DO NOTHING
             RETURNING ",
            refund_columns!()
        ))
        .bind(refund.out_refund_no)
        .bind(refund.order_id)
        .bind(refund.amount_fen)
        .bind(refund.request_id)
        .fetch_optional(&mut *conn)
        .await?;
        if let Some(row) = inserted {
            return Ok((row, true));
        }
        Self::lock_in_tx(conn, refund.out_refund_no)
            .await?
            .map(|row| (row, false))
            .ok_or(sqlx::Error::RowNotFound)
    }

    /// Claim a refund event and apply its terminal verdict in one transaction.
    /// The `eventId` insert is the idempotency gate; a duplicate event or a
    /// refund already in a terminal state never moves money again.
    pub async fn settle_in_tx(
        conn: &mut PgConnection,
        event: &NewPaymentEvent<'_>,
        out_refund_no: &str,
        status: &str,
        amount_fen: i64,
        note: &str,
        operator: &str,
    ) -> Result<SettleOutcome, PaymentError> {
        let status = match status {
            "SUCCEEDED" | "FAILED" => status,
            _ => return Ok(SettleOutcome::RefundInvalidStatus),
        };
        let refund = Self::lock_in_tx(conn, out_refund_no).await?;
        let order = match &refund {
            Some(row) => PaymentOrderRow::get_by_id_in_tx(conn, row.order_id).await?,
            None => None,
        };
        if let Some(refund) = refund
            .as_ref()
            .filter(|_| order.is_some())
            .filter(|refund| refund.amount_fen != amount_fen)
        {
            return Ok(SettleOutcome::RefundAmountMismatch {
                expected_fen: refund.amount_fen,
                received_fen: amount_fen,
            });
        }
        if !record_event_in_tx(conn, event).await? {
            return Ok(SettleOutcome::RefundDuplicateEvent);
        }
        let Some(refund) = refund else {
            return Ok(SettleOutcome::RefundUnknown);
        };
        let Some(order) = order else {
            return Err(sqlx::Error::RowNotFound.into());
        };
        if refund.status == "SUCCEEDED" || refund.status == "FAILED" {
            return Ok(SettleOutcome::RefundAlreadyTerminal);
        }
        set_refund_status_in_tx(conn, out_refund_no, status).await?;
        if status == "SUCCEEDED" {
            let entry = credit_in_tx(
                conn,
                order.user_id,
                "refund",
                -order.credit_usd_micros,
                note,
                operator,
                Some(out_refund_no),
            )
            .await?;
            if entry.is_none() {
                return Err(PaymentError::UnknownUser(order.user_id));
            }
        }
        Ok(SettleOutcome::RefundSettled)
    }
}

/// Settle one verified success event in the caller's transaction: lock the
/// order, reject a mismatched amount, claim the `eventId`, promote the status
/// and write the ledger entry plus balance under the order's FX snapshot.
/// A duplicate event or an already-succeeded order has no side effects.
///
/// The caller decides whether to commit; `AmountMismatch` and `UnknownOrder`
/// are returned for the caller to reject with its own HTTP status.
pub async fn settle_succeeded_payment_in_tx(
    conn: &mut PgConnection,
    input: SettlePaymentInput<'_>,
) -> Result<SettleOutcome, PaymentError> {
    let Some(order) = lock_order(conn, input.out_trade_no).await? else {
        return Ok(SettleOutcome::UnknownOrder);
    };
    if order.status == "SUCCEEDED" {
        return Ok(SettleOutcome::AlreadySucceeded);
    }
    if order.amount_fen != input.gross_amount_fen {
        return Ok(SettleOutcome::AmountMismatch {
            expected_fen: order.amount_fen,
            received_fen: input.gross_amount_fen,
        });
    }
    let event = NewPaymentEvent {
        event_id: input.event_id,
        event_type: input.event_type,
        payload: input.payload,
        headers_digest: input.headers_digest,
        out_trade_no: input.out_trade_no,
    };
    if !record_event_in_tx(conn, &event).await? {
        return Ok(SettleOutcome::DuplicateEvent);
    }
    update_order_status(conn, order.id, "SUCCEEDED").await?;
    let Some(entry) = credit_in_tx(
        conn,
        order.user_id,
        "topup",
        order.credit_usd_micros,
        input.note,
        input.operator,
        Some(&order.out_trade_no),
    )
    .await?
    else {
        return Err(PaymentError::UnknownUser(order.user_id));
    };
    Ok(SettleOutcome::Credited {
        entry_id: entry.id,
        balance_after_microus: entry.balance_after_microus,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const PLANTED_PAY_URL: &str = "https://PLANTED-PAY-URL-SECRET.example/pay";
    const PLANTED_QR_CODE: &str = "PLANTED-QR-CODE-SECRET";
    const PLANTED_PAYLOAD: &str = "PLANTED_PARSED_PAYLOAD_SECRET_SHOULD_NOT_APPEAR";

    fn planted_payload() -> Value {
        serde_json::json!({ "secret": PLANTED_PAYLOAD, "nested": [PLANTED_PAYLOAD] })
    }

    fn test_timestamp() -> Timestamp {
        Timestamp::from_second(1_700_000_000).expect("valid test timestamp")
    }

    fn assert_materials_redacted(output: &str) {
        assert!(
            !output.contains(PLANTED_PAY_URL) && !output.contains(PLANTED_QR_CODE),
            "payment materials leaked into Debug output: {output}"
        );
    }

    fn assert_payload_redacted(output: &str) {
        assert!(
            !output.contains(PLANTED_PAYLOAD),
            "parsed body leaked into Debug output: {output}"
        );
    }

    #[test]
    fn payment_order_row_debug_redacts_pay_url_and_qr_code() {
        let row = PaymentOrderRow {
            id: 7,
            out_trade_no: "ORDER-12345".to_owned(),
            user_id: 42,
            amount_fen: 100,
            currency: "CNY".to_owned(),
            usd_micros_per_cny_fen: 140_000,
            credit_usd_micros: 140_000,
            channel: "ALIPAY_H5".to_owned(),
            status: "PAYING".to_owned(),
            open_order_id: Some("OPEN-12345".to_owned()),
            pay_url: Some(PLANTED_PAY_URL.to_owned()),
            qr_code: Some(PLANTED_QR_CODE.to_owned()),
            expire_at: Some(test_timestamp()),
            fee_projection: Some(Json(planted_payload())),
            request_id: "REQUEST-12345".to_owned(),
            created_at: test_timestamp(),
            updated_at: test_timestamp(),
        };

        let output = format!("{row:?}");

        assert_eq!(output.matches("<redacted>").count(), 3, "{output}");
        assert_materials_redacted(&output);
        assert_payload_redacted(&output);
        assert!(output.contains("ORDER-12345"), "{output}");
    }

    #[test]
    fn payment_placement_debug_redacts_pay_url_and_qr_code() {
        let fee_projection = planted_payload();
        let placement = PaymentPlacement {
            open_order_id: "OPEN-12345",
            pay_url: PLANTED_PAY_URL,
            qr_code: Some(PLANTED_QR_CODE),
            expire_at: Some(test_timestamp()),
            fee_projection: &fee_projection,
            request_id: "REQUEST-12345",
        };

        let output = format!("{placement:?}");

        assert_eq!(output.matches("<redacted>").count(), 3, "{output}");
        assert_materials_redacted(&output);
        assert_payload_redacted(&output);
        assert!(output.contains("OPEN-12345"), "{output}");
    }

    #[test]
    fn new_payment_event_debug_redacts_payload() {
        let payload = planted_payload();
        let event = NewPaymentEvent {
            event_id: "event-12345",
            event_type: "PAYMENT_SUCCEEDED",
            payload: &payload,
            headers_digest: "digest-12345",
            out_trade_no: "ORDER-12345",
        };

        let output = format!("{event:?}");

        assert_eq!(output.matches("<redacted>").count(), 1, "{output}");
        assert_payload_redacted(&output);
        assert!(output.contains("ORDER-12345"), "{output}");
    }

    #[test]
    fn payment_event_row_debug_redacts_payload() {
        let row = PaymentEventRow {
            event_id: "event-12345".to_owned(),
            event_type: "PAYMENT_SUCCEEDED".to_owned(),
            payload: Json(planted_payload()),
            headers_digest: "digest-12345".to_owned(),
            order_id: Some(7),
            received_at: test_timestamp(),
        };

        let output = format!("{row:?}");

        assert_eq!(output.matches("<redacted>").count(), 1, "{output}");
        assert_payload_redacted(&output);
        assert!(output.contains("event-12345"), "{output}");
    }

    #[test]
    fn settle_payment_input_debug_redacts_payload() {
        let payload = planted_payload();
        let input = SettlePaymentInput {
            event_id: "event-12345",
            event_type: "PAYMENT_SUCCEEDED",
            payload: &payload,
            headers_digest: "digest-12345",
            out_trade_no: "ORDER-12345",
            gross_amount_fen: 100,
            note: "note",
            operator: "operator",
        };

        let output = format!("{input:?}");

        assert_eq!(output.matches("<redacted>").count(), 1, "{output}");
        assert_payload_redacted(&output);
        assert!(output.contains("ORDER-12345"), "{output}");
    }
}
