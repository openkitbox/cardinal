//! Xiaodou payment orchestration: decisions, upstream calls and state changes.
//!
//! The module owns the boundary between the signed Xiaodou protocol (P1) and
//! the atomic payment store (P2). HTTP handlers only authenticate, parse and
//! map results; every decision about money, state and idempotency lives here.
//! No signature material, private key, raw body, pay URL or QR code is ever
//! logged — only order/refund identifiers and integer amounts.

use std::env;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::Duration;

use jiff::Timestamp;
use reqwest::Method;
use reqwest::header::CONTENT_TYPE;
use secrecy::SecretString;
use serde::Serialize;
use serde_json::{Map, Value, json};
use sqlx::{PgConnection, PgPool};

use crate::config::{Config, XiaodouConfig};
use crate::store::{
    self, NewPaymentEvent, NewPaymentOrder, NewPaymentRefund, PaymentOrderRow, PaymentPlacement,
    PaymentRefundRow, SettleOutcome, SettlePaymentInput,
};
use crate::xiaodou_pay::{
    ApiEnvelope, PlatformKeys, ProtocolError, RequestFields, ResponseHeaders, ResponseVerification,
    SigningKey, VerifyError, WEBHOOK_SUCCESS_BODY, WebhookEvent, WebhookEventType, WebhookHeaders,
    canonical_request, generate_nonce, parse_response, sha256_hex, verify_response, verify_webhook,
};

/// Local amount window: ¥0.01 – ¥10,000. Integer CNY fen only.
pub const MIN_AMOUNT_FEN: i64 = 1;
pub const MAX_AMOUNT_FEN: i64 = 1_000_000;
const SIGNATURE_WINDOW_SECS: i64 = 300;
const QR_PREFIX: &str = "https://qr.alipay.com/";
const QUERY_LIMIT: i64 = 100;

#[derive(Debug, thiserror::Error)]
pub enum PaymentError {
    #[error("online payments are not configured")]
    Disabled,
    #[error("amount_fen must be between 1 and 1000000")]
    InvalidAmount,
    #[error("payer client IP is unavailable")]
    MissingPayerIp,
    #[error("order not found")]
    NotFound,
    #[error("order is in a terminal state for this action")]
    Terminal,
    #[error("upstream request conflict; query before retrying")]
    Conflict,
    #[error("upstream rejected the request ({status})")]
    Upstream { status: u16, code: Option<String> },
    #[error("upstream response failed verification")]
    Tampering,
    #[error("upstream response was malformed")]
    Malformed,
    #[error("upstream is unavailable")]
    Unavailable,
    #[error("amount mismatch between event and order")]
    AmountMismatch,
    #[error(transparent)]
    Store(#[from] sqlx::Error),
    #[error(transparent)]
    Payment(#[from] store::PaymentError),
    #[error(transparent)]
    Credit(#[from] store::CreditError),
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    #[error(transparent)]
    Http(#[from] reqwest::Error),
}

/// Public order projection. Never includes signature material; QR/URL come
/// straight from the signed placement response and are not re-signed here.
#[derive(Serialize)]
pub struct OrderView {
    pub id: i64,
    pub out_trade_no: String,
    pub amount_fen: i64,
    pub credit_usd_micros: i64,
    pub status: String,
    pub pay_url: Option<String>,
    pub qr_code: Option<String>,
    pub expire_at: Option<String>,
    pub created_at: String,
}

impl std::fmt::Debug for OrderView {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OrderView")
            .field("id", &self.id)
            .field("out_trade_no", &self.out_trade_no)
            .field("amount_fen", &self.amount_fen)
            .field("credit_usd_micros", &self.credit_usd_micros)
            .field("status", &self.status)
            .field("pay_url", &"<redacted>")
            .field("qr_code", &"<redacted>")
            .field("expire_at", &self.expire_at)
            .field("created_at", &self.created_at)
            .finish()
    }
}

impl From<&PaymentOrderRow> for OrderView {
    fn from(row: &PaymentOrderRow) -> Self {
        Self {
            id: row.id,
            out_trade_no: row.out_trade_no.clone(),
            amount_fen: row.amount_fen,
            credit_usd_micros: row.credit_usd_micros,
            status: row.status.clone(),
            pay_url: row.pay_url.clone(),
            qr_code: row.qr_code.clone(),
            expire_at: row.expire_at.map(|value| value.to_string()),
            created_at: row.created_at.to_string(),
        }
    }
}

/// Result of a placement or an attempt: the current materials for the order.
#[derive(Serialize)]
pub struct PlacementView {
    #[serde(flatten)]
    pub order: OrderView,
    pub replayed: bool,
}

impl std::fmt::Debug for PlacementView {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PlacementView")
            .field("order", &self.order)
            .field("replayed", &self.replayed)
            .finish()
    }
}

#[derive(Debug, Serialize)]
pub struct RefundView {
    pub out_refund_no: String,
    pub out_trade_no: String,
    pub amount_fen: i64,
    pub state: String,
}

/// The signed query's authoritative status and amount. Materials returned by
/// the query are intentionally not part of this type.
#[derive(Debug)]
pub(crate) struct QueryOutcome {
    status: String,
    amount_fen: i64,
    mismatch: bool,
}

/// Terminal verdict carried by a refund webhook, query or response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefundStatus {
    Succeeded,
    Failed,
}

impl RefundStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Succeeded => "SUCCEEDED",
            Self::Failed => "FAILED",
        }
    }
}

/// One verified refund verdict to apply atomically. All fields are identifiers
/// or integers; the parsed payload is redacted in Debug output.
#[derive(Clone, Copy)]
pub struct SettleRefundInput<'a> {
    pub event_id: &'a str,
    pub event_type: &'a str,
    pub payload: &'a Value,
    pub headers_digest: &'a str,
    pub out_trade_no: &'a str,
    pub out_refund_no: &'a str,
    pub status: RefundStatus,
    pub amount_fen: i64,
    pub note: &'a str,
    pub operator: &'a str,
}

impl std::fmt::Debug for SettleRefundInput<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SettleRefundInput")
            .field("event_id", &self.event_id)
            .field("event_type", &self.event_type)
            .field("payload", &"<redacted>")
            .field("headers_digest", &self.headers_digest)
            .field("out_trade_no", &self.out_trade_no)
            .field("out_refund_no", &self.out_refund_no)
            .field("status", &self.status)
            .field("amount_fen", &self.amount_fen)
            .field("note", &self.note)
            .field("operator", &self.operator)
            .finish()
    }
}

/// Materials from a signed placement/attempt response.
struct ParsedPlacement {
    open_order_id: String,
    pay_url: String,
    qr_code: Option<String>,
    expire_at: Option<Timestamp>,
    fee_projection: Value,
}

#[derive(Debug, Serialize)]
pub struct ReconciliationView {
    pub from: String,
    pub to: String,
    pub checked: usize,
    pub platform_succeeded_local_not: usize,
    pub local_succeeded_platform_not: usize,
    pub amount_mismatch: usize,
    pub orders: Vec<DifferenceView>,
}

#[derive(Debug, Serialize)]
pub struct DifferenceView {
    pub out_trade_no: String,
    pub local_status: String,
    pub remote_status: String,
    pub local_amount_fen: i64,
    pub remote_amount_fen: i64,
    pub difference: &'static str,
    pub compensated: bool,
}

/// Raw webhook header values extracted by the edge. The signature is verified
/// over the original bytes before any field is read.
#[derive(Clone, Copy)]
pub struct WebhookRequest<'a> {
    pub signature: Option<&'a str>,
    pub key_id: Option<&'a str>,
    pub timestamp: Option<&'a str>,
    pub nonce: Option<&'a str>,
    pub event_id: Option<&'a str>,
    pub event_type: Option<&'a str>,
}

impl std::fmt::Debug for WebhookRequest<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WebhookRequest")
            .field("signature", &"<redacted>")
            .field("key_id", &self.key_id)
            .field("timestamp", &self.timestamp)
            .field("nonce", &self.nonce)
            .field("event_id", &self.event_id)
            .field("event_type", &self.event_type)
            .finish()
    }
}

#[derive(Debug)]
pub struct WebhookVerdict {
    pub status: u16,
    pub body: &'static [u8],
}

struct Runtime {
    cfg: XiaodouConfig,
    base_url: String,
    signing: SigningKey,
    platform: PlatformKeys,
    client: reqwest::Client,
}

static RUNTIME: OnceLock<Option<Runtime>> = OnceLock::new();

/// Install a runtime from an already-loaded config. Integration tests and
/// embedding hosts use this because the gateway composition root does not pass
/// payment settings through `AppState`; production uses [`runtime`].
pub fn install_runtime(config: &Config, dev_base_url: Option<&str>) -> anyhow::Result<()> {
    let runtime = build_runtime(config, dev_base_url)?;
    match RUNTIME.set(Some(runtime)) {
        Ok(()) => Ok(()),
        Err(_) => {
            let installed = RUNTIME.get().and_then(Option::as_ref);
            if installed.is_some_and(|current| Some(current.base_url.as_str()) == dev_base_url) {
                Ok(())
            } else {
                Err(anyhow::anyhow!("payments runtime was already installed"))
            }
        }
    }
}

fn runtime() -> Option<&'static Runtime> {
    RUNTIME.get_or_init(build_runtime_from_environment).as_ref()
}

/// Whether a Xiaodou runtime is installed or loadable from config.
pub fn is_enabled() -> bool {
    runtime().is_some()
}

/// Fixed CNY-fen → USD-micros rate from the active Xiaodou runtime, if any.
pub fn usd_micros_per_cny_fen() -> Option<i64> {
    i64::try_from(runtime()?.cfg.usd_micros_per_cny_fen).ok()
}

fn build_runtime_from_environment() -> Option<Runtime> {
    let path = env::var_os("CARDINAL_CONFIG_PATH")
        .map(PathBuf::from)
        .or_else(|| dirs::home_dir().map(|home| home.join(".ox").join("config.toml")))?;
    let config = Config::load(&path).ok()?;
    let dev = env::var("CARDINAL_XIAODOU_DEV_BASE_URL").ok();
    build_runtime(&config, dev.as_deref()).ok()
}

fn build_runtime(config: &Config, dev_base_url: Option<&str>) -> anyhow::Result<Runtime> {
    let mut cfg = config
        .payments
        .xiaodou
        .clone()
        .ok_or_else(|| anyhow::anyhow!("payments.xiaodou is not configured"))?;
    let mut base_url = cfg.base_url.trim_end_matches('/').to_owned();
    if let Some(dev) = dev_base_url {
        anyhow::ensure!(
            config.allow_insecure_upstream,
            "loopback payment overrides require allow_insecure_upstream"
        );
        let url = reqwest::Url::parse(dev)?;
        let loopback = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "::1"));
        anyhow::ensure!(
            url.scheme() == "http" && loopback && url.port().is_some(),
            "dev payment base_url must be an http loopback URL with an explicit port"
        );
        base_url = dev.trim_end_matches('/').to_owned();
        cfg.base_url = base_url.clone();
    }
    let secret: &SecretString = cfg
        .private_key()
        .ok_or_else(|| anyhow::anyhow!("Xiaodou private key is not injected"))?;
    let signing =
        SigningKey::from_secret(secret).map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let platform = cfg.platform_keys()?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .pool_max_idle_per_host(0)
        .no_proxy()
        .build()?;
    Ok(Runtime {
        cfg,
        base_url,
        signing,
        platform,
        client,
    })
}

impl Runtime {
    /// One signed call. A successful response is verified against the pinned
    /// platform key; unsigned early rejections (400/401/403/409) are surfaced
    /// as business errors, never as tampering.
    async fn call(
        &self,
        method: Method,
        path: &str,
        request_id: &str,
        body: &[u8],
    ) -> Result<ApiEnvelope, PaymentError> {
        let timestamp = Timestamp::now().as_second().to_string();
        let nonce = generate_nonce()?;
        let content_type = if body.is_empty() {
            None
        } else {
            Some("application/json")
        };
        let canonical = canonical_request(&RequestFields {
            method: method.as_str(),
            path,
            query: "",
            timestamp: &timestamp,
            nonce: &nonce,
            app_id: &self.cfg.app_id,
            key_id: &self.cfg.merchant_kid,
            request_id,
            content_type,
            raw_body: body,
        })?;
        let sign = self.signing.sign(&canonical)?;
        let mut request = self
            .client
            .request(method, format!("{}{}", self.base_url, path))
            .header("X-XD-App-Id", &self.cfg.app_id)
            .header("X-XD-Timestamp", &timestamp)
            .header("X-XD-Nonce", &nonce)
            .header("X-XD-Key-Id", &self.cfg.merchant_kid)
            .header("X-XD-Request-Id", request_id)
            .header("X-XD-Sign", sign);
        if let Some(value) = content_type {
            request = request.header(CONTENT_TYPE, value);
        }
        let response = request.body(body.to_vec()).send().await?;
        let status = response.status().as_u16();
        let response_content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let response_request_id = response
            .headers()
            .get("X-XD-Request-Id")
            .and_then(|value| value.to_str().ok())
            .filter(|value| !value.is_empty())
            .unwrap_or(request_id)
            .to_owned();
        let response_header = |name: &str| {
            response
                .headers()
                .get(name)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
        };
        let sign = response_header("X-XD-Response-Sign");
        let key_id = response_header("X-XD-Response-Key-Id");
        let response_timestamp = response_header("X-XD-Response-Timestamp");
        let response_nonce = response_header("X-XD-Response-Nonce");
        let header_values = sign.zip(key_id).zip(response_timestamp).zip(response_nonce);
        let headers = header_values
            .as_ref()
            .map(|(((sign, key_id), timestamp), nonce)| ResponseHeaders {
                sign,
                key_id,
                timestamp,
                nonce,
            });
        let raw = response.bytes().await?.to_vec();
        if status < 400 || headers.is_some() {
            let verdict = verify_response(
                &ResponseVerification {
                    status,
                    content_type: response_content_type.as_deref(),
                    request_id: &response_request_id,
                    raw_body: &raw,
                    headers,
                },
                &self.platform,
                Timestamp::now().as_second(),
                SIGNATURE_WINDOW_SECS,
            );
            match verdict {
                Ok(()) => {}
                Err(VerifyError::MissingHeaders { .. }) if status >= 400 => {
                    // Early platform rejection: no response signature exists.
                }
                Err(error) => {
                    tracing::warn!(
                        request_id = %request_id,
                        status,
                        reason = %error,
                        "xiaodou response rejected before use"
                    );
                    return Err(PaymentError::Tampering);
                }
            }
        }
        let envelope = parse_response(&raw).map_err(|error| {
            tracing::warn!(request_id = %request_id, status, reason = %error, "xiaodou response malformed");
            PaymentError::Malformed
        })?;
        if status >= 400 {
            if status == 409 {
                return Err(PaymentError::Conflict);
            }
            return Err(PaymentError::Upstream {
                status,
                code: envelope.code.clone(),
            });
        }
        Ok(envelope)
    }
}

fn field_str<'a>(fields: &'a Map<String, Value>, name: &str) -> Option<&'a str> {
    fields.get(name).and_then(Value::as_str)
}

fn field_i64(fields: &Map<String, Value>, name: &str) -> Option<i64> {
    fields.get(name).and_then(Value::as_i64)
}

fn is_terminal(status: &str) -> bool {
    matches!(status, "SUCCEEDED" | "CLOSED" | "FAILED")
}

fn credit_micros(amount_fen: i64, rate: i64) -> Option<i64> {
    i128::from(amount_fen)
        .checked_mul(i128::from(rate))
        .and_then(|value| i64::try_from(value).ok())
}

fn valid_amount(amount_fen: i64) -> bool {
    (MIN_AMOUNT_FEN..=MAX_AMOUNT_FEN).contains(&amount_fen)
}

/// QR material is accepted only from a signed ALIPAY_H5 placement response
/// with an official prefix. Query responses never reach this function.
fn placement_qr_code(channel: &str, value: Option<&str>) -> Option<String> {
    if channel != "ALIPAY_H5" {
        return None;
    }
    value
        .filter(|qr| qr.starts_with(QR_PREFIX) && !qr[QR_PREFIX.len()..].is_empty())
        .map(str::to_owned)
}

fn placement_expire_at(value: Option<&str>) -> Option<Timestamp> {
    value.and_then(|value| value.parse::<Timestamp>().ok())
}

fn log_safe(out_trade_no: &str, amount_fen: i64) -> LogFields<'_> {
    LogFields {
        out_trade_no,
        amount_fen,
    }
}

struct LogFields<'a> {
    out_trade_no: &'a str,
    amount_fen: i64,
}

impl std::fmt::Debug for LogFields<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LogFields")
            .field("out_trade_no", &self.out_trade_no)
            .field("amount_fen", &self.amount_fen)
            .finish()
    }
}

fn new_placement_body(
    cfg: &XiaodouConfig,
    out_trade_no: &str,
    amount_fen: i64,
    payer_ip: &str,
) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "outTradeNo": out_trade_no,
        "channel": cfg.channel,
        "amountFen": amount_fen,
        "currency": "CNY",
        "subject": format!("Cardinal top-up {out_trade_no}"),
        "payerClientIp": payer_ip,
        "feeBearer": cfg.fee_bearer,
        "tradeScope": cfg.trade_scope,
        "returnUrl": cfg.return_url,
        "timeExpireSeconds": cfg.time_expire_seconds,
    }))
    .unwrap_or_default()
}

fn parse_placement(
    envelope: &ApiEnvelope,
    channel: &str,
    fallback_open_order_id: Option<&str>,
) -> Result<ParsedPlacement, PaymentError> {
    let fields = &envelope.fields;
    let open_order_id = field_str(fields, "openOrderId")
        .or(fallback_open_order_id)
        .ok_or(PaymentError::Malformed)?
        .to_owned();
    let pay_url = field_str(fields, "payUrl")
        .filter(|value| value.starts_with("https://"))
        .ok_or(PaymentError::Malformed)?
        .to_owned();
    let qr_code = placement_qr_code(channel, field_str(fields, "qrCode"));
    let expire_at = placement_expire_at(field_str(fields, "expireAt"));
    let fee_projection = fields
        .get("feeProjection")
        .filter(|value| value.is_object())
        .cloned()
        .unwrap_or_else(|| json!({}));
    Ok(ParsedPlacement {
        open_order_id,
        pay_url,
        qr_code,
        expire_at,
        fee_projection,
    })
}

async fn store_placement(
    pool: &PgPool,
    order: &PaymentOrderRow,
    placement: ParsedPlacement,
    request_id: &str,
) -> Result<(), PaymentError> {
    let ParsedPlacement {
        open_order_id,
        pay_url,
        qr_code,
        expire_at,
        fee_projection,
    } = placement;
    let mut tx = pool.begin().await?;
    let stored = store::record_placement_in_tx(
        &mut tx,
        &order.out_trade_no,
        PaymentPlacement {
            open_order_id: &open_order_id,
            pay_url: &pay_url,
            qr_code: qr_code.as_deref(),
            expire_at,
            fee_projection: &fee_projection,
            request_id,
        },
    )
    .await?;
    if !stored {
        return Err(PaymentError::Terminal);
    }
    tx.commit().await?;
    Ok(())
}

/// Create one order and fetch its first payment materials. A 409 means the
/// platform already has the order: query it first, then replay the exact same
/// placement request (same outTradeNo and X-XD-Request-Id) for fresh materials.
pub async fn place_order(
    pool: &PgPool,
    user_id: i64,
    amount_fen: i64,
    payer_ip: &std::net::IpAddr,
) -> Result<PlacementView, PaymentError> {
    let runtime = runtime().ok_or(PaymentError::Disabled)?;
    if !valid_amount(amount_fen) {
        return Err(PaymentError::InvalidAmount);
    }
    let rate = i64::try_from(runtime.cfg.usd_micros_per_cny_fen)
        .map_err(|_| PaymentError::InvalidAmount)?;
    let credit = credit_micros(amount_fen, rate).ok_or(PaymentError::InvalidAmount)?;
    let out_trade_no = format!("xd{}", uuid::Uuid::new_v4().simple());
    let request_id = format!("req_{}", uuid::Uuid::new_v4().simple());
    tracing::info!(?out_trade_no, amount_fen, "xiaodou placement started");
    let order = store::create_order(
        pool,
        NewPaymentOrder {
            out_trade_no: &out_trade_no,
            user_id,
            amount_fen,
            usd_micros_per_cny_fen: rate,
            credit_usd_micros: credit,
            channel: &runtime.cfg.channel,
            request_id: &request_id,
        },
    )
    .await?;
    let body = new_placement_body(
        &runtime.cfg,
        &out_trade_no,
        amount_fen,
        &payer_ip.to_string(),
    );
    let path = "/api/open/v1/payments";
    let envelope = match runtime.call(Method::POST, path, &request_id, &body).await {
        Ok(envelope) => envelope,
        Err(PaymentError::Conflict) => {
            tracing::info!(
                ?out_trade_no,
                "xiaodou placement conflict; querying before replay"
            );
            let _ = query_order(pool, &order).await?;
            runtime.call(Method::POST, path, &request_id, &body).await?
        }
        Err(error) => return Err(error),
    };
    let placement = parse_placement(&envelope, &runtime.cfg.channel, None)?;
    store_placement(pool, &order, placement, &request_id).await?;
    let stored = store::get_order(pool, order.id)
        .await?
        .ok_or(PaymentError::NotFound)?;
    Ok(PlacementView {
        order: OrderView::from(&stored),
        replayed: false,
    })
}

pub async fn list_orders(pool: &PgPool, user_id: i64) -> Result<Vec<OrderView>, PaymentError> {
    let rows = store::list_orders(pool, Some(user_id), None, QUERY_LIMIT).await?;
    Ok(rows.iter().map(OrderView::from).collect())
}

pub async fn list_all_orders(pool: &PgPool) -> Result<Vec<OrderView>, PaymentError> {
    let rows = store::list_orders(pool, None, None, QUERY_LIMIT).await?;
    Ok(rows.iter().map(OrderView::from).collect())
}

pub async fn get_order(
    pool: &PgPool,
    user_id: i64,
    id: i64,
) -> Result<Option<OrderView>, PaymentError> {
    Ok(store::get_order(pool, id)
        .await?
        .filter(|order| order.user_id == user_id)
        .as_ref()
        .map(OrderView::from))
}

/// Re-pull payment materials by closing the current attempt and creating a new
/// one. Never used as a settlement signal.
pub async fn retry_attempt(
    pool: &PgPool,
    user_id: i64,
    id: i64,
) -> Result<PlacementView, PaymentError> {
    let runtime = runtime().ok_or(PaymentError::Disabled)?;
    let order = store::get_order(pool, id)
        .await?
        .filter(|order| order.user_id == user_id)
        .ok_or(PaymentError::NotFound)?;
    if is_terminal(&order.status) {
        return Err(PaymentError::Terminal);
    }
    let request_id = format!("req_{}", uuid::Uuid::new_v4().simple());
    let path = format!("/api/open/v1/payments/{}/attempts", order.out_trade_no);
    let envelope = runtime
        .call(Method::POST, &path, &request_id, b"{}")
        .await?;
    let placement = parse_placement(
        &envelope,
        &runtime.cfg.channel,
        order.open_order_id.as_deref(),
    )?;
    store_placement(pool, &order, placement, &request_id).await?;
    let stored = store::get_order(pool, order.id)
        .await?
        .ok_or(PaymentError::NotFound)?;
    Ok(PlacementView {
        order: OrderView::from(&stored),
        replayed: true,
    })
}

/// Authoritative query. A successful response can settle, but only after the
/// amount matches the order's frozen FX snapshot. Materials in a query reply
/// are deliberately ignored.
pub(crate) async fn query_order(
    pool: &PgPool,
    order: &PaymentOrderRow,
) -> Result<QueryOutcome, PaymentError> {
    let runtime = runtime().ok_or(PaymentError::Disabled)?;
    let request_id = format!("req_{}", uuid::Uuid::new_v4().simple());
    let path = format!("/api/open/v1/payments/{}", order.out_trade_no);
    let envelope = runtime.call(Method::GET, &path, &request_id, b"").await?;
    let status = field_str(&envelope.fields, "status")
        .ok_or(PaymentError::Malformed)?
        .to_owned();
    let remote_amount = field_i64(&envelope.fields, "amountFen").ok_or(PaymentError::Malformed)?;
    tracing::info!(
        out_trade_no = %order.out_trade_no,
        amount_fen = remote_amount,
        status = %status,
        "xiaodou authoritative query"
    );
    if status == "SUCCEEDED" {
        if remote_amount != order.amount_fen {
            tracing::warn!(
                out_trade_no = %order.out_trade_no,
                amount_fen = order.amount_fen,
                remote_amount_fen = remote_amount,
                "xiaodou query amount mismatch; never settling"
            );
            return Ok(QueryOutcome {
                status,
                amount_fen: remote_amount,
                mismatch: true,
            });
        }
        let payload = json!({"outTradeNo": order.out_trade_no, "amountFen": remote_amount});
        let event_id = format!("query:{}", order.out_trade_no);
        let mut tx = pool.begin().await?;
        let outcome = store::settle_succeeded_payment_in_tx(
            &mut tx,
            SettlePaymentInput {
                event_id: &event_id,
                event_type: "QUERY_SUCCEEDED",
                payload: &payload,
                headers_digest: &sha256_hex(request_id.as_bytes()),
                out_trade_no: &order.out_trade_no,
                gross_amount_fen: remote_amount,
                note: "Xiaodou authoritative query",
                operator: "xiaodou-query",
            },
        )
        .await?;
        match outcome {
            SettleOutcome::AmountMismatch { .. } => {
                return Ok(QueryOutcome {
                    status,
                    amount_fen: remote_amount,
                    mismatch: true,
                });
            }
            SettleOutcome::UnknownOrder => return Err(PaymentError::NotFound),
            _ => {}
        }
        tx.commit().await?;
        return Ok(QueryOutcome {
            status,
            amount_fen: remote_amount,
            mismatch: false,
        });
    }
    if order.status != "SUCCEEDED" && matches!(status.as_str(), "CLOSED" | "FAILED" | "UNKNOWN") {
        let mut tx = pool.begin().await?;
        store::set_order_status_in_tx(&mut tx, &order.out_trade_no, &status).await?;
        tx.commit().await?;
    }
    Ok(QueryOutcome {
        status,
        amount_fen: remote_amount,
        mismatch: false,
    })
}

fn event_type_name(kind: WebhookEventType) -> &'static str {
    match kind {
        WebhookEventType::PaymentSucceeded => "PAYMENT_SUCCEEDED",
        WebhookEventType::PaymentClosed => "PAYMENT_CLOSED",
        WebhookEventType::PaymentFailed => "PAYMENT_FAILED",
        WebhookEventType::RefundSucceeded => "REFUND_SUCCEEDED",
        WebhookEventType::RefundFailed => "REFUND_FAILED",
    }
}

fn valid_out_trade_no(value: &str) -> bool {
    (6..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

/// Verify and apply one webhook. Only a verified `PAYMENT_SUCCEEDED` event can
/// credit; missing signature headers are an early rejection, not tampering,
/// and every failure withholds the byte-exact `success` acknowledgement.
pub async fn handle_webhook(
    pool: &PgPool,
    raw: &[u8],
    headers: WebhookRequest<'_>,
) -> WebhookVerdict {
    let Some(runtime) = runtime() else {
        return WebhookVerdict {
            status: 503,
            body: b"payments disabled",
        };
    };
    let Some((signature, key_id, timestamp, nonce, event_id, event_type)) = headers
        .signature
        .zip(headers.key_id)
        .zip(headers.timestamp)
        .zip(headers.nonce)
        .zip(headers.event_id)
        .zip(headers.event_type)
        .map(
            |(((((signature, key_id), timestamp), nonce), event_id), event_type)| {
                (signature, key_id, timestamp, nonce, event_id, event_type)
            },
        )
    else {
        tracing::info!("xiaodou webhook rejected: missing signature headers");
        return WebhookVerdict {
            status: 400,
            body: b"missing signature headers",
        };
    };
    let event = match verify_webhook(
        raw,
        WebhookHeaders {
            sign: signature,
            key_id,
            timestamp,
            nonce,
            event_id,
            event_type,
        },
        &runtime.platform,
        Timestamp::now().as_second(),
        SIGNATURE_WINDOW_SECS,
    ) {
        Ok(event) => event,
        Err(error) => {
            tracing::warn!(reason = %error, "xiaodou webhook signature rejected");
            return WebhookVerdict {
                status: 400,
                body: b"invalid webhook",
            };
        }
    };
    if event.app_id != runtime.cfg.app_id || !valid_out_trade_no(&event.out_trade_no) {
        return WebhookVerdict {
            status: 400,
            body: b"invalid webhook",
        };
    }
    tracing::info!(
        event_id = %event.event_id,
        out_trade_no = %event.out_trade_no,
        amount_fen = event.gross_amount_fen,
        "xiaodou webhook verified"
    );
    let payload = match serde_json::from_slice::<Value>(raw) {
        Ok(value) => value,
        Err(_) => {
            return WebhookVerdict {
                status: 400,
                body: b"invalid webhook",
            };
        }
    };
    let headers_digest = sha256_hex(format!("{timestamp}:{nonce}:{key_id}:{event_id}").as_bytes());
    if event.event_type == WebhookEventType::PaymentSucceeded {
        if event.status != "SUCCEEDED" {
            return WebhookVerdict {
                status: 400,
                body: b"inconsistent success event",
            };
        }
        return settle_webhook(pool, &event, &payload, &headers_digest).await;
    }
    if matches!(
        event.event_type,
        WebhookEventType::RefundSucceeded | WebhookEventType::RefundFailed
    ) {
        return settle_refund_webhook(pool, &event, &payload, &headers_digest).await;
    }
    let new_event = NewPaymentEvent {
        event_id: &event.event_id,
        event_type: event_type_name(event.event_type),
        payload: &payload,
        headers_digest: &headers_digest,
        out_trade_no: &event.out_trade_no,
    };
    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(_) => {
            return WebhookVerdict {
                status: 503,
                body: b"temporarily unavailable",
            };
        }
    };
    let record = store::record_event_in_tx(&mut tx, &new_event).await;
    let commit = match record {
        Ok(_) => tx.commit().await,
        Err(_) => tx.rollback().await,
    };
    if commit.is_err() {
        return WebhookVerdict {
            status: 503,
            body: b"temporarily unavailable",
        };
    }
    accepted()
}

async fn settle_webhook(
    pool: &PgPool,
    event: &WebhookEvent,
    payload: &Value,
    headers_digest: &str,
) -> WebhookVerdict {
    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(_) => {
            return WebhookVerdict {
                status: 503,
                body: b"temporarily unavailable",
            };
        }
    };
    let input = SettlePaymentInput {
        event_id: &event.event_id,
        event_type: "PAYMENT_SUCCEEDED",
        payload,
        headers_digest,
        out_trade_no: &event.out_trade_no,
        gross_amount_fen: i64::try_from(event.gross_amount_fen).unwrap_or(i64::MAX),
        note: "Xiaodou top-up",
        operator: "xiaodou-webhook",
    };
    let outcome = store::settle_succeeded_payment_in_tx(&mut tx, input).await;
    let settle = match outcome {
        Ok(value) => value,
        Err(error) => {
            let _ = tx.rollback().await;
            tracing::error!(
                event_id = %event.event_id,
                out_trade_no = %event.out_trade_no,
                reason = %format!("{error:#}"),
                "xiaodou settlement failed"
            );
            return WebhookVerdict {
                status: 503,
                body: b"settlement unavailable",
            };
        }
    };
    if matches!(
        settle,
        SettleOutcome::AmountMismatch { .. } | SettleOutcome::UnknownOrder
    ) {
        let _ = tx.rollback().await;
        tracing::warn!(
            event_id = %event.event_id,
            out_trade_no = %event.out_trade_no,
            amount_fen = event.gross_amount_fen,
            "xiaodou settlement rejected: amount or order mismatch"
        );
        return WebhookVerdict {
            status: 422,
            body: b"amount or order mismatch",
        };
    }
    if tx.commit().await.is_err() {
        return WebhookVerdict {
            status: 503,
            body: b"settlement unavailable",
        };
    }
    accepted()
}

fn accepted() -> WebhookVerdict {
    WebhookVerdict {
        status: 200,
        body: WEBHOOK_SUCCESS_BODY,
    }
}

/// Apply one verified refund event. The verdict, eventId claim, refund status
/// and (for success) negative ledger entry are one transaction; a replayed
/// eventId is acknowledged without moving money a second time.
async fn settle_refund_webhook(
    pool: &PgPool,
    event: &WebhookEvent,
    payload: &Value,
    headers_digest: &str,
) -> WebhookVerdict {
    let Some(out_refund_no) = event
        .out_refund_no
        .as_deref()
        .filter(|number| valid_out_trade_no(number))
    else {
        return WebhookVerdict {
            status: 400,
            body: b"invalid refund number",
        };
    };
    let status = match (event.event_type, event.status.as_str()) {
        (WebhookEventType::RefundSucceeded, "SUCCEEDED") => RefundStatus::Succeeded,
        (WebhookEventType::RefundFailed, "FAILED") => RefundStatus::Failed,
        _ => {
            return WebhookVerdict {
                status: 400,
                body: b"inconsistent refund event",
            };
        }
    };
    let Ok(amount_fen) = i64::try_from(event.gross_amount_fen) else {
        return WebhookVerdict {
            status: 422,
            body: b"invalid refund amount",
        };
    };
    let input = SettleRefundInput {
        event_id: &event.event_id,
        event_type: event_type_name(event.event_type),
        payload,
        headers_digest,
        out_trade_no: &event.out_trade_no,
        out_refund_no,
        status,
        amount_fen,
        note: "Xiaodou refund",
        operator: "xiaodou-webhook",
    };
    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(_) => {
            return WebhookVerdict {
                status: 503,
                body: b"temporarily unavailable",
            };
        }
    };
    let outcome = match settle_refund_in_tx(&mut tx, input).await {
        Ok(outcome) => outcome,
        Err(error) => {
            let _ = tx.rollback().await;
            tracing::error!(
                event_id = %event.event_id,
                out_refund_no = %out_refund_no,
                reason = %format!("{error:#}"),
                "xiaodou refund settlement failed"
            );
            return WebhookVerdict {
                status: 503,
                body: b"settlement unavailable",
            };
        }
    };
    if matches!(
        outcome,
        SettleOutcome::RefundAmountMismatch { .. } | SettleOutcome::RefundInvalidStatus
    ) {
        let _ = tx.rollback().await;
        return WebhookVerdict {
            status: 422,
            body: b"refund amount or status mismatch",
        };
    }
    if tx.commit().await.is_err() {
        return WebhookVerdict {
            status: 503,
            body: b"settlement unavailable",
        };
    }
    accepted()
}

fn refund_number(order_id: i64) -> String {
    format!("xdr_{order_id:012}")
}

/// Full-order refund with a stable business number. An existing refund is
/// returned without another upstream call; an `UNKNOWN` result stays pending
/// and is never retried under a new number.
pub async fn refund_order(
    pool: &PgPool,
    order_id: i64,
    actor: &str,
) -> Result<RefundView, PaymentError> {
    let runtime = runtime().ok_or(PaymentError::Disabled)?;
    let order = store::get_order(pool, order_id)
        .await?
        .ok_or(PaymentError::NotFound)?;
    if order.status != "SUCCEEDED" {
        return Err(PaymentError::Terminal);
    }
    let out_refund_no = refund_number(order.id);
    let mut tx = pool.begin().await?;
    let (refund, created) = ensure_refund_in_tx(
        &mut tx,
        &NewPaymentRefund {
            out_refund_no: &out_refund_no,
            order_id: order.id,
            amount_fen: order.amount_fen,
            request_id: &out_refund_no,
        },
    )
    .await?;
    tx.commit().await?;

    if !created {
        if refund.status == "SUCCEEDED" || refund.status == "FAILED" {
            return Ok(view_for(
                &refund.out_refund_no,
                &order.out_trade_no,
                refund.amount_fen,
                &refund.status,
            ));
        }
        if let Err(error) = query_refund(pool, &out_refund_no).await {
            tracing::warn!(
                out_refund_no = %out_refund_no,
                reason = %error,
                "xiaodou existing refund query failed; keeping it pending"
            );
        }
        let current = store::get_refund(pool, &out_refund_no)
            .await?
            .unwrap_or(refund);
        return Ok(view_for(
            &current.out_refund_no,
            &order.out_trade_no,
            current.amount_fen,
            &current.status,
        ));
    }
    tracing::info!(
        out_trade_no = %order.out_trade_no,
        out_refund_no = %out_refund_no,
        amount_fen = order.amount_fen,
        "xiaodou refund requested"
    );
    let body = serde_json::to_vec(&json!({
        "outTradeNo": order.out_trade_no,
        "outRefundNo": out_refund_no,
        "refundAmountFen": order.amount_fen,
        "reason": "customer refund",
    }))
    .unwrap_or_default();
    let envelope = match runtime
        .call(Method::POST, "/api/open/v1/refunds", &out_refund_no, &body)
        .await
    {
        Ok(envelope) => envelope,
        Err(PaymentError::Upstream { status: 502, .. }) => {
            // Provider rejection of this attempt is not a terminal refund
            // verdict. Query the same number instead of losing the refund.
            if let Err(error) = query_refund(pool, &out_refund_no).await {
                tracing::warn!(
                    out_refund_no = %out_refund_no,
                    reason = %error,
                    "xiaodou 502 refund query failed; keeping it pending"
                );
            }
            let current = store::get_refund(pool, &out_refund_no)
                .await?
                .unwrap_or(refund);
            return Ok(view_for(
                &current.out_refund_no,
                &order.out_trade_no,
                current.amount_fen,
                &current.status,
            ));
        }
        Err(error) => return Err(error),
    };
    let state = field_str(&envelope.fields, "state")
        .unwrap_or("UNKNOWN")
        .to_owned();
    if matches!(state.as_str(), "SUCCEEDED" | "FAILED") {
        settle_refund_response(
            pool,
            &order,
            &out_refund_no,
            &state,
            order.amount_fen,
            actor,
        )
        .await?;
    } else if let Err(error) = query_refund(pool, &out_refund_no).await {
        tracing::warn!(
            out_refund_no = %out_refund_no,
            reason = %error,
            "xiaodou nonterminal refund query failed; keeping it pending"
        );
    }
    let current = store::get_refund(pool, &out_refund_no)
        .await?
        .unwrap_or(refund);
    Ok(view_for(
        &current.out_refund_no,
        &order.out_trade_no,
        current.amount_fen,
        &current.status,
    ))
}

fn view_for(no: &str, trade: &str, amount: i64, state: &str) -> RefundView {
    RefundView {
        out_refund_no: no.to_owned(),
        out_trade_no: trade.to_owned(),
        amount_fen: amount,
        state: state.to_owned(),
    }
}

/// Claim a stable refund number in the caller's transaction. Returns the stored
/// row and whether this transaction created it.
pub async fn ensure_refund_in_tx(
    conn: &mut PgConnection,
    refund: &NewPaymentRefund<'_>,
) -> Result<(PaymentRefundRow, bool), sqlx::Error> {
    PaymentRefundRow::ensure_in_tx(conn, refund).await
}

/// Apply one refund verdict with its eventId claim in the caller's transaction.
pub async fn settle_refund_in_tx(
    conn: &mut PgConnection,
    input: SettleRefundInput<'_>,
) -> Result<SettleOutcome, store::PaymentError> {
    let event = NewPaymentEvent {
        event_id: input.event_id,
        event_type: input.event_type,
        payload: input.payload,
        headers_digest: input.headers_digest,
        out_trade_no: input.out_trade_no,
    };
    PaymentRefundRow::settle_in_tx(
        conn,
        &event,
        input.out_refund_no,
        input.status.as_str(),
        input.amount_fen,
        input.note,
        input.operator,
    )
    .await
}

/// Authoritative read for one refund. A terminal answer uses the same atomic
/// settlement as a signed webhook, under a query-scoped synthetic eventId; it
/// never creates or changes `outRefundNo`.
async fn query_refund(pool: &PgPool, out_refund_no: &str) -> Result<String, PaymentError> {
    let runtime = runtime().ok_or(PaymentError::Disabled)?;
    let refund = store::get_refund(pool, out_refund_no)
        .await?
        .ok_or(PaymentError::NotFound)?;
    let order = store::get_order(pool, refund.order_id)
        .await?
        .ok_or(PaymentError::NotFound)?;
    let path = format!("/api/open/v1/refunds/{out_refund_no}");
    let envelope = runtime.call(Method::GET, &path, out_refund_no, b"").await?;
    let state = field_str(&envelope.fields, "state")
        .ok_or(PaymentError::Malformed)?
        .to_owned();
    if field_str(&envelope.fields, "outRefundNo").is_some_and(|remote| remote != out_refund_no) {
        return Err(PaymentError::Tampering);
    }
    tracing::info!(out_refund_no = %out_refund_no, state = %state, "xiaodou refund query");
    if !matches!(state.as_str(), "SUCCEEDED" | "FAILED") {
        return Ok(state);
    }
    let amount_fen = field_i64(&envelope.fields, "amountFen").ok_or(PaymentError::Malformed)?;
    if amount_fen != refund.amount_fen {
        return Err(PaymentError::AmountMismatch);
    }
    let status = if state == "SUCCEEDED" {
        RefundStatus::Succeeded
    } else {
        RefundStatus::Failed
    };
    let event_id = format!("query:{out_refund_no}");
    let payload = json!({"outRefundNo": out_refund_no, "state": state});
    let digest = sha256_hex(out_refund_no.as_bytes());
    let input = SettleRefundInput {
        event_id: &event_id,
        event_type: if status == RefundStatus::Succeeded {
            "REFUND_QUERY_SUCCEEDED"
        } else {
            "REFUND_QUERY_FAILED"
        },
        payload: &payload,
        headers_digest: &digest,
        out_trade_no: &order.out_trade_no,
        out_refund_no,
        status,
        amount_fen,
        note: "Xiaodou authoritative refund query",
        operator: "xiaodou-query",
    };
    let mut tx = pool.begin().await?;
    let outcome = settle_refund_in_tx(&mut tx, input).await?;
    if matches!(outcome, SettleOutcome::RefundAmountMismatch { .. }) {
        return Err(PaymentError::AmountMismatch);
    }
    tx.commit().await?;
    Ok(state)
}

/// Apply the synchronous refund response's terminal state through the same
/// deduplication and ledger rules as a webhook.
async fn settle_refund_response(
    pool: &PgPool,
    order: &PaymentOrderRow,
    out_refund_no: &str,
    state: &str,
    amount_fen: i64,
    actor: &str,
) -> Result<(), PaymentError> {
    let status = match state {
        "SUCCEEDED" => RefundStatus::Succeeded,
        "FAILED" => RefundStatus::Failed,
        _ => return Ok(()),
    };
    let event_id = format!("response:{out_refund_no}");
    let payload = json!({"outRefundNo": out_refund_no, "state": state});
    let digest = sha256_hex(out_refund_no.as_bytes());
    let input = SettleRefundInput {
        event_id: &event_id,
        event_type: if status == RefundStatus::Succeeded {
            "REFUND_RESPONSE_SUCCEEDED"
        } else {
            "REFUND_RESPONSE_FAILED"
        },
        payload: &payload,
        headers_digest: &digest,
        out_trade_no: &order.out_trade_no,
        out_refund_no,
        status,
        amount_fen,
        note: "Xiaodou refund",
        operator: actor,
    };
    let mut tx = pool.begin().await?;
    let outcome = settle_refund_in_tx(&mut tx, input).await?;
    if matches!(outcome, SettleOutcome::RefundAmountMismatch { .. }) {
        return Err(PaymentError::AmountMismatch);
    }
    tx.commit().await?;
    Ok(())
}

/// Daily reconciliation: query each local order in the window, settle a
/// platform success we missed, and report the three difference classes.
///
/// The repository lists newest-first with a `before_id` cursor. Reconciliation
/// pages through that cursor until it reaches `from`, so an old window is never
/// silently skipped just because 100 newer orders exist.
async fn orders_in_window(
    pool: &PgPool,
    from: Timestamp,
    to: Timestamp,
) -> Result<Vec<PaymentOrderRow>, PaymentError> {
    let mut cursor = None;
    let mut selected = Vec::new();
    loop {
        let page = PaymentOrderRow::list_in_window(pool, from, to, cursor, QUERY_LIMIT).await?;
        let Some(last) = page.last() else {
            break;
        };
        cursor = Some(last.id);
        for order in page {
            selected.push(order);
        }
    }
    Ok(selected)
}

pub async fn reconcile(
    pool: &PgPool,
    from: Timestamp,
    to: Timestamp,
) -> Result<ReconciliationView, PaymentError> {
    let rows = orders_in_window(pool, from, to).await?;
    let mut report = ReconciliationView {
        from: from.to_string(),
        to: to.to_string(),
        checked: 0,
        platform_succeeded_local_not: 0,
        local_succeeded_platform_not: 0,
        amount_mismatch: 0,
        orders: Vec::new(),
    };
    for order in rows {
        report.checked += 1;
        let log = log_safe(&order.out_trade_no, order.amount_fen);
        let remote = match query_order(pool, &order).await {
            Ok(outcome) => outcome,
            Err(error) => {
                tracing::warn!(?log, reason = %error, "xiaodou reconciliation query failed");
                continue;
            }
        };
        let QueryOutcome {
            status: remote_status,
            amount_fen: remote_amount,
            mismatch,
        } = remote;
        let mut compensated = false;
        let difference = if mismatch {
            // A platform SUCCEEDED with the wrong amount is never settled.
            report.amount_mismatch += 1;
            "amount_mismatch"
        } else if remote_status == "SUCCEEDED" && order.status != "SUCCEEDED" {
            report.platform_succeeded_local_not += 1;
            compensated = store::get_order(pool, order.id)
                .await?
                .is_some_and(|current| current.status == "SUCCEEDED");
            "platform_succeeded_local_not"
        } else if order.status == "SUCCEEDED" && remote_status != "SUCCEEDED" {
            report.local_succeeded_platform_not += 1;
            "local_succeeded_platform_not"
        } else {
            continue;
        };
        report.orders.push(DifferenceView {
            out_trade_no: order.out_trade_no,
            local_status: order.status,
            remote_status,
            local_amount_fen: order.amount_fen,
            remote_amount_fen: remote_amount,
            difference,
            compensated,
        });
    }

    // A crash between creating a PENDING refund and applying its verdict leaves
    // no in-flight request to resume. Reconciliation queries each stable refund
    // number so it converges through the same signed, deduplicated path.
    let refunds = store::list_refunds(pool, None, QUERY_LIMIT).await?;
    for refund in refunds
        .into_iter()
        .filter(|refund| refund.status == "PENDING")
    {
        if let Err(error) = query_refund(pool, &refund.out_refund_no).await {
            tracing::warn!(
                out_refund_no = %refund.out_refund_no,
                reason = %error,
                "xiaodou pending refund query failed"
            );
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payments_amount_and_fx_arithmetic_is_checked() {
        assert!(!valid_amount(0));
        assert!(!valid_amount(1_000_001));
        assert!(valid_amount(1));
        assert_eq!(credit_micros(1200, 1000), Some(1_200_000));
        assert_eq!(credit_micros(i64::MAX, i64::MAX), None);
    }

    #[test]
    fn payments_qr_and_state_decisions_fail_closed() {
        assert_eq!(
            placement_qr_code("ALIPAY_H5", Some("https://qr.alipay.com/bax1")),
            Some("https://qr.alipay.com/bax1".to_owned())
        );
        assert_eq!(
            placement_qr_code("ALIPAY_H5", Some("https://evil.test/qr")),
            None
        );
        assert_eq!(
            placement_qr_code("WECHAT_H5", Some("https://qr.alipay.com/bax1")),
            None
        );
        assert!(is_terminal("SUCCEEDED"));
        assert!(is_terminal("CLOSED"));
        assert!(is_terminal("FAILED"));
        assert!(!is_terminal("UNKNOWN"));
        assert!(!is_terminal("PAYING"));
    }

    #[test]
    fn payments_log_fields_carry_only_ids_and_amounts() {
        let fields = log_safe("xd123", 1200);
        let text = format!("{fields:?}");
        assert!(text.contains("xd123"));
        assert!(text.contains("1200"));
        for secret in ["sign", "private", "qrCode", "payUrl", "body"] {
            assert!(
                !text.contains(secret),
                "log fields must not include {secret}"
            );
        }
    }

    #[test]
    fn payments_debug_output_redacts_materials() {
        let view = OrderView {
            id: 7,
            out_trade_no: "xd123456".to_owned(),
            amount_fen: 1200,
            credit_usd_micros: 1_200_000,
            status: "PAYING".to_owned(),
            pay_url: Some("https://cashier.example.invalid/pay/xd123456".to_owned()),
            qr_code: Some("https://qr.alipay.com/bax123456".to_owned()),
            expire_at: None,
            created_at: "2026-11-20T00:00:00Z".to_owned(),
        };
        let placement = PlacementView {
            order: view,
            replayed: false,
        };
        let text = format!("{placement:?}");
        assert!(
            text.contains("<redacted>"),
            "Debug must mark redacted fields"
        );
        for secret in ["cashier.example.invalid", "qr.alipay.com"] {
            assert!(!text.contains(secret), "Debug leaked {secret}");
        }

        let signature = "MEUCIQDCSIGNEDMATERIAL";
        let hook = WebhookRequest {
            signature: Some(signature),
            key_id: Some("xdpk-test"),
            timestamp: Some("1795184044"),
            nonce: Some("nonce123"),
            event_id: Some("evt123"),
            event_type: Some("PAYMENT_SUCCEEDED"),
        };
        let text = format!("{hook:?}");
        assert!(text.contains("<redacted>"));
        assert!(
            !text.contains(signature),
            "Debug leaked the webhook signature"
        );
    }
}
