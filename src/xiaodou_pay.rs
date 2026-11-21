//! Xiaodou Open API protocol kernel.
//!
//! Owns the three distinct signature specifications (`XD-Signature-v1`,
//! `XD-Response-v1`, `XD-Webhook-v1`), RSA2 sign/verify, and parsing of
//! responses and webhook events. Nothing here touches the database or HTTP
//! transport: callers supply raw bytes and header values, and receive typed
//! values or an error. Never log canonical strings, signatures, or keys.

use std::collections::HashMap;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use rsa::sha2::Sha256 as RsaSha256;
use rsa::sha2::digest::Digest as _;
use rsa::{Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey};
use secrecy::{ExposeSecret as _, SecretString};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

/// The only successful webhook acknowledgement: bytes exactly equal to this.
pub const WEBHOOK_SUCCESS_BODY: &[u8] = b"success";

const HEX_DIGITS: &[u8; 16] = b"0123456789ABCDEF";
const WEBHOOK_HEADERS: [&str; 6] = [
    "X-XD-Webhook-Signature",
    "X-XD-Webhook-Key-Id",
    "X-XD-Webhook-Timestamp",
    "X-XD-Webhook-Nonce",
    "X-XD-Webhook-Event-Id",
    "X-XD-Webhook-Event-Type",
];
const RESPONSE_HEADERS: [&str; 4] = [
    "X-XD-Response-Sign",
    "X-XD-Response-Key-Id",
    "X-XD-Response-Timestamp",
    "X-XD-Response-Nonce",
];

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProtocolError {
    #[error("invalid canonical path")]
    InvalidPath,
    #[error("invalid query encoding")]
    InvalidQuery,
    #[error("invalid request or response header shape")]
    InvalidHeaderShape,
    #[error("invalid RSA private key")]
    InvalidPrivateKey,
    #[error("invalid platform public key")]
    InvalidPublicKey,
    #[error("platform public key fingerprint mismatch")]
    FingerprintMismatch,
    #[error("duplicate or empty platform key id")]
    InvalidKeyId,
    #[error("no platform keys configured")]
    NoPlatformKeys,
    #[error("request signing failed")]
    SigningFailed,
    #[error("OS random source unavailable")]
    RandomSource,
    #[error("invalid JSON payload")]
    InvalidJson,
    #[error("invalid payload field: {0}")]
    InvalidPayload(&'static str),
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum VerifyError {
    /// The response/event was not signed. Callers must preserve its business
    /// error body instead of treating an unsigned early rejection as tampering.
    #[error("signature headers missing: {missing:?}")]
    MissingHeaders { missing: Vec<&'static str> },
    #[error("invalid header: {0}")]
    InvalidHeader(&'static str),
    #[error("unknown signing key id")]
    UnknownKeyId,
    #[error("timestamp outside allowed window")]
    TimestampOutsideWindow,
    #[error("invalid signature encoding")]
    InvalidSignatureEncoding,
    #[error("signature verification failed")]
    SignatureMismatch,
    #[error("invalid event payload: {0}")]
    InvalidPayload(&'static str),
}

#[derive(Clone, Copy)]
pub struct RequestFields<'a> {
    pub method: &'a str,
    pub path: &'a str,
    /// Raw query string, with or without the leading `?`.
    pub query: &'a str,
    pub timestamp: &'a str,
    pub nonce: &'a str,
    pub app_id: &'a str,
    pub key_id: &'a str,
    pub request_id: &'a str,
    /// The header actually sent, including any `;` parameters, or `None`.
    pub content_type: Option<&'a str>,
    pub raw_body: &'a [u8],
}

impl std::fmt::Debug for RequestFields<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RequestFields")
            .field("method", &self.method)
            .field("path", &self.path)
            .field("query", &self.query)
            .field("timestamp", &self.timestamp)
            .field("nonce", &self.nonce)
            .field("app_id", &self.app_id)
            .field("key_id", &self.key_id)
            .field("request_id", &self.request_id)
            .field("content_type", &self.content_type)
            .field("raw_body", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Copy)]
pub struct ResponseFields<'a> {
    pub status: u16,
    pub content_type: Option<&'a str>,
    pub request_id: &'a str,
    pub timestamp: &'a str,
    pub nonce: &'a str,
    pub key_id: &'a str,
    pub raw_body: &'a [u8],
}

impl std::fmt::Debug for ResponseFields<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ResponseFields")
            .field("status", &self.status)
            .field("content_type", &self.content_type)
            .field("request_id", &self.request_id)
            .field("timestamp", &self.timestamp)
            .field("nonce", &self.nonce)
            .field("key_id", &self.key_id)
            .field("raw_body", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Copy)]
pub struct WebhookFields<'a> {
    pub event_id: &'a str,
    pub event_type: &'a str,
    pub timestamp: &'a str,
    pub nonce: &'a str,
    pub key_id: &'a str,
    pub raw_body: &'a [u8],
}

impl std::fmt::Debug for WebhookFields<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WebhookFields")
            .field("event_id", &self.event_id)
            .field("event_type", &self.event_type)
            .field("timestamp", &self.timestamp)
            .field("nonce", &self.nonce)
            .field("key_id", &self.key_id)
            .field("raw_body", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct ResponseHeaders<'a> {
    pub sign: &'a str,
    pub key_id: &'a str,
    pub timestamp: &'a str,
    pub nonce: &'a str,
}

impl std::fmt::Debug for ResponseHeaders<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ResponseHeaders")
            .field("sign", &"<redacted>")
            .field("key_id", &self.key_id)
            .field("timestamp", &self.timestamp)
            .field("nonce", &self.nonce)
            .finish()
    }
}

#[derive(Clone)]
pub struct ResponseVerification<'a> {
    pub status: u16,
    pub content_type: Option<&'a str>,
    pub request_id: &'a str,
    pub raw_body: &'a [u8],
    /// `None` for the platform's unsigned early rejections.
    pub headers: Option<ResponseHeaders<'a>>,
}

impl std::fmt::Debug for ResponseVerification<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ResponseVerification")
            .field("status", &self.status)
            .field("content_type", &self.content_type)
            .field("request_id", &self.request_id)
            .field("raw_body", &"<redacted>")
            .field("headers", &self.headers)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct WebhookHeaders<'a> {
    pub sign: &'a str,
    pub key_id: &'a str,
    pub timestamp: &'a str,
    pub nonce: &'a str,
    pub event_id: &'a str,
    pub event_type: &'a str,
}

impl std::fmt::Debug for WebhookHeaders<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WebhookHeaders")
            .field("sign", &"<redacted>")
            .field("key_id", &self.key_id)
            .field("timestamp", &self.timestamp)
            .field("nonce", &self.nonce)
            .field("event_id", &self.event_id)
            .field("event_type", &self.event_type)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WebhookEventType {
    PaymentSucceeded,
    PaymentClosed,
    PaymentFailed,
    RefundSucceeded,
    RefundFailed,
}

#[derive(Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WebhookEvent {
    pub event_id: String,
    pub event_type: WebhookEventType,
    pub app_id: String,
    pub out_trade_no: String,
    pub out_refund_no: Option<String>,
    pub event_amount_fen: u64,
    pub gross_amount_fen: u64,
    pub fee_bearer: String,
    pub merchant_amount_fen: Option<u64>,
    pub fee_amount_fen: Option<u64>,
    pub status: String,
    pub reason: Option<String>,
    pub occurred_at: i64,
    pub state_version: i64,
    pub attach: Option<String>,
    pub fee_projection: serde_json::Value,
    /// Header values, copied after verification. Never read these from the body.
    #[serde(skip)]
    pub timestamp: String,
    #[serde(skip)]
    pub nonce: String,
    #[serde(skip)]
    pub key_id: String,
}

impl std::fmt::Debug for WebhookEvent {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WebhookEvent")
            .field("event_id", &self.event_id)
            .field("event_type", &self.event_type)
            .field("app_id", &self.app_id)
            .field("out_trade_no", &self.out_trade_no)
            .field("out_refund_no", &self.out_refund_no)
            .field("event_amount_fen", &self.event_amount_fen)
            .field("gross_amount_fen", &self.gross_amount_fen)
            .field("fee_bearer", &self.fee_bearer)
            .field("merchant_amount_fen", &self.merchant_amount_fen)
            .field("fee_amount_fen", &self.fee_amount_fen)
            .field("status", &self.status)
            .field("reason", &self.reason)
            .field("occurred_at", &self.occurred_at)
            .field("state_version", &self.state_version)
            .field("attach", &self.attach)
            .field("fee_projection", &"<redacted>")
            .field("timestamp", &self.timestamp)
            .field("nonce", &self.nonce)
            .field("key_id", &self.key_id)
            .finish()
    }
}

/// Generic response envelope. Business fields stay in `fields` so the caller
/// can read the exact endpoint projection without this module owning it.
#[derive(Clone, Deserialize)]
pub struct ApiEnvelope {
    #[serde(rename = "requestId")]
    pub request_id: String,
    pub code: Option<String>,
    pub message: Option<String>,
    #[serde(flatten)]
    pub fields: serde_json::Map<String, serde_json::Value>,
}

impl std::fmt::Debug for ApiEnvelope {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ApiEnvelope")
            .field("request_id", &self.request_id)
            .field("code", &self.code)
            .field("message", &self.message)
            .field("fields", &"<redacted>")
            .finish()
    }
}

/// RSA private key used only for request signing; parsed once at the boundary.
pub struct SigningKey {
    key: RsaPrivateKey,
}

impl SigningKey {
    pub fn from_pem(pem: &str) -> Result<Self, ProtocolError> {
        use rsa::pkcs1::DecodeRsaPrivateKey;
        use rsa::pkcs8::DecodePrivateKey;

        let key = RsaPrivateKey::from_pkcs1_pem(pem)
            .or_else(|_| RsaPrivateKey::from_pkcs8_pem(pem))
            .map_err(|_| ProtocolError::InvalidPrivateKey)?;
        Ok(Self { key })
    }

    pub fn from_secret(secret: &SecretString) -> Result<Self, ProtocolError> {
        Self::from_pem(secret.expose_secret())
    }

    pub fn sign(&self, canonical: &str) -> Result<String, ProtocolError> {
        let digest = RsaSha256::digest(canonical.as_bytes());
        let signature = self
            .key
            .sign(Pkcs1v15Sign::new::<RsaSha256>(), &digest)
            .map_err(|_| ProtocolError::SigningFailed)?;
        Ok(BASE64.encode(signature))
    }
}

struct PlatformPublicKey {
    public_key: RsaPublicKey,
}

/// Platform keys pinned by kid. Never populated from a response or event.
pub struct PlatformKeys {
    by_kid: HashMap<String, PlatformPublicKey>,
}

impl PlatformKeys {
    /// Entries are `(kid, PEM, expected fingerprint)`. The fingerprint is
    /// recomputed over normalized PEM bytes before the key is accepted.
    pub fn from_entries<'a>(
        entries: impl IntoIterator<Item = (&'a str, &'a str, &'a str)>,
    ) -> Result<Self, ProtocolError> {
        use rsa::pkcs8::DecodePublicKey;

        let mut by_kid = HashMap::new();
        for (kid, pem, expected_fingerprint) in entries {
            if kid.is_empty() || by_kid.contains_key(kid) {
                return Err(ProtocolError::InvalidKeyId);
            }
            if fingerprint_public_key_pem(pem) != expected_fingerprint {
                return Err(ProtocolError::FingerprintMismatch);
            }
            let public_key = RsaPublicKey::from_public_key_pem(&normalize_pem(pem))
                .map_err(|_| ProtocolError::InvalidPublicKey)?;
            by_kid.insert(kid.to_owned(), PlatformPublicKey { public_key });
        }
        if by_kid.is_empty() {
            return Err(ProtocolError::NoPlatformKeys);
        }
        Ok(Self { by_kid })
    }

    pub fn contains(&self, kid: &str) -> bool {
        self.by_kid.contains_key(kid)
    }

    pub fn verify(&self, kid: &str, canonical: &str, signature: &str) -> Result<(), VerifyError> {
        let entry = self.by_kid.get(kid).ok_or(VerifyError::UnknownKeyId)?;
        let signature = BASE64
            .decode(signature)
            .map_err(|_| VerifyError::InvalidSignatureEncoding)?;
        let digest = RsaSha256::digest(canonical.as_bytes());
        entry
            .public_key
            .verify(Pkcs1v15Sign::new::<RsaSha256>(), &digest, &signature)
            .map_err(|_| VerifyError::SignatureMismatch)
    }
}

pub fn normalize_pem(pem: &str) -> String {
    pem.replace("\r\n", "\n")
        .replace('\r', "\n")
        .trim()
        .to_owned()
}

/// Fingerprint of the normalized UTF-8 PEM bytes, as published by Xiaodou.
pub fn fingerprint_public_key_pem(pem: &str) -> String {
    hex::encode(Sha256::digest(normalize_pem(pem).as_bytes()))
}

pub fn sha256_hex(raw: &[u8]) -> String {
    hex::encode(Sha256::digest(raw))
}

pub fn normalize_content_type(value: Option<&str>) -> String {
    match value {
        Some(value) => value
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase(),
        None => String::new(),
    }
}

pub fn canonical_request(fields: &RequestFields<'_>) -> Result<String, ProtocolError> {
    if !matches!(fields.method, "GET" | "POST") {
        return Err(ProtocolError::InvalidHeaderShape);
    }
    validate_common_fields(
        fields.timestamp,
        fields.nonce,
        fields.app_id,
        fields.key_id,
        fields.request_id,
    )?;
    Ok(format!(
        "XD-Signature-v1\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
        fields.method,
        canonical_path(fields.path)?,
        canonical_query(fields.query)?,
        fields.timestamp,
        fields.nonce,
        fields.app_id,
        fields.key_id,
        fields.request_id,
        normalize_content_type(fields.content_type),
        sha256_hex(fields.raw_body),
    ))
}

pub fn canonical_response(fields: &ResponseFields<'_>) -> Result<String, ProtocolError> {
    validate_common_fields(
        fields.timestamp,
        fields.nonce,
        "",
        fields.key_id,
        fields.request_id,
    )?;
    Ok(format!(
        "XD-Response-v1\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
        fields.status,
        normalize_content_type(fields.content_type),
        fields.request_id,
        fields.timestamp,
        fields.nonce,
        fields.key_id,
        sha256_hex(fields.raw_body),
    ))
}

pub fn canonical_webhook(fields: &WebhookFields<'_>) -> Result<String, ProtocolError> {
    if !visible_ascii(fields.event_id, 1, 128)
        || !visible_ascii(fields.event_type, 1, 64)
        || !valid_timestamp(fields.timestamp)
        || !visible_ascii(fields.nonce, 16, 64)
        || !visible_ascii(fields.key_id, 1, 128)
    {
        return Err(ProtocolError::InvalidHeaderShape);
    }
    Ok(format!(
        "XD-Webhook-v1\n{}\n{}\n{}\n{}\n{}\n{}",
        fields.event_id,
        fields.event_type,
        fields.timestamp,
        fields.nonce,
        fields.key_id,
        sha256_hex(fields.raw_body),
    ))
}

pub fn verify_response(
    input: &ResponseVerification<'_>,
    keys: &PlatformKeys,
    now_secs: i64,
    window_secs: i64,
) -> Result<(), VerifyError> {
    let missing = missing_response_headers(input.headers.as_ref());
    if !missing.is_empty() {
        return Err(VerifyError::MissingHeaders { missing });
    }
    let headers = match input.headers.as_ref() {
        Some(headers) => headers,
        None => {
            return Err(VerifyError::MissingHeaders {
                missing: RESPONSE_HEADERS.to_vec(),
            });
        }
    };
    check_response_header_shapes(headers, input.request_id)?;
    check_time_window(
        headers.timestamp,
        now_secs,
        window_secs,
        "X-XD-Response-Timestamp",
    )?;
    let canonical = canonical_response(&ResponseFields {
        status: input.status,
        content_type: input.content_type,
        request_id: input.request_id,
        timestamp: headers.timestamp,
        nonce: headers.nonce,
        key_id: headers.key_id,
        raw_body: input.raw_body,
    })
    .map_err(|_| VerifyError::InvalidHeader("X-XD-Response-Sign"))?;
    keys.verify(headers.key_id, &canonical, headers.sign)
}

pub fn verify_webhook(
    raw_body: &[u8],
    headers: WebhookHeaders<'_>,
    keys: &PlatformKeys,
    now_secs: i64,
    window_secs: i64,
) -> Result<WebhookEvent, VerifyError> {
    let missing = missing_webhook_headers(&headers);
    if !missing.is_empty() {
        return Err(VerifyError::MissingHeaders { missing });
    }
    check_webhook_header_shapes(&headers)?;
    check_time_window(
        headers.timestamp,
        now_secs,
        window_secs,
        "X-XD-Webhook-Timestamp",
    )?;
    let canonical = canonical_webhook(&WebhookFields {
        event_id: headers.event_id,
        event_type: headers.event_type,
        timestamp: headers.timestamp,
        nonce: headers.nonce,
        key_id: headers.key_id,
        raw_body,
    })
    .map_err(|_| VerifyError::InvalidHeader("X-XD-Webhook-Signature"))?;
    keys.verify(headers.key_id, &canonical, headers.sign)?;
    parse_verified_event(raw_body, &headers)
}

pub fn parse_response(raw_body: &[u8]) -> Result<ApiEnvelope, ProtocolError> {
    let envelope: ApiEnvelope =
        serde_json::from_slice(raw_body).map_err(|_| ProtocolError::InvalidJson)?;
    if !valid_request_id(&envelope.request_id) {
        return Err(ProtocolError::InvalidPayload("requestId"));
    }
    if envelope.code.is_some() && envelope.message.is_none() {
        return Err(ProtocolError::InvalidPayload("message"));
    }
    Ok(envelope)
}

/// Fresh request nonce: visible ASCII, 16-64 characters, cryptographically random.
pub fn generate_nonce() -> Result<String, ProtocolError> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| ProtocolError::RandomSource)?;
    Ok(hex::encode(bytes))
}

fn parse_verified_event(
    raw_body: &[u8],
    headers: &WebhookHeaders<'_>,
) -> Result<WebhookEvent, VerifyError> {
    let mut event: WebhookEvent =
        serde_json::from_slice(raw_body).map_err(|_| VerifyError::InvalidPayload("JSON"))?;
    if event.event_id != headers.event_id || event.event_type_name() != headers.event_type {
        return Err(VerifyError::InvalidPayload("event identity"));
    }
    if !valid_out_trade_no(&event.out_trade_no) || event.gross_amount_fen == 0 {
        return Err(VerifyError::InvalidPayload("event amount or order"));
    }
    if !matches!(event.fee_bearer.as_str(), "SELLER" | "BUYER") {
        return Err(VerifyError::InvalidPayload("feeBearer"));
    }
    event.timestamp = headers.timestamp.to_owned();
    event.nonce = headers.nonce.to_owned();
    event.key_id = headers.key_id.to_owned();
    Ok(event)
}

impl WebhookEvent {
    fn event_type_name(&self) -> &'static str {
        match self.event_type {
            WebhookEventType::PaymentSucceeded => "PAYMENT_SUCCEEDED",
            WebhookEventType::PaymentClosed => "PAYMENT_CLOSED",
            WebhookEventType::PaymentFailed => "PAYMENT_FAILED",
            WebhookEventType::RefundSucceeded => "REFUND_SUCCEEDED",
            WebhookEventType::RefundFailed => "REFUND_FAILED",
        }
    }
}

fn canonical_path(raw: &str) -> Result<String, ProtocolError> {
    let decoded = percent_decode_once(raw).ok_or(ProtocolError::InvalidPath)?;
    if !decoded.starts_with('/')
        || decoded.contains("//")
        || decoded.contains("..")
        || decoded.contains(['\\', '?', '#'])
        || decoded.chars().any(char::is_control)
    {
        return Err(ProtocolError::InvalidPath);
    }
    Ok(decoded)
}

fn canonical_query(raw: &str) -> Result<String, ProtocolError> {
    let raw = raw.strip_prefix('?').unwrap_or(raw);
    if raw.is_empty() {
        return Ok(String::new());
    }
    let mut pairs: Vec<(String, String)> = Vec::new();
    for part in raw.split('&') {
        let (key, value) = part.split_once('=').unwrap_or((part, ""));
        let key = percent_decode_once(key).ok_or(ProtocolError::InvalidQuery)?;
        let value = percent_decode_once(value).ok_or(ProtocolError::InvalidQuery)?;
        pairs.push((key, value));
    }
    // Stable sort keeps the relative order of repeated keys.
    pairs.sort_by(|left, right| left.0.cmp(&right.0));
    let encoded: Vec<String> = pairs
        .into_iter()
        .map(|(key, value)| format!("{}={}", percent_encode(&key), percent_encode(&value)))
        .collect();
    Ok(encoded.join("&"))
}

fn percent_decode_once(input: &str) -> Option<String> {
    let bytes = input.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let high = hex_value(*bytes.get(index + 1)?)?;
            let low = hex_value(*bytes.get(index + 2)?)?;
            decoded.push((high << 4) | low);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded).ok()
}

fn percent_encode(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX_DIGITS[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX_DIGITS[usize::from(byte & 0x0f)]));
        }
    }
    encoded
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn validate_common_fields(
    timestamp: &str,
    nonce: &str,
    app_id: &str,
    key_id: &str,
    request_id: &str,
) -> Result<(), ProtocolError> {
    let app_id_ok = app_id.is_empty() || visible_ascii(app_id, 1, 128);
    if !valid_timestamp(timestamp)
        || !visible_ascii(nonce, 16, 64)
        || !app_id_ok
        || !visible_ascii(key_id, 1, 128)
        || !valid_request_id(request_id)
    {
        return Err(ProtocolError::InvalidHeaderShape);
    }
    Ok(())
}

fn visible_ascii(value: &str, min: usize, max: usize) -> bool {
    value.len() >= min
        && value.len() <= max
        && value.bytes().all(|byte| (b'!'..=b'~').contains(&byte))
}

fn valid_timestamp(value: &str) -> bool {
    !value.is_empty() && value.len() <= 10 && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn valid_request_id(value: &str) -> bool {
    visible_ascii(value, 8, 128)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

fn valid_out_trade_no(value: &str) -> bool {
    visible_ascii(value, 6, 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn check_time_window(
    timestamp: &str,
    now_secs: i64,
    window_secs: i64,
    header: &'static str,
) -> Result<(), VerifyError> {
    let parsed: i64 = timestamp
        .parse()
        .map_err(|_| VerifyError::InvalidHeader(header))?;
    let difference = now_secs
        .checked_sub(parsed)
        .ok_or(VerifyError::TimestampOutsideWindow)?;
    if difference.unsigned_abs() > window_secs.unsigned_abs() {
        return Err(VerifyError::TimestampOutsideWindow);
    }
    Ok(())
}

fn check_response_header_shapes(
    headers: &ResponseHeaders<'_>,
    request_id: &str,
) -> Result<(), VerifyError> {
    if !visible_ascii(headers.sign, 64, 1024) {
        return Err(VerifyError::InvalidHeader("X-XD-Response-Sign"));
    }
    if !visible_ascii(headers.key_id, 1, 128) {
        return Err(VerifyError::InvalidHeader("X-XD-Response-Key-Id"));
    }
    if !valid_timestamp(headers.timestamp) {
        return Err(VerifyError::InvalidHeader("X-XD-Response-Timestamp"));
    }
    if !visible_ascii(headers.nonce, 16, 64) {
        return Err(VerifyError::InvalidHeader("X-XD-Response-Nonce"));
    }
    if !valid_request_id(request_id) {
        return Err(VerifyError::InvalidHeader("X-XD-Request-Id"));
    }
    Ok(())
}

fn check_webhook_header_shapes(headers: &WebhookHeaders<'_>) -> Result<(), VerifyError> {
    if !visible_ascii(headers.sign, 64, 1024) {
        return Err(VerifyError::InvalidHeader("X-XD-Webhook-Signature"));
    }
    if !visible_ascii(headers.key_id, 1, 128) {
        return Err(VerifyError::InvalidHeader("X-XD-Webhook-Key-Id"));
    }
    if !valid_timestamp(headers.timestamp) {
        return Err(VerifyError::InvalidHeader("X-XD-Webhook-Timestamp"));
    }
    if !visible_ascii(headers.nonce, 16, 64) {
        return Err(VerifyError::InvalidHeader("X-XD-Webhook-Nonce"));
    }
    if !visible_ascii(headers.event_id, 1, 128) {
        return Err(VerifyError::InvalidHeader("X-XD-Webhook-Event-Id"));
    }
    if !visible_ascii(headers.event_type, 1, 64) {
        return Err(VerifyError::InvalidHeader("X-XD-Webhook-Event-Type"));
    }
    Ok(())
}

fn missing_response_headers(headers: Option<&ResponseHeaders<'_>>) -> Vec<&'static str> {
    let Some(headers) = headers else {
        return RESPONSE_HEADERS.to_vec();
    };
    let values = [
        headers.sign,
        headers.key_id,
        headers.timestamp,
        headers.nonce,
    ];
    RESPONSE_HEADERS
        .into_iter()
        .zip(values)
        .filter_map(|(name, value)| value.is_empty().then_some(name))
        .collect()
}

fn missing_webhook_headers(headers: &WebhookHeaders<'_>) -> Vec<&'static str> {
    let values = [
        headers.sign,
        headers.key_id,
        headers.timestamp,
        headers.nonce,
        headers.event_id,
        headers.event_type,
    ];
    WEBHOOK_HEADERS
        .into_iter()
        .zip(values)
        .filter_map(|(name, value)| value.is_empty().then_some(name))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const PLANTED_BODY: &str = "PLANTED_RAW_BODY_SECRET_SHOULD_NOT_APPEAR";
    const PLANTED_SIGN: &str = "PLANTED_SIGNATURE_SECRET_SHOULD_NOT_APPEAR";
    const PLANTED_PAYLOAD: &str = "PLANTED_PARSED_PAYLOAD_SECRET_SHOULD_NOT_APPEAR";

    fn planted_payload() -> serde_json::Value {
        serde_json::json!({ "secret": PLANTED_PAYLOAD, "nested": [PLANTED_PAYLOAD] })
    }

    fn assert_payload_redacted(output: &str) {
        assert!(
            !output.contains(PLANTED_PAYLOAD),
            "parsed body leaked into Debug output: {output}"
        );
    }

    fn assert_body_redacted(output: &str) {
        let byte_debug = format!("{:?}", PLANTED_BODY.as_bytes());
        assert!(
            !output.contains(PLANTED_BODY) && !output.contains(&byte_debug),
            "raw body leaked into Debug output: {output}"
        );
    }

    #[test]
    fn request_fields_debug_redacts_raw_body() {
        let fields = RequestFields {
            method: "POST",
            path: "/api/open/v1/payments",
            query: "",
            timestamp: "1700000000",
            nonce: "0123456789abcdef",
            app_id: "app-id",
            key_id: "key-id",
            request_id: "request-12345",
            content_type: Some("application/json"),
            raw_body: PLANTED_BODY.as_bytes(),
        };

        let output = format!("{fields:?}");

        assert_eq!(output.matches("<redacted>").count(), 1, "{output}");
        assert_body_redacted(&output);
        assert!(output.contains("/api/open/v1/payments"), "{output}");
    }

    #[test]
    fn response_fields_debug_redacts_raw_body() {
        let fields = ResponseFields {
            status: 200,
            content_type: Some("application/json"),
            request_id: "request-12345",
            timestamp: "1700000000",
            nonce: "0123456789abcdef",
            key_id: "key-id",
            raw_body: PLANTED_BODY.as_bytes(),
        };

        let output = format!("{fields:?}");

        assert_eq!(output.matches("<redacted>").count(), 1, "{output}");
        assert_body_redacted(&output);
        assert!(output.contains("request-12345"), "{output}");
    }

    #[test]
    fn webhook_fields_debug_redacts_raw_body() {
        let fields = WebhookFields {
            event_id: "event-12345",
            event_type: "PAYMENT_SUCCEEDED",
            timestamp: "1700000000",
            nonce: "0123456789abcdef",
            key_id: "key-id",
            raw_body: PLANTED_BODY.as_bytes(),
        };

        let output = format!("{fields:?}");

        assert_eq!(output.matches("<redacted>").count(), 1, "{output}");
        assert_body_redacted(&output);
        assert!(output.contains("PAYMENT_SUCCEEDED"), "{output}");
    }

    #[test]
    fn response_headers_debug_redacts_sign() {
        let headers = ResponseHeaders {
            sign: PLANTED_SIGN,
            key_id: "key-id",
            timestamp: "1700000000",
            nonce: "0123456789abcdef",
        };

        let output = format!("{headers:?}");

        assert_eq!(output.matches("<redacted>").count(), 1, "{output}");
        assert!(!output.contains(PLANTED_SIGN), "signature leaked: {output}");
        assert!(output.contains("key-id"), "{output}");
    }

    #[test]
    fn webhook_headers_debug_redacts_sign() {
        let headers = WebhookHeaders {
            sign: PLANTED_SIGN,
            key_id: "key-id",
            timestamp: "1700000000",
            nonce: "0123456789abcdef",
            event_id: "event-12345",
            event_type: "PAYMENT_SUCCEEDED",
        };

        let output = format!("{headers:?}");

        assert_eq!(output.matches("<redacted>").count(), 1, "{output}");
        assert!(!output.contains(PLANTED_SIGN), "signature leaked: {output}");
        assert!(output.contains("event-12345"), "{output}");
    }

    #[test]
    fn response_verification_debug_redacts_body_and_nested_sign() {
        let verification = ResponseVerification {
            status: 200,
            content_type: Some("application/json"),
            request_id: "request-12345",
            raw_body: PLANTED_BODY.as_bytes(),
            headers: Some(ResponseHeaders {
                sign: PLANTED_SIGN,
                key_id: "key-id",
                timestamp: "1700000000",
                nonce: "0123456789abcdef",
            }),
        };

        let output = format!("{verification:?}");

        assert_eq!(output.matches("<redacted>").count(), 2, "{output}");
        assert_body_redacted(&output);
        assert!(!output.contains(PLANTED_SIGN), "signature leaked: {output}");
        assert!(output.contains("request-12345"), "{output}");
    }

    #[test]
    fn webhook_event_debug_redacts_fee_projection() {
        let event = WebhookEvent {
            event_id: "event-12345".to_owned(),
            event_type: WebhookEventType::PaymentSucceeded,
            app_id: "app-id".to_owned(),
            out_trade_no: "ORDER-12345".to_owned(),
            out_refund_no: None,
            event_amount_fen: 100,
            gross_amount_fen: 100,
            fee_bearer: "SELLER".to_owned(),
            merchant_amount_fen: Some(100),
            fee_amount_fen: None,
            status: "SUCCESS".to_owned(),
            reason: None,
            occurred_at: 1_700_000_000,
            state_version: 1,
            attach: None,
            fee_projection: planted_payload(),
            timestamp: "1700000000".to_owned(),
            nonce: "0123456789abcdef".to_owned(),
            key_id: "key-id".to_owned(),
        };

        let output = format!("{event:?}");

        assert_eq!(output.matches("<redacted>").count(), 1, "{output}");
        assert_payload_redacted(&output);
        assert!(output.contains("ORDER-12345"), "{output}");
    }

    #[test]
    fn api_envelope_debug_redacts_fields() {
        let mut fields = serde_json::Map::new();
        fields.insert(
            "secret".to_owned(),
            serde_json::Value::String(PLANTED_PAYLOAD.to_owned()),
        );
        let envelope = ApiEnvelope {
            request_id: "request-12345".to_owned(),
            code: None,
            message: None,
            fields,
        };

        let output = format!("{envelope:?}");

        assert_eq!(output.matches("<redacted>").count(), 1, "{output}");
        assert_payload_redacted(&output);
        assert!(output.contains("request-12345"), "{output}");
    }
}
