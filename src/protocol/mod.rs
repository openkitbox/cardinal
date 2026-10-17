//! Server role: relay-side protocol kernels (A §5 `protocols`, B §2–§5).
//!
//! Each protocol has its own preparation, JSON/SSE observation and termination
//! rules. There is deliberately **no** universal multi-protocol trait: the
//! facade below dispatches with an exhaustive match, so adding a protocol is an
//! explicit code change and never a silent fallback (A §2 rule 3, §5).
//!
//! Kernels work at the `serde_json::Value` level. They never see credentials,
//! `CredentialHandle`, database rows or the supply snapshot. They receive a
//! prepared, non-secret request view and return wire bytes plus observation
//! results. [`ProtocolId`] / [`ProtocolError`] are the server role's closed
//! identifier/error taxonomy.
//!
//! This half of the crate imports nothing from `crate::client` — the two
//! roles only share the wire formats, not code.

pub mod anthropic_messages;
pub mod gemini;
pub mod openai_chat;
pub mod openai_responses;
pub mod sse;
pub mod usage;

use self::usage::UsageCounts;
use serde::{Deserialize, Serialize};

/// The closed protocol identifiers (B §2.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolId {
    OpenAiChat,
    OpenAiResponses,
    AnthropicMessages,
    /// Google Gemini `generateContent` / `streamGenerateContent`.
    Gemini,
}

impl ProtocolId {
    pub const ALL: [Self; 4] = [
        Self::OpenAiChat,
        Self::OpenAiResponses,
        Self::AnthropicMessages,
        Self::Gemini,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OpenAiChat => "openai_chat",
            Self::OpenAiResponses => "openai_responses",
            Self::AnthropicMessages => "anthropic_messages",
            Self::Gemini => "gemini",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|protocol| protocol.as_str() == value)
    }

    /// Client-visible inference entrypoints for the static-path protocols
    /// (B §2.1). Gemini is NOT listed: its client path is dynamic (model and
    /// method live in the URL — `/v1beta/models/{model}:generateContent`), so
    /// routing is handled by a dedicated handler in the gateway instead of
    /// this table.
    pub const fn client_paths(self) -> &'static [&'static str] {
        match self {
            Self::OpenAiChat => &["/v1/chat/completions"],
            Self::OpenAiResponses => &["/v1/responses"],
            Self::AnthropicMessages => &["/v1/messages"],
            // Dynamic routing: the model and method are path segments, matched by
            // the `/v1beta/models/<**call>` handler in `gateway::api`.
            Self::Gemini => &[],
        }
    }

    /// Whether JSON and SSE share one physical URL. Gemini does not:
    /// `generateContent` and `streamGenerateContent` are different paths, so
    /// `TargetView::url(stream)` routes through `stream_endpoint`.
    pub const fn streaming_shares_endpoint(self) -> bool {
        match self {
            Self::OpenAiChat | Self::OpenAiResponses | Self::AnthropicMessages => true,
            Self::Gemini => false,
        }
    }
}

impl std::fmt::Display for ProtocolId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Stable machine codes for platform-generated protocol errors (B §2.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtocolError {
    /// Body/field validation failed before any send.
    InvalidRequest,
    /// A field or capability is not supported for this profile/model.
    UnsupportedParameter,
    /// The requested model is unknown or not visible to this caller.
    ModelNotFound,
    /// The requested model exists but has no eligible source.
    ModelUnavailable,
    /// The request body exceeds the entry limit.
    RequestTooLarge,
    /// More than one client authentication carrier was supplied.
    AmbiguousAuthentication,
    /// The request media type is not supported.
    UnsupportedMediaType,
    /// A resource or API outside the supported set was requested.
    UnsupportedApi,
    /// The parent reference is missing, malformed or unusable (B §5).
    InvalidContinuation,
    /// The caller excluded the media type the protocol must return.
    NotAcceptable,
    /// The relay authentication carrier or token is invalid.
    AuthenticationFailed,
    /// A platform-side dependency is unavailable.
    PlatformUnavailable,
    /// A replay conflicts with the immutable recorded request.
    IdempotencyConflict,
    /// The caller is not authorized for the requested resource.
    PermissionDenied,
    /// The caller cannot fund this request.
    InsufficientFunds,
    /// The caller's token quota cannot fund this request.
    TokenLimitExceeded,
    /// Upstream authentication was rejected.
    UpstreamAuthenticationFailed,
    /// Upstream rate/quota rejection.
    UpstreamRateLimited,
    /// The upstream response could not be parsed as this protocol.
    InvalidUpstreamResponse,
    /// Upstream returned an error status.
    UpstreamError,
    /// Deadline/idle/connect expiry.
    UpstreamTimeout,
}

impl ProtocolError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::UnsupportedParameter => "unsupported_parameter",
            Self::ModelNotFound => "model_not_found",
            Self::ModelUnavailable => "model_unavailable",
            Self::RequestTooLarge => "request_too_large",
            Self::AmbiguousAuthentication => "ambiguous_authentication",
            Self::UnsupportedMediaType => "unsupported_media_type",
            Self::UnsupportedApi => "unsupported_api",
            Self::InvalidContinuation => "invalid_continuation",
            Self::NotAcceptable => "not_acceptable",
            Self::AuthenticationFailed => "invalid_api_key",
            Self::IdempotencyConflict => "idempotency_conflict",
            Self::PermissionDenied => "permission_denied",
            Self::PlatformUnavailable => "platform_unavailable",
            Self::UpstreamAuthenticationFailed => "upstream_authentication_failed",
            Self::UpstreamRateLimited => "rate_limit_exceeded",
            Self::InvalidUpstreamResponse => "invalid_upstream_response",
            Self::UpstreamError => "upstream_error",
            Self::UpstreamTimeout => "upstream_timeout",
            Self::InsufficientFunds => "insufficient_funds",
            Self::TokenLimitExceeded => "token_limit_exceeded",
        }
    }

    /// HTTP status the client sees (B §2.4).
    pub const fn status(self) -> u16 {
        match self {
            Self::InvalidRequest
            | Self::UnsupportedParameter
            | Self::AmbiguousAuthentication
            | Self::InvalidContinuation => 400,
            Self::AuthenticationFailed => 401,
            Self::IdempotencyConflict => 409,
            Self::PermissionDenied => 403,
            Self::ModelNotFound => 404,
            Self::ModelUnavailable | Self::PlatformUnavailable => 503,
            Self::RequestTooLarge => 413,
            Self::UnsupportedMediaType => 415,
            Self::UnsupportedApi => 501,
            Self::NotAcceptable => 406,
            Self::UpstreamAuthenticationFailed => 502,
            Self::UpstreamRateLimited => 429,
            Self::InvalidUpstreamResponse | Self::UpstreamError => 502,
            Self::UpstreamTimeout => 504,
            Self::InsufficientFunds | Self::TokenLimitExceeded => 402,
        }
    }

    /// Chat `type` (B §2.4 closed mapping).
    pub const fn openai_type(self) -> &'static str {
        match self {
            Self::UpstreamAuthenticationFailed => "authentication_error",
            Self::UpstreamRateLimited => "rate_limit_error",
            Self::ModelUnavailable
            | Self::InvalidUpstreamResponse
            | Self::UpstreamError
            | Self::UpstreamTimeout
            | Self::PlatformUnavailable
            | Self::UnsupportedApi => "api_error",
            _ => "invalid_request_error",
        }
    }

    /// Messages `error.type` (B §2.4 closed mapping).
    pub const fn anthropic_type(self) -> &'static str {
        match self {
            Self::ModelNotFound => "not_found_error",
            Self::RequestTooLarge => "request_too_large",
            Self::AuthenticationFailed | Self::UpstreamAuthenticationFailed => {
                "authentication_error"
            }
            Self::PermissionDenied => "permission_error",
            Self::UpstreamRateLimited => "rate_limit_error",
            Self::ModelUnavailable
            | Self::InvalidUpstreamResponse
            | Self::UpstreamError
            | Self::UpstreamTimeout
            | Self::PlatformUnavailable
            | Self::UnsupportedApi => "api_error",
            Self::InsufficientFunds | Self::TokenLimitExceeded => "billing_error",
            _ => "invalid_request_error",
        }
    }
}

impl std::fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for ProtocolError {}

/// Serialize one JSON piece straight into the wire buffer. Building the wire
/// field-by-field (rather than an intermediate `Value` tree) is what keeps
/// `prepare` free of a deep copy of the client request.
fn write_json<T: serde::Serialize + ?Sized>(
    out: &mut Vec<u8>,
    value: &T,
) -> Result<(), ProtocolError> {
    serde_json::to_writer(out, value).map_err(|_| ProtocolError::InvalidRequest)
}

/// Borrowed, zero-copy view of one observed JSON field (`serde_json`
/// `raw_value` feature): a reference into the response bytes, never a copy.
/// Non-streaming responses can be tens of megabytes while observation reads a
/// handful of scalars, so the `parse_json` kernels deserialize only the
/// observed fields through these helpers and ignore the rest — no `Value`
/// tree of the body is ever built. Semantics follow the old `Value`-path
/// accessors exactly: a wrongly-typed field reads as absent, never as a
/// parse error.
use serde_json::value::RawValue;

/// Decode one observed raw field exactly like `Value::as_str`: a JSON string
/// yields its decoded text; anything else (number, bool, null, absent) yields
/// `None`.
pub(super) fn raw_str(raw: Option<&RawValue>) -> Option<&str> {
    serde_json::from_str(raw?.get()).ok()
}

/// Split an array-valued observed field into borrowed elements without
/// materializing any of them; `None` when the field is not an array — the
/// `Value::as_array` verdict.
pub(super) fn raw_array(raw: &RawValue) -> Option<Vec<&RawValue>> {
    serde_json::from_str(raw.get()).ok()
}

/// Whether an observed raw field is a JSON array (its first byte — a
/// `RawValue` starts at the value, with no surrounding whitespace): the cheap
/// form of `Value::as_array(..).is_some()`.
pub(super) fn raw_is_array(raw: &RawValue) -> bool {
    raw.get().as_bytes().first() == Some(&b'[')
}

/// Parse one small observed subtree (a usage object: a handful of scalars)
/// into a `Value` so the existing usage extractors keep their exact logic.
/// The whole-body tree this replaces carried every content byte; this carries
/// only the counters.
pub(super) fn raw_value(raw: &RawValue) -> Option<serde_json::Value> {
    serde_json::from_str(raw.get()).ok()
}

/// Exhaustive dispatch. A new protocol must be added here explicitly; there is
/// no catch-all that would silently downgrade to another protocol (A §5).
///
/// `skip` names top-level fields the wire must not carry (learned upstream
/// refusals, vendor fixups): the kernels omit them while building the body,
/// so a strip never costs a parse/re-serialize round-trip of the wire.
pub fn prepare(
    protocol: ProtocolId,
    client_body: &serde_json::Value,
    target: &TargetView<'_>,
    stream: bool,
    skip: &[&str],
) -> Result<Prepared, ProtocolError> {
    debug_assert_eq!(protocol, target.protocol);
    match protocol {
        ProtocolId::OpenAiChat => openai_chat::prepare(client_body, target, stream, skip),
        ProtocolId::OpenAiResponses => openai_responses::prepare(client_body, target, stream, skip),
        ProtocolId::AnthropicMessages => {
            anthropic_messages::prepare(client_body, target, stream, skip)
        }
        ProtocolId::Gemini => gemini::prepare(client_body, target, stream, skip),
    }
}

/// Observe a complete non-streaming response for the given protocol.
pub fn parse_json(protocol: ProtocolId, body: &[u8]) -> Result<ObservedResponse, ProtocolError> {
    match protocol {
        ProtocolId::OpenAiChat => openai_chat::parse_json(body),
        ProtocolId::OpenAiResponses => openai_responses::parse_json(body),
        ProtocolId::AnthropicMessages => anthropic_messages::parse_json(body),
        ProtocolId::Gemini => gemini::parse_json(body),
    }
}

/// Per-protocol streaming observer. Each variant keeps its own termination
/// rules; nothing is shared except the framing (B §4.1).
pub enum Decoder {
    Chat(openai_chat::StreamDecoder),
    Responses(openai_responses::StreamDecoder),
    Messages(anthropic_messages::StreamDecoder),
    Gemini(gemini::StreamDecoder),
}

impl Decoder {
    pub fn new(protocol: ProtocolId) -> Self {
        match protocol {
            ProtocolId::OpenAiChat => Self::Chat(openai_chat::StreamDecoder::new()),
            ProtocolId::OpenAiResponses => Self::Responses(openai_responses::StreamDecoder::new()),
            ProtocolId::AnthropicMessages => {
                Self::Messages(anthropic_messages::StreamDecoder::new())
            }
            ProtocolId::Gemini => Self::Gemini(gemini::StreamDecoder::new()),
        }
    }

    pub fn observe(&mut self, frame: &sse::Frame) -> Result<Vec<StreamEvent>, ProtocolError> {
        match self {
            Self::Chat(decoder) => decoder.observe(frame),
            Self::Responses(decoder) => decoder.observe(frame),
            Self::Messages(decoder) => decoder.observe(frame),
            Self::Gemini(decoder) => decoder.observe(frame),
        }
    }

    /// Observe a raw relay frame on the translation path, materializing the
    /// events a translating pump consumes. Byte input: no `String` re-framing
    /// hop, no per-frame copy of the payload.
    pub fn observe_raw(
        &mut self,
        frame: &sse::RawFrame,
    ) -> Result<Vec<StreamEvent>, ProtocolError> {
        match self {
            Self::Chat(decoder) => decoder.observe_raw(&frame.data),
            Self::Responses(decoder) => decoder.observe_raw(&frame.data),
            Self::Messages(decoder) => decoder.observe_raw(frame.event.as_deref(), &frame.data),
            Self::Gemini(decoder) => decoder.observe_raw(&frame.data),
        }
    }
    /// Validate and observe a relay frame without constructing unused events.
    pub fn observe_for_relay(&mut self, frame: &sse::Frame) -> Result<(), ProtocolError> {
        match self {
            Self::Chat(decoder) => decoder.observe_for_relay(frame),
            Self::Responses(decoder) => decoder.observe_for_relay(frame),
            Self::Messages(decoder) => decoder.observe(frame).map(|_| ()),
            Self::Gemini(decoder) => decoder.observe(frame).map(|_| ()),
        }
    }
    pub fn observe_raw_for_relay(&mut self, frame: &sse::RawFrame) -> Result<(), ProtocolError> {
        match self {
            Self::Chat(decoder) => decoder.observe_raw_frame_for_relay(frame),
            Self::Responses(decoder) => decoder.observe_raw_frame_for_relay(frame),
            Self::Messages(decoder) => decoder.observe_raw_for_relay(frame),
            Self::Gemini(decoder) => decoder.observe_raw_for_relay(frame),
        }
    }

    pub fn finish(&self) -> Terminal {
        match self {
            Self::Chat(decoder) => decoder.finish(),
            Self::Responses(decoder) => decoder.finish(),
            Self::Messages(decoder) => decoder.finish(),
            Self::Gemini(decoder) => decoder.finish(),
        }
    }

    pub fn usage(&self) -> Option<UsageCounts> {
        match self {
            Self::Chat(decoder) => decoder.usage(),
            Self::Responses(decoder) => decoder.usage(),
            Self::Messages(decoder) => decoder.usage(),
            Self::Gemini(decoder) => decoder.usage(),
        }
    }
    pub fn terminal_seen(&self) -> bool {
        match self {
            Self::Chat(decoder) => decoder.terminal_seen(),
            Self::Responses(decoder) => decoder.terminal_seen(),
            Self::Messages(decoder) => decoder.terminal_seen(),
            Self::Gemini(decoder) => decoder.terminal_seen(),
        }
    }

    /// Whether any real content (text / reasoning / tool-call delta) has been
    /// observed on either the event or the relay path. The relay streaming hold
    /// commits (stops buffering, starts forwarding) the moment this flips.
    pub fn content_seen(&self) -> bool {
        match self {
            Self::Chat(decoder) => decoder.content_seen(),
            Self::Responses(decoder) => decoder.content_seen(),
            Self::Messages(decoder) => decoder.content_seen(),
            Self::Gemini(decoder) => decoder.content_seen(),
        }
    }
}
/// Non-secret view of the selected target handed to a kernel.
pub struct TargetView<'a> {
    pub protocol: ProtocolId,
    pub endpoint: &'a str,
    pub stream_endpoint: Option<&'a str>,
    pub upstream_model: &'a str,
}

impl TargetView<'_> {
    /// The URL to use for this request. A missing streaming endpoint is an
    /// error, never a guessed path (A §4.6.1).
    pub fn url(&self, stream: bool) -> Result<&str, ProtocolError> {
        if stream && !self.protocol.streaming_shares_endpoint() {
            return self.stream_endpoint.ok_or(ProtocolError::InvalidRequest);
        }
        Ok(self.endpoint)
    }
}

/// Fully prepared outbound request. Contains no secret material.
#[derive(Clone, Debug)]
pub struct Prepared {
    pub protocol: ProtocolId,
    pub url: String,
    pub content_type: &'static str,
    pub body: bytes::Bytes,
    pub stream: bool,
    /// Protocol-required, non-secret upstream headers (for example the Anthropic
    /// API version). Credentials are never placed here.
    pub headers: Vec<(&'static str, String)>,
}

/// One decoded stream event, used for observation only. The relay forwards the
/// original upstream bytes, so no protocol rewriting happens here.
#[derive(Clone, Debug, PartialEq)]
pub enum StreamEvent {
    TextDelta(String),
    ReasoningDelta(String),
    ToolCallDelta {
        index: u32,
        id: Option<String>,
        name: Option<String>,
        arguments: String,
    },
    Usage(UsageCounts),
    Finish {
        reason: String,
    },
}

/// How a stream ended (B §4.1, per-protocol terminal rules).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Terminal {
    Completed,
    Incomplete,
    Failed,
    Cancelled,
}

/// Observation result of one non-streaming response.
#[derive(Clone, Debug)]
pub struct ObservedResponse {
    pub usage: Option<UsageCounts>,
    pub terminal: Terminal,
    /// Model id echoed by the upstream, kept for evidence only.
    pub upstream_model: Option<String>,
}
