//! The Cursor protocol kernel: an upstream-only translation target (plan
//! 2026-11-06-cursor-protocol, Phase 1).
//!
//! Cursor's agent endpoint is not a JSON/SSE API. A Run is one Connect bidi
//! stream of length-prefixed protobuf messages (`AgentService/Run` over
//! HTTP/2, as the IDE does it); when HTTP/2 is unavailable the same messages
//! travel split, the downlink as `AgentService/RunSSE` and the uplink as one
//! `BidiService/BidiAppend` request per message (the IDE's own HTTP/1.1
//! fallback, and what the headless CLI does). The kernel is split by
//! responsibility, every part a pure byte transform with no I/O, timers,
//! credentials or database:
//!
//! * [`pb`] — protobuf scalars, nested messages and `google.protobuf.Value`
//!   (`serde_json::Value`) conversion;
//! * [`connect`] — Connect version-1 framing, as a splitter for the downlink
//!   and a wrapper for the uplink;
//! * [`msg`] — the `agent.v1` field numbers, in one place;
//! * [`request`] — the dialect body → `run_request`, blobs and the opening
//!   HTTP request ([`request::RunPlan`]);
//! * [`response`] — the downlink frames → [`crate::protocol::StreamEvent`]s,
//!   usage and the Run's terminal verdict ([`response::StreamDecoder`]);
//! * [`uplink`] — the answers a downlink frame calls for (KV blobs, the tool
//!   list, the environment, refusals of Cursor's own tools).
//!
//! Timers, sequencing and the two HTTP legs live in `upstream::cursor_run`;
//! bearer resolution and refresh in `upstream::cursor_tokens`; dashboard usage
//! reconciliation in `upstream::cursor_usage`; the browser login in
//! `crate::cursor`. The plan's deviation ledger
//! (`.ox/plans/2026-11-06-cursor-protocol.md`, "落地偏差") records where the
//! implementation departs from the plan text.
//!
//! Deliberately no `prost`/`tonic` (plan D8): the schema surface is a few
//! dozen fields, and a build-time codegen step plus checked-in `.proto` files
//! would be a second source of truth that drifts silently from what the vendor
//! sends. The reference implementation writes its protobuf by hand for the
//! same reason.
//!
//! Every reader is bounded and fail-closed: a length-delimited value is
//! refused above [`pb::MAX_FIELD_LEN`] or [`connect::MAX_INBOUND_PAYLOAD`]
//! before a single byte is buffered, a truncated input is an error rather than
//! a short read, recursion depth is capped ([`pb::MAX_VALUE_DEPTH`]), and
//! nothing here can panic on malformed input. Unknown fields are skipped by
//! wire type instead of failing the message, so a vendor adding a field does
//! not break the stream.

pub mod connect;
pub mod msg;
pub mod pb;
pub mod request;
pub mod response;
pub mod uplink;

use crate::protocol::ProtocolError;

pub use request::RunPlan;
pub use response::{Retention, StreamDecoder};

/// The Cursor API origin the vendor's own clients dial for everything but the
/// agent stream: the unary agent calls (the usable-models list), the credential
/// plane and the dashboard. Also where the HTTP/1.1 agent fallback goes (the
/// IDE rewrites every `*.api5.cursor.sh` host to this one when it cannot use
/// HTTP/2). Fixed, never derived from provider input.
pub const API_ORIGIN: &str = "https://api2.cursor.sh";

/// The agent-stream origin the IDE dials (`cursorCreds.agentBackendUrlNonPrivacy`
/// in Cursor 3.29.9, `cursor-always-local`'s `agentBidiTransport`): the
/// HTTP/2 bidi `AgentService/Run` lives here. HTTP/2 only — the IDE never
/// sends an HTTP/1.1 request to it. The regional variants the IDE may switch
/// to from `GetServerConfig` (`agentn-gcpp-{uswest,eucentral,apsoutheast}`)
/// are the same service behind closer front doors; the default is what every
/// fresh install uses. Fixed, never derived from provider input.
pub const AGENT_ORIGIN: &str = "https://agentn.api5.cursor.sh";

/// Why a Cursor wire byte sequence could not be read — or, on the uplink, why
/// one message cannot be framed.
///
/// A module-local error instead of [`ProtocolError`] because the platform
/// taxonomy is deliberately coarse: it has no way to say "the peer compressed
/// a frame we never negotiated", "a declared length is implausible", or "the
/// input ended mid-frame", and those distinctions are what the transport layer
/// (stall/truncation vs. protocol mismatch) and the diagnostics need. The
/// variants carry no payload, and [`std::fmt::Display`] prints only the fixed
/// texts below, so no request content, blob or credential can ever reach a log
/// line through an error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CursorError {
    /// The input ended inside a value or a frame.
    Truncated,
    /// A declared length exceeds the accepted bound.
    TooLarge,
    /// A frame is gzip-compressed; the Connect compression flag is refused.
    Compressed,
    /// The bytes are not valid for the shape being read.
    Malformed,
    /// Nested `google.protobuf.Value` recursion exceeds the depth bound.
    TooDeep,
}

impl std::fmt::Display for CursorError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Truncated => "cursor: input ended inside a value",
            Self::TooLarge => "cursor: declared length is above the accepted bound",
            Self::Compressed => "cursor: compressed frames are not supported",
            Self::Malformed => "cursor: malformed wire bytes",
            Self::TooDeep => "cursor: nested value is too deep",
        })
    }
}

impl std::error::Error for CursorError {}

/// Read-side failures all mean the same thing to the platform: the upstream
/// wire could not be understood. The one write-side error
/// ([`CursorError::TooLarge`], our own message not fitting the `u32` frame
/// length) is checked before sending and never travels through this mapping.
impl From<CursorError> for ProtocolError {
    fn from(_: CursorError) -> Self {
        Self::InvalidUpstreamResponse
    }
}
