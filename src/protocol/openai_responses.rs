//! `openai_responses` kernel (B §4.3).
//!
//! Preparation validates structure and passes every other field through
//! verbatim: whether a field is supported is the upstream's call, and
//! per-upstream refusals are learned and stripped by the relay (gateway
//! `relay::optional`). The relay is stateless,
//! so server-side state features (`previous_response_id`, `store: true`,
//! `background: true`) are still rejected rather than silently downgraded —
//! those are semantic constraints of the relay, not a field allowlist.
//!
//! Observation extracts usage and termination from the upstream wire without
//! rewriting it — the relay forwards the original bytes because the client
//! protocol equals the upstream protocol. Responses terminal events always
//! carry usage, so no `stream_options` injection is needed.

use super::sse::{Frame, RawFrame};
use super::usage::UsageCounts;
use super::{
    ObservedResponse, Prepared, ProtocolError, ProtocolId, RawValue, StreamEvent, TargetView,
    Terminal,
};
use serde_json::Value;

/// Build the upstream request for one attempt.
///
/// The wire is written field-by-field straight from the client's tree — no
/// intermediate `Value`, no deep copy — with only the model overridden.
/// `skip` names top-level fields the wire must not carry (learned refusals,
/// vendor fixups); a skipped `store` also suppresses the pin below, which is
/// the old strip-after-prepare result.
pub fn prepare(
    client_body: &Value,
    target: &TargetView<'_>,
    stream: bool,
    skip: &[&str],
) -> Result<Prepared, ProtocolError> {
    validate_request(client_body)?;
    let object = client_body
        .as_object()
        .ok_or(ProtocolError::InvalidRequest)?;
    let url = target.url(stream)?;
    let pin_store = !skip.contains(&"store");
    let mut out = Vec::new();
    out.push(b'{');
    let mut first = true;
    for (field, value) in object {
        if skip.contains(&field.as_str()) {
            continue;
        }
        if !first {
            out.push(b',');
        }
        first = false;
        super::write_json(&mut out, field)?;
        out.push(b':');
        if field == "model" {
            super::write_json(&mut out, target.upstream_model)?;
        } else {
            super::write_json(&mut out, value)?;
        }
    }
    // Stateless relay: pin store=false when the client omitted it, so upstreams
    // whose default is store=true (OpenAI) cannot keep server-side state. A
    // skipped `store` stays absent, matching the old strip-after-prepare result.
    if pin_store && !object.contains_key("store") {
        if !first {
            out.push(b',');
        }
        out.extend_from_slice(b"\"store\":false");
    }
    out.push(b'}');
    let body = bytes::Bytes::from(out);
    Ok(Prepared {
        protocol: ProtocolId::OpenAiResponses,
        url: url.to_owned(),
        content_type: "application/json",
        body,
        stream,
        headers: Vec::new(),
    })
}

/// Shared request validation for remote and in-process execution.
pub fn validate_request(client_body: &Value) -> Result<(), ProtocolError> {
    let object = client_body
        .as_object()
        .ok_or(ProtocolError::InvalidRequest)?;
    if object
        .get("model")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        return Err(ProtocolError::InvalidRequest);
    }
    // `input` is required: a non-empty string or a non-empty item array.
    match object.get("input") {
        Some(value) if value.as_str().is_some_and(|input| !input.is_empty()) => {}
        Some(value) if value.as_array().is_some_and(|items| !items.is_empty()) => {}
        _ => return Err(ProtocolError::InvalidRequest),
    }
    // The gateway provides no server-side state: a response id can only refer
    // to upstream storage the relay never created (Kimi pins
    // `previous_response_id: null`, which passes through).
    if object
        .get("previous_response_id")
        .is_some_and(|id| !id.is_null())
    {
        return Err(ProtocolError::InvalidContinuation);
    }
    // Stateless relay: the upstream must not keep the response either.
    if object.get("store").and_then(Value::as_bool) == Some(true) {
        return Err(ProtocolError::UnsupportedParameter);
    }
    // store/background, when present, must be booleans — a string "true" must
    // not sail through validation to a confused upstream 400.
    for field in ["store", "background"] {
        if let Some(value) = object.get(field)
            && !value.is_boolean()
        {
            return Err(ProtocolError::InvalidRequest);
        }
    }
    if object.get("background").and_then(Value::as_bool) == Some(true) {
        return Err(ProtocolError::UnsupportedParameter);
    }
    if let Some(value) = object.get("max_output_tokens")
        && value.as_u64().filter(|value| *value > 0).is_none()
    {
        return Err(ProtocolError::InvalidRequest);
    }
    Ok(())
}

/// Observe a non-streaming response.
///
/// Only the observed fields are deserialized, borrowed straight from the wire
/// (`raw_str`/`raw_value`); the response body itself — `output` with its
/// whole content — is never materialized.
pub fn parse_json(body: &[u8]) -> Result<ObservedResponse, ProtocolError> {
    let obs: ResponsesObservation =
        serde_json::from_slice(body).map_err(|_| ProtocolError::InvalidUpstreamResponse)?;
    // JSON `null` deserializes to `None` here, so `is_some()` is exactly the
    // old `!error.is_null()` verdict.
    if obs.error.is_some() {
        return Ok(ObservedResponse {
            usage: None,
            terminal: Terminal::Failed,
            upstream_model: None,
        });
    }
    // No terminal status is not success (B §4.7).
    let terminal = match super::raw_str(obs.status) {
        Some("completed") => Terminal::Completed,
        Some("incomplete") => Terminal::Incomplete,
        Some("failed") => Terminal::Failed,
        Some("cancelled") => Terminal::Cancelled,
        _ => Terminal::Failed,
    };
    Ok(ObservedResponse {
        usage: obs
            .usage
            .as_ref()
            .and_then(|usage| super::raw_value(usage))
            .as_ref()
            .and_then(usage_counts),
        terminal,
        upstream_model: super::raw_str(obs.model).map(str::to_owned),
    })
}

/// The observed fields of a Responses response; everything else (the `output`
/// array above all) is ignored without being materialized.
#[derive(serde::Deserialize)]
struct ResponsesObservation<'a> {
    #[serde(default, borrow)]
    error: Option<&'a RawValue>,
    #[serde(default, borrow)]
    status: Option<&'a RawValue>,
    #[serde(default, borrow)]
    usage: Option<&'a RawValue>,
    #[serde(default, borrow)]
    model: Option<&'a RawValue>,
}

/// Usage is total-based: the cached/reasoning sub-items are already inside the
/// reported totals and are evidence only — never added (B §4.2).
fn usage_from(value: &Value) -> Option<UsageCounts> {
    value.get("usage").and_then(usage_counts)
}

fn usage_counts(usage: &Value) -> Option<UsageCounts> {
    let input = usage.get("input_tokens").and_then(Value::as_u64)?;
    let output = usage.get("output_tokens").and_then(Value::as_u64)?;
    Some(UsageCounts {
        input_tokens: input,
        output_tokens: output,
        calls: 0,
        cached_input_tokens: usage
            .get("input_tokens_details")
            .and_then(|details| details.get("cached_tokens"))
            .and_then(Value::as_u64),
        reasoning_output_tokens: usage
            .get("output_tokens_details")
            .and_then(|details| details.get("reasoning_tokens"))
            .and_then(Value::as_u64),
        ..Default::default()
    })
}

/// Streaming observer: accumulates usage and detects the terminal event.
///
/// No per-delta events are emitted: the relay forwards the original bytes on
/// the pass-through path and never consumes deltas there, and no Responses
/// translation exists that would need them (the chat decoder emits deltas only
/// because the Chat↔Messages translation consumes them). Terminal and usage
/// accounting is the whole contract here.
#[derive(Default)]
pub struct StreamDecoder {
    usage: Option<UsageCounts>,
    terminal: Option<Terminal>,
    content_seen: bool,
}

impl StreamDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn usage(&self) -> Option<UsageCounts> {
        self.usage.clone()
    }

    /// Observe one frame. There is no `[DONE]` framing in Responses: the
    /// terminal event is the terminator.
    pub fn observe(&mut self, frame: &Frame) -> Result<Vec<StreamEvent>, ProtocolError> {
        self.observe_raw(frame.data.as_bytes())
    }

    /// Observe one raw SSE payload by bytes — the translated pump's entry
    /// point, with no `String` re-framing hop in between.
    pub fn observe_raw(&mut self, data: &[u8]) -> Result<Vec<StreamEvent>, ProtocolError> {
        let mut events = Vec::new();
        let data = std::str::from_utf8(data)
            .map_err(|_| ProtocolError::InvalidUpstreamResponse)?
            .trim();
        if data.is_empty() {
            return Ok(events);
        }
        let value: Value =
            serde_json::from_str(data).map_err(|_| ProtocolError::InvalidUpstreamResponse)?;
        if let Some(terminal) = self.observe_event(&value)? {
            if let Some(usage) = self.usage.clone() {
                events.push(StreamEvent::Usage(usage));
            }
            events.push(StreamEvent::Finish {
                reason: terminal_reason(terminal).to_owned(),
            });
        }
        Ok(events)
    }

    /// Observe a relay frame without materializing unused customer events.
    pub fn observe_for_relay(&mut self, frame: &Frame) -> Result<(), ProtocolError> {
        self.observe_raw_for_relay(frame.data.as_bytes())
    }

    /// Observe a parsed raw SSE frame on the Responses protocol path.
    pub fn observe_raw_frame_for_relay(&mut self, frame: &RawFrame) -> Result<(), ProtocolError> {
        self.observe_raw_for_relay(&frame.data)
    }

    /// Observe a raw Responses SSE payload without materializing customer events.
    pub fn observe_raw_for_relay(&mut self, data: &[u8]) -> Result<(), ProtocolError> {
        let data = std::str::from_utf8(data)
            .map_err(|_| ProtocolError::InvalidUpstreamResponse)?
            .trim();
        if data.is_empty() {
            return Ok(());
        }
        // Fast path: only a terminal, error, or content-delta event can change
        // the observation; every other frame is skipped without a parse. The
        // marker set below is a superset of everything the observer consumes:
        // `type` (`*.delta` events flip `content_seen`; the four terminal
        // `response.*` events fix the verdict and carry `response.usage`; `error`
        // fails the stream). Delta events are exactly the `*.delta` vocabulary,
        // so a `.delta` substring routes them through the full parse that flips
        // `content_seen` (a false positive there costs one ignored parse, never a
        // wrong flag).
        let content_delta = data.contains(".delta");
        if !content_delta
            && !TERMINAL_SNIFF.iter().any(|needle| data.contains(needle))
            && !data.contains("\"error\"")
        {
            // The frame's JSON shape is still validated without materializing it:
            // a malformed frame is rejected exactly as before (the scan touches no
            // `Value` tree).
            serde_json::from_str::<serde::de::IgnoredAny>(data)
                .map_err(|_| ProtocolError::InvalidUpstreamResponse)?;
            return Ok(());
        }
        let value: Value =
            serde_json::from_str(data).map_err(|_| ProtocolError::InvalidUpstreamResponse)?;
        self.observe_event(&value)?;
        Ok(())
    }

    /// Apply one parsed event to the observation. Returns the terminal verdict
    /// when this event is terminal. Usage from a terminal event's `response`
    /// object overwrites any earlier value (last wins, as in chat).
    fn observe_event(&mut self, value: &Value) -> Result<Option<Terminal>, ProtocolError> {
        match value.get("type").and_then(Value::as_str) {
            // Content deltas: the relay streaming hold's commit signal. Refusal and
            // custom-tool-call-input deltas are user-visible content too.
            Some("response.output_text.delta")
            | Some("response.reasoning_summary_text.delta")
            | Some("response.reasoning_text.delta")
            | Some("response.function_call_arguments.delta")
            | Some("response.refusal.delta")
            | Some("response.custom_tool_call_input.delta")
            | Some("response.code_interpreter_call_code.delta") => self.content_seen = true,
            _ => {}
        }
        let terminal = match value.get("type").and_then(Value::as_str) {
            Some("response.completed") => Some(Terminal::Completed),
            Some("response.incomplete") => Some(Terminal::Incomplete),
            Some("response.failed") => Some(Terminal::Failed),
            Some("response.cancelled") => Some(Terminal::Cancelled),
            Some("error") => return Err(ProtocolError::UpstreamError),
            _ => None,
        };
        if let Some(terminal) = terminal {
            self.terminal = Some(terminal);
            if let Some(usage) = value.get("response").and_then(usage_from) {
                self.usage = Some(usage);
            }
        }
        Ok(terminal)
    }

    /// Terminal verdict. A stream that ends without a terminal event is not a
    /// success (B §4.7).
    pub fn finish(&self) -> Terminal {
        match self.terminal {
            Some(terminal) => terminal,
            None => Terminal::Failed,
        }
    }

    pub fn terminal_seen(&self) -> bool {
        self.terminal.is_some()
    }

    /// Whether a content delta event was observed: the relay streaming hold's
    /// commit signal (see the chat kernel for the full contract).
    pub fn content_seen(&self) -> bool {
        self.content_seen
    }
}

/// The `type` strings whose presence marks a frame worth a full parse on the
/// relay fast path.
const TERMINAL_SNIFF: &[&str] = &[
    "response.completed",
    "response.incomplete",
    "response.failed",
    "response.cancelled",
];

fn terminal_reason(terminal: Terminal) -> &'static str {
    match terminal {
        Terminal::Completed => "completed",
        Terminal::Incomplete => "incomplete",
        Terminal::Failed => "failed",
        Terminal::Cancelled => "cancelled",
    }
}
