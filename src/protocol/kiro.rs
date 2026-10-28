//! Kiro (KAS) protocol kernel — request preparation.
//!
//! Kiro is an upstream-only protocol: it has no client-facing endpoint, and the
//! gateway reaches it by translating an `openai_chat` request into the KAS
//! session shape. This kernel owns the *wire* half of that shape: it renders the
//! body the translation layer built (omitting learned-refused fields, never
//! adding `stream`), stamps the static KAS identity from
//! [`crate::kiro::profile`], and attaches this logical call's retry headers.
//!
//! The endpoint is the capability's — a Kiro row's `base_url` IS its runtime
//! root (`https://runtime.{region}.kiro.dev/`), so the row's region and the URL
//! can never disagree. `kas_endpoint` exists for the admin/quota side, not as a
//! second URL source here.
//!
//! Response observation: [`StreamDecoder`] is the single AWS Event Stream state
//! machine behind both the relay's translated pump and the non-streaming
//! [`parse_json`] / `translation::kiro::response_to_ir` aggregation, so a
//! streamed and a buffered answer can never disagree.
//!
//! Semantics follow the reference `kiro2claude`
//! (`packages/core/src/kiro/model/events/base.ts` and
//! `packages/core/src/claude/stream.ts`). Deliberate deviations, all because
//! the first version carries a smaller concept set:
//!
//! * **No legacy `<thinking>` decoding and no leaked tool-call text rescue.**
//!   The reference's `LegacyThinkingDecoder` and `tool-call-text` detector
//!   rewrite assistant text the model never described as reasoning/tools; this
//!   kernel only reports what the upstream's own events said.
//! * **Estimated token accounting is ledger-only.** Input is `floor(advertised
//!   context window × contextUsagePercentage / 100)`; output is `floor(total
//!   chars / 4)` across accumulated text, reasoning and every tool call's
//!   arguments. These are estimates, not vendor-reported token counts. A
//!   missing window or percentage omits usage entirely rather than fabricating
//!   zeros. `meteringEvent` credits are tracing evidence only: they are never
//!   converted to USD or to a cached-token split. Kiro does not produce
//!   `StreamEvent::Usage`, so these estimates never enter client-visible
//!   frames.
//! * **`metadataEvent` is the only normal-end evidence.** Its `stopReason` is
//!   never trusted (real tool-calling responses report `END_TURN`); the
//!   terminal state is inferred — tools present ⇒ `tool_calls`, a tool whose
//!   completion frame never arrived ⇒ `length`, otherwise `stop`. A stream
//!   that ends without it is [`Terminal::Failed`], never a clean stop.
//! * **Tool indexes are assigned by `toolUseId`**, first-seen order, so
//!   parallel calls stay stable end to end (the reference's block indexes do
//!   the same inside one stream). A completed id is never reused and a name
//!   never changes mid-input ([`ProtocolError::InvalidUpstreamResponse`]).
//! * **Unknown ordinary events are ignored**, an unknown *message* type is an
//!   error; `error` frames and non-benign `exception` frames fail with
//!   [`ProtocolError::InvalidUpstreamResponse`] and log only their code/type —
//!   payloads are upstream data, not diagnostics. The one benign exception is
//!   `ContentLengthExceededException`, which is the output-ceiling terminal
//!   (see [`StreamDecoder::finish`]).
//! * **A truncated body is refused.** [`aggregate`] frames the whole body with
//!   the AWS framer and fails on a partial frame, so `parse_json` and
//!   `response_to_ir` can never observe half a response.
//! * **GPT reasoning is surfaced as ordinary thinking.** On V3 GPT routes KAS
//!   sends `reasoningContentEvent.text` as a placeholder whose real content is
//!   the encrypted signature; the reference accumulates it opaquely and never
//!   shows it to the client. This kernel forwards every reasoning delta as
//!   [`StreamEvent::ReasoningDelta`], so a GPT route shows the placeholder as
//!   visible thinking. Not hidden yet: the IR has no opaque-reasoning concept.
//! * **Post-`metadataEvent` frames are drained after the terminal.** KAS sends
//!   `contextUsageEvent`/`meteringEvent` after `metadataEvent`; the relay's
//!   translated pump keeps reading for a bounded window after the `Finish`
//!   event and observes — never forwards — those frames. That read is what
//!   gives the ledger its usage estimate on streamed responses; a buffered
//!   response observes the whole body by construction.
//! * **The streaming decoder accumulates the full text and reasoning.** The
//!   same [`StreamDecoder`] backs the streamed and buffered paths (one state
//!   machine, no drift), so a streamed response keeps one full copy of the
//!   text/reasoning in memory although only deltas are forwarded, and each
//!   delta event costs one small allocation. The buffered path moves the
//!   accumulated text into the IR rather than copying it again.

use super::awseventstream::{Framer, Message};
use super::usage::UsageCounts;
use super::{
    ObservedResponse, Prepared, ProtocolError, ProtocolId, StreamEvent, TargetView, Terminal,
    write_json, write_json_value,
};
use crate::kiro::profile::{self, KIRO_MAX_ATTEMPTS};
use serde_json::Value;
use std::collections::HashMap;

/// Prepare one outbound KAS request.
///
/// `stream` describes how the *client* asked to be answered, not the request:
/// the KAS body has no `stream` field, so it is only recorded on
/// [`Prepared::stream`] (the response side decides what to do with the AWS
/// Event Stream). `skip` names top-level fields the wire must not carry
/// (learned refusals): they are omitted while the body is rendered, so a strip
/// never costs a parse/re-serialize round-trip.
pub fn prepare(
    client_body: &Value,
    target: &TargetView<'_>,
    stream: bool,
    skip: &[&str],
    strip_images: bool,
) -> Result<Prepared, ProtocolError> {
    let object = client_body
        .as_object()
        .ok_or(ProtocolError::InvalidRequest)?;
    // A body that carries `stream` did not come from the KAS conversion: refuse
    // it instead of quietly forwarding a field the vendor never sends.
    if object.contains_key("stream") {
        return Err(ProtocolError::InvalidRequest);
    }
    // The invocation id and attempt counter belong to the relay's per-candidate
    // dispatch. Without that state there is no honest retry identity to send.
    let call = target
        .kas_call
        .ok_or(ProtocolError::UpstreamAuthenticationFailed)?;
    let url = target.url(stream)?;
    let mut headers = profile::kas_static_headers();
    headers.extend(profile::retry_headers(
        call.invocation(),
        call.next_attempt(),
        KIRO_MAX_ATTEMPTS,
        true,
        chrono::Utc::now(),
    ));
    // Field-by-field straight from the translated tree — no intermediate
    // `Value`, no deep copy of the session.
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
        write_json(&mut out, field)?;
        out.push(b':');
        write_json_value(&mut out, value, strip_images)?;
    }
    out.push(b'}');
    Ok(Prepared {
        protocol: ProtocolId::Kiro,
        url: url.to_owned(),
        // The transport writes this header for every protocol, so it is not
        // repeated in `headers` (see the profile module's deviation notes).
        content_type: "application/x-amz-json-1.0",
        body: bytes::Bytes::from(out),
        stream,
        headers,
    })
}

/// One tool call accumulated across `toolUseEvent` frames.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToolCall {
    pub id: String,
    pub name: String,
    /// The raw JSON fragments exactly as the upstream streamed them; the
    /// translation layer decides whether they parse into an object.
    pub arguments: String,
    /// Whether the upstream sent the completion frame (`stop: true`).
    pub complete: bool,
}

/// Raw `meteringEvent` evidence, kept as diagnostics only.
///
/// KAS bills credits, not total tokens: [`StreamDecoder::usage`] estimates the
/// token counts from the context percentage and accumulated content and never
/// reads this. Fields stay optional so nothing is invented for absent or
/// wrongly-typed data.
#[derive(Clone, Debug, PartialEq)]
pub struct Metering {
    pub usage: Option<f64>,
    pub unit: Option<String>,
    pub unit_plural: Option<String>,
}

/// The KAS response state machine: one instance per logical response.
///
/// It aggregates content (for `translation::kiro`) and materializes the
/// [`StreamEvent`]s the relay's translated pump forwards, so both paths read
/// the same events.
#[derive(Debug, Default)]
pub struct StreamDecoder {
    text: String,
    reasoning: String,
    /// Native reasoning signature. Kept as internal evidence only: no
    /// translated hop can carry a signature, and faking one outward would
    /// poison a client that replays it.
    reasoning_signature: Option<String>,
    /// Stable tool index per `toolUseId`, first-seen order.
    tool_indices: HashMap<String, u32>,
    tools: Vec<ToolCall>,
    /// The only normal-end evidence (`metadataEvent`).
    metadata_seen: bool,
    /// A benign `ContentLengthExceededException` frame was seen. The reference
    /// (`stream.ts` `classifyUpstreamErrorEvent`) classifies it as a legitimate
    /// `max_tokens` terminal, not an error.
    content_length_exceeded: bool,
    /// `stopReason` from the metadata frame — diagnostics only.
    stop_reason: Option<String>,
    metering: Option<Metering>,
    context_usage_percentage: Option<f64>,
    /// The served model's declared context window (`tokenLimits.maxInputTokens`
    /// from KAS `ListAvailableModels`), used to convert `contextUsagePercentage`
    /// into prompt tokens. `None` when the snapshot carries no window, and
    /// `None` means "no input estimate" — never zero.
    context_window: Option<u64>,
    /// Set by the first undecodable/invalid frame; every later frame is
    /// refused, so content is never spliced across a known-broken span.
    failed: bool,
}

impl StreamDecoder {
    pub fn new(context_window: Option<u64>) -> Self {
        Self {
            context_window,
            ..Self::default()
        }
    }

    /// Decode one completed AWS message.
    ///
    /// An ordinary unknown event yields no events; an unknown message type, a
    /// malformed known event, or an upstream error/exception frame yields
    /// [`ProtocolError::InvalidUpstreamResponse`] and marks the response
    /// failed.
    pub fn observe(&mut self, message: &Message) -> Result<Vec<StreamEvent>, ProtocolError> {
        if self.failed {
            return Err(ProtocolError::InvalidUpstreamResponse);
        }
        let result = match message.string_header(":message-type") {
            // The reference treats a missing message type as `event`.
            Some("event") | None => self.observe_event(message),
            Some("error") => {
                tracing::warn!(
                    error_code = message
                        .string_header(":error-code")
                        .unwrap_or("UnknownError"),
                    "KAS response carried an error frame"
                );
                Err(ProtocolError::InvalidUpstreamResponse)
            }
            Some("exception") => {
                // `ContentLengthExceededException` is the upstream's way of
                // saying the output hit its ceiling: a legitimate truncation
                // terminal, never an error (the reference's classifier returns
                // `undefined` for it and the reducer sets `max_tokens`).
                if message.string_header(":exception-type")
                    == Some("ContentLengthExceededException")
                {
                    tracing::debug!(
                        "KAS response reported ContentLengthExceededException (max_tokens terminal)"
                    );
                    self.content_length_exceeded = true;
                    Ok(Vec::new())
                } else {
                    tracing::warn!(
                        exception_type = message
                            .string_header(":exception-type")
                            .unwrap_or("UnknownException"),
                        "KAS response carried an exception frame"
                    );
                    Err(ProtocolError::InvalidUpstreamResponse)
                }
            }
            Some(other) => {
                tracing::warn!(message_type = other, "unknown KAS message type");
                Err(ProtocolError::InvalidUpstreamResponse)
            }
        };
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    fn observe_event(&mut self, message: &Message) -> Result<Vec<StreamEvent>, ProtocolError> {
        let event_type = message.string_header(":event-type").unwrap_or("");
        match event_type {
            "assistantResponseEvent" => {
                let payload = payload_object(message)?;
                let content = optional_str(&payload, "content")?.unwrap_or("");
                if content.is_empty() {
                    return Ok(Vec::new());
                }
                self.text.push_str(content);
                Ok(vec![StreamEvent::TextDelta(content.to_owned())])
            }
            "reasoningContentEvent" => {
                let payload = payload_object(message)?;
                let text = optional_str(&payload, "text")?.unwrap_or("");
                if let Some(signature) = optional_str(&payload, "signature")? {
                    self.reasoning_signature = Some(signature.to_owned());
                }
                if text.is_empty() {
                    return Ok(Vec::new());
                }
                self.reasoning.push_str(text);
                Ok(vec![StreamEvent::ReasoningDelta(text.to_owned())])
            }
            "toolUseEvent" => self.observe_tool_use(message),
            "metadataEvent" => {
                let payload = payload_object(message)?;
                self.stop_reason = optional_str(&payload, "stopReason")?.map(str::to_owned);
                self.metadata_seen = true;
                // `finish_reason` is only `None` while no metadata was seen, so
                // the fallback cannot be reached here.
                let reason = self.finish_reason().unwrap_or("stop");
                Ok(vec![StreamEvent::Finish {
                    reason: reason.to_owned(),
                }])
            }
            "meteringEvent" => {
                let payload = payload_object(message)?;
                let metering = Metering {
                    usage: payload.get("usage").and_then(Value::as_f64),
                    unit: diagnostic_str(&payload, "unit"),
                    unit_plural: diagnostic_str(&payload, "unitPlural"),
                };
                tracing::debug!(
                    usage = ?metering.usage,
                    unit = ?metering.unit,
                    unit_plural = ?metering.unit_plural,
                    "KAS metering (credits, never token usage)"
                );
                self.metering = Some(metering);
                Ok(Vec::new())
            }
            "contextUsageEvent" => {
                let payload = payload_object(message)?;
                let percentage = payload
                    .get("contextUsagePercentage")
                    .and_then(Value::as_f64);
                tracing::debug!(
                    context_usage_percentage = ?percentage,
                    // Diagnostics only: the pair that would yield a prompt-token
                    // estimate, logged so a missing window is visible next to
                    // the percentage it would scale.
                    context_window = self.context_window,
                    "KAS context usage"
                );
                self.context_usage_percentage = percentage;
                Ok(Vec::new())
            }
            // Forward compatibility: an unknown ordinary event has no
            // downstream semantic. Its payload stays opaque, never parsed.
            _ => Ok(Vec::new()),
        }
    }

    fn observe_tool_use(&mut self, message: &Message) -> Result<Vec<StreamEvent>, ProtocolError> {
        let payload = payload_object(message)?;
        let id = optional_str(&payload, "toolUseId")?
            .filter(|id| !id.trim().is_empty())
            .ok_or(ProtocolError::InvalidUpstreamResponse)?;
        let name = optional_str(&payload, "name")?
            .filter(|name| !name.trim().is_empty())
            .ok_or(ProtocolError::InvalidUpstreamResponse)?;
        let input = optional_str(&payload, "input")?.unwrap_or("");
        let stop = match payload.get("stop") {
            None | Some(Value::Null) => false,
            Some(Value::Bool(stop)) => *stop,
            Some(_) => return Err(ProtocolError::InvalidUpstreamResponse),
        };
        let (index, new_call) = match self.tool_indices.get(id).copied() {
            Some(index) => {
                let tool = self
                    .tools
                    .get(index as usize)
                    .ok_or(ProtocolError::InvalidUpstreamResponse)?;
                // An id identifies one immutable invocation: its name cannot
                // change mid-input and a completed id cannot run again.
                if tool.name != name || tool.complete {
                    return Err(ProtocolError::InvalidUpstreamResponse);
                }
                (index, false)
            }
            None => {
                let index = u32::try_from(self.tools.len())
                    .map_err(|_| ProtocolError::InvalidUpstreamResponse)?;
                self.tool_indices.insert(id.to_owned(), index);
                self.tools.push(ToolCall {
                    id: id.to_owned(),
                    name: name.to_owned(),
                    arguments: String::new(),
                    complete: false,
                });
                (index, true)
            }
        };
        let tool = self
            .tools
            .get_mut(index as usize)
            .ok_or(ProtocolError::InvalidUpstreamResponse)?;
        tool.arguments.push_str(input);
        if stop {
            tool.complete = true;
        }
        // Identity travels once per call, like a native Chat stream; the
        // request/response entry dialect repeats it only when it must.
        Ok(vec![StreamEvent::ToolCallDelta {
            index,
            id: new_call.then(|| id.to_owned()),
            name: new_call.then(|| name.to_owned()),
            arguments: input.to_owned(),
        }])
    }

    /// How the response ended. `metadataEvent` is the only normal-end evidence,
    /// so a body that never carried it failed even when its last frame was a
    /// clean frame boundary — except a benign `ContentLengthExceededException`,
    /// which is a legitimate truncated terminal of its own.
    pub fn finish(&self) -> Terminal {
        if self.failed {
            Terminal::Failed
        } else if self.content_length_exceeded {
            // The upstream stopped at the output ceiling. Content observed so
            // far is real; report the honest truncation verdict.
            Terminal::Incomplete
        } else if !self.metadata_seen {
            Terminal::Failed
        } else if self.tools.iter().any(|tool| !tool.complete) {
            // The upstream ended while a tool's input was still incomplete:
            // truncated output, not a usable tool call (the reference reports
            // `max_tokens` rather than `tool_use` for the same shape).
            Terminal::Incomplete
        } else {
            Terminal::Completed
        }
    }

    /// The client-facing `finish_reason`, inferred from accumulated state —
    /// never from the metadata frame's `stopReason`.
    pub fn finish_reason(&self) -> Option<&'static str> {
        if self.failed {
            return None;
        }
        if self.content_length_exceeded {
            // An explicit ceiling terminal outranks the inferred reason, as in
            // the reference's reducer.
            return Some("length");
        }
        if !self.metadata_seen {
            return None;
        }
        if self.tools.iter().any(|tool| !tool.complete) {
            return Some("length");
        }
        if self.tools.is_empty() {
            Some("stop")
        } else {
            Some("tool_calls")
        }
    }

    /// Estimate token usage from the upstream context reading and content.
    ///
    /// These are **estimates**, not vendor-reported token counts: input is the
    /// upstream's context percentage times the advertised window, and output
    /// uses a chars/4 heuristic over text, reasoning and tool arguments. A
    /// missing window or percentage yields `None`, never zero-filled counts;
    /// non-finite and negative percentages are rejected as corrupt evidence.
    pub fn usage(&self) -> Option<UsageCounts> {
        let context_window = self.context_window?;
        let percentage = self.context_usage_percentage?;
        if !percentage.is_finite() || percentage < 0.0 {
            return None;
        }
        let input_tokens = (context_window as f64 * percentage / 100.0).floor() as u64;
        let total_chars = self.text.chars().count()
            + self.reasoning.chars().count()
            + self
                .tools
                .iter()
                .map(|call| call.arguments.chars().count())
                .sum::<usize>();
        let output_tokens = (total_chars / 4) as u64;
        Some(UsageCounts {
            input_tokens,
            output_tokens,
            ..Default::default()
        })
    }

    pub fn terminal_seen(&self) -> bool {
        self.metadata_seen || self.content_length_exceeded
    }

    /// Whether a frame (error, non-benign exception, or undecodable payload)
    /// proved the response broken. Content already accumulated stays readable,
    /// but the response must not be delivered as a success.
    pub fn failed(&self) -> bool {
        self.failed
    }

    /// Whether the upstream reported the benign output-ceiling exception. Only
    /// this terminal may deliver a truncated body with no recoverable content
    /// (the reference's silent-failure check exempts `max_tokens`).
    pub fn content_length_exceeded(&self) -> bool {
        self.content_length_exceeded
    }

    /// Whether real content (text, reasoning or a tool call) was observed.
    pub fn content_seen(&self) -> bool {
        !self.text.is_empty() || !self.reasoning.is_empty() || !self.tools.is_empty()
    }

    pub fn text(&self) -> &str {
        &self.text
    }

    pub fn reasoning(&self) -> &str {
        &self.reasoning
    }

    /// Move the accumulated text out, leaving the decoder's copy empty. Call
    /// it after every read that depends on the text ([`Self::usage`] counts
    /// its characters, [`Self::content_seen`] its emptiness).
    pub fn take_text(&mut self) -> String {
        std::mem::take(&mut self.text)
    }

    /// Move the accumulated reasoning out; same ordering caveat as
    /// [`Self::take_text`].
    pub fn take_reasoning(&mut self) -> String {
        std::mem::take(&mut self.reasoning)
    }

    pub fn reasoning_signature(&self) -> Option<&str> {
        self.reasoning_signature.as_deref()
    }

    pub fn tool_calls(&self) -> &[ToolCall] {
        &self.tools
    }

    pub fn metering(&self) -> Option<&Metering> {
        self.metering.as_ref()
    }

    pub fn context_usage_percentage(&self) -> Option<f64> {
        self.context_usage_percentage
    }

    pub fn stop_reason(&self) -> Option<&str> {
        self.stop_reason.as_deref()
    }
}

/// The event payload as a JSON object; a known event with a non-object or
/// undecodable payload is an invalid upstream response.
fn payload_object(message: &Message) -> Result<serde_json::Map<String, Value>, ProtocolError> {
    match serde_json::from_slice::<Value>(&message.payload) {
        Ok(Value::Object(object)) => Ok(object),
        _ => Err(ProtocolError::InvalidUpstreamResponse),
    }
}

/// A consumed string field: absent/null is `None`, a string is its text, any
/// other type is invalid (the reference's `optionalString` contract).
fn optional_str<'a>(
    payload: &'a serde_json::Map<String, Value>,
    field: &str,
) -> Result<Option<&'a str>, ProtocolError> {
    match payload.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) => Ok(Some(text)),
        Some(_) => Err(ProtocolError::InvalidUpstreamResponse),
    }
}

/// A diagnostics-only string field: a wrongly-typed value reads as absent
/// instead of failing a response nobody bills from it.
fn diagnostic_str(payload: &serde_json::Map<String, Value>, field: &str) -> Option<String> {
    payload
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_owned)
}

/// Frame and decode one complete KAS body into its terminal decoder state.
///
/// A partial frame at the end of the body is [`AwsError::Truncated`], never a
/// silent clean end, so callers can never observe half a response.
pub fn aggregate(body: &[u8], context_window: Option<u64>) -> Result<StreamDecoder, ProtocolError> {
    let mut framer = Framer::new();
    let messages = framer
        .push(body)
        .map_err(|_| ProtocolError::InvalidUpstreamResponse)?;
    framer
        .finish()
        .map_err(|_| ProtocolError::InvalidUpstreamResponse)?;
    let mut decoder = StreamDecoder::new(context_window);
    for message in &messages {
        decoder.observe(message)?;
    }
    Ok(decoder)
}

/// Observe one complete (aggregated) KAS response.
///
/// `usage` estimates input tokens from `context_window` and the KAS context
/// percentage, and output tokens from accumulated content with a chars/4
/// heuristic. Missing input evidence omits usage rather than recording zeros;
/// the estimates are ledger-only and never appear on the client wire.
/// `context_window` is the served model's declared input window; the decoder
/// combines it with the context percentage for the input estimate rather than
/// inventing one from a bare percentage.
pub fn parse_json(
    body: &[u8],
    context_window: Option<u64>,
) -> Result<ObservedResponse, ProtocolError> {
    let decoder = aggregate(body, context_window)?;
    Ok(ObservedResponse {
        usage: decoder.usage(),
        terminal: decoder.finish(),
        // KAS events carry no model identity; the requested model is the
        // relay's knowledge, not the response's.
        upstream_model: None,
    })
}
