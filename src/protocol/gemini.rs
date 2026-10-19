//! `gemini` kernel (Google Gemini generateContent, B §4.6).
//!
//! The Gemini API keeps the model and the streaming choice in the URL
//! (`/v1beta/models/{model}:generateContent` vs `…:streamGenerateContent` —
//! the model is baked into the target endpoint by the capability table), so
//! preparation here is a passthrough: the body is forwarded byte-identical
//! except for a snake_case → camelCase key normalization ([`write_camelized`]).
//! Google's proto JSON accepts both spellings, but read only one way the
//! other is silently dropped — an image sent as `inline_data` was invisible
//! to the model, and it made the content up. Unlike the responses kernel
//! there is NO allowlist: passthrough fidelity matters more than
//! pre-validation.
//!
//! Streaming (`streamGenerateContent?alt=sse`) sends bare `data:` frames with
//! NO event names, and no comments/keepalives are ever emitted or expected —
//! Google's SDK chokes on anything else. Usage arrives in `usageMetadata`,
//! usually on the last frame; a candidate's `finishReason` is the terminal.

use super::sse::{Frame, RawFrame};
use super::usage::UsageCounts;
use super::{
    ObservedResponse, Prepared, ProtocolError, ProtocolId, RawValue, StreamEvent, TargetView,
    Terminal,
};
use serde_json::Value;

/// Key sets whose VALUES belong to the caller, not Google: their inner keys
/// are kept exactly as sent (a tool's `args`, a function result's `response`,
/// the JSON schemas, `labels`).
const CALLER_OWNED_KEYS: &[&str] = &[
    "args",
    "response",
    "parameters",
    "parametersJsonSchema",
    "responseSchema",
    "responseJsonSchema",
    "labels",
];

/// Build the upstream request for one attempt. The body passes through with
/// its keys camelized, written straight from the client's tree (no
/// intermediate `Value`, no deep copy); the model lives in the URL (already
/// baked into `target.endpoint`), so the body's `model`/`stream` bookkeeping
/// fields the gateway folded in — and every `skip` field (learned refusals,
/// vendor fixups) — are dropped in the same walk rather than forwarded to
/// Google.
pub fn prepare(
    client_body: &Value,
    target: &TargetView<'_>,
    stream: bool,
    render: &super::Render<'_>,
) -> Result<Prepared, ProtocolError> {
    if !client_body.is_object() {
        return Err(ProtocolError::InvalidRequest);
    }
    let mut out = Vec::new();
    write_camelized(&mut out, client_body, &["model", "stream"], render)?;
    let mut url = target.url(stream)?.to_owned();
    if stream {
        // `alt=sse` picks the SSE wire over Google's default chunked-JSON.
        url.push_str(if url.contains('?') {
            "&alt=sse"
        } else {
            "?alt=sse"
        });
    }
    let body = bytes::Bytes::from(out);
    Ok(Prepared {
        protocol: ProtocolId::Gemini,
        url,
        content_type: "application/json",
        body,
        stream,
        headers: Vec::new(),
    })
}

/// Write a Gemini request's keys in camelCase, recursively, straight to the
/// wire — one pass over the client's tree, no output tree. `strip`/`skip`
/// drop top-level keys in the same pass (the `model`/`stream` bookkeeping the
/// gateway folds in, plus learned refusals / vendor fixups); nested objects
/// only fold. When both spellings of a key are present, the camelCase one
/// wins and the folded one is dropped. Caller-owned
/// value objects (see [`CALLER_OWNED_KEYS`]) keep their inner keys as sent.
fn write_camelized(
    out: &mut Vec<u8>,
    value: &Value,
    strip: &[&str],
    render: &super::Render<'_>,
) -> Result<(), ProtocolError> {
    match value {
        Value::Object(object) => {
            out.push(b'{');
            let mut first = true;
            // Folded names already emitted at this level: two distinct snake keys
            // can fold to the same camelCase name (`a_b` and `a__b` both → `aB`),
            // and only the first may be written — a second would produce a
            // duplicate JSON key on the wire. The names are collected owned
            // because each is the emitted key of its write.
            let mut folded_names: Vec<String> = Vec::new();
            for (key, item) in object {
                if strip.contains(&key.as_str()) || render.skip.contains(&key.as_str()) {
                    continue;
                }
                // A snake_case key folds into its camelCase spelling; when the
                // original camelCase key is also present — before or after — it wins,
                // so the folded one is never written. Same for a name another snake
                // key already folded into.
                let folded;
                let name = if key.contains('_') {
                    folded = snake_to_camel(key);
                    if object.contains_key(&folded)
                        || folded_names.iter().any(|emitted| emitted == &folded)
                    {
                        continue;
                    }
                    folded_names.push(folded.clone());
                    folded.as_str()
                } else {
                    key.as_str()
                };
                if !first {
                    out.push(b',');
                }
                first = false;
                super::write_json(out, name)?;
                out.push(b':');
                if CALLER_OWNED_KEYS.contains(&name)
                    || super::protected_key(name)
                    || crate::privacy::structural(name)
                {
                    super::write_json(out, item)?;
                } else {
                    write_camelized(out, item, &[], render)?;
                }
            }
            out.push(b'}');
        }
        Value::Array(items) => {
            out.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_camelized(out, item, &[], render)?;
            }
            out.push(b']');
        }
        scalar => super::write_scalar(out, scalar, render)?,
    }
    Ok(())
}

/// `inline_data` → `inlineData`. Empty segments are skipped (`a__b` → `aB`).
fn snake_to_camel(key: &str) -> String {
    let mut out = String::with_capacity(key.len());
    let mut upper = false;
    for ch in key.chars() {
        if ch == '_' {
            upper = true;
        } else if upper {
            upper = false;
            out.extend(ch.to_uppercase());
        } else {
            out.push(ch);
        }
    }
    out
}

/// Observe a non-streaming response.
///
/// Only the observed fields are deserialized, borrowed straight from the wire
/// (`raw_str`/`raw_array`/`raw_value`); the response body itself —
/// `candidates` with their whole parts — is never materialized.
pub fn parse_json(body: &[u8]) -> Result<ObservedResponse, ProtocolError> {
    let obs: GeminiObservation =
        serde_json::from_slice(body).map_err(|_| ProtocolError::InvalidUpstreamResponse)?;
    // Google's error shape: {"error":{"code":…,"message":…,"status":…}}. JSON
    // `null` deserializes to `None` here, so `is_some()` is exactly the old
    // `!error.is_null()` verdict.
    if obs.error.is_some() {
        return Ok(ObservedResponse {
            usage: None,
            terminal: Terminal::Failed,
            upstream_model: None,
        });
    }
    // A prompt-level safety block (promptFeedback.blockReason, no candidates):
    // the upstream refused — Failed, not Completed, even when usage rides along.
    let blocked = obs
        .prompt_feedback
        .as_ref()
        .and_then(|feedback| super::raw_value(feedback))
        .is_some_and(|feedback| feedback.get("blockReason").is_some());
    if blocked {
        return Ok(ObservedResponse {
            usage: obs
                .usage_metadata
                .as_ref()
                .and_then(|usage| super::raw_value(usage))
                .as_ref()
                .and_then(usage_counts),
            terminal: Terminal::Failed,
            upstream_model: None,
        });
    }
    let finish_reason = obs
        .candidates
        .as_ref()
        .and_then(|candidates| super::raw_array(candidates))
        .and_then(|candidates| candidates.first().copied())
        .and_then(|first| serde_json::from_str::<GeminiCandidate>(first.get()).ok())
        .and_then(|first| super::raw_str(first.finish_reason));
    let terminal = finish_reason.map(finish_terminal).unwrap_or_else(|| {
        // No finishReason at all: an answer that carries usage counts as complete
        // (chunked replies reassembled upstream-side, empty candidates); one
        // without any evidence does not.
        if obs.usage_metadata.is_some() {
            Terminal::Completed
        } else {
            Terminal::Failed
        }
    });
    Ok(ObservedResponse {
        usage: obs
            .usage_metadata
            .as_ref()
            .and_then(|usage| super::raw_value(usage))
            .as_ref()
            .and_then(usage_counts),
        terminal,
        upstream_model: super::raw_str(obs.model_version).map(str::to_owned),
    })
}

/// The observed fields of a Gemini response; everything else (the
/// `candidates` parts above all) is ignored without being materialized.
#[derive(serde::Deserialize)]
struct GeminiObservation<'a> {
    #[serde(default, borrow)]
    error: Option<&'a RawValue>,
    #[serde(default, borrow, rename = "promptFeedback")]
    prompt_feedback: Option<&'a RawValue>,
    #[serde(default, borrow)]
    candidates: Option<&'a RawValue>,
    #[serde(default, borrow, rename = "usageMetadata")]
    usage_metadata: Option<&'a RawValue>,
    #[serde(default, borrow, rename = "modelVersion")]
    model_version: Option<&'a RawValue>,
}

/// One candidate, observed: only the finish reason. A non-object element
/// reads as an absent reason, exactly like the old `Value::pointer` probe.
#[derive(serde::Deserialize)]
struct GeminiCandidate<'a> {
    #[serde(default, borrow, rename = "finishReason")]
    finish_reason: Option<&'a RawValue>,
}

fn finish_terminal(reason: &str) -> Terminal {
    match reason {
        "STOP" => Terminal::Completed,
        "MAX_TOKENS" => Terminal::Incomplete,
        // SAFETY / RECITATION / BLOCKLIST / PROHIBITED_CONTENT / SPII / …: the
        // upstream refused; anything unlisted is not a success either (B §4.7).
        _ => Terminal::Failed,
    }
}

/// `promptTokenCount` already includes the cached portion (Google reports
/// them together, like OpenAI's totals); `thoughtsTokenCount` is a distinct
/// quantity folded into the billable output, as every other dialect reports
/// reasoning inside its output total.
fn usage_from(value: &Value) -> Option<UsageCounts> {
    value.get("usageMetadata").and_then(usage_counts)
}

fn usage_counts(usage: &Value) -> Option<UsageCounts> {
    let input = usage.get("promptTokenCount").and_then(Value::as_u64)?;
    let candidates = usage
        .get("candidatesTokenCount")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let thoughts = usage
        .get("thoughtsTokenCount")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    Some(UsageCounts {
        input_tokens: input,
        output_tokens: candidates.saturating_add(thoughts),
        calls: 0,
        cached_input_tokens: usage.get("cachedContentTokenCount").and_then(Value::as_u64),
        thought_output_tokens: if thoughts > 0 { Some(thoughts) } else { None },
        ..Default::default()
    })
}

/// Streaming observer: bare `data: {json}` frames, usage in `usageMetadata`
/// (usually the last frame), terminal on a candidate's `finishReason`. The
/// terminal guard keeps a frame arriving after the finishReason from
/// double-counting usage.
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

    /// Observe one frame, materializing events for the observe path.
    pub fn observe(&mut self, frame: &Frame) -> Result<Vec<StreamEvent>, ProtocolError> {
        self.observe_raw(frame.data.as_bytes())
    }

    /// Observe one raw SSE payload by bytes — the translated pump's entry
    /// point, with no `String` re-framing hop in between.
    pub fn observe_raw(&mut self, data: &[u8]) -> Result<Vec<StreamEvent>, ProtocolError> {
        let data = std::str::from_utf8(data)
            .map_err(|_| ProtocolError::InvalidUpstreamResponse)?
            .trim();
        if data.is_empty() {
            return Ok(Vec::new());
        }
        let value: Value =
            serde_json::from_str(data).map_err(|_| ProtocolError::InvalidUpstreamResponse)?;
        let mut events = Vec::new();
        for candidate in value
            .get("candidates")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            for part in candidate
                .pointer("/content/parts")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                if let Some(text) = part.get("text").and_then(Value::as_str)
                    && !text.is_empty()
                {
                    events.push(StreamEvent::TextDelta(text.to_owned()));
                }
            }
            if let Some(reason) = candidate.get("finishReason").and_then(Value::as_str) {
                events.push(StreamEvent::Finish {
                    reason: reason.to_owned(),
                });
            }
        }
        if self.observe_frame(&value)?
            && let Some(usage) = self.usage.clone()
        {
            events.push(StreamEvent::Usage(usage));
        }
        Ok(events)
    }

    /// Observe a parsed relay frame without materializing events.
    pub fn observe_for_relay(&mut self, frame: &Frame) -> Result<(), ProtocolError> {
        self.observe_raw_for_relay_data(frame.data.as_bytes())
    }

    /// Observe a raw SSE frame on the relay path.
    pub fn observe_raw_for_relay(&mut self, frame: &RawFrame) -> Result<(), ProtocolError> {
        self.observe_raw_for_relay_data(&frame.data)
    }

    fn observe_raw_for_relay_data(&mut self, data: &[u8]) -> Result<(), ProtocolError> {
        let data = std::str::from_utf8(data)
            .map_err(|_| ProtocolError::InvalidUpstreamResponse)?
            .trim();
        if data.is_empty() {
            return Ok(());
        }
        // Pre-filter: only a frame mentioning a field the observer consumes is
        // worth a full parse. The set below is a superset of every state input
        // (see `observe_frame`): `"error"` (mid-stream failure),
        // `"promptFeedback"` (safety block), `"usageMetadata"` (token counts),
        // `"finishReason"` (terminal verdict), and the candidate-part content the
        // commit flag reads (`"text"`, `"functionCall"`, `"inlineData"`). A frame
        // with none of them — the vast majority — cannot change any state.
        if !data.contains("\"error\"")
            && !data.contains("promptFeedback")
            && !data.contains("\"usageMetadata\"")
            && !data.contains("\"finishReason\"")
            && !data.contains("\"text\"")
            && !data.contains("\"functionCall\"")
            && !data.contains("\"inlineData\"")
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
        self.observe_frame(&value)?;
        Ok(())
    }

    /// Apply one parsed frame. Returns whether this frame carried a terminal
    /// finishReason (the frame's own terminal, guarded against repeats).
    fn observe_frame(&mut self, value: &Value) -> Result<bool, ProtocolError> {
        // An error object mid-stream fails the stream, like the responses kernel's
        // `type: error`.
        if value.get("error").is_some_and(|error| !error.is_null()) {
            if self.terminal.is_none() {
                self.terminal = Some(Terminal::Failed);
            }
            return Err(ProtocolError::UpstreamError);
        }
        if let Some(usage) = usage_from(value) {
            self.usage = Some(usage);
        }
        // A prompt-level safety block carries no candidates and no finishReason —
        // without this verdict the hold never commits, the relay would burn every
        // candidate on an identical block, and the client would lose Google's
        // structured block payload. It is terminal (failed), so the buffered
        // frame is delivered.
        if value.pointer("/promptFeedback/blockReason").is_some() {
            if self.terminal.is_none() {
                self.terminal = Some(Terminal::Failed);
                return Ok(true);
            }
            return Ok(false);
        }
        let mut terminal = None;
        for candidate in value
            .get("candidates")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if !self.content_seen
                && candidate
                    .pointer("/content/parts")
                    .and_then(Value::as_array)
                    .is_some_and(|parts| {
                        parts.iter().any(|part| {
                            part.get("text")
                                .and_then(Value::as_str)
                                .is_some_and(|text| !text.is_empty())
                                || part.get("functionCall").is_some()
                                || part.get("inlineData").is_some()
                        })
                    })
            {
                self.content_seen = true;
            }
            if let Some(reason) = candidate.get("finishReason").and_then(Value::as_str) {
                terminal = Some(finish_terminal(reason));
            }
        }
        if let Some(terminal) = terminal {
            // Terminal guard: the FIRST finishReason fixes the verdict; later
            // frames carrying another one (or the same) must not re-open it, and
            // usage observed after it must not double-count into a fresh result.
            if self.terminal.is_some() {
                return Ok(false);
            }
            self.terminal = Some(terminal);
            return Ok(true);
        }
        Ok(false)
    }

    /// Terminal verdict. A stream that ends without a finishReason is not a
    /// success (B §4.7).
    pub fn finish(&self) -> Terminal {
        self.terminal.unwrap_or(Terminal::Failed)
    }

    pub fn terminal_seen(&self) -> bool {
        self.terminal.is_some()
    }

    /// Whether a candidate part with real content (text / functionCall /
    /// inlineData) was observed: the relay streaming hold's commit signal.
    pub fn content_seen(&self) -> bool {
        self.content_seen
    }
}
