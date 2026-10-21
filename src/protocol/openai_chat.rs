//! `openai_chat` kernel (B §4.2).
//!
//! Preparation validates structure (model, messages, token bounds) and passes
//! every other field through verbatim: whether a field is supported is the
//! upstream's call, and per-upstream refusals are learned and stripped by the
//! relay (gateway `relay::optional`).
//! Observation extracts usage and termination
//! from the upstream wire without rewriting it — the relay forwards the
//! original bytes because the client protocol equals the upstream protocol.

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
/// intermediate `Value`, no deep copy — with only the model overridden and,
/// when streaming, `include_usage` pinned into `stream_options` (appended in
/// the client's own order when the client omitted the field, forced true in
/// place when it sent one). `skip` names top-level fields the wire must not
/// carry (learned refusals, vendor fixups); a skipped `stream_options` also
/// suppresses the pin, which is the old strip-after-prepare result.
pub fn prepare(
    client_body: &Value,
    target: &TargetView<'_>,
    stream: bool,
    skip: &[&str],
    strip_images: bool,
) -> Result<Prepared, ProtocolError> {
    validate_request(client_body)?;
    let object = client_body
        .as_object()
        .ok_or(ProtocolError::InvalidRequest)?;
    let url = target.url(stream)?;
    let pin_usage = stream && !skip.contains(&"stream_options");
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
        } else if field == "stream_options" {
            if stream {
                // The client's object stays in place; include_usage is forced true.
                let options = value.as_object().ok_or(ProtocolError::InvalidRequest)?;
                out.push(b'{');
                let mut inner_first = true;
                let mut forced = false;
                for (key, item) in options {
                    if key == "include_usage" {
                        forced = true;
                    }
                    if !inner_first {
                        out.push(b',');
                    }
                    inner_first = false;
                    super::write_json(&mut out, key)?;
                    out.push(b':');
                    if key == "include_usage" {
                        out.extend_from_slice(b"true");
                    } else {
                        super::write_json_value(&mut out, item, strip_images)?;
                    }
                }
                if !forced {
                    if !inner_first {
                        out.push(b',');
                    }
                    out.extend_from_slice(b"\"include_usage\":true");
                }
                out.push(b'}');
            } else {
                super::write_json_value(&mut out, value, strip_images)?;
            }
        } else {
            super::write_json_value(&mut out, value, strip_images)?;
        }
    }
    if pin_usage && !object.contains_key("stream_options") {
        if !first {
            out.push(b',');
        }
        out.extend_from_slice(b"\"stream_options\":{\"include_usage\":true}");
    }
    out.push(b'}');
    let body = bytes::Bytes::from(out);
    Ok(Prepared {
        protocol: ProtocolId::OpenAiChat,
        url: url.to_owned(),
        content_type: "application/json",
        body,
        stream,
        headers: Vec::new(),
    })
}

/// Shared request validation for remote and in-process execution. Structural
/// only: whether a field is supported is the upstream's call — the relay
/// learns and strips per-upstream refusals instead of guessing locally.
pub fn validate_request(client_body: &Value) -> Result<(), ProtocolError> {
    let object = client_body
        .as_object()
        .ok_or(ProtocolError::InvalidRequest)?;
    if object.get("model").and_then(Value::as_str).is_none() {
        return Err(ProtocolError::InvalidRequest);
    }
    match object.get("messages").and_then(Value::as_array) {
        Some(messages) if !messages.is_empty() => {}
        _ => return Err(ProtocolError::InvalidRequest),
    }
    for field in ["max_tokens", "max_completion_tokens"] {
        if let Some(value) = object.get(field)
            && value.as_u64().filter(|value| *value > 0).is_none()
        {
            return Err(ProtocolError::InvalidRequest);
        }
    }
    if let (Some(max_tokens), Some(max_completion_tokens)) = (
        object.get("max_tokens"),
        object.get("max_completion_tokens"),
    ) && max_tokens != max_completion_tokens
    {
        return Err(ProtocolError::InvalidRequest);
    }
    Ok(())
}

/// Observe a non-streaming response.
///
/// Only the observed fields are deserialized, borrowed straight from the wire
/// (`raw_str`/`raw_array`/`raw_value`); the response body itself — choices
/// with their whole message content — is never materialized.
pub fn parse_json(body: &[u8]) -> Result<ObservedResponse, ProtocolError> {
    let obs: ChatObservation =
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
    let choices = obs
        .choices
        .as_ref()
        .and_then(|choices| super::raw_array(choices))
        .ok_or(ProtocolError::InvalidUpstreamResponse)?;
    let finish = choices
        .first()
        .and_then(|choice| serde_json::from_str::<ChatChoice>(choice.get()).ok())
        .and_then(|choice| super::raw_str(choice.finish_reason));
    Ok(ObservedResponse {
        usage: obs
            .usage
            .as_ref()
            .and_then(|usage| super::raw_value(usage))
            .as_ref()
            .and_then(usage_counts),
        terminal: terminal_from(finish, true),
        upstream_model: super::raw_str(obs.model).map(str::to_owned),
    })
}

/// The observed fields of a Chat completion response; everything else
/// (the message content above all) is ignored without being materialized.
#[derive(serde::Deserialize)]
struct ChatObservation<'a> {
    #[serde(default, borrow)]
    error: Option<&'a RawValue>,
    #[serde(default, borrow)]
    choices: Option<&'a RawValue>,
    #[serde(default, borrow)]
    usage: Option<&'a RawValue>,
    #[serde(default, borrow)]
    model: Option<&'a RawValue>,
}

/// One choice, observed: only the finish reason. A non-object element reads
/// as an absent reason, exactly like the old `Value::get` probe.
#[derive(serde::Deserialize)]
struct ChatChoice<'a> {
    #[serde(default, borrow)]
    finish_reason: Option<&'a RawValue>,
}

fn usage_from(value: &Value) -> Option<UsageCounts> {
    value.get("usage").and_then(usage_counts)
}

fn usage_counts(usage: &Value) -> Option<UsageCounts> {
    let input = usage.get("prompt_tokens").and_then(Value::as_u64)?;
    let output = usage.get("completion_tokens").and_then(Value::as_u64)?;
    Some(UsageCounts {
        input_tokens: input,
        output_tokens: output,
        calls: 0,
        cached_input_tokens: usage
            .get("prompt_cache_hit_tokens")
            .or_else(|| {
                usage
                    .get("prompt_tokens_details")
                    .and_then(|details| details.get("cached_tokens"))
            })
            .and_then(Value::as_u64),
        reasoning_output_tokens: usage
            .get("completion_tokens_details")
            .and_then(|details| details.get("reasoning_tokens"))
            .or_else(|| usage.get("reasoning_tokens"))
            .and_then(Value::as_u64),
        ..Default::default()
    })
}

fn terminal_from(finish: Option<&str>, saw_terminal: bool) -> Terminal {
    match finish {
        Some("length") => Terminal::Incomplete,
        Some(_) => Terminal::Completed,
        None if saw_terminal => Terminal::Completed,
        None => Terminal::Failed,
    }
}

/// Streaming observer: accumulates usage, detects the terminal frame, and
/// marks the first real content (the relay streaming hold's commit signal).
#[derive(Default)]
pub struct StreamDecoder {
    usage: Option<UsageCounts>,
    finish: Option<String>,
    done: bool,
    tool_index: u32,
    saw_payload: bool,
    content_seen: bool,
    /// Upstream chunk identity, captured for synthesized terminal frames on
    /// post-commit truncation (cold path only).
    upstream_id: Option<String>,
    upstream_model: Option<String>,
}

impl StreamDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn usage(&self) -> Option<UsageCounts> {
        self.usage.clone()
    }

    /// Observe one frame. `[DONE]` is framing, not a payload.
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
        if data == "[DONE]" {
            self.done = true;
            return Ok(events);
        }
        let value: Value =
            serde_json::from_str(data).map_err(|_| ProtocolError::InvalidUpstreamResponse)?;
        self.saw_payload = true;
        if value.get("error").is_some_and(|error| !error.is_null()) {
            return Err(ProtocolError::UpstreamError);
        }
        if self.upstream_id.is_none() {
            if let Some(id) = value.get("id").and_then(Value::as_str) {
                self.upstream_id = Some(id.to_owned());
            }
        }
        if self.upstream_model.is_none() {
            if let Some(model) = value.get("model").and_then(Value::as_str) {
                self.upstream_model = Some(model.to_owned());
            }
        }
        if let Some(usage) = usage_from(&value) {
            events.push(StreamEvent::Usage(usage.clone()));
            self.usage = Some(usage);
        }
        let Some(choice) = value
            .get("choices")
            .and_then(Value::as_array)
            .and_then(|choices| choices.first())
        else {
            // A usage-only chunk with an empty `choices` array is valid and does not
            // terminate the stream (B §4.2).
            return Ok(events);
        };
        if let Some(delta) = choice.get("delta") {
            if let Some(text) = delta.get("content").and_then(Value::as_str)
                && !text.is_empty()
            {
                self.content_seen = true;
                events.push(StreamEvent::TextDelta(text.to_owned()));
            }
            // Vendors disagree on the thinking-delta field: DeepSeek-style
            // `reasoning_content` versus OpenRouter-style `reasoning`. Both carry
            // the same concept; dropping either one silently hides thinking from
            // translated streaming clients.
            let reasoning = delta
                .get("reasoning_content")
                .and_then(Value::as_str)
                .or_else(|| delta.get("reasoning").and_then(Value::as_str));
            if let Some(reasoning) = reasoning
                && !reasoning.is_empty()
            {
                self.content_seen = true;
                events.push(StreamEvent::ReasoningDelta(reasoning.to_owned()));
            }
            if let Some(tool_calls) = delta.get("tool_calls").and_then(Value::as_array) {
                for call in tool_calls {
                    let index =
                        call.get("index")
                            .and_then(Value::as_u64)
                            .unwrap_or(u64::from(self.tool_index)) as u32;
                    self.tool_index = self.tool_index.max(index);
                    let function = call.get("function");
                    self.content_seen = true;
                    events.push(StreamEvent::ToolCallDelta {
                        index,
                        id: call.get("id").and_then(Value::as_str).map(str::to_owned),
                        name: function
                            .and_then(|function| function.get("name"))
                            .and_then(Value::as_str)
                            .map(str::to_owned),
                        arguments: function
                            .and_then(|function| function.get("arguments"))
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_owned(),
                    });
                }
            }
        }
        if let Some(reason) = choice.get("finish_reason").and_then(Value::as_str) {
            self.finish = Some(reason.to_owned());
            events.push(StreamEvent::Finish {
                reason: reason.to_owned(),
            });
        }
        Ok(events)
    }
    /// Observe a relay frame without materializing unused customer events.
    pub fn observe_for_relay(&mut self, frame: &Frame) -> Result<(), ProtocolError> {
        self.observe_raw_for_relay(frame.data.as_bytes())
    }

    /// Observe a parsed raw SSE frame on the Chat protocol path.
    pub fn observe_raw_frame_for_relay(&mut self, frame: &RawFrame) -> Result<(), ProtocolError> {
        self.observe_raw_for_relay(&frame.data)
    }

    /// Observe a raw Chat SSE payload without materializing customer events.
    pub fn observe_raw_for_relay(&mut self, data: &[u8]) -> Result<(), ProtocolError> {
        let data = std::str::from_utf8(data)
            .map_err(|_| ProtocolError::InvalidUpstreamResponse)?
            .trim();
        if data.is_empty() {
            return Ok(());
        }
        if data == "[DONE]" {
            self.done = true;
            return Ok(());
        }
        // Cheap sniff first: a plain content delta mentions none of the fields
        // the observer consumes — `"error"` (upstream failure), `"finish_reason"`
        // (terminal verdict), `"usage"` (token counts) — so it skips the parse
        // entirely and is flagged for content by substring alone. The vocabulary
        // keys on the delta object; a role-only first chunk (or an empty-string
        // delta) keeps the hold standing. A false positive only commits the hold
        // one frame early — fail-safe in the deliver direction.
        if !data.contains("\"finish_reason\"")
            && !data.contains("\"usage\"")
            && !data.contains("\"error\"")
        {
            let content = (data.contains("\"content\":\"") && !data.contains("\"content\":\"\""))
                || (data.contains("\"reasoning\":\"") && !data.contains("\"reasoning\":\"\""))
                || (data.contains("\"reasoning_content\":\"")
                    && !data.contains("\"reasoning_content\":\"\""))
                || data.contains("\"tool_calls\"");
            if content {
                self.content_seen = true;
            }
            // Still validate the frame's JSON shape without materializing it: a
            // malformed marker-less frame must be rejected exactly as before (the
            // scan touches no `Value` tree), and only a well-formed frame counts
            // as payload.
            serde_json::from_str::<serde::de::IgnoredAny>(data)
                .map_err(|_| ProtocolError::InvalidUpstreamResponse)?;
            self.saw_payload = true;
            return Ok(());
        }
        let value: Value =
            serde_json::from_str(data).map_err(|_| ProtocolError::InvalidUpstreamResponse)?;
        self.saw_payload = true;
        if value.get("error").is_some_and(|error| !error.is_null()) {
            return Err(ProtocolError::UpstreamError);
        }
        if self.upstream_id.is_none() {
            if let Some(id) = value.get("id").and_then(Value::as_str) {
                self.upstream_id = Some(id.to_owned());
            }
        }
        if self.upstream_model.is_none() {
            if let Some(model) = value.get("model").and_then(Value::as_str) {
                self.upstream_model = Some(model.to_owned());
            }
        }
        if let Some(usage) = usage_from(&value) {
            self.usage = Some(usage);
        }
        self.mark_content(&value);
        if let Some(choice) = value
            .get("choices")
            .and_then(Value::as_array)
            .and_then(|choices| choices.first())
            && let Some(reason) = choice.get("finish_reason").and_then(Value::as_str)
        {
            self.finish = Some(reason.to_owned());
        }
        Ok(())
    }

    /// Set `content_seen` when the parsed chunk carries real content (a
    /// non-empty text/reasoning delta or a tool_calls entry). Only the
    /// lifecycle fast path calls this — the plain-delta path flags content by
    /// substring without a DOM. Wire knowledge stays in the kernel; the relay
    /// only reads the flag.
    fn mark_content(&mut self, value: &Value) {
        if self.content_seen {
            return;
        }
        let Some(delta) = value
            .get("choices")
            .and_then(Value::as_array)
            .and_then(|choices| choices.first())
            .and_then(|choice| choice.get("delta"))
        else {
            return;
        };
        let has_text = delta
            .get("content")
            .and_then(Value::as_str)
            .is_some_and(|text| !text.is_empty());
        let has_reasoning = delta
            .get("reasoning_content")
            .and_then(Value::as_str)
            .is_some_and(|text| !text.is_empty())
            || delta
                .get("reasoning")
                .and_then(Value::as_str)
                .is_some_and(|text| !text.is_empty());
        let has_tools = delta
            .get("tool_calls")
            .and_then(Value::as_array)
            .is_some_and(|calls| !calls.is_empty());
        if has_text || has_reasoning || has_tools {
            self.content_seen = true;
        }
    }

    /// Terminal verdict. A stream that ends without `[DONE]` or a finish reason
    /// is not a success (B §4.2, §4.7).
    pub fn finish(&self) -> Terminal {
        match self.finish.as_deref() {
            Some("length") => Terminal::Incomplete,
            Some(_) => Terminal::Completed,
            None if self.done && self.saw_payload => Terminal::Completed,
            None => Terminal::Failed,
        }
    }
    pub fn terminal_seen(&self) -> bool {
        self.done && self.finish.is_some()
    }

    /// Whether the wire stream carried any closing signal — a finish_reason
    /// chunk or the `[DONE]` marker. Post-commit synthesis only fires when
    /// neither arrived (B §4.2): a delivered finish_reason already closes the
    /// client stream, so an error chunk on top would contradict it.
    pub fn wire_terminal_seen(&self) -> bool {
        self.finish.is_some() || self.done
    }

    /// Upstream chunk `id` captured from the first parsed chunk — the echo
    /// identity for a synthesized terminal frame on post-commit truncation.
    pub fn upstream_id(&self) -> Option<&str> {
        self.upstream_id.as_deref()
    }

    /// Upstream chunk `model` captured from the first parsed chunk — the echo
    /// identity for a synthesized terminal frame on post-commit truncation.
    pub fn upstream_model(&self) -> Option<&str> {
        self.upstream_model.as_deref()
    }

    /// Whether real content (text / reasoning / tool_calls delta) was observed.
    /// The relay streaming hold's commit signal: once set, the response has
    /// begun reaching the client and must never be replaced by a failover.
    pub fn content_seen(&self) -> bool {
        self.content_seen
    }
}

/// Synthesized terminal frames for a post-commit upstream truncation
/// (OpenRouter convention: a chunk carrying `finish_reason:"error"` plus a
/// top-level `error` object, then the stream terminates — no `[DONE]`).
pub fn stream_error_frames(
    id: Option<&str>,
    model: Option<&str>,
    message: &str,
    created: i64,
) -> Vec<RawFrame> {
    let chunk = serde_json::json!({
        "id": id.unwrap_or("cardinal-error"),
        "object": "chat.completion.chunk",
        "created": created,
        "model": model.unwrap_or("unknown"),
        "choices": [{"index": 0, "delta": {}, "finish_reason": "error"}],
        "error": {"message": message, "type": "server_error", "code": 502},
    });
    vec![RawFrame {
        event: None,
        id: None,
        data: bytes::Bytes::from(chunk.to_string()),
    }]
}
