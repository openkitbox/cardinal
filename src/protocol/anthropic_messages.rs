//! `anthropic_messages` kernel (B §4.4).
//!
//! Messages keeps its own contract: `system` is a top-level field, roles are
//! only `user`/`assistant`, and `max_tokens` is mandatory and positive. The
//! kernel never borrows Chat semantics.

use super::sse::{Frame, RawFrame};
use super::usage::UsageCounts;
use super::{
    ObservedResponse, Prepared, ProtocolError, ProtocolId, RawValue, StreamEvent, TargetView,
    Terminal,
};
use serde_json::Value;

pub fn validate_request(client_body: &Value) -> Result<(), ProtocolError> {
    let object = client_body
        .as_object()
        .ok_or(ProtocolError::InvalidRequest)?;
    if object.get("model").and_then(Value::as_str).is_none() {
        return Err(ProtocolError::InvalidRequest);
    }
    match object.get("max_tokens").and_then(Value::as_u64) {
        Some(max_tokens) if max_tokens > 0 => {}
        _ => return Err(ProtocolError::InvalidRequest),
    }
    let messages = object
        .get("messages")
        .and_then(Value::as_array)
        .ok_or(ProtocolError::InvalidRequest)?;
    if messages.is_empty() {
        return Err(ProtocolError::InvalidRequest);
    }
    for message in messages {
        match message.get("role").and_then(Value::as_str) {
            Some("user") | Some("assistant") => {}
            _ => return Err(ProtocolError::InvalidRequest),
        }
    }
    Ok(())
}

/// Build the upstream request for one attempt. The wire is written
/// field-by-field straight from the client's tree — no intermediate `Value`,
/// no deep copy — with only the model overridden. `skip` names top-level
/// fields the wire must not carry (learned refusals, vendor fixups).
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
            super::write_json_value(&mut out, value, strip_images)?;
        }
    }
    out.push(b'}');
    let body = bytes::Bytes::from(out);
    Ok(Prepared {
        protocol: ProtocolId::AnthropicMessages,
        url: url.to_owned(),
        content_type: "application/json",
        body,
        stream,
        // Required by every Messages upstream (B §6.6).
        headers: vec![("anthropic-version", "2023-06-01".to_owned())],
    })
}

/// Observe a non-streaming response.
///
/// Only the observed fields are deserialized, borrowed straight from the wire
/// (`raw_str`/`raw_value`); the response body itself — `content` with its
/// whole text — is never materialized.
pub fn parse_json(body: &[u8]) -> Result<ObservedResponse, ProtocolError> {
    let obs: MessagesObservation =
        serde_json::from_slice(body).map_err(|_| ProtocolError::InvalidUpstreamResponse)?;
    if super::raw_str(obs.r#type) == Some("error") {
        return Ok(ObservedResponse {
            usage: None,
            terminal: Terminal::Failed,
            upstream_model: None,
        });
    }
    // `content` must be an array (the old `as_array` probe's verdict; absent
    // and null read the same way here).
    if !obs.content.is_some_and(super::raw_is_array) {
        return Err(ProtocolError::InvalidUpstreamResponse);
    }
    Ok(ObservedResponse {
        usage: obs
            .usage
            .as_ref()
            .and_then(|usage| super::raw_value(usage))
            .as_ref()
            .and_then(usage_counts),
        terminal: terminal_from(super::raw_str(obs.stop_reason), true),
        upstream_model: super::raw_str(obs.model).map(str::to_owned),
    })
}

/// The observed fields of a Messages response; everything else (the `content`
/// array above all) is ignored without being materialized.
#[derive(serde::Deserialize)]
struct MessagesObservation<'a> {
    #[serde(default, borrow, rename = "type")]
    r#type: Option<&'a RawValue>,
    #[serde(default, borrow)]
    content: Option<&'a RawValue>,
    #[serde(default, borrow)]
    stop_reason: Option<&'a RawValue>,
    #[serde(default, borrow)]
    usage: Option<&'a RawValue>,
    #[serde(default, borrow)]
    model: Option<&'a RawValue>,
}

/// Messages reports the non-cached input separately: the billable input is the
/// sum of the non-cached part, cache creation and cache read, which are
/// mutually exclusive (B §4.4). `output_tokens` already includes thinking.
/// The cache write and its 1-hour part: the flat `cache_creation_input_tokens`
/// when the upstream reports it, else the sum of the `cache_creation` object's
/// TTL parts; the 1-hour part is the object's `ephemeral_1h_input_tokens`.
fn cache_creation_parts(usage: &Value) -> (Option<u64>, Option<u64>) {
    let object = usage.get("cache_creation");
    let one_hour = object
        .and_then(|c| c.get("ephemeral_1h_input_tokens"))
        .and_then(Value::as_u64);
    let five_min = object
        .and_then(|c| c.get("ephemeral_5m_input_tokens"))
        .and_then(Value::as_u64);
    let total = usage
        .get("cache_creation_input_tokens")
        .and_then(Value::as_u64)
        .or_else(|| match (five_min, one_hour) {
            (Some(m), h) => Some(m + h.unwrap_or(0)),
            (None, Some(h)) => Some(h),
            (None, None) => None,
        });
    (total, one_hour)
}

fn usage_counts(usage: &Value) -> Option<UsageCounts> {
    let input = usage.get("input_tokens").and_then(Value::as_u64)?;
    let output = usage.get("output_tokens").and_then(Value::as_u64)?;
    let cache_read = usage.get("cache_read_input_tokens").and_then(Value::as_u64);
    let (cache_creation, cache_creation_1h) = cache_creation_parts(usage);
    let billable_input = input
        .checked_add(cache_read.unwrap_or(0))?
        .checked_add(cache_creation.unwrap_or(0))?;
    Some(UsageCounts {
        input_tokens: billable_input,
        output_tokens: output,
        calls: 0,
        cached_input_tokens: cache_read,
        cache_creation_input_tokens: cache_creation,
        cache_creation_1h_input_tokens: cache_creation_1h,
        ..Default::default()
    })
}

fn terminal_from(stop_reason: Option<&str>, saw_terminal: bool) -> Terminal {
    match stop_reason {
        Some("max_tokens") => Terminal::Incomplete,
        Some(_) => Terminal::Completed,
        None if saw_terminal => Terminal::Completed,
        None => Terminal::Failed,
    }
}

/// Streaming observer. `message_stop` is the only successful terminal; an
/// `error` event fails the stream even after output was committed (B §4.4).
#[derive(Default)]
pub struct StreamDecoder {
    input_tokens: Option<u64>,
    cache_creation_input_tokens: Option<u64>,
    cache_creation_1h_input_tokens: Option<u64>,
    cache_read_input_tokens: Option<u64>,
    output_tokens: Option<u64>,
    stop_reason: Option<String>,
    stopped: bool,
    failed: bool,
    saw_payload: bool,
    content_seen: bool,
    /// `content_block_start` (tool_use) identity by block index: the id/name
    /// ride on the start frame while the JSON arguments trickle in as deltas.
    tool_identities: std::collections::HashMap<u32, (Option<String>, Option<String>)>,
}

impl StreamDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn usage(&self) -> Option<UsageCounts> {
        let (Some(input), Some(output)) = (self.input_tokens, self.output_tokens) else {
            return None;
        };
        // The same mutual-exclusion rule as the JSON path (B §4.4).
        let billable_input = input
            .checked_add(self.cache_read_input_tokens.unwrap_or(0))?
            .checked_add(self.cache_creation_input_tokens.unwrap_or(0))?;
        Some(UsageCounts {
            input_tokens: billable_input,
            output_tokens: output,
            calls: 0,
            cached_input_tokens: self.cache_read_input_tokens,
            cache_creation_input_tokens: self.cache_creation_input_tokens,
            cache_creation_1h_input_tokens: self.cache_creation_1h_input_tokens,
            ..Default::default()
        })
    }

    pub fn observe(&mut self, frame: &Frame) -> Result<Vec<StreamEvent>, ProtocolError> {
        self.observe_raw(frame.event.as_deref(), frame.data.as_bytes())
    }

    /// Observe one raw SSE payload by event name and bytes — the translated
    /// pump's entry point, with no `String` re-framing hop in between.
    pub fn observe_raw(
        &mut self,
        event: Option<&str>,
        data: &[u8],
    ) -> Result<Vec<StreamEvent>, ProtocolError> {
        let mut events = Vec::new();
        let data = std::str::from_utf8(data)
            .map_err(|_| ProtocolError::InvalidUpstreamResponse)?
            .trim();
        if data.is_empty() {
            return Ok(events);
        }
        if data == "[DONE]" {
            return Ok(events);
        }
        let value: Value =
            serde_json::from_str(data).map_err(|_| ProtocolError::InvalidUpstreamResponse)?;
        let event_type = event
            .or_else(|| value.get("type").and_then(Value::as_str))
            .unwrap_or_default();
        match event_type {
            // Keepalive frames are not payload.
            "ping" => return Ok(events),
            "error" => {
                self.failed = true;
                return Err(ProtocolError::UpstreamError);
            }
            _ => {}
        }
        self.saw_payload = true;
        match event_type {
            "content_block_start" => {
                let index = value.get("index").and_then(Value::as_u64).unwrap_or(0) as u32;
                if let Some(block) = value.get("content_block")
                    && block.get("type").and_then(Value::as_str) == Some("tool_use")
                {
                    let id = block.get("id").and_then(Value::as_str).map(str::to_owned);
                    let name = block.get("name").and_then(Value::as_str).map(str::to_owned);
                    self.tool_identities.insert(index, (id, name));
                }
            }
            "message_start" => {
                if let Some(usage) = value
                    .get("message")
                    .and_then(|message| message.get("usage"))
                {
                    self.input_tokens = usage.get("input_tokens").and_then(Value::as_u64);
                    (
                        self.cache_creation_input_tokens,
                        self.cache_creation_1h_input_tokens,
                    ) = cache_creation_parts(usage);
                    self.cache_read_input_tokens =
                        usage.get("cache_read_input_tokens").and_then(Value::as_u64);
                }
                // SH-05: emit the running usage so a translating observer sees the
                // input side before the deltas (the internal counters feed settlement
                // either way; this event feeds the client-facing translation).
                if let Some(usage) = self.usage() {
                    events.push(StreamEvent::Usage(usage));
                }
            }
            "content_block_delta" => {
                self.content_seen = true;
                if let Some(delta) = value.get("delta") {
                    match delta.get("type").and_then(Value::as_str) {
                        Some("text_delta") => {
                            if let Some(text) = delta.get("text").and_then(Value::as_str) {
                                events.push(StreamEvent::TextDelta(text.to_owned()));
                            }
                        }
                        Some("thinking_delta") => {
                            if let Some(thinking) = delta.get("thinking").and_then(Value::as_str) {
                                events.push(StreamEvent::ReasoningDelta(thinking.to_owned()));
                            }
                        }
                        Some("input_json_delta") => {
                            let index =
                                value.get("index").and_then(Value::as_u64).unwrap_or(0) as u32;
                            let (id, name) = self
                                .tool_identities
                                .get(&index)
                                .cloned()
                                .unwrap_or((None, None));
                            events.push(StreamEvent::ToolCallDelta {
                                index,
                                id,
                                name,
                                arguments: delta
                                    .get("partial_json")
                                    .and_then(Value::as_str)
                                    .unwrap_or_default()
                                    .to_owned(),
                            });
                        }
                        _ => {}
                    }
                }
            }
            "message_delta" => {
                if let Some(usage) = value.get("usage") {
                    if let Some(output) = usage.get("output_tokens").and_then(Value::as_u64) {
                        self.output_tokens = Some(output);
                    }
                    // A delta may carry the cache counters when start did not.
                    if let Some(value) = usage
                        .get("cache_creation_input_tokens")
                        .and_then(Value::as_u64)
                    {
                        self.cache_creation_input_tokens = Some(value);
                    }
                    let (_, one_hour) = cache_creation_parts(usage);
                    if let Some(one_hour) = one_hour {
                        self.cache_creation_1h_input_tokens = Some(one_hour);
                    }
                    if let Some(value) =
                        usage.get("cache_read_input_tokens").and_then(Value::as_u64)
                    {
                        self.cache_read_input_tokens = Some(value);
                    }
                }
                // SH-05: message_delta is where Anthropic reports the final output
                // count; the Usage event precedes Finish so a translating stream
                // closes with real usage instead of zeros.
                if let Some(usage) = self.usage() {
                    events.push(StreamEvent::Usage(usage));
                }
                if let Some(reason) = value
                    .get("delta")
                    .and_then(|delta| delta.get("stop_reason"))
                    .and_then(Value::as_str)
                {
                    self.stop_reason = Some(reason.to_owned());
                    events.push(StreamEvent::Finish {
                        reason: reason.to_owned(),
                    });
                }
            }
            "message_stop" => self.stopped = true,
            _ => {}
        }
        Ok(events)
    }

    /// Zero-copy relay observation of a raw SSE frame: validates the payload
    /// and updates only the settlement state (usage / stop_reason / stopped /
    /// error), without building a JSON DOM for plain content frames.
    ///
    /// Lifecycle frames are identified by the SSE `event:` line when present,
    /// otherwise by a marker scan of the data. `content_block_delta` is content
    /// by name (every delta type carries bytes) and flips the hold's commit
    /// flag by string match alone — the delta payload itself stays unparsed. A
    /// false positive in the scan only costs one extra parse; the dispatch
    /// below is authoritative.
    pub fn observe_raw_for_relay(&mut self, frame: &RawFrame) -> Result<(), ProtocolError> {
        let data = std::str::from_utf8(&frame.data)
            .map_err(|_| ProtocolError::InvalidUpstreamResponse)?
            .trim();
        if data.is_empty() || data == "[DONE]" {
            return Ok(());
        }
        const LIFECYCLE: [&str; 5] = [
            "message_start",
            "message_delta",
            "message_stop",
            "error",
            "ping",
        ];
        let event_hint = frame.event.as_deref().unwrap_or("");
        // Any content_block_delta is user-visible content; flag it by name only.
        if event_hint == "content_block_delta"
            || (event_hint.is_empty() && data.contains("content_block_delta"))
        {
            self.content_seen = true;
        }
        let needs_parse = if event_hint.is_empty() {
            LIFECYCLE.iter().any(|marker| data.contains(marker))
        } else {
            LIFECYCLE.contains(&event_hint)
        };
        if !needs_parse {
            // No lifecycle marker: nothing this frame can say changes the
            // settlement state (`content_block_delta` was already flagged above) —
            // the observation parse is skipped entirely. The frame's JSON shape is
            // still validated without materializing it: a malformed frame is
            // rejected exactly as before, and only a well-formed one counts as
            // payload.
            serde_json::from_str::<serde::de::IgnoredAny>(data)
                .map_err(|_| ProtocolError::InvalidUpstreamResponse)?;
            self.saw_payload = true;
            return Ok(());
        }
        let value: Value =
            serde_json::from_str(data).map_err(|_| ProtocolError::InvalidUpstreamResponse)?;
        let event_type = if event_hint.is_empty() {
            value
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or_default()
        } else {
            event_hint
        };
        match event_type {
            "ping" => return Ok(()),
            "error" => {
                self.failed = true;
                return Err(ProtocolError::UpstreamError);
            }
            _ => {}
        }
        self.saw_payload = true;
        match event_type {
            "message_start" => {
                if let Some(usage) = value
                    .get("message")
                    .and_then(|message| message.get("usage"))
                {
                    self.input_tokens = usage.get("input_tokens").and_then(Value::as_u64);
                    (
                        self.cache_creation_input_tokens,
                        self.cache_creation_1h_input_tokens,
                    ) = cache_creation_parts(usage);
                    self.cache_read_input_tokens =
                        usage.get("cache_read_input_tokens").and_then(Value::as_u64);
                }
            }
            "message_delta" => {
                if let Some(usage) = value.get("usage") {
                    if let Some(output) = usage.get("output_tokens").and_then(Value::as_u64) {
                        self.output_tokens = Some(output);
                    }
                    if let Some(value) = usage
                        .get("cache_creation_input_tokens")
                        .and_then(Value::as_u64)
                    {
                        self.cache_creation_input_tokens = Some(value);
                    }
                    let (_, one_hour) = cache_creation_parts(usage);
                    if let Some(one_hour) = one_hour {
                        self.cache_creation_1h_input_tokens = Some(one_hour);
                    }
                    if let Some(value) =
                        usage.get("cache_read_input_tokens").and_then(Value::as_u64)
                    {
                        self.cache_read_input_tokens = Some(value);
                    }
                }
                if let Some(reason) = value
                    .get("delta")
                    .and_then(|delta| delta.get("stop_reason"))
                    .and_then(Value::as_str)
                {
                    self.stop_reason = Some(reason.to_owned());
                }
            }
            "message_stop" => self.stopped = true,
            _ => {}
        }
        Ok(())
    }

    pub fn finish(&self) -> Terminal {
        if self.failed {
            return Terminal::Failed;
        }
        if !self.stopped {
            return Terminal::Failed;
        }
        terminal_from(self.stop_reason.as_deref(), self.saw_payload)
    }
    pub fn terminal_seen(&self) -> bool {
        self.stopped
    }

    /// Whether a `content_block_delta` was observed: the relay streaming hold's
    /// commit signal (see the chat kernel for the full contract).
    pub fn content_seen(&self) -> bool {
        self.content_seen
    }
}
