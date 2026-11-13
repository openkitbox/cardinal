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
//!
//! The translated path additionally decodes text, reasoning and function-call
//! deltas into [`StreamEvent`]s (see [`StreamDecoder::observe_raw`]).

use super::sse::{Frame, RawFrame};
use super::usage::UsageCounts;
use super::{
    ObservedResponse, Prepared, ProtocolError, ProtocolId, RawValue, StreamEvent, TargetView,
    Terminal,
};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

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
    strip_images: bool,
) -> Result<Prepared, ProtocolError> {
    validate_request(client_body)?;
    let object = client_body
        .as_object()
        .ok_or(ProtocolError::InvalidRequest)?;
    let url = target.url(stream)?;
    let forces = |name: &str| target.forced.iter().any(|(forced, _)| *forced == name);
    let pin_store = !skip.contains(&"store") && !forces("store");
    let mut out = Vec::new();
    out.push(b'{');
    let mut first = true;
    for (field, value) in object {
        if skip.contains(&field.as_str()) || forces(field) {
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
    // Stateless relay: pin store=false when the client omitted it, so upstreams
    // whose default is store=true (OpenAI) cannot keep server-side state. A
    // skipped `store` stays absent, matching the old strip-after-prepare result.
    if pin_store && !object.contains_key("store") {
        if !first {
            out.push(b',');
        }
        out.extend_from_slice(b"\"store\":false");
        first = false;
    }
    let missing = target
        .required
        .iter()
        .filter(|(field, _)| !object.contains_key(*field) && !skip.contains(field));
    for (field, literal) in target.forced.iter().chain(missing) {
        if !first {
            out.push(b',');
        }
        first = false;
        super::write_json(&mut out, field)?;
        out.push(b':');
        out.extend_from_slice(literal.as_bytes());
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
        cursor: None,
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
        reasoning_tokens_included: usage
            .get("output_tokens_details")
            .and_then(|details| details.get("reasoning_tokens"))
            .and_then(Value::as_u64)
            .map(|_| true),
        ..Default::default()
    })
}

/// Streaming observer: accumulates usage and detects the terminal event.
///
/// The translated path (`observe_raw`) decodes deltas into events because the
/// Chat↔Responses translation consumes them. The pass-through path
/// (`observe_raw_for_relay`) forwards the original bytes, never materializes
/// events, and keeps only the terminal, usage and `content_seen` observation.
#[derive(Default)]
pub struct StreamDecoder {
    usage: Option<UsageCounts>,
    terminal: Option<Terminal>,
    content_seen: bool,
    /// Responses output positions include non-tool items; Chat needs dense
    /// tool indexes. Grows only on `output_item.added` of a function_call.
    tool_slots: Vec<ToolSlot>,
    /// Reasoning snapshots are keyed by their Responses output position so a
    /// completion snapshot can be reconciled with deltas from the same item.
    reasoning_slots: Vec<ReasoningSlot>,
    refusal_slots: Vec<(u64, u64, String)>,
    argument_bytes: usize,
    payload_log: bool,
    upstream_error_event: bool,
}

const MAX_TOOL_CALLS: usize = 128;
const MAX_TOOL_ARGUMENT_BYTES: usize = 1024 * 1024;

struct ToolSlot {
    output_index: u64,
    index: u32,
    /// Arguments already emitted, retained to reconcile completion snapshots.
    arguments: String,
    id: Option<String>,
    name: Option<String>,
    announced: bool,
}

struct ReasoningSlot {
    output_index: u64,
    /// Reasoning text already emitted to the translated client.
    text: String,
}

impl StreamDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_payload_log(&mut self, enabled: bool) {
        self.payload_log = enabled;
    }

    pub fn usage(&self) -> Option<UsageCounts> {
        self.usage_ref().cloned()
    }

    pub fn usage_ref(&self) -> Option<&UsageCounts> {
        self.usage.as_ref()
    }

    pub fn usage_if_changed(&self, previous: Option<&UsageCounts>) -> Option<UsageCounts> {
        (self.usage.as_ref() != previous)
            .then(|| self.usage_ref().cloned())
            .flatten()
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
        let text = match std::str::from_utf8(data) {
            Ok(text) => text,
            Err(_) => {
                self.diagnostic_decode("utf8", data, None);
                return Err(ProtocolError::InvalidUpstreamResponse);
            }
        };
        let data = text.trim();
        if data.is_empty() {
            return Ok(events);
        }
        if self.terminal.is_some() {
            return Ok(events);
        }
        let value: Value = match serde_json::from_str(data) {
            Ok(value) => value,
            Err(_) => {
                self.diagnostic_decode("json", data.as_bytes(), None);
                return Err(ProtocolError::InvalidUpstreamResponse);
            }
        };
        self.diagnostic_event(&value, data.as_bytes());
        let terminal = match self.observe_event(&value) {
            Ok(terminal) => terminal,
            Err(error) => {
                self.diagnostic_decode("event", data.as_bytes(), Some(&value));
                return Err(error);
            }
        };
        if let Err(error) = self.decode_delta(&value, &mut events) {
            self.diagnostic_decode("fields", data.as_bytes(), Some(&value));
            return Err(error);
        }
        if let Some(terminal) = terminal {
            if terminal == Terminal::Completed
                && !self.tool_slots.is_empty()
                && value
                    .pointer("/response/output")
                    .and_then(Value::as_array)
                    .is_none()
            {
                return Err(ProtocolError::InvalidUpstreamResponse);
            }
            if terminal == Terminal::Completed
                && let Some(output) = value.pointer("/response/output").and_then(Value::as_array)
            {
                for index in 0..self.tool_slots.len() {
                    let output_index = self.tool_slots[index].output_index;
                    let item = usize::try_from(output_index)
                        .ok()
                        .and_then(|index| output.get(index))
                        .ok_or(ProtocolError::InvalidUpstreamResponse)?;
                    if item.get("type").and_then(Value::as_str) != Some("function_call") {
                        return Err(ProtocolError::InvalidUpstreamResponse);
                    }
                    self.reconcile_tool_snapshot(output_index, item)?;
                }
                for (position, item) in output.iter().enumerate() {
                    match item.get("type").and_then(Value::as_str) {
                        Some("function_call") => {
                            let slot = self
                                .tool_slots
                                .iter()
                                .find(|slot| slot.output_index == position as u64)
                                .ok_or(ProtocolError::InvalidUpstreamResponse)?;
                            if item.get("call_id").and_then(Value::as_str) != slot.id.as_deref()
                                || item.get("name").and_then(Value::as_str) != slot.name.as_deref()
                                || item.get("arguments").and_then(Value::as_str)
                                    != Some(slot.arguments.as_str())
                            {
                                return Err(ProtocolError::InvalidUpstreamResponse);
                            }
                        }
                        Some("message" | "reasoning") => {}
                        _ => return Err(ProtocolError::InvalidUpstreamResponse),
                    }
                }
                for (position, item) in output.iter().enumerate() {
                    if item.get("type").and_then(Value::as_str) == Some("reasoning") {
                        let output_index = position as u64;
                        self.reconcile_reasoning_snapshot(output_index, item)?;
                    }
                }
                for slot in &mut self.tool_slots {
                    if !slot.announced {
                        let (Some(id), Some(name)) = (&slot.id, &slot.name) else {
                            return Err(ProtocolError::InvalidUpstreamResponse);
                        };
                        events.push(StreamEvent::ToolCallDelta {
                            index: slot.index,
                            id: Some(id.clone()),
                            name: Some(name.clone()),
                            arguments: slot.arguments.clone(),
                        });
                        slot.announced = true;
                    }
                }
            }
            if let Some(usage) = self.usage.clone() {
                events.push(StreamEvent::Usage(usage));
            }
            // Failed and cancelled responses do not have a Chat finish reason;
            // the pump still observes their terminal state independently.
            if let Some(reason) = self.finish_reason(terminal, &value) {
                events.push(StreamEvent::Finish {
                    reason: reason.to_owned(),
                });
            }
        }
        Ok(events)
    }

    /// Map one incremental event to its `StreamEvent`. Every other event type
    /// yields nothing; the observation state is `observe_event`'s alone.
    fn decode_delta(
        &mut self,
        value: &Value,
        events: &mut Vec<StreamEvent>,
    ) -> Result<(), ProtocolError> {
        match value.get("type").and_then(Value::as_str) {
            Some("response.refusal.delta" | "response.refusal.done") => {
                let output = output_index(value)?;
                let content = value
                    .get("content_index")
                    .and_then(Value::as_u64)
                    .ok_or(ProtocolError::InvalidUpstreamResponse)?;
                let position = self
                    .refusal_slots
                    .iter()
                    .position(|slot| slot.0 == output && slot.1 == content);
                let position = position.unwrap_or_else(|| {
                    self.refusal_slots.push((output, content, String::new()));
                    self.refusal_slots.len() - 1
                });
                let emitted = &mut self.refusal_slots[position].2;
                let is_delta =
                    value.get("type").and_then(Value::as_str) == Some("response.refusal.delta");
                let text = if is_delta {
                    value.get("delta")
                } else {
                    value.get("refusal")
                }
                .and_then(Value::as_str)
                .ok_or(ProtocolError::InvalidUpstreamResponse)?;
                let suffix = if is_delta {
                    text
                } else {
                    text.strip_prefix(emitted.as_str())
                        .ok_or(ProtocolError::InvalidUpstreamResponse)?
                };
                if !suffix.is_empty() {
                    emitted.push_str(suffix);
                    events.push(StreamEvent::TextDelta(suffix.to_owned()));
                }
            }
            Some("response.output_text.delta") => {
                if let Some(text) = non_empty_delta(value) {
                    events.push(StreamEvent::TextDelta(text.to_owned()));
                }
            }
            Some("response.reasoning_summary_text.delta" | "response.reasoning_text.delta") => {
                if let Some(text) = non_empty_delta(value) {
                    let Ok(output_index) = output_index(value) else {
                        return Ok(());
                    };
                    self.append_reasoning_delta(output_index, text);
                    events.push(StreamEvent::ReasoningDelta(text.to_owned()));
                }
            }
            Some("response.output_item.added") => {
                let Some(item) = value.get("item") else {
                    return Err(ProtocolError::InvalidUpstreamResponse);
                };
                if item.get("type").and_then(Value::as_str) == Some("custom_tool_call") {
                    return Err(ProtocolError::InvalidUpstreamResponse);
                }
                if !matches!(
                    item.get("type").and_then(Value::as_str),
                    Some("message" | "reasoning" | "function_call")
                ) {
                    return Err(ProtocolError::InvalidUpstreamResponse);
                }
                if item.get("type").and_then(Value::as_str) != Some("function_call") {
                    return Ok(());
                }
                let output_index = output_index(value)?;
                if self
                    .tool_slots
                    .iter()
                    .any(|slot| slot.output_index == output_index)
                {
                    return Err(ProtocolError::InvalidUpstreamResponse);
                }
                let index = u32::try_from(self.tool_slots.len())
                    .map_err(|_| ProtocolError::InvalidUpstreamResponse)?;
                if self.tool_slots.len() >= MAX_TOOL_CALLS {
                    return Err(ProtocolError::InvalidUpstreamResponse);
                }
                let arguments = item
                    .get("arguments")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                self.reserve_argument_bytes(arguments.len())?;
                self.tool_slots.push(ToolSlot {
                    output_index,
                    index,
                    arguments: arguments.to_owned(),
                    id: None,
                    name: None,
                    announced: false,
                });
                self.complete_identity(value, item, events)?;
            }
            Some("response.function_call_arguments.delta") => {
                if let Some(arguments) = non_empty_delta(value) {
                    let output_index = output_index(value)?;
                    let slot_index = self
                        .tool_slots
                        .iter()
                        .position(|slot| slot.output_index == output_index)
                        .ok_or(ProtocolError::InvalidUpstreamResponse)?;
                    self.reserve_argument_bytes(arguments.len())?;
                    let slot = &mut self.tool_slots[slot_index];
                    slot.arguments.push_str(arguments);
                    if slot.announced {
                        events.push(StreamEvent::ToolCallDelta {
                            index: slot.index,
                            id: None,
                            name: None,
                            arguments: arguments.to_owned(),
                        });
                    }
                }
            }
            Some("response.function_call_arguments.done") => {
                self.complete_arguments(value, value, events)?;
            }
            Some(
                "response.custom_tool_call_input.delta" | "response.custom_tool_call_input.done",
            ) => return Err(ProtocolError::InvalidUpstreamResponse),
            Some("response.output_item.done") => {
                let item = value
                    .get("item")
                    .ok_or(ProtocolError::InvalidUpstreamResponse)?;
                match item.get("type").and_then(Value::as_str) {
                    Some("function_call") => {
                        self.complete_identity(value, item, events)?;
                        self.complete_arguments(value, item, events)?;
                    }
                    Some("reasoning") => {
                        let output_index = output_index(value)?;
                        self.emit_reasoning_item_snapshot(output_index, item, events)?;
                    }
                    Some("message") => {}
                    _ => return Err(ProtocolError::InvalidUpstreamResponse),
                }
            }
            Some("response.reasoning_summary_text.done") => {
                let Some(text) = value.get("text").and_then(Value::as_str) else {
                    return Ok(());
                };
                let Ok(output_index) = output_index(value) else {
                    return Ok(());
                };
                self.emit_reasoning_snapshot(output_index, text, events)?;
            }
            _ => {}
        }
        Ok(())
    }

    fn append_reasoning_delta(&mut self, output_index: u64, text: &str) {
        if let Some(slot) = self
            .reasoning_slots
            .iter_mut()
            .find(|slot| slot.output_index == output_index)
        {
            slot.text.push_str(text);
        } else {
            self.reasoning_slots.push(ReasoningSlot {
                output_index,
                text: text.to_owned(),
            });
        }
    }

    fn emit_reasoning_snapshot(
        &mut self,
        output_index: u64,
        snapshot: &str,
        events: &mut Vec<StreamEvent>,
    ) -> Result<(), ProtocolError> {
        let slot = if let Some(position) = self
            .reasoning_slots
            .iter()
            .position(|slot| slot.output_index == output_index)
        {
            &mut self.reasoning_slots[position]
        } else {
            self.reasoning_slots.push(ReasoningSlot {
                output_index,
                text: String::new(),
            });
            let position = self.reasoning_slots.len() - 1;
            &mut self.reasoning_slots[position]
        };
        let Some(suffix) = snapshot.strip_prefix(slot.text.as_str()) else {
            return Err(ProtocolError::InvalidUpstreamResponse);
        };
        if !suffix.is_empty() {
            events.push(StreamEvent::ReasoningDelta(suffix.to_owned()));
            slot.text.push_str(suffix);
        }
        Ok(())
    }

    fn emit_reasoning_item_snapshot(
        &mut self,
        output_index: u64,
        item: &Value,
        events: &mut Vec<StreamEvent>,
    ) -> Result<(), ProtocolError> {
        let position = if let Some(position) = self
            .reasoning_slots
            .iter()
            .position(|slot| slot.output_index == output_index)
        {
            position
        } else {
            self.reasoning_slots.push(ReasoningSlot {
                output_index,
                text: String::new(),
            });
            self.reasoning_slots.len() - 1
        };
        let emitted = &self.reasoning_slots[position].text;
        let suffix = reasoning_snapshot_suffix(emitted, item)
            .ok_or(ProtocolError::InvalidUpstreamResponse)?;
        if suffix.is_empty() {
            return Ok(());
        }
        self.reasoning_slots[position].text.push_str(&suffix);
        events.push(StreamEvent::ReasoningDelta(suffix));
        Ok(())
    }

    fn reconcile_reasoning_snapshot(
        &self,
        output_index: u64,
        item: &Value,
    ) -> Result<(), ProtocolError> {
        let Some(slot) = self
            .reasoning_slots
            .iter()
            .find(|slot| slot.output_index == output_index)
        else {
            return Ok(());
        };
        reasoning_snapshot_suffix(&slot.text, item)
            .map(|_| ())
            .ok_or(ProtocolError::InvalidUpstreamResponse)
    }

    fn complete_identity(
        &mut self,
        value: &Value,
        item: &Value,
        events: &mut Vec<StreamEvent>,
    ) -> Result<(), ProtocolError> {
        let output_index = output_index(value)?;
        let slot_index = self
            .tool_slots
            .iter()
            .position(|slot| slot.output_index == output_index)
            .ok_or(ProtocolError::InvalidUpstreamResponse)?;
        let slot = &mut self.tool_slots[slot_index];
        for (field, current) in [("call_id", &mut slot.id), ("name", &mut slot.name)] {
            if let Some(incoming) = item
                .get(field)
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
            {
                match current {
                    Some(old) if old != incoming => {
                        return Err(ProtocolError::InvalidUpstreamResponse);
                    }
                    None => *current = Some(incoming.to_owned()),
                    _ => {}
                }
            }
        }
        if !slot.announced
            && let (Some(id), Some(name)) = (&slot.id, &slot.name)
        {
            events.push(StreamEvent::ToolCallDelta {
                index: slot.index,
                id: Some(id.clone()),
                name: Some(name.clone()),
                arguments: slot.arguments.clone(),
            });
            slot.announced = true;
        }
        Ok(())
    }

    fn reserve_argument_bytes(&mut self, additional: usize) -> Result<(), ProtocolError> {
        let total = self
            .argument_bytes
            .checked_add(additional)
            .ok_or(ProtocolError::InvalidUpstreamResponse)?;
        if total > MAX_TOOL_ARGUMENT_BYTES {
            return Err(ProtocolError::InvalidUpstreamResponse);
        }
        self.argument_bytes = total;
        Ok(())
    }

    fn reconcile_tool_snapshot(
        &mut self,
        output_index: u64,
        item: &Value,
    ) -> Result<(), ProtocolError> {
        let Some(slot_index) = self
            .tool_slots
            .iter()
            .position(|slot| slot.output_index == output_index)
        else {
            return Err(ProtocolError::InvalidUpstreamResponse);
        };
        let slot = &mut self.tool_slots[slot_index];
        for (field, current) in [("call_id", &mut slot.id), ("name", &mut slot.name)] {
            let incoming = item
                .get(field)
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .ok_or(ProtocolError::InvalidUpstreamResponse)?;
            match current {
                Some(old) if old != incoming => {
                    return Err(ProtocolError::InvalidUpstreamResponse);
                }
                None => *current = Some(incoming.to_owned()),
                _ => {}
            }
        }
        let arguments = item
            .get("arguments")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let suffix_len = {
            let slot = &self.tool_slots[slot_index];
            arguments
                .strip_prefix(slot.arguments.as_str())
                .ok_or(ProtocolError::InvalidUpstreamResponse)?
                .len()
        };
        self.reserve_argument_bytes(suffix_len)?;
        let current_len = self.tool_slots[slot_index].arguments.len();
        self.tool_slots[slot_index]
            .arguments
            .push_str(&arguments[current_len..]);
        Ok(())
    }

    /// Completion events carry the full arguments, sometimes without deltas.
    /// Reconcile against what was emitted so both done forms are idempotent.
    fn complete_arguments(
        &mut self,
        value: &Value,
        snapshot: &Value,
        events: &mut Vec<StreamEvent>,
    ) -> Result<(), ProtocolError> {
        let arguments = snapshot
            .get("arguments")
            .and_then(Value::as_str)
            .ok_or(ProtocolError::InvalidUpstreamResponse)?;
        let output_index = output_index(value)?;
        let Some(slot_index) = self
            .tool_slots
            .iter()
            .position(|slot| slot.output_index == output_index)
        else {
            return Err(ProtocolError::InvalidUpstreamResponse);
        };
        let current_arguments = self.tool_slots[slot_index].arguments.clone();
        let Some(suffix) = arguments.strip_prefix(current_arguments.as_str()) else {
            return Err(ProtocolError::InvalidUpstreamResponse);
        };
        if !suffix.is_empty() {
            self.reserve_argument_bytes(suffix.len())?;
            self.tool_slots[slot_index].arguments.push_str(suffix);
            if self.tool_slots[slot_index].announced {
                events.push(StreamEvent::ToolCallDelta {
                    index: self.tool_slots[slot_index].index,
                    id: None,
                    name: None,
                    arguments: suffix.to_owned(),
                });
            }
        }
        Ok(())
    }

    /// The Chat-vocabulary finish reason for a terminal event: tool use and
    /// output-token truncation are the two outcomes a Chat client can act on.
    /// Failure and cancellation have no Chat finish reason, hence `None`.
    fn finish_reason(&self, terminal: Terminal, value: &Value) -> Option<&'static str> {
        match terminal {
            Terminal::Completed if !self.tool_slots.is_empty() => Some("tool_calls"),
            Terminal::Completed => Some("stop"),
            Terminal::Incomplete => {
                let reason = value
                    .get("response")
                    .and_then(|response| response.get("incomplete_details"))
                    .and_then(|details| details.get("reason"))
                    .and_then(Value::as_str);
                if reason == Some("max_output_tokens") {
                    Some("length")
                } else {
                    Some("max_tokens_truncated")
                }
            }
            Terminal::Failed | Terminal::Cancelled => None,
        }
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
        let text = match std::str::from_utf8(data) {
            Ok(text) => text,
            Err(_) => {
                self.diagnostic_decode("utf8", data, None);
                return Err(ProtocolError::InvalidUpstreamResponse);
            }
        };
        let data = text.trim();
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
            match serde_json::from_str::<serde::de::IgnoredAny>(data) {
                Ok(_) => return Ok(()),
                Err(_) => {
                    self.diagnostic_decode("json", data.as_bytes(), None);
                    return Err(ProtocolError::InvalidUpstreamResponse);
                }
            }
        }
        let value: Value = match serde_json::from_str(data) {
            Ok(value) => value,
            Err(_) => {
                self.diagnostic_decode("json", data.as_bytes(), None);
                return Err(ProtocolError::InvalidUpstreamResponse);
            }
        };
        self.diagnostic_event(&value, data.as_bytes());
        if let Err(error) = self.observe_event(&value) {
            self.diagnostic_decode("event", data.as_bytes(), Some(&value));
            return Err(error);
        }
        Ok(())
    }

    /// Apply one parsed event to the observation. Returns the terminal verdict
    /// when this event is terminal. Usage from a terminal event's `response`
    /// object overwrites any earlier value (last wins, as in chat).
    fn observe_event(&mut self, value: &Value) -> Result<Option<Terminal>, ProtocolError> {
        if self.terminal.is_some() {
            return Ok(None);
        }
        match value.get("type").and_then(Value::as_str) {
            // Content deltas: the relay streaming hold's commit signal. Refusal and
            // custom-tool-call-input deltas are user-visible content too.
            Some("response.output_text.delta")
            | Some("response.reasoning_summary_text.delta")
            | Some("response.reasoning_text.delta")
            | Some("response.function_call_arguments.delta")
            | Some("response.refusal.delta")
            | Some("response.refusal.done")
            | Some("response.custom_tool_call_input.delta")
            | Some("response.code_interpreter_call_code.delta") => self.content_seen = true,
            _ => {}
        }
        let terminal = match value.get("type").and_then(Value::as_str) {
            Some("response.completed") => Some(Terminal::Completed),
            Some("response.incomplete") => Some(Terminal::Incomplete),
            Some("response.failed") => Some(Terminal::Failed),
            Some("response.cancelled") => Some(Terminal::Cancelled),
            Some("error") => {
                self.upstream_error_event = true;
                self.diagnostic_upstream_error(value);
                self.terminal = Some(Terminal::Failed);
                Some(Terminal::Failed)
            }
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

    fn diagnostic_event(&self, value: &Value, data: &[u8]) {
        if !self.payload_log
            || !tracing::enabled!(target: "gateway::payload", tracing::Level::DEBUG)
        {
            return;
        }
        let event_type = value.get("type").and_then(Value::as_str).unwrap_or("");
        let mut hash = Sha256::new();
        hash.update(data);
        let digest = hash.finalize();
        let event_type = event_type.chars().take(128).collect::<String>();
        tracing::debug!(
            target: "gateway::payload",
            event_type,
            data_len = data.len(),
            data_hash = %hex::encode(&digest[..16]),
            has_response = value.get("response").is_some(),
            has_item = value.get("item").is_some(),
            "Responses stream event diagnostics"
        );
    }

    fn diagnostic_decode(&self, stage: &str, data: &[u8], value: Option<&Value>) {
        if !self.payload_log
            || !tracing::enabled!(target: "gateway::payload", tracing::Level::DEBUG)
        {
            return;
        }
        let event_type = value
            .and_then(|value| value.get("type"))
            .and_then(Value::as_str)
            .unwrap_or("");
        let digest = Sha256::digest(data);
        tracing::debug!(
            target: "gateway::payload",
            decode_stage = stage,
            event_type = %event_type.chars().take(128).collect::<String>(),
            data_len = data.len(),
            data_hash = %hex::encode(&digest[..16]),
            has_type = value.is_some_and(|value| value.get("type").is_some()),
            has_response = value.is_some_and(|value| value.get("response").is_some()),
            has_item = value.is_some_and(|value| value.get("item").is_some()),
            has_delta = value.is_some_and(|value| value.get("delta").is_some()),
            has_output_index = value.is_some_and(|value| value.get("output_index").is_some()),
            has_arguments = value.is_some_and(|value| value.get("arguments").is_some()),
            has_call_id = value.is_some_and(|value| value.get("call_id").is_some()),
            has_name = value.is_some_and(|value| value.get("name").is_some()),
            "Responses stream decode diagnostics"
        );
    }

    fn diagnostic_upstream_error(&self, value: &Value) {
        if !self.payload_log
            || !tracing::enabled!(target: "gateway::payload", tracing::Level::DEBUG)
        {
            return;
        }
        let error = value.get("error");
        let error_type = error
            .and_then(|error| error.get("type"))
            .and_then(Value::as_str)
            .unwrap_or("");
        let code = error
            .and_then(|error| error.get("code"))
            .and_then(Value::as_str)
            .unwrap_or("");
        let param_present = error.is_some_and(|error| error.get("param").is_some());
        let message = error
            .and_then(|error| error.get("message"))
            .and_then(Value::as_str)
            .unwrap_or("");
        let message_hash = Sha256::digest(message.as_bytes());
        tracing::debug!(
            target: "gateway::payload",
            error_type = %error_type.chars().take(128).collect::<String>(),
            error_code = %code.chars().take(128).collect::<String>(),
            param_present,
            message_len = message.len(),
            message_hash = %hex::encode(&message_hash[..16]),
            "Responses upstream error event"
        );
    }

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

    /// Whether the upstream emitted a Responses `error` event.
    pub fn upstream_error_event(&self) -> bool {
        self.upstream_error_event
    }
}

/// Synthesized terminal frames for a post-commit upstream truncation:
/// the protocol's own `error` stream event (not `response.failed` — that one
/// needs the full response object), then the stream terminates.
pub fn stream_error_frames(message: &str) -> Vec<RawFrame> {
    let payload = serde_json::json!({
        "type": "error",
        "code": "server_error",
        "message": message,
        "param": serde_json::Value::Null,
    });
    vec![RawFrame {
        event: Some("error".to_owned()),
        id: None,
        data: bytes::Bytes::from(payload.to_string()),
    }]
}

/// The `type` strings whose presence marks a frame worth a full parse on the
/// relay fast path.
const TERMINAL_SNIFF: &[&str] = &[
    "response.completed",
    "response.incomplete",
    "response.failed",
    "response.cancelled",
    "response.refusal.done",
];

fn non_empty_delta(value: &Value) -> Option<&str> {
    value
        .get("delta")
        .and_then(Value::as_str)
        .filter(|delta| !delta.is_empty())
}

fn reasoning_snapshot_suffix(emitted: &str, item: &Value) -> Option<String> {
    for field in ["summary", "content"] {
        let Some(parts) = item.get(field).and_then(Value::as_array) else {
            continue;
        };
        let mut remaining = emitted;
        let mut suffix = String::new();
        let mut saw_text = false;
        for part in parts {
            let Some(part_text) = part.get("text").and_then(Value::as_str) else {
                continue;
            };
            saw_text = true;
            if remaining.is_empty() {
                suffix.push_str(part_text);
            } else if let Some(rest) = part_text.strip_prefix(remaining) {
                remaining = "";
                suffix.push_str(rest);
            } else if let Some(rest) = remaining.strip_prefix(part_text) {
                remaining = rest;
            } else {
                break;
            }
        }
        if remaining.is_empty() && (saw_text || emitted.is_empty()) {
            return Some(suffix);
        }
    }
    None
}

fn output_index(value: &Value) -> Result<u64, ProtocolError> {
    value
        .get("output_index")
        .and_then(Value::as_u64)
        .ok_or(ProtocolError::InvalidUpstreamResponse)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feed(decoder: &mut StreamDecoder, frames: &[&str]) -> Vec<StreamEvent> {
        let mut events = Vec::new();
        for frame in frames {
            events.extend(
                decoder
                    .observe_raw(frame.as_bytes())
                    .expect("frame decodes"),
            );
        }
        events
    }

    fn tool_added(output_index: u32, call_id: &str, name: &str) -> String {
        format!(
            r#"{{"type":"response.output_item.added","output_index":{output_index},"item":{{"type":"function_call","call_id":"{call_id}","name":"{name}","arguments":""}}}}"#
        )
    }

    fn args_delta(output_index: u32, delta: &str) -> String {
        format!(
            r#"{{"type":"response.function_call_arguments.delta","output_index":{output_index},"delta":{}}}"#,
            serde_json::to_string(delta).expect("argument delta serializes")
        )
    }

    fn args_done(output_index: u32, arguments: &str) -> String {
        format!(
            r#"{{"type":"response.function_call_arguments.done","output_index":{output_index},"arguments":{}}}"#,
            serde_json::to_string(arguments).expect("argument snapshot serializes")
        )
    }

    const COMPLETED: &str = r#"{"type":"response.completed","response":{"status":"completed","usage":{"input_tokens":10,"output_tokens":4,"input_tokens_details":{"cached_tokens":3}}}}"#;

    #[test]
    fn text_and_reasoning_deltas_become_events() {
        let mut decoder = StreamDecoder::new();
        let events = feed(
            &mut decoder,
            &[
                r#"{"type":"response.output_text.delta","output_index":0,"delta":"hi"}"#,
                r#"{"type":"response.output_text.delta","output_index":0,"delta":""}"#,
                r#"{"type":"response.reasoning_summary_text.delta","output_index":0,"delta":"think"}"#,
                r#"{"type":"response.reasoning_text.delta","output_index":0,"delta":"more"}"#,
            ],
        );
        assert_eq!(
            events,
            vec![
                StreamEvent::TextDelta("hi".to_owned()),
                StreamEvent::ReasoningDelta("think".to_owned()),
                StreamEvent::ReasoningDelta("more".to_owned()),
            ]
        );
    }

    #[test]
    fn tool_calls_get_dense_indexes_by_output_index() {
        let mut decoder = StreamDecoder::new();
        let frames = [
            r#"{"type":"response.output_item.added","output_index":0,"item":{"type":"reasoning","id":"rs_1"}}"#.to_owned(),
            r#"{"type":"response.output_item.added","output_index":1,"item":{"type":"message","id":"msg_1"}}"#.to_owned(),
            tool_added(2, "call_a", "alpha"),
            tool_added(3, "call_b", "beta"),
            args_delta(3, r#"{"b""#),
            args_delta(2, "{}"),
        ];
        let refs: Vec<&str> = frames.iter().map(String::as_str).collect();
        let events = feed(&mut decoder, &refs);
        assert_eq!(
            events,
            vec![
                StreamEvent::ToolCallDelta {
                    index: 0,
                    id: Some("call_a".to_owned()),
                    name: Some("alpha".to_owned()),
                    arguments: String::new(),
                },
                StreamEvent::ToolCallDelta {
                    index: 1,
                    id: Some("call_b".to_owned()),
                    name: Some("beta".to_owned()),
                    arguments: String::new(),
                },
                StreamEvent::ToolCallDelta {
                    index: 1,
                    id: None,
                    name: None,
                    arguments: "{\"b\"".to_owned(),
                },
                StreamEvent::ToolCallDelta {
                    index: 0,
                    id: None,
                    name: None,
                    arguments: "{}".to_owned(),
                },
            ]
        );
    }

    #[test]
    fn completed_reason_depends_on_tool_calls() {
        let mut with_tool = StreamDecoder::new();
        let added = tool_added(0, "call_a", "alpha");
        let completed_with_tool = r#"{"type":"response.completed","response":{"status":"completed","output":[{"type":"function_call","call_id":"call_a","name":"alpha","arguments":""}],"usage":{"input_tokens":10,"output_tokens":4,"input_tokens_details":{"cached_tokens":3}}}}"#;
        let events = feed(&mut with_tool, &[&added, completed_with_tool]);
        let usage = UsageCounts {
            input_tokens: 10,
            output_tokens: 4,
            cached_input_tokens: Some(3),
            ..Default::default()
        };
        assert_eq!(
            events[1..],
            [
                StreamEvent::Usage(usage.clone()),
                StreamEvent::Finish {
                    reason: "tool_calls".to_owned()
                },
            ]
        );

        let mut plain = StreamDecoder::new();
        let events = feed(&mut plain, &[COMPLETED]);
        assert_eq!(
            events,
            vec![
                StreamEvent::Usage(usage),
                StreamEvent::Finish {
                    reason: "stop".to_owned()
                },
            ]
        );
        assert_eq!(plain.finish(), Terminal::Completed);
    }

    #[test]
    fn incomplete_and_failed_reasons() {
        let mut length = StreamDecoder::new();
        let events = feed(
            &mut length,
            &[
                r#"{"type":"response.incomplete","response":{"incomplete_details":{"reason":"max_output_tokens"}}}"#,
            ],
        );
        assert_eq!(
            events,
            vec![StreamEvent::Finish {
                reason: "length".to_owned()
            }]
        );
        assert_eq!(length.finish(), Terminal::Incomplete);

        let mut other = StreamDecoder::new();
        let events = feed(
            &mut other,
            &[
                r#"{"type":"response.incomplete","response":{"incomplete_details":{"reason":"content_filter"}}}"#,
            ],
        );
        assert_eq!(
            events,
            vec![StreamEvent::Finish {
                reason: "max_tokens_truncated".to_owned()
            }],
            "content_filter must remain an incomplete terminal, not a successful Chat stop"
        );

        let mut failed = StreamDecoder::new();
        let events = feed(
            &mut failed,
            &[r#"{"type":"response.failed","response":{}}"#],
        );
        // No Finish: the relay's EOF verdict owns failure, not a Chat reason.
        assert!(
            events.is_empty(),
            "failed must not yield a finish: {events:?}"
        );
        let mut cancelled = StreamDecoder::new();
        let events = feed(
            &mut cancelled,
            &[r#"{"type":"response.cancelled","response":{}}"#],
        );
        assert!(
            events.is_empty(),
            "cancelled must not yield a finish: {events:?}"
        );
    }

    #[test]
    fn incomplete_output_item_snapshot_fails() {
        let mut decoder = StreamDecoder::new();
        assert!(decoder.observe_raw(br#"{"type":"response.output_item.done","output_index":0,"item":{"type":"function_call"}}"#).is_err());
    }

    #[test]
    fn incomplete_codex_metadata_fails() {
        let mut decoder = StreamDecoder::new();
        let incomplete_added =
            r#"{"type":"response.output_item.added","item":{"type":"function_call"}}"#;
        assert!(decoder.observe_raw(incomplete_added.as_bytes()).is_err());
        assert!(
            decoder
                .observe_raw(br#"{"type":"response.function_call_arguments.delta","delta":"x"}"#)
                .is_err()
        );
    }

    #[test]
    fn inconsistent_completion_snapshot_fails() {
        let mut decoder = StreamDecoder::new();
        let added = tool_added(0, "call_a", "alpha");
        let events = feed(&mut decoder, &[&added, &args_delta(0, "{\\\"ok\\\":true}")]);
        assert_eq!(events.len(), 2);
        let completion = r#"{"type":"response.function_call_arguments.done","output_index":0,"arguments":"not-the-emitted-prefix"}"#;
        assert!(decoder.observe_raw(completion.as_bytes()).is_err());
    }

    #[test]
    fn arguments_done_without_delta_emits_complete_snapshot() {
        let mut decoder = StreamDecoder::new();
        let added = tool_added(0, "call_a", "alpha");
        let events = feed(&mut decoder, &[&added, &args_done(0, r#"{"x":1}"#)]);
        assert_eq!(
            events,
            vec![
                StreamEvent::ToolCallDelta {
                    index: 0,
                    id: Some("call_a".to_owned()),
                    name: Some("alpha".to_owned()),
                    arguments: String::new(),
                },
                StreamEvent::ToolCallDelta {
                    index: 0,
                    id: None,
                    name: None,
                    arguments: "{\"x\":1}".to_owned(),
                },
            ]
        );
    }

    #[test]
    fn arguments_done_emits_only_snapshot_suffix_after_delta() {
        let mut decoder = StreamDecoder::new();
        let added = tool_added(0, "call_a", "alpha");
        let delta = args_delta(0, r#"{"x""#);
        let events = feed(&mut decoder, &[&added, &delta, &args_done(0, r#"{"x":1}"#)]);
        assert_eq!(
            events,
            vec![
                StreamEvent::ToolCallDelta {
                    index: 0,
                    id: Some("call_a".to_owned()),
                    name: Some("alpha".to_owned()),
                    arguments: String::new(),
                },
                StreamEvent::ToolCallDelta {
                    index: 0,
                    id: None,
                    name: None,
                    arguments: "{\"x\"".to_owned(),
                },
                StreamEvent::ToolCallDelta {
                    index: 0,
                    id: None,
                    name: None,
                    arguments: ":1}".to_owned(),
                },
            ]
        );
    }

    #[test]
    fn repeated_arguments_done_is_idempotent() {
        let mut decoder = StreamDecoder::new();
        let added = tool_added(0, "call_a", "alpha");
        let done =
            r#"{"type":"response.function_call_arguments.done","output_index":0,"arguments":"{}"}"#;
        let events = feed(&mut decoder, &[&added, done, done]);
        assert_eq!(
            events,
            vec![
                StreamEvent::ToolCallDelta {
                    index: 0,
                    id: Some("call_a".to_owned()),
                    name: Some("alpha".to_owned()),
                    arguments: String::new(),
                },
                StreamEvent::ToolCallDelta {
                    index: 0,
                    id: None,
                    name: None,
                    arguments: "{}".to_owned(),
                },
            ]
        );
    }

    #[test]
    fn argument_snapshots_match_interleaved_output_indexes() {
        let mut decoder = StreamDecoder::new();
        let first = tool_added(2, "call_a", "alpha");
        let second = tool_added(7, "call_b", "beta");
        let first_delta = args_delta(2, r#"{"a""#);
        let second_delta = args_delta(7, r#"{"b""#);
        let events = feed(
            &mut decoder,
            &[
                &first,
                &second,
                &first_delta,
                &second_delta,
                &args_done(7, r#"{"b":2}"#),
                &args_done(2, r#"{"a":1}"#),
            ],
        );
        assert_eq!(
            events,
            vec![
                StreamEvent::ToolCallDelta {
                    index: 0,
                    id: Some("call_a".to_owned()),
                    name: Some("alpha".to_owned()),
                    arguments: String::new(),
                },
                StreamEvent::ToolCallDelta {
                    index: 1,
                    id: Some("call_b".to_owned()),
                    name: Some("beta".to_owned()),
                    arguments: String::new(),
                },
                StreamEvent::ToolCallDelta {
                    index: 0,
                    id: None,
                    name: None,
                    arguments: "{\"a\"".to_owned(),
                },
                StreamEvent::ToolCallDelta {
                    index: 1,
                    id: None,
                    name: None,
                    arguments: "{\"b\"".to_owned(),
                },
                StreamEvent::ToolCallDelta {
                    index: 1,
                    id: None,
                    name: None,
                    arguments: ":2}".to_owned(),
                },
                StreamEvent::ToolCallDelta {
                    index: 0,
                    id: None,
                    name: None,
                    arguments: ":1}".to_owned(),
                },
            ]
        );
    }

    #[test]
    fn bad_frames_fail() {
        let mut decoder = StreamDecoder::new();
        assert!(
            decoder.observe_raw(args_delta(9, "x").as_bytes()).is_err(),
            "an argument delta for an unseen slot cannot be reconciled"
        );
        let no_call_id = r#"{"type":"response.output_item.added","output_index":0,"item":{"type":"function_call","name":"n"}}"#;
        assert!(
            decoder
                .observe_raw(no_call_id.as_bytes())
                .expect("missing optional function-call identity is ignored")
                .is_empty()
        );
        decoder
            .observe_raw(
                br#"{"type":"error","error":{"type":"service_unavailable","message":"boom"}}"#,
            )
            .expect("upstream error is a valid terminal event");
        assert!(decoder.upstream_error_event());
        assert_eq!(decoder.finish(), Terminal::Failed);
        assert!(
            decoder
                .observe_raw(b"  ")
                .expect("empty payload is ignored")
                .is_empty()
        );
    }

    #[test]
    fn relay_observation_rejects_invalid_utf8_and_json() {
        let mut decoder = StreamDecoder::new();
        assert_eq!(
            decoder.observe_raw_for_relay(b"\xff"),
            Err(ProtocolError::InvalidUpstreamResponse)
        );
        assert_eq!(
            decoder.observe_raw_for_relay(b"{"),
            Err(ProtocolError::InvalidUpstreamResponse)
        );
    }

    #[test]
    fn diagnostics_classify_decode_failures_without_payload() {
        let mut decoder = StreamDecoder::new();
        decoder.set_payload_log(true);
        assert_eq!(
            decoder.observe_raw_for_relay(b"\xff"),
            Err(ProtocolError::InvalidUpstreamResponse)
        );
        assert_eq!(
            decoder.observe_raw_for_relay(br#"{"type":"response.completed""#),
            Err(ProtocolError::InvalidUpstreamResponse)
        );
        assert_eq!(
            decoder.observe_raw_for_relay(
                br#"{"type":"error","error":{"type":"service_unavailable","message":"boom"}}"#
            ),
            Ok(())
        );
        assert!(decoder.upstream_error_event());
        assert_eq!(decoder.finish(), Terminal::Failed);
    }
    #[test]
    fn relay_observation_is_unchanged() {
        let added = tool_added(0, "call_a", "alpha");
        let args = args_delta(0, "{}");
        let mut relay = StreamDecoder::new();
        relay
            .observe_raw_for_relay(added.as_bytes())
            .expect("added observed");
        assert!(!relay.content_seen(), "item.added is not content");
        relay
            .observe_raw_for_relay(args.as_bytes())
            .expect("delta observed");
        assert!(relay.content_seen(), "*.delta flips content_seen");
        relay
            .observe_raw_for_relay(COMPLETED.as_bytes())
            .expect("terminal observed");
        assert_eq!(relay.finish(), Terminal::Completed);
        assert!(relay.terminal_seen());
        let usage = relay.usage().expect("usage observed");
        assert_eq!((usage.input_tokens, usage.output_tokens), (10, 4));
        assert_eq!(usage.cached_input_tokens, Some(3));
    }
}
