//! IR ↔ OpenAI Responses adapter — only the "Responses as upstream" half.
//!
//! `from_ir` builds a Responses request body from the IR and `response_to_ir`
//! decodes a non-streaming Responses body back into it; the pair serves the
//! `Chat → Responses` hop. The "Responses as client" half lives in
//! `openai_responses.rs`; the two halves run in opposite directions and share
//! no state.
//!
//! Deliberate deviations from the sub2api reference
//! (`chatcompletions_to_responses.go`), recorded in the plan's deviation
//! ledger:
//! - no `store`/`stream`/`include`/`service_tier`: the kernel pins `store` and
//!   the relay injects `stream`; encrypted reasoning is not replayed;
//! - assistant thinking is dropped (recorded), not wrapped in `<thinking>`;
//! - in-history system/developer turns fold into `instructions` (this wire has
//!   no in-history instruction slot, and the Codex backend rejects a `system`
//!   role inside `input`);
//! - output ceiling floor is 16, not 128, and an undeclared ceiling is omitted;
//! - function tools always carry an explicit `strict: false` (Responses
//!   defaults to `true`, Chat to `false`).

use super::Parsed;
use super::ir::{
    Effort, FileSource, ImageSource, IrPart, IrRequest, IrResponse, IrRole, IrStop, IrTool,
    IrToolChoice, NO_DECLARED_LIMIT, SYSTEM_JOIN,
};
use crate::protocol::ProtocolError;
use crate::protocol::usage::UsageCounts;
use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256};
use std::collections::HashMap;
use std::mem;

/// Responses rejects a `max_output_tokens` below this floor.
const MIN_OUTPUT_TOKENS: u64 = 16;

/// Build a Responses request from the IR. `stream` and `store` are left to the
/// relay and the kernel's `prepare`. The product must pass
/// `crate::protocol::openai_responses::validate_request`.
pub fn from_ir(request: &IrRequest, model: &str) -> Parsed<Value> {
    let mut dropped: Vec<&'static str> = Vec::new();
    let mut body = Map::new();
    body.insert("model".to_owned(), Value::String(model.to_owned()));
    // An empty prompt is omitted, not sent as `""`: the upstream treats a
    // missing field as "no instructions". `folded_system` also carries the
    // in-history system/developer turns: a Responses upstream reads
    // instructions from this top-level field alone, and several reject a
    // `system` role inside `input` outright — the ChatGPT Codex backend
    // answers `{"detail":"System messages are not allowed"}`. The Chat emitter
    // folds the same entries (`openai_chat::from_ir`), so both targets see one
    // prompt.
    if let Some(system) = request.folded_system().filter(|text| !text.is_empty()) {
        body.insert("instructions".to_owned(), Value::String(system));
    }
    body.insert(
        "input".to_owned(),
        Value::Array(build_input(request, &mut dropped)?),
    );

    if !request.tools.is_empty() {
        let tools: Vec<Value> = request.tools.iter().map(tool_value).collect();
        body.insert("tools".to_owned(), Value::Array(tools));
        if let Some(choice) = &request.tool_choice {
            body.insert("tool_choice".to_owned(), tool_choice_value(choice));
        }
    }
    if let Some(format) = &request.structured_output {
        let mut text = Map::new();
        text.insert("format".to_owned(), text_format(format));
        body.insert("text".to_owned(), Value::Object(text));
    }
    // `Effort::None` is the relay's to inject (it knows the upstream's off
    // spelling); an absent effort says nothing.
    if let Some(effort) = request.effort
        && !matches!(effort, Effort::None)
    {
        body.insert(
            "reasoning".to_owned(),
            serde_json::json!({"effort": effort.chat_name(), "summary": "auto"}),
        );
    }
    // Reasoning models answer sampling parameters with a 400.
    if !is_reasoning_model(model) {
        if let Some(temperature) = request.temperature {
            body.insert("temperature".to_owned(), serde_json::json!(temperature));
        }
        if let Some(top_p) = request.top_p {
            body.insert("top_p".to_owned(), serde_json::json!(top_p));
        }
    }
    if request.ceiling != NO_DECLARED_LIMIT {
        body.insert(
            "max_output_tokens".to_owned(),
            Value::from(request.ceiling.max(MIN_OUTPUT_TOKENS)),
        );
    }
    if let Some(parallel) = request.parallel_tool_calls {
        body.insert("parallel_tool_calls".to_owned(), Value::Bool(parallel));
    }
    if !request.stop.is_empty() {
        note(&mut dropped, "stop");
    }
    if request.top_k.is_some() {
        note(&mut dropped, "top_k");
    }
    let cache_key = match &request.prompt_cache_key {
        Some(key) => Some(key.clone()),
        None => derive_prompt_cache_key(request, model),
    };
    if let Some(key) = cache_key {
        body.insert("prompt_cache_key".to_owned(), Value::String(key));
    } else {
        note(&mut dropped, "prompt_cache_key");
    }

    let value = Value::Object(body);
    crate::protocol::openai_responses::validate_request(&value)?;
    Ok((value, dropped))
}

/// Record a loss once, however many parts hit it.
fn note(dropped: &mut Vec<&'static str>, reason: &'static str) {
    if !dropped.contains(&reason) {
        dropped.push(reason);
    }
}

/// The `input[]` item list under construction.
///
/// Tool results must follow their call; images a tool returned ride in a
/// following user message (`function_call_output` holds text only).
#[derive(Default)]
struct InputBuilder {
    items: Vec<Value>,
    pending_images: Vec<Value>,
    /// original IR call id -> the id this body emits for the call; results are
    /// routed through it so synthesized ids stay paired with their results.
    call_ids: HashMap<String, String>,
    /// emitted call id -> tool name, for the label on returned images.
    call_names: HashMap<String, String>,
    synthesized: u64,
    paired: std::collections::HashSet<String>,
}

fn build_input(
    request: &IrRequest,
    dropped: &mut Vec<&'static str>,
) -> Result<Vec<Value>, ProtocolError> {
    let mut input = InputBuilder::default();
    for message in &request.messages {
        match message.role {
            IrRole::Assistant => input.assistant(&message.parts, dropped)?,
            IrRole::User => input.user(&message.parts, dropped)?,
            // `from_ir` folds these into `instructions`; this wire has no
            // in-history instruction item.
            IrRole::System | IrRole::Developer => {}
        }
    }
    input.flush_pending_images();
    Ok(input.items)
}

impl InputBuilder {
    fn assistant(
        &mut self,
        parts: &[IrPart],
        dropped: &mut Vec<&'static str>,
    ) -> Result<(), ProtocolError> {
        self.flush_pending_images();
        let mut content: Vec<Value> = Vec::new();
        for part in parts {
            match part {
                IrPart::Text(text) => {
                    if !text.is_empty() {
                        content.push(typed_text("output_text", text));
                    }
                }
                IrPart::ToolCall { id, name, args } => {
                    // Text before a call stays before it.
                    self.flush_message("assistant", &mut content);
                    let arguments = args.to_string();
                    let (ir_id, wire_id) = match id {
                        Some(id) if self.call_ids.contains_key(id) => {
                            return Err(ProtocolError::ToolPairingUnrepresentable);
                        }
                        Some(id) => (id.clone(), id.clone()),
                        None if self.call_ids.contains_key("") => {
                            return Err(ProtocolError::ToolPairingUnrepresentable);
                        }
                        None => {
                            self.synthesized += 1;
                            (
                                String::new(),
                                format!("call_{:016x}{:08x}", self.synthesized, arguments.len()),
                            )
                        }
                    };
                    self.call_names.insert(wire_id.clone(), name.clone());
                    self.items.push(serde_json::json!({
                        "type": "function_call",
                        "call_id": wire_id,
                        "name": name,
                        "arguments": arguments,
                    }));
                    self.call_ids.insert(ir_id, wire_id);
                }
                // The summary is not the real chain of thought and no
                // signature survives the hop; replaying it as text would teach
                // the model to emit the tags.
                IrPart::Thinking { .. } => note(dropped, "thinking"),
                IrPart::Image { .. } | IrPart::File { .. } | IrPart::ToolResult { .. } => {}
            }
        }
        self.flush_message("assistant", &mut content);
        Ok(())
    }

    fn user(
        &mut self,
        parts: &[IrPart],
        dropped: &mut Vec<&'static str>,
    ) -> Result<(), ProtocolError> {
        let mut content: Vec<Value> = Vec::new();
        for part in parts {
            match part {
                IrPart::Text(text) => content.push(typed_text("input_text", text)),
                IrPart::Image { media, source } => content.push(input_image(media, source)),
                IrPart::File { media, source } => {
                    let placeholder = match source {
                        FileSource::Url(url) => format!("[attachment {media}: {url}]"),
                        FileSource::Base64(_) => format!("[attachment {media}]"),
                    };
                    content.push(typed_text("input_text", &placeholder));
                    note(dropped, "file");
                }
                IrPart::ToolResult {
                    call_id,
                    text,
                    images,
                    is_error,
                } => {
                    let Some(wire_id) = self.call_ids.get(call_id) else {
                        return Err(ProtocolError::ToolPairingUnrepresentable);
                    };
                    if !self.paired.insert(call_id.clone()) {
                        return Err(ProtocolError::ToolPairingUnrepresentable);
                    }
                    // Images from the previous result open the user's own
                    // message rather than a second consecutive one.
                    content.append(&mut self.pending_images);
                    let mut output = text.clone();
                    if !images.is_empty() {
                        if !output.trim().is_empty() {
                            output.push_str("\n\n");
                        }
                        output.push_str(if images.len() == 1 {
                            "[The tool returned an image; it follows in the next message.]"
                        } else {
                            "[The tool returned images; they follow in the next message.]"
                        });
                    }
                    let label = match self.call_names.get(wire_id) {
                        Some(name) => format!("[From the result of {name}:]"),
                        None => format!("[From the result of tool call {wire_id}:]"),
                    };
                    self.items.push(serde_json::json!({
                        "type": "function_call_output",
                        "call_id": wire_id,
                        "output": output,
                    }));
                    // Armed only for actual images: a text-only result leaves
                    // nothing pending.
                    if !images.is_empty() {
                        let mut seen = vec![typed_text("input_text", &label)];
                        for image in images {
                            if let IrPart::Image { media, source } = image {
                                seen.push(input_image(media, source));
                            }
                        }
                        self.pending_images = seen;
                    }
                    if *is_error {
                        note(dropped, "tool_result.is_error");
                    }
                }
                IrPart::Thinking { .. } | IrPart::ToolCall { .. } => {}
            }
        }
        // A turn holding nothing but tool results emits no message here; the
        // pending images wait for content or the next assistant turn.
        if !content.is_empty() {
            let mut full = mem::take(&mut self.pending_images);
            full.append(&mut content);
            self.flush_message("user", &mut full);
        }
        Ok(())
    }

    fn flush_pending_images(&mut self) {
        let mut images = mem::take(&mut self.pending_images);
        self.flush_message("user", &mut images);
    }

    /// Emit `content` as one message item and leave it empty; nothing is
    /// emitted for an empty content list.
    fn flush_message(&mut self, role: &'static str, content: &mut Vec<Value>) {
        if content.is_empty() {
            return;
        }
        self.items.push(serde_json::json!({
            "type": "message",
            "role": role,
            "content": mem::take(content),
        }));
    }
}

fn typed_text(kind: &'static str, text: &str) -> Value {
    serde_json::json!({"type": kind, "text": text})
}

fn input_image(media: &str, source: &ImageSource) -> Value {
    let url = match source {
        ImageSource::Url(url) => url.clone(),
        ImageSource::Base64(data) => format!("data:{media};base64,{data}"),
    };
    serde_json::json!({"type": "input_image", "image_url": url})
}

/// Responses function tools default `strict` to true (Chat: false); the
/// explicit `false` keeps the client's semantics.
fn tool_value(tool: &IrTool) -> Value {
    serde_json::json!({
        "type": "function",
        "name": tool.name,
        "description": tool.description,
        "parameters": tool.schema,
        "strict": false,
    })
}

fn tool_choice_value(choice: &IrToolChoice) -> Value {
    match choice {
        IrToolChoice::Auto => Value::String("auto".to_owned()),
        IrToolChoice::None => Value::String("none".to_owned()),
        IrToolChoice::Required => Value::String("required".to_owned()),
        IrToolChoice::Name(name) => serde_json::json!({"type": "function", "name": name}),
    }
}

/// Reverse of the Chat emitter's `response_format` normalization: a nested
/// Chat `json_schema` envelope is flattened into the Responses `text.format`
/// shape; an already-flat format and `json_object` pass through untouched.
fn text_format(format: &Value) -> Value {
    let nested = match format.get("json_schema") {
        Some(envelope) if format.get("type").and_then(Value::as_str) == Some("json_schema") => {
            envelope.get("schema").map(|schema| (envelope, schema))
        }
        _ => None,
    };
    let Some((envelope, schema)) = nested else {
        return format.clone();
    };
    serde_json::json!({
        "type": "json_schema",
        "name": envelope.get("name").cloned().unwrap_or_else(|| Value::String("response".to_owned())),
        "schema": schema,
        "strict": envelope.get("strict").cloned().unwrap_or(Value::Bool(true)),
    })
}

/// `gpt-N…` with N ≥ 5, or `o<digit>…` (o1, o3, o4-mini): the families that
/// refuse `temperature`/`top_p`.
fn is_reasoning_model(model: &str) -> bool {
    let name = model.trim().to_ascii_lowercase();
    if let Some(rest) = name.strip_prefix("gpt-") {
        let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
        return digits.parse::<u32>().is_ok_and(|major| major >= 5);
    }
    name.strip_prefix('o')
        .is_some_and(|rest| rest.starts_with(|c: char| c.is_ascii_digit()))
}

/// A stable cache-routing key for clients that sent none.
///
/// The translation boundary has no upstream account identity: `from_ir` receives
/// only the target model. The generated key is therefore deliberately scoped to
/// Cardinal's target model, not presented as a globally unique account key. The
/// upstream account remains the security/cache boundary, so two accounts may
/// derive the same value without sharing cached prompt data. An explicit client
/// key is preserved separately above and is the client's responsibility.
fn derive_prompt_cache_key(request: &IrRequest, model: &str) -> Option<String> {
    let first_user: String = request
        .messages
        .iter()
        .find(|message| message.role == IrRole::User)
        .map(|message| {
            message
                .parts
                .iter()
                .filter_map(|part| match part {
                    IrPart::Text(text) => Some(text.as_str()),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();
    let system = request.system.as_deref().unwrap_or_default();
    if system.is_empty() && first_user.is_empty() {
        return None;
    }
    let mut hasher = Sha256::new();
    frame(&mut hasher, model);
    frame(&mut hasher, request.effort.map_or("", Effort::chat_name));
    let choice = request.tool_choice.as_ref().map(tool_choice_value);
    frame(
        &mut hasher,
        &choice.map_or_else(String::new, |choice| choice.to_string()),
    );
    for tool in &request.tools {
        frame(&mut hasher, &tool.name);
        frame(&mut hasher, &tool.schema.to_string());
    }
    frame(&mut hasher, system);
    frame(&mut hasher, &first_user);
    // The source position is part of the digest because the folded text alone
    // is not authoritative when an instruction moves relative to other items.
    // The same target-scoped key may occur on two accounts, but account-local
    // upstream cache state prevents cross-account cache reads.
    for (position, message) in request.messages.iter().enumerate() {
        let role = match message.role {
            IrRole::System => Some("system"),
            IrRole::Developer => Some("developer"),
            IrRole::User | IrRole::Assistant => None,
        };
        if let Some(role) = role {
            frame(&mut hasher, role);
            frame(&mut hasher, &position.to_string());
            for part in &message.parts {
                if let IrPart::Text(text) = part {
                    frame(&mut hasher, text);
                }
            }
        }
    }
    let digest = hasher.finalize();
    Some(format!("cardinal_cc_{}", hex::encode(&digest[..16])))
}

fn frame(hasher: &mut Sha256, text: &str) {
    hasher.update((text.len() as u64).to_le_bytes());
    hasher.update(text.as_bytes());
}

/// Decode a non-streaming Responses body into the IR response.
pub fn response_to_ir(
    raw: &[u8],
    _context_window: Option<u64>,
) -> Result<IrResponse, ProtocolError> {
    let body: Value = serde_json::from_slice(raw).map_err(|_| ProtocolError::UpstreamError)?;
    if body.get("error").is_some_and(|error| match error {
        Value::Null => false,
        Value::String(text) => !text.is_empty(),
        Value::Object(fields) => !fields.is_empty(),
        _ => true,
    }) {
        return Err(ProtocolError::UpstreamError);
    }
    let status = body.get("status").and_then(Value::as_str);
    if !matches!(status, Some("completed" | "incomplete")) {
        return Err(ProtocolError::UpstreamError);
    }

    let completed = status == Some("completed");
    let output = body.get("output").and_then(Value::as_array);
    if completed && output.is_none() {
        return Err(ProtocolError::UpstreamError);
    }
    let mut parts: Vec<IrPart> = Vec::new();
    let mut has_call = false;
    for item in output.into_iter().flatten() {
        match item.get("type").and_then(Value::as_str) {
            Some("reasoning") => {
                if completed && item.get("status").and_then(Value::as_str) == Some("incomplete") {
                    return Err(ProtocolError::UpstreamError);
                }
                let Some(summary_items) = item.get("summary").and_then(Value::as_array) else {
                    if completed {
                        return Err(ProtocolError::UpstreamError);
                    }
                    continue;
                };
                let mut summary = Vec::new();
                for entry in summary_items {
                    let Some(text) = entry.get("text").and_then(Value::as_str) else {
                        if completed {
                            return Err(ProtocolError::UpstreamError);
                        }
                        continue;
                    };
                    if !text.is_empty() {
                        summary.push(text);
                    }
                }
                if !summary.is_empty() {
                    parts.push(IrPart::Thinking {
                        text: summary.join(SYSTEM_JOIN),
                    });
                }
            }
            Some("message") => {
                let Some(content) = item.get("content").and_then(Value::as_array) else {
                    if completed {
                        return Err(ProtocolError::UpstreamError);
                    }
                    continue;
                };
                for entry in content {
                    let text = match entry.get("type").and_then(Value::as_str) {
                        Some("output_text") => entry.get("text").and_then(Value::as_str),
                        Some("refusal") => entry.get("refusal").and_then(Value::as_str),
                        _ if completed => return Err(ProtocolError::UpstreamError),
                        _ => continue,
                    };
                    if completed && text.is_none() {
                        return Err(ProtocolError::UpstreamError);
                    }
                    if let Some(text) = text.filter(|text| !text.is_empty()) {
                        parts.push(IrPart::Text(text.to_owned()));
                    }
                }
            }
            Some("function_call") => {
                has_call = true;
                let arguments = item
                    .get("arguments")
                    .and_then(Value::as_str)
                    .filter(|text| !text.trim().is_empty());
                let args: Value = match arguments {
                    Some(text) => {
                        serde_json::from_str(text).map_err(|_| ProtocolError::UpstreamError)?
                    }
                    None => Value::Object(Map::new()),
                };
                let call_id = item
                    .get("call_id")
                    .or_else(|| item.get("id"))
                    .and_then(Value::as_str)
                    .ok_or(ProtocolError::UpstreamError)?;
                parts.push(IrPart::ToolCall {
                    id: Some(call_id.to_owned()),
                    name: item
                        .get("name")
                        .and_then(Value::as_str)
                        .ok_or(ProtocolError::UpstreamError)?
                        .to_owned(),
                    args,
                });
            }
            _ if completed => return Err(ProtocolError::UpstreamError),
            _ => {}
        }
    }

    let stop = match status {
        Some("completed") => {
            if has_call {
                IrStop::ToolUse
            } else {
                IrStop::Stop
            }
        }
        Some("incomplete") => match body
            .pointer("/incomplete_details/reason")
            .and_then(Value::as_str)
        {
            Some("max_output_tokens") => IrStop::Length,
            Some(reason) => IrStop::Other(reason.to_owned()),
            None => IrStop::Other("incomplete".to_owned()),
        },
        _ => IrStop::Other("incomplete".to_owned()),
    };
    Ok(IrResponse {
        model: body
            .get("model")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        content: parts,
        stop,
        usage: body.get("usage").and_then(usage_counts),
    })
}

/// Same reading as the protocol kernel's observer: totals are billable, the
/// cached/reasoning sub-items are evidence only.
fn usage_counts(usage: &Value) -> Option<UsageCounts> {
    Some(UsageCounts {
        input_tokens: usage.get("input_tokens").and_then(Value::as_u64)?,
        output_tokens: usage.get("output_tokens").and_then(Value::as_u64)?,
        cached_input_tokens: usage
            .pointer("/input_tokens_details/cached_tokens")
            .and_then(Value::as_u64),
        reasoning_output_tokens: usage
            .pointer("/output_tokens_details/reasoning_tokens")
            .and_then(Value::as_u64),
        reasoning_tokens_included: usage
            .pointer("/output_tokens_details/reasoning_tokens")
            .and_then(Value::as_u64)
            .map(|_| true),
        ..Default::default()
    })
}
