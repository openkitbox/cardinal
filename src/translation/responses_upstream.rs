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

/// Prefix of a derived `prompt_cache_key`; marks keys this gateway invented.
const CACHE_KEY_PREFIX: &str = "cardinal_cc_";

/// Build a Responses request from the IR. `stream` and `store` are left to the
/// relay and the kernel's `prepare`. The product must pass
/// `crate::protocol::openai_responses::validate_request`.
pub fn from_ir(request: &IrRequest, model: &str) -> Parsed<Value> {
    let mut dropped: Vec<&'static str> = Vec::new();
    let mut body = Map::new();
    body.insert("model".to_owned(), Value::String(model.to_owned()));
    // An empty prompt is omitted, not sent as `""`: the upstream treats a
    // missing field as "no instructions".
    if let Some(system) = request.system.as_deref().filter(|text| !text.is_empty()) {
        body.insert("instructions".to_owned(), Value::String(system.to_owned()));
    }
    body.insert(
        "input".to_owned(),
        Value::Array(build_input(request, &mut dropped)),
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
}

fn build_input(request: &IrRequest, dropped: &mut Vec<&'static str>) -> Vec<Value> {
    let mut input = InputBuilder::default();
    for message in &request.messages {
        match message.role {
            IrRole::Assistant => input.assistant(&message.parts, dropped),
            IrRole::User => input.user(&message.parts, dropped),
        }
    }
    input.flush_pending_images();
    input.items
}

impl InputBuilder {
    fn assistant(&mut self, parts: &[IrPart], dropped: &mut Vec<&'static str>) {
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
                        Some(id) => (id.clone(), id.clone()),
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
    }

    fn user(&mut self, parts: &[IrPart], dropped: &mut Vec<&'static str>) {
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
                        note(dropped, "tool_result.unpaired");
                        continue;
                    };
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

/// A stable cache-routing key for clients that sent none: the same model,
/// effort, tool set, system prompt and opening user turn always land on the
/// same key, so the upstream can reuse the prompt prefix. `None` when there is
/// neither a system prompt nor user text to anchor on.
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
    let digest = hasher.finalize();
    Some(format!("{CACHE_KEY_PREFIX}{}", hex::encode(&digest[..16])))
}

/// Length-framed so adjacent fields can never run together.
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

    let mut parts: Vec<IrPart> = Vec::new();
    let mut has_call = false;
    for item in body
        .get("output")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        match item.get("type").and_then(Value::as_str) {
            Some("reasoning") => {
                let summary: Vec<&str> = item
                    .get("summary")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(|entry| entry.get("text").and_then(Value::as_str))
                    .filter(|text| !text.is_empty())
                    .collect();
                if !summary.is_empty() {
                    parts.push(IrPart::Thinking {
                        text: summary.join(SYSTEM_JOIN),
                    });
                }
            }
            Some("message") => {
                for entry in item
                    .get("content")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    let text = match entry.get("type").and_then(Value::as_str) {
                        Some("output_text") => entry.get("text").and_then(Value::as_str),
                        Some("refusal") => entry.get("refusal").and_then(Value::as_str),
                        _ => None,
                    };
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
            _ => {}
        }
    }

    let stop = if status == Some("completed") {
        if has_call {
            IrStop::ToolUse
        } else {
            IrStop::Stop
        }
    } else {
        match body
            .pointer("/incomplete_details/reason")
            .and_then(Value::as_str)
        {
            Some("max_output_tokens") => IrStop::Length,
            Some(reason) => IrStop::Other(reason.to_owned()),
            None => IrStop::Other("incomplete".to_owned()),
        }
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
        ..Default::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::translation::ir::{IrMessage, IrTool};
    use serde_json::json;

    fn request() -> IrRequest {
        IrRequest {
            system: None,
            messages: Vec::new(),
            tools: Vec::new(),
            tool_choice: None,
            ceiling: NO_DECLARED_LIMIT,
            temperature: None,
            top_p: None,
            top_k: None,
            stop: Vec::new(),
            effort: None,
            parallel_tool_calls: None,
            structured_output: None,
            prompt_cache_key: None,
        }
    }

    fn user(parts: Vec<IrPart>) -> IrMessage {
        IrMessage {
            role: IrRole::User,
            parts,
        }
    }

    fn assistant(parts: Vec<IrPart>) -> IrMessage {
        IrMessage {
            role: IrRole::Assistant,
            parts,
        }
    }

    fn text(value: &str) -> IrPart {
        IrPart::Text(value.to_owned())
    }

    fn tool(name: &str) -> IrTool {
        IrTool {
            name: name.to_owned(),
            description: format!("{name} tool"),
            schema: json!({"type": "object", "properties": {"q": {"type": "string"}}}),
        }
    }

    fn build(request: &IrRequest, model: &str) -> (Value, Vec<&'static str>) {
        from_ir(request, model).expect("request should translate")
    }

    #[test]
    fn system_becomes_instructions_and_empty_system_is_omitted() {
        let mut ir = request();
        ir.messages.push(user(vec![text("hi")]));
        ir.system = Some("be brief".to_owned());
        let (body, _) = build(&ir, "gpt-4o");
        assert_eq!(body["model"], "gpt-4o");
        assert_eq!(body["instructions"], "be brief");

        ir.system = Some(String::new());
        let (body, _) = build(&ir, "gpt-4o");
        assert!(body.get("instructions").is_none(), "{body}");
        ir.system = None;
        let (body, _) = build(&ir, "gpt-4o");
        assert!(body.get("instructions").is_none(), "{body}");
    }

    #[test]
    fn body_never_carries_wire_state_fields() {
        let mut ir = request();
        ir.messages.push(user(vec![text("hi")]));
        let (body, _) = build(&ir, "gpt-4o");
        for field in ["stream", "store", "include", "service_tier"] {
            assert!(body.get(field).is_none(), "{field} leaked: {body}");
        }
    }

    #[test]
    fn user_parts_become_typed_input_items() {
        let mut ir = request();
        ir.messages.push(user(vec![
            text("look"),
            IrPart::Image {
                media: "image/png".to_owned(),
                source: ImageSource::Url("https://x/y.png".to_owned()),
            },
            IrPart::Image {
                media: "image/jpeg".to_owned(),
                source: ImageSource::Base64("QUJD".to_owned()),
            },
        ]));
        let (body, dropped) = build(&ir, "gpt-4o");
        assert_eq!(
            body["input"],
            json!([{"type": "message", "role": "user", "content": [
                {"type": "input_text", "text": "look"},
                {"type": "input_image", "image_url": "https://x/y.png"},
                {"type": "input_image", "image_url": "data:image/jpeg;base64,QUJD"},
            ]}])
        );
        assert!(dropped.is_empty(), "{dropped:?}");
    }

    #[test]
    fn file_degrades_to_a_text_placeholder_and_is_recorded() {
        let mut ir = request();
        ir.messages.push(user(vec![
            IrPart::File {
                media: "application/pdf".to_owned(),
                source: FileSource::Url("https://x/a.pdf".to_owned()),
            },
            IrPart::File {
                media: "application/pdf".to_owned(),
                source: FileSource::Base64("AAAA".to_owned()),
            },
        ]));
        let (body, dropped) = build(&ir, "gpt-4o");
        assert_eq!(
            body["input"][0]["content"],
            json!([
                {"type": "input_text", "text": "[attachment application/pdf: https://x/a.pdf]"},
                {"type": "input_text", "text": "[attachment application/pdf]"},
            ])
        );
        assert_eq!(dropped, vec!["file"]);
    }

    #[test]
    fn assistant_turn_keeps_text_and_call_order() {
        let mut ir = request();
        ir.messages.push(user(vec![text("go")]));
        ir.messages.push(assistant(vec![
            text("before"),
            IrPart::ToolCall {
                id: Some("call_1".to_owned()),
                name: "search".to_owned(),
                args: json!({"q": "rust"}),
            },
            text("after"),
        ]));
        let (body, _) = build(&ir, "gpt-4o");
        assert_eq!(
            body["input"][1],
            json!({"type": "message", "role": "assistant",
                   "content": [{"type": "output_text", "text": "before"}]})
        );
        assert_eq!(body["input"][2]["type"], "function_call");
        assert_eq!(body["input"][2]["call_id"], "call_1");
        assert_eq!(body["input"][2]["name"], "search");
        assert_eq!(body["input"][2]["arguments"], "{\"q\":\"rust\"}");
        assert_eq!(
            body["input"][3],
            json!({"type": "message", "role": "assistant",
                   "content": [{"type": "output_text", "text": "after"}]})
        );
    }

    #[test]
    fn thinking_is_dropped_and_recorded() {
        let mut ir = request();
        ir.messages.push(assistant(vec![
            IrPart::Thinking {
                text: "pondering".to_owned(),
            },
            text("answer"),
        ]));
        let (body, dropped) = build(&ir, "gpt-4o");
        assert!(!body.to_string().contains("pondering"), "{body}");
        assert_eq!(dropped, vec!["thinking"]);
    }

    #[test]
    fn synthesized_call_id_pairs_with_its_result() {
        let mut ir = request();
        ir.messages.push(assistant(vec![IrPart::ToolCall {
            id: None,
            name: "search".to_owned(),
            args: json!({}),
        }]));
        ir.messages.push(user(vec![IrPart::ToolResult {
            call_id: String::new(),
            text: "found".to_owned(),
            images: Vec::new(),
            is_error: false,
        }]));
        let (body, dropped) = build(&ir, "gpt-4o");
        let call = &body["input"][0];
        let output = &body["input"][1];
        assert_eq!(call["type"], "function_call");
        assert_eq!(output["type"], "function_call_output");
        let id = call["call_id"].as_str().expect("call id");
        assert!(id.starts_with("call_"), "{id}");
        assert_eq!(output["call_id"], id);
        assert_eq!(output["output"], "found");
        assert!(dropped.is_empty(), "{dropped:?}");
    }

    #[test]
    fn unpaired_result_is_dropped_and_error_flag_recorded() {
        let mut ir = request();
        ir.messages.push(assistant(vec![IrPart::ToolCall {
            id: Some("c1".to_owned()),
            name: "run".to_owned(),
            args: json!({}),
        }]));
        ir.messages.push(user(vec![
            IrPart::ToolResult {
                call_id: "c1".to_owned(),
                text: "boom".to_owned(),
                images: Vec::new(),
                is_error: true,
            },
            IrPart::ToolResult {
                call_id: "ghost".to_owned(),
                text: "x".to_owned(),
                images: Vec::new(),
                is_error: false,
            },
        ]));
        let (body, dropped) = build(&ir, "gpt-4o");
        let items = body["input"].as_array().expect("input");
        assert_eq!(items.len(), 2, "{body}");
        assert_eq!(items[1]["output"], "boom");
        assert!(dropped.contains(&"tool_result.is_error"), "{dropped:?}");
        assert!(dropped.contains(&"tool_result.unpaired"), "{dropped:?}");
    }

    #[test]
    fn tool_result_images_ride_in_the_following_user_message() {
        let mut ir = request();
        ir.messages.push(assistant(vec![IrPart::ToolCall {
            id: Some("c1".to_owned()),
            name: "shot".to_owned(),
            args: json!({}),
        }]));
        ir.messages.push(user(vec![IrPart::ToolResult {
            call_id: "c1".to_owned(),
            text: "taken".to_owned(),
            images: vec![IrPart::Image {
                media: "image/png".to_owned(),
                source: ImageSource::Base64("QUJD".to_owned()),
            }],
            is_error: false,
        }]));
        let (body, _) = build(&ir, "gpt-4o");
        let items = body["input"].as_array().expect("input");
        assert_eq!(items.len(), 3, "{body}");
        assert_eq!(items[1]["type"], "function_call_output");
        assert!(
            items[1]["output"]
                .as_str()
                .expect("output")
                .starts_with("taken"),
            "{body}"
        );
        assert_eq!(items[2]["role"], "user");
        let content = items[2]["content"].as_array().expect("content");
        assert_eq!(content[0]["type"], "input_text");
        assert_eq!(content[1]["type"], "input_image");
        assert_eq!(content[1]["image_url"], "data:image/png;base64,QUJD");
    }

    #[test]
    fn tools_are_flat_with_explicit_non_strict() {
        let mut ir = request();
        ir.messages.push(user(vec![text("hi")]));
        ir.tools.push(tool("search"));
        let (body, _) = build(&ir, "gpt-4o");
        assert_eq!(
            body["tools"],
            json!([{"type": "function", "name": "search", "description": "search tool",
                    "parameters": {"type": "object", "properties": {"q": {"type": "string"}}},
                    "strict": false}])
        );
    }

    #[test]
    fn tool_choice_maps_each_variant() {
        let mut ir = request();
        ir.messages.push(user(vec![text("hi")]));
        ir.tools.push(tool("search"));
        let cases = [
            (IrToolChoice::Auto, json!("auto")),
            (IrToolChoice::None, json!("none")),
            (IrToolChoice::Required, json!("required")),
            (
                IrToolChoice::Name("search".to_owned()),
                json!({"type": "function", "name": "search"}),
            ),
        ];
        for (choice, expected) in cases {
            ir.tool_choice = Some(choice);
            let (body, _) = build(&ir, "gpt-4o");
            assert_eq!(body["tool_choice"], expected);
        }
    }

    #[test]
    fn structured_output_is_flattened_into_text_format() {
        let mut ir = request();
        ir.messages.push(user(vec![text("hi")]));
        ir.structured_output = Some(json!({"type": "json_schema", "json_schema": {
            "name": "answer", "schema": {"type": "object"}, "strict": false}}));
        let (body, _) = build(&ir, "gpt-4o");
        assert_eq!(
            body["text"],
            json!({"format": {"type": "json_schema", "name": "answer",
                              "schema": {"type": "object"}, "strict": false}})
        );

        // Defaults: strict true, name "response".
        ir.structured_output = Some(json!({"type": "json_schema", "json_schema": {
            "schema": {"type": "object"}}}));
        let (body, _) = build(&ir, "gpt-4o");
        assert_eq!(body["text"]["format"]["name"], "response");
        assert_eq!(body["text"]["format"]["strict"], true);

        // Already flat and json_object pass through untouched.
        let flat = json!({"type": "json_schema", "name": "n", "schema": {}, "strict": true});
        ir.structured_output = Some(flat.clone());
        assert_eq!(build(&ir, "gpt-4o").0["text"]["format"], flat);
        ir.structured_output = Some(json!({"type": "json_object"}));
        assert_eq!(
            build(&ir, "gpt-4o").0["text"]["format"],
            json!({"type": "json_object"})
        );
    }

    #[test]
    fn effort_maps_to_reasoning_with_summary() {
        let mut ir = request();
        ir.messages.push(user(vec![text("hi")]));
        ir.effort = Some(Effort::High);
        let (body, _) = build(&ir, "gpt-5");
        assert_eq!(
            body["reasoning"],
            json!({"effort": "high", "summary": "auto"})
        );

        // Explicit off is the relay's to inject; absent effort sends nothing.
        ir.effort = Some(Effort::None);
        assert!(build(&ir, "gpt-5").0.get("reasoning").is_none());
        ir.effort = None;
        assert!(build(&ir, "gpt-5").0.get("reasoning").is_none());
    }

    #[test]
    fn reasoning_models_get_no_sampling_parameters() {
        let mut ir = request();
        ir.messages.push(user(vec![text("hi")]));
        ir.temperature = Some(0.5);
        ir.top_p = Some(0.9);
        for model in ["gpt-5", "gpt-5.1-codex", " GPT-6 ", "o3", "o4-mini", "o1"] {
            let (body, _) = build(&ir, model);
            assert!(body.get("temperature").is_none(), "{model}: {body}");
            assert!(body.get("top_p").is_none(), "{model}: {body}");
        }
        for model in ["gpt-4o", "gpt-4.1", "gpt-oss-120b", "omni-x", "claude-x"] {
            let (body, _) = build(&ir, model);
            assert_eq!(body["temperature"], 0.5, "{model}");
            assert_eq!(body["top_p"], 0.9, "{model}");
        }
    }

    #[test]
    fn ceiling_is_omitted_when_undeclared_and_floored_at_sixteen() {
        let mut ir = request();
        ir.messages.push(user(vec![text("hi")]));
        assert!(build(&ir, "gpt-4o").0.get("max_output_tokens").is_none());
        ir.ceiling = 4;
        assert_eq!(build(&ir, "gpt-4o").0["max_output_tokens"], 16);
        ir.ceiling = 4096;
        assert_eq!(build(&ir, "gpt-4o").0["max_output_tokens"], 4096);
    }

    #[test]
    fn unsupported_fields_are_recorded_and_parallel_calls_pass_through() {
        let mut ir = request();
        ir.messages.push(user(vec![text("hi")]));
        ir.stop = vec!["END".to_owned()];
        ir.top_k = Some(40);
        ir.parallel_tool_calls = Some(false);
        let (body, dropped) = build(&ir, "gpt-4o");
        assert_eq!(body["parallel_tool_calls"], false);
        assert!(body.get("stop").is_none() && body.get("top_k").is_none());
        assert!(
            dropped.contains(&"stop") && dropped.contains(&"top_k"),
            "{dropped:?}"
        );
    }

    #[test]
    fn prompt_cache_key_is_client_supplied_or_derived() {
        let mut ir = request();
        ir.system = Some("sys".to_owned());
        ir.messages.push(user(vec![text("hello")]));
        ir.tools.push(tool("search"));

        let (first, _) = build(&ir, "gpt-4o");
        let (second, _) = build(&ir, "gpt-4o");
        let key = first["prompt_cache_key"].as_str().expect("derived key");
        assert_eq!(second["prompt_cache_key"], key, "same input, same key");
        assert!(key.starts_with("cardinal_cc_"), "{key}");
        assert_eq!(key.len(), "cardinal_cc_".len() + 32, "{key}");

        ir.tools.push(tool("fetch"));
        let (other_tools, _) = build(&ir, "gpt-4o");
        assert_ne!(other_tools["prompt_cache_key"], key);
        let (other_model, _) = build(&ir, "gpt-5");
        assert_ne!(
            other_model["prompt_cache_key"],
            other_tools["prompt_cache_key"]
        );

        ir.prompt_cache_key = Some("client-key".to_owned());
        assert_eq!(build(&ir, "gpt-4o").0["prompt_cache_key"], "client-key");
    }

    #[test]
    fn prompt_cache_key_needs_a_system_or_user_text() {
        let mut ir = request();
        ir.tools.push(tool("search"));
        ir.messages.push(assistant(vec![text("only assistant")]));
        assert!(derive_prompt_cache_key(&ir, "gpt-4o").is_none());
        ir.system = Some("sys".to_owned());
        assert!(derive_prompt_cache_key(&ir, "gpt-4o").is_some());
    }

    fn response_bytes(value: &Value) -> Vec<u8> {
        serde_json::to_vec(value).expect("serialize")
    }

    #[test]
    fn response_decodes_reasoning_message_and_function_call_in_order() {
        let raw = response_bytes(&json!({
            "status": "completed", "model": "gpt-5-2025",
            "output": [
                {"type": "reasoning", "summary": [
                    {"type": "summary_text", "text": "first"},
                    {"type": "summary_text", "text": "second"}]},
                {"type": "message", "role": "assistant", "content": [
                    {"type": "output_text", "text": "hello"},
                    {"type": "refusal", "refusal": "no"}]},
                {"type": "function_call", "call_id": "call_9", "name": "search",
                 "arguments": "{\"q\":\"x\"}"},
            ],
            "usage": {"input_tokens": 10, "output_tokens": 5,
                      "input_tokens_details": {"cached_tokens": 4},
                      "output_tokens_details": {"reasoning_tokens": 2}},
        }));
        let response = response_to_ir(&raw, None).expect("decode");
        assert_eq!(response.model, "gpt-5-2025");
        assert_eq!(
            response.content,
            vec![
                IrPart::Thinking {
                    text: "first\n\nsecond".to_owned()
                },
                text("hello"),
                text("no"),
                IrPart::ToolCall {
                    id: Some("call_9".to_owned()),
                    name: "search".to_owned(),
                    args: json!({"q": "x"}),
                },
            ]
        );
        assert_eq!(response.stop, IrStop::ToolUse);
        let usage = response.usage.expect("usage");
        assert_eq!(usage.input_tokens, 10);
        assert_eq!(usage.output_tokens, 5);
        assert_eq!(usage.cached_input_tokens, Some(4));
        assert_eq!(usage.reasoning_output_tokens, Some(2));
    }

    #[test]
    fn response_completed_text_only_is_stop_and_empty_arguments_are_an_object() {
        let raw = response_bytes(&json!({
            "status": "completed",
            "output": [{"type": "message", "content": [{"type": "output_text", "text": "ok"}]}],
        }));
        let response = response_to_ir(&raw, None).expect("decode");
        assert_eq!(response.stop, IrStop::Stop);
        assert_eq!(response.model, "");
        assert!(response.usage.is_none());

        let raw = response_bytes(&json!({
            "status": "completed",
            "output": [{"type": "function_call", "call_id": "c", "name": "n", "arguments": ""}],
        }));
        let response = response_to_ir(&raw, None).expect("decode");
        assert_eq!(
            response.content,
            vec![IrPart::ToolCall {
                id: Some("c".to_owned()),
                name: "n".to_owned(),
                args: json!({}),
            }]
        );
    }

    #[test]
    fn response_incomplete_maps_to_length_or_other() {
        let length = response_bytes(&json!({
            "status": "incomplete", "incomplete_details": {"reason": "max_output_tokens"},
            "output": [],
        }));
        assert_eq!(
            response_to_ir(&length, None).expect("decode").stop,
            IrStop::Length
        );
        let filter = response_bytes(&json!({
            "status": "incomplete", "incomplete_details": {"reason": "content_filter"},
            "output": [],
        }));
        assert_eq!(
            response_to_ir(&filter, None).expect("decode").stop,
            IrStop::Other("content_filter".to_owned())
        );
    }

    #[test]
    fn response_failures_are_upstream_errors() {
        let cases = [
            json!({"status": "failed", "output": []}),
            json!({"output": []}),
            json!({"status": "completed", "error": {"message": "x"}, "output": []}),
            json!({"status": "completed", "output": [
                {"type": "function_call", "call_id": "c", "name": "n", "arguments": "{oops"}]}),
        ];
        for case in cases {
            let outcome = response_to_ir(&response_bytes(&case), None);
            assert!(
                matches!(outcome, Err(ProtocolError::UpstreamError)),
                "{case}: {outcome:?}"
            );
        }
        assert!(matches!(
            response_to_ir(b"not json", None),
            Err(ProtocolError::UpstreamError)
        ));
    }
}
