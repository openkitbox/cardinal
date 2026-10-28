//! `openai_chat` ↔ IR adapter.
//!
//! Parse (`to_ir`) reads a Chat Completions envelope into the IR, dropping
//! concepts no translated hop can carry. Emit (`from_ir`) rebuilds a Chat
//! envelope whose product must pass the kernel's own `validate_request`
//! (the composition gate).

use super::ir::{
    Effort, FileSource, ImageSource, IrMessage, IrPart, IrRequest, IrRole, IrStop, IrTool,
    IrToolChoice,
};
use crate::protocol::ProtocolError;
use serde_json::{Map, Value};

const DROPPED_FIELDS: &[&str] = &[
    "logprobs",
    "top_logprobs",
    "seed",
    "service_tier",
    "presence_penalty",
    "frequency_penalty",
    "n",
];

/// Parse a validated Chat request body into the IR.
pub fn to_ir(body: &Value, ceiling: u64) -> Result<(IrRequest, Vec<&'static str>), ProtocolError> {
    let object = body.as_object().ok_or(ProtocolError::InvalidRequest)?;
    let mut dropped: Vec<&'static str> = DROPPED_FIELDS
        .iter()
        .filter(|field| object.contains_key(**field))
        .copied()
        .collect();

    let mut system: Vec<String> = Vec::new();
    let mut messages: Vec<IrMessage> = Vec::new();
    let raw_messages = object
        .get("messages")
        .and_then(Value::as_array)
        .ok_or(ProtocolError::InvalidRequest)?;
    for message in raw_messages {
        let role = message
            .get("role")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let content = message.get("content");
        match role {
            "system" | "developer" => {
                if let Some(text) = content.and_then(string_or_text) {
                    system.push(text);
                }
            }
            "user" => {
                messages.push(IrMessage {
                    role: IrRole::User,
                    parts: content.map_or_else(Vec::new, chat_parts),
                });
            }
            "assistant" => {
                let mut parts: Vec<IrPart> = Vec::new();
                // DeepSeek-style `reasoning_content` or OpenRouter-style `reasoning`.
                if let Some(reasoning) = message
                    .get("reasoning_content")
                    .and_then(Value::as_str)
                    .or_else(|| message.get("reasoning").and_then(Value::as_str))
                    && !reasoning.is_empty()
                {
                    parts.push(IrPart::Thinking {
                        text: reasoning.to_owned(),
                    });
                }
                parts.extend(content.map_or_else(Vec::new, chat_parts));
                for call in message
                    .get("tool_calls")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    let function = call
                        .get("function")
                        .cloned()
                        .unwrap_or_else(|| Value::Object(Map::new()));
                    let name = function
                        .get("name")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned();
                    if name.is_empty() {
                        continue;
                    }
                    parts.push(IrPart::ToolCall {
                        id: call
                            .get("id")
                            .and_then(Value::as_str)
                            .map(str::to_owned)
                            .filter(|id| !id.is_empty()),
                        name,
                        args: parse_args(function.get("arguments")),
                    });
                }
                messages.push(IrMessage {
                    role: IrRole::Assistant,
                    parts,
                });
            }
            "tool" => {
                let call_id = message
                    .get("tool_call_id")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned();
                let content = content
                    .cloned()
                    .unwrap_or_else(|| Value::String(String::new()));
                let (text, images) = tool_output(&content);
                messages.push(IrMessage {
                    role: IrRole::User,
                    parts: vec![IrPart::ToolResult {
                        call_id,
                        text,
                        images,
                        is_error: false,
                    }],
                });
            }
            _ => return Err(ProtocolError::InvalidRequest),
        }
    }

    let tools = object
        .get("tools")
        .and_then(Value::as_array)
        .map(|tools| {
            tools
                .iter()
                .filter(|tool| {
                    let kind = tool.get("type").and_then(Value::as_str);
                    let kept = kind.is_none_or(|kind| kind.is_empty() || kind == "function");
                    if !kept {
                        dropped.push("tool_type");
                    }
                    kept
                })
                .filter_map(|tool| {
                    let function = tool.get("function")?;
                    let name = function.get("name").and_then(Value::as_str)?;
                    Some(IrTool {
                        name: name.to_owned(),
                        description: function
                            .get("description")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_owned(),
                        schema: function
                            .get("parameters")
                            .cloned()
                            .unwrap_or_else(|| Value::Object(Map::new())),
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let tool_choice = match object.get("tool_choice") {
        Some(Value::String(choice)) => match choice.as_str() {
            "auto" => Some(IrToolChoice::Auto),
            "none" => Some(IrToolChoice::None),
            "required" => Some(IrToolChoice::Required),
            _ => None,
        },
        Some(Value::Object(choice)) => choice
            .get("function")
            .and_then(|function| function.get("name"))
            .and_then(Value::as_str)
            .filter(|name| !name.is_empty())
            .map(|name| IrToolChoice::Name(name.to_owned())),
        _ => None,
    };

    let effort = object
        .get("reasoning_effort")
        .and_then(Value::as_str)
        .and_then(Effort::parse_name);
    // The upstream cache-routing hint rides the IR; Kiro derives its
    // conversation id from it. A present-but-unusable value is a recorded loss,
    // never a claimed hint.
    let prompt_cache_key = super::ir::prompt_cache_key_of(object);
    if prompt_cache_key.is_none() && object.contains_key("prompt_cache_key") {
        dropped.push("prompt_cache_key");
    }
    let mut stop = Vec::new();
    match object.get("stop") {
        Some(Value::String(text)) if !text.is_empty() => stop.push(text.clone()),
        Some(Value::Array(items)) => {
            stop.extend(
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .filter(|text| !text.is_empty())
                    .map(str::to_owned),
            );
        }
        _ => {}
    }

    // The client's declared output limit lowers the caller-supplied ceiling
    // reservation; it never raises it. Both chat spellings count.
    let ceiling = object
        .get("max_tokens")
        .and_then(Value::as_u64)
        .or_else(|| object.get("max_completion_tokens").and_then(Value::as_u64))
        .map_or(ceiling, |limit| limit.min(ceiling));

    Ok((
        IrRequest {
            system: if system.is_empty() {
                None
            } else {
                Some(system.join(super::ir::SYSTEM_JOIN))
            },
            messages,
            tools,
            tool_choice,
            ceiling,
            temperature: object.get("temperature").and_then(Value::as_f64),
            top_p: object.get("top_p").and_then(Value::as_f64),
            top_k: None,
            stop,
            effort,
            parallel_tool_calls: object.get("parallel_tool_calls").and_then(Value::as_bool),
            structured_output: object.get("response_format").cloned(),
            prompt_cache_key,
        },
        dropped,
    ))
}

/// Rebuild a Chat envelope from the IR. `model` is left to the kernel's
/// `prepare`; `stream` is the pipeline's concern. The product must pass
/// `crate::protocol::openai_chat::validate_request`.
pub fn from_ir(
    request: &IrRequest,
    model: &str,
) -> Result<(Value, Vec<&'static str>), ProtocolError> {
    // DeepSeek requires the thinking of a tool-calling assistant turn to be
    // replayed as `reasoning_content` (an unsigned-thinking upstream answers a
    // missing one with HTTP 400 — misread as a pairing bug). So Thinking is
    // always kept here; vendors that ignore the field do no harm with it.
    let mut dropped: Vec<&'static str> = Vec::new();
    // No Chat-family upstream consumes the cache-routing hint; record the loss
    // instead of emitting a field the target never asked for.
    if request.prompt_cache_key.is_some() {
        dropped.push("prompt_cache_key");
    }
    let mut messages: Vec<Value> = Vec::new();
    // Tool results must follow their call's assistant turn; images a tool
    // returned ride in a following user message (Chat tool messages hold text).
    let mut pending_images: Vec<Value> = Vec::new();
    let mut call_names: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    // original IR call id -> the id this body emits for the call; results are
    // routed through it so synthesized ids stay paired with their results.
    let mut call_ids: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut synthesized = 0u64;
    for message in &request.messages {
        match message.role {
            IrRole::Assistant => {
                if !pending_images.is_empty() {
                    let mut image_parts = vec![
                        serde_json::json!({"type": "text", "text": "[From the previous tool result:]"}),
                    ];
                    image_parts.append(&mut pending_images);
                    messages.push(serde_json::json!({"role": "user", "content": image_parts}));
                }
                let mut calls: Vec<Value> = Vec::new();
                let mut text = String::new();
                let mut reasoning = String::new();
                for part in &message.parts {
                    match part {
                        IrPart::ToolCall { id, name, args } => {
                            let ir_id = id.clone().unwrap_or_default();
                            let id = match id {
                                Some(id) => id.clone(),
                                None => {
                                    synthesized += 1;
                                    format!("call_{synthesized:016x}{:08x}", args.to_string().len())
                                }
                            };
                            call_names.insert(id.clone(), name.clone());
                            call_ids.insert(ir_id, id.clone());
                            calls.push(serde_json::json!({"id": id, "type": "function", "function": {"name": name, "arguments": args.to_string()}}));
                        }
                        // DeepSeek requires reasoning_content replay when tools
                        // are present; other vendors ignore the field.
                        IrPart::Thinking { text: thinking } => reasoning.push_str(thinking),
                        IrPart::Text(value) => text.push_str(value),
                        _ => {}
                    }
                }
                let mut entry = Map::new();
                entry.insert("role".to_owned(), Value::String("assistant".to_owned()));
                entry.insert("content".to_owned(), Value::String(text));
                if !reasoning.is_empty() {
                    entry.insert("reasoning_content".to_owned(), Value::String(reasoning));
                }
                if !calls.is_empty() {
                    entry.insert("tool_calls".to_owned(), Value::Array(calls));
                }
                messages.push(Value::Object(entry));
            }
            IrRole::User => {
                let mut content: Vec<Value> = Vec::new();
                for part in &message.parts {
                    match part {
                        IrPart::Text(value) => {
                            content.push(serde_json::json!({"type": "text", "text": value}))
                        }
                        IrPart::Image { media, source } => {
                            let url = match source {
                                ImageSource::Url(url) => url.clone(),
                                ImageSource::Base64(data) => format!("data:{media};base64,{data}"),
                            };
                            content.push(
                                serde_json::json!({"type": "image_url", "image_url": {"url": url}}),
                            );
                        }
                        IrPart::File { media, source } => {
                            let where_at = match source {
                                FileSource::Url(url) => format!("[attachment {media}: {url}]"),
                                FileSource::Base64(_) => format!("[attachment {media}]"),
                            };
                            content.push(serde_json::json!({"type": "text", "text": where_at}));
                        }
                        IrPart::ToolResult {
                            call_id,
                            text,
                            images,
                            is_error,
                        } => {
                            let Some(wire_id) = call_ids.get(call_id).cloned() else {
                                dropped.push("tool_result.unpaired");
                                continue;
                            };
                            let call_id = wire_id.as_str();
                            if !pending_images.is_empty() {
                                let mut image_parts = vec![
                                    serde_json::json!({"type": "text", "text": "[From the previous tool result:]"}),
                                ];
                                image_parts.append(&mut pending_images);
                                content.append(&mut image_parts);
                            }
                            let mut out = text.clone();
                            if !images.is_empty() {
                                if !out.trim().is_empty() {
                                    out.push_str("\n\n");
                                }
                                out.push_str(if images.len() == 1 {
                                    "[The tool returned an image; it follows in the next message.]"
                                } else {
                                    "[The tool returned images; they follow in the next message.]"
                                });
                            }
                            let of = call_names
                                .get(call_id)
                                .cloned()
                                .unwrap_or_else(|| format!("tool call {call_id}"));
                            messages.push(serde_json::json!({"role": "tool", "tool_call_id": call_id, "content": out}));
                            let mut seen = vec![
                                serde_json::json!({"type": "text", "text": format!("[From the result of {of}:]")}),
                            ];
                            for image in images {
                                if let IrPart::Image { media, source } = image {
                                    let url = match source {
                                        ImageSource::Url(url) => url.clone(),
                                        ImageSource::Base64(data) => {
                                            format!("data:{media};base64,{data}")
                                        }
                                    };
                                    seen.push(serde_json::json!({"type": "image_url", "image_url": {"url": url}}));
                                }
                            }
                            // Image gating arms only for actual images: a text-only
                            // result leaves nothing pending (a bare marker would inject a
                            // type-less array element GLM refuses outright).
                            pending_images = if images.is_empty() { Vec::new() } else { seen };
                            if *is_error {
                                dropped.push("tool_result.is_error");
                            }
                        }
                        IrPart::Thinking { .. } | IrPart::ToolCall { .. } => {}
                    }
                }
                // Images a tool returned open the user's own next
                // message (some chat templates turn away two user messages in a
                // row); a turn holding nothing but tool results emits nothing here —
                // the pending images wait for content or the next assistant turn.
                let plain = pending_images.is_empty()
                    && content
                        .iter()
                        .all(|part| part.get("type").and_then(Value::as_str) == Some("text"));
                if plain && !content.is_empty() {
                    let joined = content
                        .iter()
                        .filter_map(|part| part.get("text").and_then(Value::as_str))
                        .collect::<String>();
                    messages.push(serde_json::json!({"role": "user", "content": joined}));
                } else if !content.is_empty() {
                    let mut full = std::mem::take(&mut pending_images);
                    full.append(&mut content);
                    messages.push(serde_json::json!({"role": "user", "content": full}));
                }
            }
        }
    }
    if !pending_images.is_empty() {
        messages.push(serde_json::json!({"role": "user", "content": pending_images}));
    }
    dropped.dedup();

    let mut body = Map::new();
    body.insert("model".to_owned(), Value::String(model.to_owned()));
    body.insert("messages".to_owned(), Value::Array(messages));
    if let Some(system) = &request.system {
        let mut system_entry = Map::new();
        system_entry.insert("role".to_owned(), Value::String("system".to_owned()));
        system_entry.insert("content".to_owned(), Value::String(system.clone()));
        if let Some(Value::Array(items)) = body.get_mut("messages") {
            items.insert(0, Value::Object(system_entry));
        }
    }
    // max_tokens is optional on the chat wire: with no declared client limit,
    // omit it and let the vendor default apply (some vendors reject absurd
    // values — DeepSeek answers u64::MAX with a 422).
    if request.ceiling != crate::translation::ir::NO_DECLARED_LIMIT {
        body.insert("max_tokens".to_owned(), Value::from(request.ceiling));
    }
    if let Some(temperature) = request.temperature {
        body.insert("temperature".to_owned(), serde_json::json!(temperature));
    }
    if let Some(top_p) = request.top_p {
        body.insert("top_p".to_owned(), serde_json::json!(top_p));
    }
    if !request.stop.is_empty() {
        body.insert("stop".to_owned(), serde_json::json!(request.stop));
    }
    if let Some(effort) = request.effort
        && !matches!(effort, Effort::None)
    {
        body.insert(
            "reasoning_effort".to_owned(),
            Value::String(effort.chat_name().to_owned()),
        );
    }
    if let Some(parallel) = request.parallel_tool_calls {
        body.insert("parallel_tool_calls".to_owned(), Value::Bool(parallel));
    }
    if let Some(format) = &request.structured_output {
        // SH-07: the IR carries the source envelope. A Responses-shaped flat
        // format (type/name/schema/strict side by side) is rebuilt as the nested
        // chat envelope; a chat envelope passes through untouched.
        let normalized = if format.get("type").and_then(Value::as_str) == Some("json_schema")
            && format.get("schema").is_some()
            && format.get("json_schema").is_none()
        {
            serde_json::json!({
              "type": "json_schema",
              "json_schema": {
                "name": format.get("name").cloned().unwrap_or(Value::String("response".to_owned())),
                "schema": format["schema"].clone(),
                "strict": format.get("strict").cloned().unwrap_or(Value::Bool(true)),
              }
            })
        } else {
            format.clone()
        };
        body.insert("response_format".to_owned(), normalized);
    }
    if !request.tools.is_empty() {
        let tools = request
            .tools
            .iter()
            .map(|tool| {
                serde_json::json!({"type": "function", "function": {
                  "name": tool.name, "description": tool.description, "parameters": tool.schema,
                }})
            })
            .collect::<Vec<_>>();
        body.insert("tools".to_owned(), Value::Array(tools));
        if let Some(choice) = &request.tool_choice {
            let choice = match choice {
                IrToolChoice::Auto => Value::String("auto".to_owned()),
                IrToolChoice::None => Value::String("none".to_owned()),
                IrToolChoice::Required => Value::String("required".to_owned()),
                IrToolChoice::Name(name) => {
                    serde_json::json!({"type": "function", "function": {"name": name}})
                }
            };
            body.insert("tool_choice".to_owned(), choice);
        }
    }
    let value = Value::Object(body);
    crate::protocol::openai_chat::validate_request(&value)?;
    Ok((value, dropped))
}

/// Parse an upstream `chat.completion` body into the IR response.
pub fn response_to_ir(
    raw: &[u8],
    _context_window: Option<u64>,
) -> Result<super::ir::IrResponse, ProtocolError> {
    let body: Value = serde_json::from_slice(raw).map_err(|_| ProtocolError::UpstreamError)?;
    let choice = body
        .get("choices")
        .and_then(Value::as_array)
        .and_then(|choices| choices.first())
        .ok_or(ProtocolError::UpstreamError)?;
    let message = choice.get("message").ok_or(ProtocolError::UpstreamError)?;
    let mut parts = Vec::new();
    // DeepSeek-style `reasoning_content` or OpenRouter-style `reasoning`.
    if let Some(reasoning) = message
        .get("reasoning_content")
        .and_then(Value::as_str)
        .or_else(|| message.get("reasoning").and_then(Value::as_str))
    {
        parts.push(IrPart::Thinking {
            text: reasoning.to_owned(),
        });
    }
    if let Some(text) = message
        .get("content")
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
    {
        parts.push(IrPart::Text(text.to_owned()));
    }
    for call in message
        .get("tool_calls")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let function = call.get("function").ok_or(ProtocolError::UpstreamError)?;
        let arguments = function
            .get("arguments")
            .and_then(Value::as_str)
            .unwrap_or("{}");
        let arguments: Value =
            serde_json::from_str(arguments).map_err(|_| ProtocolError::UpstreamError)?;
        parts.push(IrPart::ToolCall {
            id: Some(
                call.get("id")
                    .and_then(Value::as_str)
                    .ok_or(ProtocolError::UpstreamError)?
                    .to_owned(),
            ),
            name: function
                .get("name")
                .and_then(Value::as_str)
                .ok_or(ProtocolError::UpstreamError)?
                .to_owned(),
            args: arguments,
        });
    }
    Ok(super::ir::IrResponse {
        model: body
            .get("model")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        content: parts,
        stop: stop_from_chat(choice.get("finish_reason").and_then(Value::as_str)),
        usage: usage_from_chat(body.get("usage")),
    })
}

/// Rebuild a Chat response body from the parsed IR response.
///
/// A source that reported no token usage (`usage: None`, e.g. Kiro) yields a
/// body without a `usage` object at all: three fabricated zeroes would be read
/// as a free request and mis-bill it.
pub fn emit_response_json(response: &super::ir::IrResponse) -> Result<Vec<u8>, ProtocolError> {
    let mut content: Option<String> = None;
    let mut calls: Vec<Value> = Vec::new();
    let mut reasoning = String::new();
    for (index, part) in response.content.iter().enumerate() {
        match part {
            IrPart::Text(text) => {
                let slot = content.get_or_insert_with(String::new);
                slot.push_str(text);
            }
            IrPart::Thinking { text } => reasoning.push_str(text),
            IrPart::ToolCall { id, name, args } => {
                let id = id.clone().unwrap_or_else(|| {
                    format!("call_{:016x}", index as u64 + args.to_string().len() as u64)
                });
                calls.push(serde_json::json!({"id": id, "type": "function", "function": {"name": name, "arguments": args.to_string()}}));
            }
            _ => {}
        }
    }
    let mut message = Map::new();
    message.insert("role".to_owned(), Value::String("assistant".to_owned()));
    message.insert(
        "content".to_owned(),
        content.map(Value::String).unwrap_or(Value::Null),
    );
    if !calls.is_empty() {
        message.insert("tool_calls".to_owned(), Value::Array(calls));
    }
    if !reasoning.is_empty() {
        message.insert("reasoning_content".to_owned(), Value::String(reasoning));
    }
    let finish_reason = match &response.stop {
        IrStop::Length => "length",
        IrStop::ToolUse => "tool_calls",
        // A content filter must not read as a natural stop; other dialect-specific
        // reasons keep collapsing to it (there is no richer wire value).
        IrStop::Stop => "stop",
        IrStop::Other(reason) if reason == "content_filter" => "content_filter",
        IrStop::Other(_) => "stop",
    };
    let mut body = serde_json::json!({
      "id": format!("chatcmpl-{:032x}", chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default().unsigned_abs()),
      "object": "chat.completion",
      "created": chrono::Utc::now().timestamp(),
      "model": response.model,
      "choices": [{"index": 0, "message": Value::Object(message), "finish_reason": finish_reason}],
    });
    if let Some(usage) = &response.usage {
        body["usage"] = usage_to_chat(usage);
    }
    serde_json::to_vec(&body).map_err(|_| ProtocolError::InvalidUpstreamResponse)
}

/// Chat usage wire shape from `UsageCounts`.
pub(crate) fn usage_to_chat(usage: &crate::protocol::usage::UsageCounts) -> Value {
    serde_json::json!({
      "prompt_tokens": usage.input_tokens,
      "completion_tokens": usage.output_tokens,
      "total_tokens": usage.input_tokens.saturating_add(usage.output_tokens),
      "prompt_tokens_details": {"cached_tokens": usage.cached_input_tokens.unwrap_or(0)},
      "completion_tokens_details": {"reasoning_tokens": usage.reasoning_output_tokens.unwrap_or(0)},
    })
}

/// Chat `finish_reason` back into the IR stop concept.
pub(crate) fn stop_from_chat(finish: Option<&str>) -> IrStop {
    match finish {
        Some("stop") | None => IrStop::Stop,
        Some("length") => IrStop::Length,
        Some("tool_calls" | "function_call") => IrStop::ToolUse,
        Some(reason) => IrStop::Other(reason.to_owned()),
    }
}

/// Inverse of [`usage_to_chat`] for an upstream Chat usage object.
pub(crate) fn usage_from_chat(
    usage: Option<&Value>,
) -> Option<crate::protocol::usage::UsageCounts> {
    let usage = usage?;
    let cached = usage
        .pointer("/prompt_tokens_details/cached_tokens")
        .and_then(Value::as_u64);
    let reasoning = usage
        .pointer("/completion_tokens_details/reasoning_tokens")
        .and_then(Value::as_u64);
    Some(crate::protocol::usage::UsageCounts {
        input_tokens: usage
            .get("prompt_tokens")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        output_tokens: usage
            .get("completion_tokens")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        calls: 0,
        cached_input_tokens: cached,
        cache_creation_input_tokens: None,
        cache_creation_1h_input_tokens: None,
        reasoning_output_tokens: reasoning,
        thought_output_tokens: None,
        tool_prompt_tokens: None,
        tool_use_tokens: None,
    })
}

/// Read a Chat content value: string or part array.
fn chat_parts(content: &Value) -> Vec<IrPart> {
    if let Some(text) = content.as_str() {
        return if text.is_empty() {
            Vec::new()
        } else {
            vec![IrPart::Text(text.to_owned())]
        };
    }
    let Some(items) = content.as_array() else {
        return Vec::new();
    };
    items
        .iter()
        .filter_map(|item| match item.get("type").and_then(Value::as_str) {
            Some("text") => item
                .get("text")
                .and_then(Value::as_str)
                .map(|text| IrPart::Text(text.to_owned())),
            Some("image_url") => {
                let url = item.get("image_url").and_then(|image| {
                    image
                        .as_str()
                        .map(str::to_owned)
                        .or_else(|| image.get("url").and_then(Value::as_str).map(str::to_owned))
                })?;
                Some(image_part(&url))
            }
            _ => None,
        })
        .collect()
}

/// Split a data URL into inline bytes, or keep the URL.
pub(crate) fn image_part(url: &str) -> IrPart {
    if let Some(rest) = url.strip_prefix("data:")
        && let Some((meta, data)) = rest.split_once(',')
    {
        return IrPart::Image {
            media: meta.trim_end_matches(";base64").to_owned(),
            source: ImageSource::Base64(data.to_owned()),
        };
    }
    IrPart::Image {
        media: String::new(),
        source: ImageSource::Url(url.to_owned()),
    }
}

/// Read a tool result: text plus any images beside it.
fn tool_output(content: &Value) -> (String, Vec<IrPart>) {
    let Some(text) = string_or_text(content) else {
        return (String::new(), Vec::new());
    };
    let mut images = Vec::new();
    for item in content.as_array().into_iter().flatten() {
        if item.get("type").and_then(Value::as_str) == Some("image_url")
            && let Some(url) = item.get("image_url").and_then(|image| {
                image
                    .as_str()
                    .map(str::to_owned)
                    .or_else(|| image.get("url").and_then(Value::as_str).map(str::to_owned))
            })
        {
            images.push(image_part(&url));
        }
    }
    (text, images)
}

/// Read a JSON value that is either a string or an array of text blocks.
fn string_or_text(value: &Value) -> Option<String> {
    if let Some(text) = value.as_str() {
        return Some(text.to_owned());
    }
    let mut out = String::new();
    for item in value.as_array()? {
        if matches!(
            item.get("type").and_then(Value::as_str),
            Some("text" | "input_text" | "output_text")
        ) {
            out.push_str(item.get("text").and_then(Value::as_str).unwrap_or_default());
        }
    }
    Some(out)
}

/// Tool arguments: an object when parseable, otherwise wrapped so nothing is
/// lost.
pub(super) fn parse_args(arguments: Option<&Value>) -> Value {
    let Some(raw) = arguments.and_then(Value::as_str) else {
        return serde_json::json!({});
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return serde_json::json!({});
    }
    if let Ok(value) = serde_json::from_str::<Value>(trimmed)
        && value.is_object()
    {
        return value;
    }
    serde_json::json!({"input": raw})
}
