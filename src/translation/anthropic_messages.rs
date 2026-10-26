//! `anthropic_messages` ↔ IR adapter.
//!
//! Parse reads a validated Anthropic Messages envelope into the IR; emit
//! rebuilds an Anthropic envelope that must pass the kernel's own
//! `validate_request` (the composition gate). Anthropic-only concepts —
//! `metadata`, thinking signatures, `container`, `mcp_servers`, service
//! tiers — do not survive a translated hop and are recorded as dropped.

use super::ir::{
    Effort, FileSource, ImageSource, IrMessage, IrPart, IrRequest, IrRole, IrStop, IrTool,
    IrToolChoice,
};
use crate::protocol::ProtocolError;
use serde_json::{Map, Value};

const DROPPED_FIELDS: &[&str] = &[
    "metadata",
    "container",
    "mcp_servers",
    "service_tier",
    "betas",
    "thinking",
];

/// Parse an Anthropic request body into the IR.
pub fn to_ir(body: &Value, ceiling: u64) -> Result<(IrRequest, Vec<&'static str>), ProtocolError> {
    let object = body.as_object().ok_or(ProtocolError::InvalidRequest)?;
    let mut dropped: Vec<&'static str> = DROPPED_FIELDS
        .iter()
        .filter(|field| object.contains_key(**field))
        .copied()
        .collect();

    let system = object.get("system").and_then(|system| match system {
        Value::String(text) => Some(text.clone()),
        Value::Array(blocks) => {
            if blocks.iter().any(|block| {
                block
                    .get("cache_control")
                    .is_some_and(|value| !value.is_null())
            }) {
                dropped.push("cache_control");
            }
            let parts: Vec<&str> = blocks
                .iter()
                .filter(|block| block.get("type").and_then(Value::as_str) == Some("text"))
                .filter_map(|block| block.get("text").and_then(Value::as_str))
                .collect();
            if parts.is_empty() {
                None
            } else {
                Some(parts.join(super::ir::SYSTEM_JOIN))
            }
        }
        _ => None,
    });

    let mut messages: Vec<IrMessage> = Vec::new();
    for message in object
        .get("messages")
        .and_then(Value::as_array)
        .ok_or(ProtocolError::InvalidRequest)?
    {
        let role = message
            .get("role")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let role = match role {
            "user" => IrRole::User,
            "assistant" => IrRole::Assistant,
            _ => return Err(ProtocolError::InvalidRequest),
        };
        let mut parts: Vec<IrPart> = Vec::new();
        let raw = message
            .get("content")
            .cloned()
            .unwrap_or_else(|| Value::String(String::new()));
        let blocks: Vec<Value> = match raw {
            Value::String(text) => vec![serde_json::json!({"type": "text", "text": text})],
            Value::Array(blocks) => blocks,
            _ => Vec::new(),
        };
        for block in blocks {
            if block
                .get("cache_control")
                .is_some_and(|value| !value.is_null())
            {
                dropped.push("cache_control");
            }
            match block.get("type").and_then(Value::as_str) {
                Some("text") => {
                    let text = block
                        .get("text")
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    if !text.is_empty() {
                        parts.push(IrPart::Text(text.to_owned()));
                    }
                }
                Some("thinking") => {
                    let text = block
                        .get("thinking")
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    if !text.is_empty() {
                        parts.push(IrPart::Thinking {
                            text: text.to_owned(),
                        });
                    }
                }
                Some("redacted_thinking") => {
                    dropped.push("redacted_thinking");
                }
                Some("image") => {
                    let Some(source) = block.get("source") else {
                        continue;
                    };
                    let media = source
                        .get("media_type")
                        .and_then(Value::as_str)
                        .unwrap_or("image/png")
                        .to_owned();
                    match source.get("type").and_then(Value::as_str) {
                        Some("base64") => parts.push(IrPart::Image {
                            media,
                            source: ImageSource::Base64(
                                source
                                    .get("data")
                                    .and_then(Value::as_str)
                                    .unwrap_or_default()
                                    .to_owned(),
                            ),
                        }),
                        Some("url") => parts.push(IrPart::Image {
                            media,
                            source: ImageSource::Url(
                                source
                                    .get("url")
                                    .and_then(Value::as_str)
                                    .unwrap_or_default()
                                    .to_owned(),
                            ),
                        }),
                        _ => {}
                    }
                }
                Some("document") => {
                    let Some(source) = block.get("source") else {
                        continue;
                    };
                    let media = source
                        .get("media_type")
                        .and_then(Value::as_str)
                        .unwrap_or("application/pdf")
                        .to_owned();
                    match source.get("type").and_then(Value::as_str) {
                        Some("base64") => parts.push(IrPart::File {
                            media,
                            source: FileSource::Base64(
                                source
                                    .get("data")
                                    .and_then(Value::as_str)
                                    .unwrap_or_default()
                                    .to_owned(),
                            ),
                        }),
                        Some("url") => parts.push(IrPart::File {
                            media,
                            source: FileSource::Url(
                                source
                                    .get("url")
                                    .and_then(Value::as_str)
                                    .unwrap_or_default()
                                    .to_owned(),
                            ),
                        }),
                        _ => {}
                    }
                }
                Some("tool_use") => parts.push(IrPart::ToolCall {
                    id: block.get("id").and_then(Value::as_str).map(str::to_owned),
                    name: block
                        .get("name")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned(),
                    args: block
                        .get("input")
                        .cloned()
                        .unwrap_or_else(|| serde_json::json!({})),
                }),
                Some("tool_result") => {
                    let call_id = block
                        .get("tool_use_id")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned();
                    let content = block
                        .get("content")
                        .cloned()
                        .unwrap_or_else(|| Value::String(String::new()));
                    let (text, images) = tool_result_content(&content);
                    parts.push(IrPart::ToolResult {
                        call_id,
                        text,
                        images,
                        is_error: block
                            .get("is_error")
                            .and_then(Value::as_bool)
                            .unwrap_or(false),
                    });
                }
                _ => {}
            }
        }
        messages.push(IrMessage { role, parts });
    }

    let tools = object
        .get("tools")
        .and_then(Value::as_array)
        .map(|tools| {
            tools
                .iter()
                .filter(|tool| tool.get("input_schema").is_some())
                .filter_map(|tool| {
                    let name = tool.get("name").and_then(Value::as_str)?;
                    Some(IrTool {
                        name: name.to_owned(),
                        description: tool
                            .get("description")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_owned(),
                        schema: tool
                            .get("input_schema")
                            .cloned()
                            .unwrap_or_else(|| serde_json::json!({})),
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let tool_choice = match object.get("tool_choice") {
        Some(Value::Object(choice)) => match choice.get("type").and_then(Value::as_str) {
            Some("auto") => Some(IrToolChoice::Auto),
            Some("none") => Some(IrToolChoice::None),
            Some("any") => Some(IrToolChoice::Required),
            Some("tool") => choice
                .get("name")
                .and_then(Value::as_str)
                .filter(|name| !name.is_empty())
                .map(|name| IrToolChoice::Name(name.to_owned())),
            _ => None,
        },
        _ => None,
    };

    // Anthropic clients declare thinking via output_config.effort (per the spec)
    // or a thinking budget block; both normalize to Effort.
    let effort = object
        .get("output_config")
        .and_then(|config| config.get("effort"))
        .and_then(Value::as_str)
        .and_then(Effort::parse_name)
        .or_else(|| {
            object
                .get("thinking")
                .and_then(|thinking| thinking.get("budget_tokens"))
                .and_then(Value::as_u64)
                .and_then(Effort::from_budget)
        });

    // The client's declared output limit lowers the caller-supplied ceiling
    // reservation; it never raises it.
    let ceiling = object
        .get("max_tokens")
        .and_then(Value::as_u64)
        .map_or(ceiling, |limit| limit.min(ceiling));

    Ok((
        IrRequest {
            system,
            messages,
            tools,
            tool_choice,
            ceiling,
            temperature: object.get("temperature").and_then(Value::as_f64),
            top_p: object.get("top_p").and_then(Value::as_f64),
            top_k: object.get("top_k").and_then(Value::as_u64),
            stop: object
                .get("stop_sequences")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(Value::as_str)
                        .filter(|text| !text.is_empty())
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default(),
            effort,
            parallel_tool_calls: object.get("parallel_tool_calls").and_then(Value::as_bool),
            structured_output: None,
            // Anthropic has no cache-routing key concept.
            prompt_cache_key: None,
        },
        dropped,
    ))
}

/// Rebuild an Anthropic envelope from the IR. The product must pass
/// `crate::protocol::anthropic_messages::validate_request`, which requires
/// `model` and `max_tokens` and rejects unknown top-level fields.
pub fn from_ir(
    request: &IrRequest,
    model: &str,
) -> Result<(Value, Vec<&'static str>), ProtocolError> {
    let mut dropped: Vec<&'static str> = Vec::new();
    // The Anthropic kernel rejects parallel_tool_calls on the wire.
    if request.parallel_tool_calls.is_some() {
        dropped.push("parallel_tool_calls");
    }
    // Nor does Anthropic consume the cache-routing hint: record the loss.
    if request.prompt_cache_key.is_some() {
        dropped.push("prompt_cache_key");
    }
    // SH-07: Anthropic has no structured-output envelope; a translated hop
    // drops the constraint audibly instead of silently losing the guarantee.
    if request.structured_output.is_some() {
        dropped.push("structured_output");
    }
    // original IR call id -> the tool_use id this body emits; results route
    // through it so synthesized ids stay paired with their results.
    let mut call_ids: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut messages: Vec<Value> = Vec::new();
    for message in &request.messages {
        let mut blocks: Vec<Value> = Vec::new();
        for part in &message.parts {
            match part {
                IrPart::Text(text) => {
                    blocks.push(serde_json::json!({"type": "text", "text": text}))
                }
                IrPart::Image { media, source } => {
                    let source = match source {
                        ImageSource::Base64(data) => {
                            serde_json::json!({"type": "base64", "media_type": media, "data": data})
                        }
                        ImageSource::Url(url) => serde_json::json!({"type": "url", "url": url}),
                    };
                    blocks.push(serde_json::json!({"type": "image", "source": source}));
                }
                IrPart::File { media, source } => {
                    let source = match source {
                        FileSource::Base64(data) => {
                            serde_json::json!({"type": "base64", "media_type": media, "data": data})
                        }
                        FileSource::Url(url) => serde_json::json!({"type": "url", "url": url}),
                    };
                    blocks.push(serde_json::json!({"type": "document", "source": source}));
                }
                IrPart::ToolCall { id, name, args } => {
                    let ir_id = id.clone();
                    let id = match id {
                        Some(id) => id.clone(),
                        None => format!(
                            "toolu_{:024x}",
                            (name.len() as u64) << 32 | args.to_string().len() as u64
                        ),
                    };
                    if let Some(ir_id) = ir_id {
                        call_ids.insert(ir_id, id.clone());
                    }
                    blocks.push(serde_json::json!({"type": "tool_use", "id": id, "name": name, "input": args}));
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
                    let mut entry = Map::new();
                    entry.insert("type".to_owned(), Value::String("tool_result".to_owned()));
                    entry.insert("tool_use_id".to_owned(), Value::String(wire_id));
                    let mut content: Vec<Value> = Vec::new();
                    if !text.is_empty() {
                        content.push(serde_json::json!({"type": "text", "text": text}));
                    }
                    for image in images {
                        if let IrPart::Image { media, source } = image {
                            let source = match source {
                                ImageSource::Base64(data) => {
                                    serde_json::json!({"type": "base64", "media_type": media, "data": data})
                                }
                                ImageSource::Url(url) => {
                                    serde_json::json!({"type": "url", "url": url})
                                }
                            };
                            content.push(serde_json::json!({"type": "image", "source": source}));
                        }
                    }
                    match content.len() {
                        // tool_result.content accepts a string or a content-block array;
                        // a single bare block object is rejected by strict validators.
                        0 => entry.insert("content".to_owned(), Value::String(String::new())),
                        1 if content[0].get("type").and_then(Value::as_str) == Some("text") => {
                            entry.insert(
                                "content".to_owned(),
                                content
                                    .swap_remove(0)
                                    .get("text")
                                    .cloned()
                                    .unwrap_or_default(),
                            )
                        }
                        _ => entry.insert("content".to_owned(), Value::Array(content)),
                    };
                    if *is_error {
                        entry.insert("is_error".to_owned(), Value::Bool(true));
                    }
                    blocks.push(Value::Object(entry));
                }
                IrPart::Thinking { .. } => dropped.push("thinking"),
            }
        }
        if blocks.is_empty() {
            blocks.push(serde_json::json!({"type": "text", "text": "[empty]"}));
        }
        let role = match message.role {
            IrRole::User => "user",
            IrRole::Assistant => "assistant",
        };
        messages.push(serde_json::json!({"role": role, "content": blocks}));
    }
    dropped.sort_unstable();
    dropped.dedup();

    let mut body = Map::new();
    body.insert("model".to_owned(), Value::String(model.to_owned()));
    // max_tokens is mandatory on the anthropic wire: with no declared client
    // limit, fall back to a conservative default rather than emitting an
    // invalid value (the reservation sentinel would be rejected upstream).
    let max_tokens = if request.ceiling == crate::translation::ir::NO_DECLARED_LIMIT {
        crate::translation::ir::DEFAULT_ANTHROPIC_MAX_TOKENS
    } else {
        request.ceiling
    };
    body.insert("max_tokens".to_owned(), Value::from(max_tokens));
    body.insert("messages".to_owned(), Value::Array(messages));
    if let Some(system) = &request.system {
        body.insert("system".to_owned(), Value::String(system.clone()));
    }
    if let Some(temperature) = request.temperature {
        body.insert("temperature".to_owned(), serde_json::json!(temperature));
    }
    if let Some(top_p) = request.top_p {
        body.insert("top_p".to_owned(), serde_json::json!(top_p));
    }
    if let Some(top_k) = request.top_k {
        body.insert("top_k".to_owned(), Value::from(top_k));
    }
    if !request.stop.is_empty() {
        body.insert("stop_sequences".to_owned(), serde_json::json!(request.stop));
    }
    if let Some(effort) = request.effort {
        match effort {
            Effort::None => {
                body.insert(
                    "thinking".to_owned(),
                    serde_json::json!({"type": "disabled"}),
                );
            }
            Effort::Budget(budget) => {
                // Raise max_tokens when the budget does not fit
                // under it; the F1 ceiling is frozen here, so an infeasible budget is
                // refused instead of silently distorted.
                if budget.saturating_add(1024) > max_tokens {
                    return Err(ProtocolError::UnsupportedParameter);
                }
                body.insert(
                    "thinking".to_owned(),
                    serde_json::json!({"type": "enabled", "budget_tokens": budget}),
                );
            }
            other => {
                body.insert(
                    "output_config".to_owned(),
                    serde_json::json!({"effort": effort_name(other)}),
                );
            }
        }
    }
    if !request.tools.is_empty() {
        let tools = request
      .tools
      .iter()
      .map(|tool| serde_json::json!({"name": tool.name, "description": tool.description, "input_schema": tool.schema}))
      .collect::<Vec<_>>();
        body.insert("tools".to_owned(), Value::Array(tools));
        if let Some(choice) = &request.tool_choice {
            let choice = match choice {
                IrToolChoice::Auto => serde_json::json!({"type": "auto"}),
                IrToolChoice::None => serde_json::json!({"type": "none"}),
                IrToolChoice::Required => serde_json::json!({"type": "any"}),
                IrToolChoice::Name(name) => serde_json::json!({"type": "tool", "name": name}),
            };
            body.insert("tool_choice".to_owned(), choice);
        }
    }
    let value = Value::Object(body);
    crate::protocol::anthropic_messages::validate_request(&value)?;
    Ok((value, dropped))
}

/// Rebuild an Anthropic response body from the parsed IR response.
/// Parse an upstream Messages response body into the IR response.
pub fn response_to_ir(raw: &[u8]) -> Result<super::ir::IrResponse, ProtocolError> {
    let body: Value = serde_json::from_slice(raw).map_err(|_| ProtocolError::UpstreamError)?;
    let mut content = Vec::new();
    for block in body
        .get("content")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        match block.get("type").and_then(Value::as_str) {
            Some("text") => {
                let text = block
                    .get("text")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                if !text.is_empty() {
                    content.push(IrPart::Text(text.to_owned()));
                }
            }
            Some("thinking") => {
                content.push(IrPart::Thinking {
                    text: block
                        .get("thinking")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned(),
                });
            }
            Some("tool_use") => {
                content.push(IrPart::ToolCall {
                    id: Some(
                        block
                            .get("id")
                            .and_then(Value::as_str)
                            .ok_or(ProtocolError::UpstreamError)?
                            .to_owned(),
                    ),
                    name: block
                        .get("name")
                        .and_then(Value::as_str)
                        .ok_or(ProtocolError::UpstreamError)?
                        .to_owned(),
                    args: block
                        .get("input")
                        .cloned()
                        .unwrap_or_else(|| Value::Object(serde_json::Map::new())),
                });
            }
            _ => {}
        }
    }
    Ok(super::ir::IrResponse {
        model: body
            .get("model")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        content,
        stop: stop_from_anthropic(body.get("stop_reason").and_then(Value::as_str)),
        usage: usage_from_anthropic(body.get("usage")),
    })
}

/// Inverse of the usage mapping the kernel uses: Messages usage object to
/// `UsageCounts`, folding cache reads/writes into billable input like the
/// protocol observer does.
///
/// Partial usage objects are real (a stream can report only one side), so each
/// token field falls back to zero independently — the Chat parser's rule. A
/// known input is never dropped just because the output count is absent.
pub(crate) fn usage_from_anthropic(
    usage: Option<&Value>,
) -> Option<crate::protocol::usage::UsageCounts> {
    let usage = usage?;
    let input = usage.get("input_tokens").and_then(Value::as_u64);
    let output = usage.get("output_tokens").and_then(Value::as_u64);
    let cache_read = usage.get("cache_read_input_tokens").and_then(Value::as_u64);
    let cache_creation = usage
        .get("cache_creation_input_tokens")
        .and_then(Value::as_u64);
    if input.is_none() && output.is_none() && cache_read.is_none() && cache_creation.is_none() {
        return None;
    }
    let input = input.unwrap_or(0);
    let output = output.unwrap_or(0);
    let billable_input = input
        .checked_add(cache_read.unwrap_or(0))?
        .checked_add(cache_creation.unwrap_or(0))?;
    Some(crate::protocol::usage::UsageCounts {
        input_tokens: billable_input,
        output_tokens: output,
        calls: 0,
        cached_input_tokens: cache_read,
        cache_creation_input_tokens: cache_creation,
        ..Default::default()
    })
}

/// Anthropic `stop_reason` back into the IR stop concept.
pub(crate) fn stop_from_anthropic(stop: Option<&str>) -> IrStop {
    match stop {
        Some("end_turn" | "stop_sequence") | None => IrStop::Stop,
        Some("max_tokens") => IrStop::Length,
        Some("tool_use") => IrStop::ToolUse,
        Some(reason) => IrStop::Other(reason.to_owned()),
    }
}

pub fn emit_response_json(
    response: &super::ir::IrResponse,
) -> Result<Vec<u8>, crate::protocol::ProtocolError> {
    let mut content: Vec<Value> = Vec::new();
    for part in &response.content {
        match part {
            IrPart::Text(text) => {
                // Merge adjacent text parts into one text block.
                if let Some(last) = content.last_mut()
                    && last.get("type").and_then(Value::as_str) == Some("text")
                {
                    let existing = last.get("text").and_then(Value::as_str).unwrap_or_default();
                    *last =
                        serde_json::json!({"type": "text", "text": format!("{existing}{text}")});
                    continue;
                }
                content.push(serde_json::json!({"type": "text", "text": text}));
            }
            IrPart::ToolCall { id, name, args } => {
                let id = id.clone().unwrap_or_else(|| {
                    format!(
                        "toolu_{:024x}",
                        (name.len() as u64) << 32 | args.to_string().len() as u64
                    )
                });
                content.push(
                    serde_json::json!({"type": "tool_use", "id": id, "name": name, "input": args}),
                );
            }
            // Upstream thinking signatures were discarded at parse time; emitting
            // an unsigned block would poison a client that replays it. Drop it.
            IrPart::Thinking { .. } => {}
            _ => {}
        }
    }
    let (stop_reason, stop_sequence): (Value, Value) = match &response.stop {
        IrStop::Stop => (Value::String("end_turn".to_owned()), Value::Null),
        IrStop::Length => (Value::String("max_tokens".to_owned()), Value::Null),
        IrStop::ToolUse => (Value::String("tool_use".to_owned()), Value::Null),
        IrStop::Other(reason) => (
            Value::String("refusal".to_owned()),
            Value::String(reason.clone()),
        ),
    };
    let mut body = serde_json::json!({
      "id": format!("msg_{:024x}", chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default().unsigned_abs()),
      "type": "message",
      "role": "assistant",
      "model": response.model,
      "content": content,
      "stop_reason": stop_reason,
      "stop_sequence": stop_sequence,
    });
    // An upstream that reported no token usage leaves the field out entirely:
    // zeroes would be read as a real (free) measurement.
    if let Some(usage) = &response.usage {
        body["usage"] = serde_json::json!({
          "input_tokens": usage.input_tokens,
          "output_tokens": usage.output_tokens,
          "cache_read_input_tokens": usage.cached_input_tokens.unwrap_or(0),
        });
    }
    serde_json::to_vec(&body).map_err(|_| crate::protocol::ProtocolError::InvalidUpstreamResponse)
}

pub(crate) fn effort_name(effort: Effort) -> &'static str {
    match effort {
        Effort::None | Effort::Low => "low",
        Effort::Medium => "medium",
        Effort::High => "high",
        Effort::Xhigh | Effort::Max | Effort::Budget(_) => "max",
    }
}

/// Tool result content: string or blocks.
fn tool_result_content(content: &Value) -> (String, Vec<IrPart>) {
    if let Some(text) = content.as_str() {
        return (text.to_owned(), Vec::new());
    }
    let Some(blocks) = content.as_array() else {
        return (String::new(), Vec::new());
    };
    let mut text = String::new();
    let mut images = Vec::new();
    for block in blocks {
        match block.get("type").and_then(Value::as_str) {
            Some("text") => text.push_str(
                block
                    .get("text")
                    .and_then(Value::as_str)
                    .unwrap_or_default(),
            ),
            Some("image") => {
                if let Some(source) = block.get("source") {
                    let media = source
                        .get("media_type")
                        .and_then(Value::as_str)
                        .unwrap_or("image/png")
                        .to_owned();
                    match source.get("type").and_then(Value::as_str) {
                        Some("base64") => images.push(IrPart::Image {
                            media,
                            source: ImageSource::Base64(
                                source
                                    .get("data")
                                    .and_then(Value::as_str)
                                    .unwrap_or_default()
                                    .to_owned(),
                            ),
                        }),
                        Some("url") => images.push(IrPart::Image {
                            media,
                            source: ImageSource::Url(
                                source
                                    .get("url")
                                    .and_then(Value::as_str)
                                    .unwrap_or_default()
                                    .to_owned(),
                            ),
                        }),
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    (text, images)
}
