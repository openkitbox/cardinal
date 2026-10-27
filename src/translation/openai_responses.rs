//! `openai_responses` ↔ IR adapter — only the "Responses as client" half.
//!
//! `to_ir` parses a Responses request envelope into the IR and
//! `emit_response_json` rebuilds a Responses response body from it; the pair
//! serves the single open directed hop Responses → Chat. Nothing translates
//! *into* a Responses upstream (`OPENED` has no `* → OpenAiResponses` pair),
//! so `from_ir`/`response_to_ir` exist only to fill the `Dialect` vtable and
//! refuse defensively.

use super::ir::{
    Effort, IrMessage, IrPart, IrRequest, IrResponse, IrRole, IrStop, IrTool, IrToolChoice,
};
use crate::protocol::ProtocolError;
use serde_json::Value;

/// Responses-only concepts no translated hop can carry. `store`/`background`
/// are stateless-relay concerns: the kernel refuses their non-default values
/// on the pass-through path; on a translated hop the concept has no upstream
/// meaning at all, so a non-default value is recorded, not rejected.
/// `prompt_cache_key` is not listed: it has an IR slot and survives the hop.
const DROPPED_FIELDS: &[&str] = &["metadata", "include", "truncation", "service_tier"];

/// Parse a Responses request body into the IR. Unknown input items hard-fail:
/// refusing beats silently dropping content the client believes was sent.
pub fn to_ir(body: &Value, ceiling: u64) -> Result<(IrRequest, Vec<&'static str>), ProtocolError> {
    let object = body.as_object().ok_or(ProtocolError::InvalidRequest)?;
    let mut dropped: Vec<&'static str> = DROPPED_FIELDS
        .iter()
        .filter(|field| object.contains_key(**field))
        .copied()
        .collect();

    // A continuation references upstream server-side state the stateless relay
    // never created. The kernel refuses it on the pass-through path, but the
    // translation path never runs the client kernel — refuse here too.
    if object
        .get("previous_response_id")
        .is_some_and(|id| !id.is_null())
    {
        return Err(ProtocolError::InvalidContinuation);
    }
    // Non-default store/background ask for upstream state; the hop drops the
    // concept, so the request is served and the loss recorded (the kernel
    // rejects these outright only on the pass-through path it guards).
    for field in ["store", "background"] {
        if object.get(field).and_then(Value::as_bool) == Some(true) {
            dropped.push(field);
        }
    }

    let mut system: Vec<String> = Vec::new();
    // `instructions` leads the system prompt, ahead of any system/developer
    // message items the input array carries.
    if let Some(instructions) = object
        .get("instructions")
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
    {
        system.push(instructions.to_owned());
    }

    let mut messages: Vec<IrMessage> = Vec::new();
    match object.get("input") {
        Some(Value::String(text)) => {
            if text.is_empty() {
                return Err(ProtocolError::InvalidRequest);
            }
            messages.push(IrMessage {
                role: IrRole::User,
                parts: vec![IrPart::Text(text.clone())],
            });
        }
        Some(Value::Array(items)) => {
            if items.is_empty() {
                return Err(ProtocolError::InvalidRequest);
            }
            for item in items {
                input_item(item, &mut system, &mut messages, &mut dropped)?;
            }
        }
        _ => return Err(ProtocolError::InvalidRequest),
    }

    let mut tools = Vec::new();
    if let Some(declared) = object.get("tools").and_then(Value::as_array) {
        for tool in declared {
            // Hosted tools (web_search etc.) cannot cross a translated hop.
            if tool.get("type").and_then(Value::as_str) != Some("function") {
                dropped.push("tool_type");
                continue;
            }
            // A function tool without a name is malformed, not droppable — same
            // hard-fail discipline as a `function_call` item without one.
            let name = tool
                .get("name")
                .and_then(Value::as_str)
                .filter(|name| !name.is_empty())
                .ok_or(ProtocolError::InvalidRequest)?;
            // Responses carries `strict` beside the schema; IrTool has no slot
            // for it, so its presence is recorded, not carried.
            if tool.get("strict").is_some() {
                dropped.push("tool_strict");
            }
            tools.push(IrTool {
                name: name.to_owned(),
                description: tool
                    .get("description")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                schema: tool
                    .get("parameters")
                    .cloned()
                    .unwrap_or_else(|| serde_json::json!({})),
            });
        }
    }

    let tool_choice = match object.get("tool_choice") {
        Some(Value::String(choice)) => match choice.as_str() {
            "auto" => Some(IrToolChoice::Auto),
            "none" => Some(IrToolChoice::None),
            "required" => Some(IrToolChoice::Required),
            // An unknown mode string (e.g. a newer dialect's mode) degrades to
            // auto with an audit note rather than failing the turn.
            _ => {
                dropped.push("tool_choice");
                Some(IrToolChoice::Auto)
            }
        },
        // Responses names the forced function flat: {"type": "function", "name": …}.
        Some(Value::Object(choice))
            if choice.get("type").and_then(Value::as_str) == Some("function") =>
        {
            choice
                .get("name")
                .and_then(Value::as_str)
                .filter(|name| !name.is_empty())
                .map(|name| IrToolChoice::Name(name.to_owned()))
        }
        _ => None,
    };

    // max_output_tokens is the dialect's output limit; it lowers the ceiling,
    // never raises it (the F1 reservation wins over the client's ask).
    let ceiling = match object.get("max_output_tokens") {
        Some(value) => {
            let limit = value
                .as_u64()
                .filter(|limit| *limit > 0)
                .ok_or(ProtocolError::InvalidRequest)?;
            limit.min(ceiling)
        }
        None => ceiling,
    };

    let effort = object
        .get("reasoning")
        .and_then(|reasoning| reasoning.get("effort"))
        .and_then(Value::as_str)
        .and_then(Effort::parse_name);
    // The upstream cache-routing hint rides the IR (Kiro derives its
    // conversation id from it); a present-but-unusable value is a recorded loss.
    let prompt_cache_key = super::ir::prompt_cache_key_of(object);
    if prompt_cache_key.is_none() && object.contains_key("prompt_cache_key") {
        dropped.push("prompt_cache_key");
    }
    // SH-07: the IR carries the source envelope. Responses `text.format` is the
    // flat shape (type/name/schema/strict side by side); the Chat emitter
    // rebuilds its nested envelope from it.
    let structured_output = object
        .get("text")
        .and_then(|text| text.get("format"))
        .filter(|format| {
            matches!(
                format.get("type").and_then(Value::as_str),
                Some("json_schema" | "json_object")
            )
        })
        .cloned();

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
            stop: Vec::new(),
            effort,
            parallel_tool_calls: object.get("parallel_tool_calls").and_then(Value::as_bool),
            structured_output,
            prompt_cache_key,
        },
        dropped,
    ))
}

/// One typed input item (or the untyped `{"role": …, "content": …}` message
/// shorthand the wire also allows).
fn input_item(
    item: &Value,
    system: &mut Vec<String>,
    messages: &mut Vec<IrMessage>,
    // Reasoning items are now kept (replayed as Thinking), so nothing here
    // drops audibly any more; the parameter stays for the call-site symmetry
    // with the other dialect adapters.
    _dropped: &mut [&'static str],
) -> Result<(), ProtocolError> {
    let kind = match item.get("type").and_then(Value::as_str) {
        Some(kind) => kind,
        None if item.get("role").is_some() => "message",
        None => return Err(ProtocolError::InvalidRequest),
    };
    match kind {
        "message" => {
            // Missing content is an empty turn; present-but-mistyped content is
            // refused inside `content_parts` (never silently stripped).
            let empty = Value::String(String::new());
            let content = item.get("content").unwrap_or(&empty);
            match item.get("role").and_then(Value::as_str).unwrap_or_default() {
                "system" | "developer" => {
                    let parts = content_parts(content)?;
                    let mut text = String::new();
                    for part in parts {
                        let IrPart::Text(part) = part else {
                            // Images/files in a system turn have no IR home.
                            return Err(ProtocolError::InvalidRequest);
                        };
                        text.push_str(&part);
                    }
                    if !text.is_empty() {
                        system.push(text);
                    }
                }
                "user" => messages.push(IrMessage {
                    role: IrRole::User,
                    parts: content_parts(content)?,
                }),
                "assistant" => messages.push(IrMessage {
                    role: IrRole::Assistant,
                    parts: content_parts(content)?,
                }),
                _ => return Err(ProtocolError::InvalidRequest),
            }
        }
        "function_call" => {
            let name = item
                .get("name")
                .and_then(Value::as_str)
                .filter(|name| !name.is_empty())
                .ok_or(ProtocolError::InvalidRequest)?;
            messages.push(IrMessage {
                role: IrRole::Assistant,
                parts: vec![IrPart::ToolCall {
                    id: item
                        .get("call_id")
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                        .filter(|id| !id.is_empty()),
                    name: name.to_owned(),
                    args: super::openai_chat::parse_args(item.get("arguments")),
                }],
            });
        }
        "function_call_output" => {
            // The result must name the call it answers — same hard-fail discipline
            // as the function_call arm (a dangling result would corrupt the
            // upstream's tool-pairing).
            let call_id = item
                .get("call_id")
                .and_then(Value::as_str)
                .filter(|id| !id.is_empty())
                .ok_or(ProtocolError::InvalidRequest)?;
            let empty = Value::String(String::new());
            let output = item.get("output").unwrap_or(&empty);
            messages.push(IrMessage {
                role: IrRole::User,
                parts: vec![IrPart::ToolResult {
                    call_id: call_id.to_owned(),
                    text: tool_output_text(output)?,
                    images: Vec::new(),
                    is_error: false,
                }],
            });
        }
        // A reasoning item carries the thinking a client must replay on the
        // next turn (DeepSeek rejects a tool-calling assistant turn without
        // it). Accumulate its text into the following assistant message; the
        // signature never survives a translated hop, so only the text is kept.
        "reasoning" => {
            let mut text = String::new();
            // Responses reasoning items carry their thinking in `summary` (an
            // array of summary_text parts) or, on some clients, `content`.
            for field in ["summary", "content"] {
                if let Some(parts) = item.get(field).and_then(Value::as_array) {
                    for part in parts {
                        if let Some(t) = part.get("text").and_then(Value::as_str) {
                            text.push_str(t);
                        }
                    }
                }
            }
            if !text.is_empty() {
                messages.push(IrMessage {
                    role: IrRole::Assistant,
                    parts: vec![IrPart::Thinking { text }],
                });
            }
        }
        // Hard fail over silent content loss (unknown item kinds included).
        _ => return Err(ProtocolError::InvalidRequest),
    }
    Ok(())
}

/// Message content: a bare string or a part array. `output_text` is a
/// response-side concept; a client sending it as input is refused rather than
/// silently stripped. Any other shape (number, object, null) hard-fails for
/// the same reason.
fn content_parts(content: &Value) -> Result<Vec<IrPart>, ProtocolError> {
    if let Some(text) = content.as_str() {
        return Ok(if text.is_empty() {
            Vec::new()
        } else {
            vec![IrPart::Text(text.to_owned())]
        });
    }
    let Some(items) = content.as_array() else {
        return Err(ProtocolError::InvalidRequest);
    };
    let mut parts = Vec::new();
    for item in items {
        match item.get("type").and_then(Value::as_str) {
            // `output_text` is the assistant-history part type the Responses wire
            // carries back in `input` (stateless replay of a previous turn); it is
            // plain text here, same as the responses-part fold.
            Some("input_text" | "output_text" | "text") => {
                if let Some(text) = item.get("text").and_then(Value::as_str)
                    && !text.is_empty()
                {
                    parts.push(IrPart::Text(text.to_owned()));
                }
            }
            Some("input_image") => {
                // Only the two wire forms IrPart knows: a data URL carries inline
                // bytes, anything else stays a URL. A `file_id` reference is upstream
                // server-side state the stateless relay cannot resolve.
                let url = item
                    .get("image_url")
                    .and_then(Value::as_str)
                    .filter(|url| !url.is_empty())
                    .ok_or(ProtocolError::InvalidRequest)?;
                parts.push(super::openai_chat::image_part(url));
            }
            _ => return Err(ProtocolError::InvalidRequest),
        }
    }
    Ok(parts)
}

/// A tool output value: a string, or a part array whose text blocks join.
fn tool_output_text(output: &Value) -> Result<String, ProtocolError> {
    if let Some(text) = output.as_str() {
        return Ok(text.to_owned());
    }
    let Some(items) = output.as_array() else {
        return Ok(String::new());
    };
    let mut out = String::new();
    for item in items {
        match item.get("type").and_then(Value::as_str) {
            Some("input_text" | "output_text" | "text") => {
                out.push_str(item.get("text").and_then(Value::as_str).unwrap_or_default())
            }
            _ => return Err(ProtocolError::InvalidRequest),
        }
    }
    Ok(out)
}

/// Rebuild a Responses body from the IR response — the return leg of the
/// Responses → Chat hop, where the upstream answer re-enters the client
/// dialect.
pub fn emit_response_json(
    response: &IrResponse,
) -> Result<Vec<u8>, crate::protocol::ProtocolError> {
    let mut output: Vec<Value> = Vec::new();
    let mut pending = String::new();
    let mut thinking = String::new();
    let mut messages = 0u64;
    let mut calls = 0u64;
    let mut reasonings = 0u64;
    for part in &response.content {
        match part {
            // Thinking rides its own reasoning item so the client can replay it
            // next turn (DeepSeek requires it back); the text accumulates until a
            // non-thinking part flushes it as one reasoning item.
            IrPart::Thinking { text } => thinking.push_str(text),
            IrPart::Text(text) => {
                flush_reasoning(&mut output, &mut thinking, &mut reasonings);
                pending.push_str(text);
            }
            IrPart::ToolCall { id, name, args } => {
                // A tool call flushes any pending reasoning and text ahead of it
                // so item order mirrors the IR.
                flush_reasoning(&mut output, &mut thinking, &mut reasonings);
                if !pending.is_empty() {
                    messages += 1;
                    output.push(message_item(messages, std::mem::take(&mut pending)));
                }
                calls += 1;
                // The fallback id derives from the monotonic call counter: unique
                // within the response by construction (a hash of position/args can
                // collide on repeated identical calls).
                let call_id = id.clone().unwrap_or_else(|| format!("call_{calls}"));
                output.push(serde_json::json!({
                  "id": format!("fc_{calls:016x}"),
                  "type": "function_call",
                  "call_id": call_id,
                  "name": name,
                  "arguments": args.to_string(),
                }));
            }
            // The Thinking arm above accumulates into `thinking`; nothing else
            // to do here.
            _ => {}
        }
    }
    flush_reasoning(&mut output, &mut thinking, &mut reasonings);
    if !pending.is_empty() {
        messages += 1;
        output.push(message_item(messages, pending));
    }
    // A tool-call turn is still a completed response; only truncation is
    // incomplete (B §4.7 terminal semantics).
    let (status, incomplete_details) = match &response.stop {
        IrStop::Length => (
            "incomplete",
            Some(serde_json::json!({"reason": "max_output_tokens"})),
        ),
        IrStop::Stop | IrStop::ToolUse | IrStop::Other(_) => ("completed", None),
    };
    let mut body = serde_json::json!({
      "id": format!("resp_{:032x}", chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default().unsigned_abs()),
      "object": "response",
      "created_at": chrono::Utc::now().timestamp(),
      "status": status,
      "model": response.model,
      "output": output,
    });
    // Unknown usage stays unknown: an absent `usage` is honest, three zeroes
    // are not (same rule as the streaming terminal).
    if let Some(usage) = &response.usage {
        let mut usage_json = serde_json::json!({
          "input_tokens": usage.input_tokens,
          "output_tokens": usage.output_tokens,
          "total_tokens": usage.input_tokens.saturating_add(usage.output_tokens),
        });
        if let Some(cached) = usage.cached_input_tokens {
            usage_json["input_tokens_details"] = serde_json::json!({"cached_tokens": cached});
        }
        if let Some(reasoning) = usage.reasoning_output_tokens {
            usage_json["output_tokens_details"] =
                serde_json::json!({"reasoning_tokens": reasoning});
        }
        body["usage"] = usage_json;
    }
    if let Some(details) = incomplete_details {
        body["incomplete_details"] = details;
    }
    serde_json::to_vec(&body).map_err(|_| crate::protocol::ProtocolError::InvalidUpstreamResponse)
}

fn message_item(seq: u64, text: String) -> Value {
    serde_json::json!({
      "id": format!("msg_{seq:016x}"),
      "type": "message",
      "status": "completed",
      "role": "assistant",
      "content": [{"type": "output_text", "text": text}],
    })
}

/// Push the accumulated thinking as one reasoning item, if any. The client's
/// next turn replays this item; `to_ir` reads its `summary` text back into a
/// Thinking part so a thinking-mode upstream (DeepSeek) gets its reasoning.
fn flush_reasoning(output: &mut Vec<Value>, thinking: &mut String, seq: &mut u64) {
    if thinking.is_empty() {
        return;
    }
    *seq += 1;
    let text = std::mem::take(thinking);
    output.push(serde_json::json!({
      "id": format!("rs_{seq:016x}"),
      "type": "reasoning",
      "summary": [{"type": "summary_text", "text": text}],
    }));
}

/// Responses is never the translation *target* (`OPENED` carries only the
/// Responses → Chat direction), so the relay never calls this; the refusal
/// exists because the `Dialect` vtable is total.
pub fn from_ir(
    _request: &IrRequest,
    _model: &str,
) -> Result<(Value, Vec<&'static str>), ProtocolError> {
    Err(ProtocolError::UnsupportedApi)
}

/// No upstream ever speaks Responses on a translated hop (see [`from_ir`]).
pub fn response_to_ir(
    _raw: &[u8],
    _context_window: Option<u64>,
    _rate_multiplier: Option<f64>,
    _model: Option<&str>,
) -> Result<IrResponse, ProtocolError> {
    Err(ProtocolError::UnsupportedApi)
}
