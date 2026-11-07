//! Cursor dialect: a translation **target** only (plan D6).
//!
//! `from_ir` stages the conversation in the JSON `protocol::cursor::request`
//! encodes (its module docs give the shape); `response_to_ir` decodes a
//! complete Run body through the protocol kernel's own state machine; the
//! ingress half (`to_ir`, `emit_response_json`) refuses — nothing serves
//! Cursor's wire inbound.
//!
//! The conversation Cursor's agent host takes is a list of AI SDK messages,
//! one content-addressed blob each (reference `conversation()`):
//!
//! * every system/developer text becomes one `system` message, with the
//!   caller's tools listed after it as a `<dynamic_tool_catalog>` — the host
//!   only knows MCP tools through `CallDynamicTool`, and without the list the
//!   model says it has no such tool;
//! * an assistant turn carries `reasoning`, `text` and `tool-call` parts; a
//!   tool call is a `CallDynamicTool` call whose `arguments` name the caller's
//!   tool, so the model's later calls take the same shape;
//! * tool results answer the calls of the assistant turn before them as one
//!   `tool` message; a call the client never answered is answered for
//!   ([`NO_RESULT`], marked an error), because the API wants every call to
//!   have its result;
//! * a user turn carries text and inline images (a data URL becomes the
//!   host's `Uint8Array` encoding); a remote image or a document becomes a
//!   text placeholder.
//!
//! Model selection is deliberately plain in Phase 1: the configured model id
//! is one of Cursor's own usable ids (`claude-opus-5-5-high`,
//! `gpt-5.6-fast`, …), which already name their effort and speed, so the
//! client's `reasoning_effort` is dropped (recorded) rather than re-derived
//! without the catalog. Max Mode is off by default; the relay retries once
//! with it on when Cursor says the model requires it.

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::ir::{
    FileSource, ImageSource, IrMessage, IrPart, IrRequest, IrResponse, IrRole, IrStop, IrTool,
    NO_DECLARED_LIMIT,
};
use crate::protocol::ProtocolError;
use crate::protocol::cursor::msg::{CALL_TOOL, LIST_TOOLS, NAMESPACE};

/// The result given for a tool call the client never answered.
pub const NO_RESULT: &str = "Tool use was interrupted and did not produce a result.";

/// Stage one Chat request as the Cursor run body.
pub fn from_ir(request: &IrRequest, model: &str) -> super::Parsed<Value> {
    if model.is_empty() {
        return Err(ProtocolError::InvalidRequest);
    }
    if !request
        .messages
        .iter()
        .any(|message| message.role == IrRole::User)
    {
        // A Run needs a user turn to answer; an assistant-only history has
        // nothing to run.
        return Err(ProtocolError::InvalidRequest);
    }
    let mut dropped: Vec<&'static str> = Vec::new();
    record_request_losses(request, &mut dropped);

    let mut staging = Staging::default();
    let system = {
        let mut text = request.system.clone().unwrap_or_default();
        text.push_str(&catalog(&request.tools));
        text
    };
    if !system.is_empty() {
        staging.size += system.len();
        staging.push(json!({"role": "system", "content": system}));
    }
    for message in &request.messages {
        match message.role {
            IrRole::Assistant => staging.assistant(message, &mut dropped),
            IrRole::User => staging.user(message, &mut dropped),
        }
    }
    staging.answer();
    for tool in &request.tools {
        staging.size += tool.name.len() + tool.description.len() + tool.schema.to_string().len();
    }

    let conversation_id = request
        .prompt_cache_key
        .as_deref()
        .filter(|key| !key.trim().is_empty())
        .map(|key| conversation_id(key.trim(), staging.first_user.as_ref()))
        .unwrap_or_default();
    let tools: Vec<Value> = request
        .tools
        .iter()
        .map(|tool| {
            json!({
                "name": tool.name,
                "description": tool.description,
                "schema": tool.schema,
            })
        })
        .collect();
    let staged = json!({
        "model": model,
        "max_mode": false,
        "params": [],
        "messages": staging.messages,
        "last_user": staging.last_user.unwrap_or_else(|| ".".to_owned()),
        "tools": tools,
        "conversation_id": conversation_id,
        "prompt_chars": staging.size as u64,
    });
    Ok((staged, dropped))
}

/// The conversation under construction.
#[derive(Default)]
struct Staging {
    messages: Vec<Value>,
    /// Calls of the latest assistant turn not yet answered, by wire id.
    pending: Vec<String>,
    /// Results collected for the pending calls.
    results: Vec<Value>,
    /// The first text of the latest user turn (the Run's `user` blob).
    last_user: Option<String>,
    /// The first user message as staged (the conversation id's salt).
    first_user: Option<Value>,
    /// Characters of prompt content, for the usage estimate.
    size: usize,
}

impl Staging {
    fn push(&mut self, message: Value) {
        self.messages.push(message);
    }

    /// Flush the tool results: every pending call gets one (the real result
    /// or [`NO_RESULT`]), as one `tool` message.
    fn answer(&mut self) {
        for id in std::mem::take(&mut self.pending) {
            self.results.push(tool_result(&id, NO_RESULT, true));
        }
        if !self.results.is_empty() {
            let content = std::mem::take(&mut self.results);
            self.push(json!({"role": "tool", "content": content}));
        }
    }

    fn assistant(&mut self, message: &IrMessage, dropped: &mut Vec<&'static str>) {
        self.answer();
        let mut content = Vec::new();
        for part in &message.parts {
            match part {
                IrPart::Thinking { text } if !text.is_empty() => {
                    self.size += text.len();
                    content.push(json!({"type": "reasoning", "text": text}));
                }
                IrPart::Thinking { .. } => {}
                IrPart::Text(text) if !text.is_empty() => {
                    self.size += text.len();
                    content.push(json!({"type": "text", "text": text}));
                }
                IrPart::Text(_) => {}
                IrPart::ToolCall { id, name, args } => {
                    let wire_id = id
                        .clone()
                        .filter(|id| !id.is_empty())
                        .unwrap_or_else(|| format!("call_{}", uuid::Uuid::new_v4().simple()));
                    self.size += name.len() + args.to_string().len();
                    content.push(json!({
                        "type": "tool-call",
                        "toolCallId": call_id(&wire_id),
                        "toolName": CALL_TOOL,
                        "args": {"namespace": NAMESPACE, "toolName": name, "arguments": args},
                    }));
                    self.pending.push(wire_id);
                }
                IrPart::Image { .. } => dropped.push("assistant_image"),
                IrPart::File { .. } => dropped.push("assistant_file"),
                IrPart::ToolResult { .. } => dropped.push("assistant_tool_result"),
            }
        }
        if !content.is_empty() {
            self.push(json!({"role": "assistant", "content": content}));
        }
    }

    fn user(&mut self, message: &IrMessage, dropped: &mut Vec<&'static str>) {
        // Tool results come first: they answer the assistant turn before.
        for part in &message.parts {
            if let IrPart::ToolResult {
                call_id: id,
                text,
                images,
                is_error,
            } = part
            {
                if let Some(position) = self.pending.iter().position(|pending| pending == id) {
                    self.pending.remove(position);
                    self.size += text.len();
                    self.results.push(tool_result(id, text, *is_error));
                } else {
                    dropped.push("unpaired_tool_result");
                }
                if !images.is_empty() {
                    dropped.push("tool_result_image");
                }
            }
        }
        let mut content = Vec::new();
        let mut first_text: Option<String> = None;
        for part in &message.parts {
            match part {
                IrPart::Text(text) if !text.is_empty() => {
                    self.size += text.len();
                    first_text.get_or_insert_with(|| text.clone());
                    content.push(json!({"type": "text", "text": text}));
                }
                IrPart::Text(_) | IrPart::ToolResult { .. } => {}
                IrPart::Image { media, source } => {
                    match source {
                        ImageSource::Base64(data) => match base64_decode(data) {
                            Some(bytes) => content.push(json!({
                                "type": "image",
                                "mimeType": media,
                                "image": {"__type": "Uint8Array", "hex": hex::encode(bytes)},
                            })),
                            None => {
                                dropped.push("image");
                            }
                        },
                        ImageSource::Url(url) => {
                            content.push(json!({"type": "text", "text": format!("[attachment image: {url}]")}));
                        }
                    }
                }
                IrPart::File { source, .. } => {
                    let name = match source {
                        FileSource::Url(url) => url.as_str(),
                        FileSource::Base64(_) => "file",
                    };
                    content.push(json!({"type": "text", "text": format!("[attachment {name}]")}));
                    dropped.push("file");
                }
                IrPart::Thinking { .. } => dropped.push("user_thinking"),
                IrPart::ToolCall { .. } => dropped.push("user_tool_call"),
            }
        }
        self.answer();
        if let Some(text) = first_text {
            self.last_user = Some(text);
        }
        if !content.is_empty() {
            let message = json!({"role": "user", "content": content});
            if self.first_user.is_none() {
                self.first_user = Some(message.clone());
            }
            self.push(message);
        }
    }
}

/// One AI SDK `tool-result` part. A JSON-shaped result travels parsed, as
/// the host's own client sends it.
fn tool_result(id: &str, text: &str, is_error: bool) -> Value {
    let result =
        serde_json::from_str::<Value>(text).unwrap_or_else(|_| Value::String(text.to_owned()));
    let mut part = json!({
        "type": "tool-result",
        "toolCallId": call_id(id),
        "toolName": CALL_TOOL,
        "result": result,
        "experimental_content": [{"type": "text", "text": text}],
    });
    if is_error {
        part["isError"] = Value::Bool(true);
    }
    part
}

/// A call id as Cursor gave it: an OpenAI-style id carries a newline between
/// its two halves, which the decoder sent out as `__`; restore it so the
/// host recognizes its own id.
fn call_id(id: &str) -> String {
    if id.starts_with("call_") {
        id.replace("__fc_", "\nfc_")
    } else {
        id.to_owned()
    }
}

/// The tool list the model reads: every tool as the exact `CallDynamicTool`
/// call to make, with its schema.
fn catalog(tools: &[IrTool]) -> String {
    if tools.is_empty() {
        return String::new();
    }
    let mut text = format!(
        "\n\n<dynamic_tool_catalog>\nThe MCP namespace \"{NAMESPACE}\" has the tools below. They are reached only through `{CALL_TOOL}`, never as tools of their own. Each entry is the exact call to make; its arguments must match the schema given. The schemas are complete, so there is no need to call `{LIST_TOOLS}` first.\n"
    );
    for tool in tools {
        text.push_str(&format!(
            "<call>{CALL_TOOL}({{\"namespace\":\"{NAMESPACE}\",\"toolName\":\"{}\",\"arguments\":{{...}}}})\n{}\narguments schema: {}\n</call>\n",
            tool.name, tool.description, tool.schema
        ));
    }
    text.push_str("</dynamic_tool_catalog>");
    text
}

/// The Run's `conversation_id` for a prompt-cache key: stable across the
/// requests of one conversation, so Cursor's backend keeps routing it to the
/// machine holding its prompt cache (reference `conversationID`). A version-4
/// UUID made of `sha256("cursor conversation\0" + key + "\0" + first user
/// message)`.
fn conversation_id(key: &str, first_user: Option<&Value>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"cursor conversation\0");
    hasher.update(key.as_bytes());
    hasher.update(b"\0");
    if let Some(first) = first_user {
        hasher.update(first.to_string().as_bytes());
    }
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    uuid::Uuid::from_bytes(bytes).to_string()
}

/// Decode standard or URL-safe base64 (padding optional). `None` on any
/// byte outside the alphabet.
fn base64_decode(input: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut buffer = 0u32;
    let mut bits = 0u8;
    for byte in input.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' | b'\n' | b'\r' | b' ' => continue,
            _ => return None,
        };
        buffer = (buffer << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    Some(out)
}

fn record_request_losses(request: &IrRequest, dropped: &mut Vec<&'static str>) {
    if request.temperature.is_some() {
        dropped.push("temperature");
    }
    if request.top_p.is_some() {
        dropped.push("top_p");
    }
    if request.top_k.is_some() {
        dropped.push("top_k");
    }
    if !request.stop.is_empty() {
        dropped.push("stop");
    }
    if request.ceiling != NO_DECLARED_LIMIT {
        dropped.push("max_tokens");
    }
    if request.tool_choice.is_some() {
        dropped.push("tool_choice");
    }
    if request.structured_output.is_some() {
        dropped.push("response_format");
    }
    if request.parallel_tool_calls.is_some() {
        dropped.push("parallel_tool_calls");
    }
    if request.effort.is_some() {
        // The usable id names its effort; see the module docs.
        dropped.push("reasoning_effort");
    }
}

/// Decode one complete Run body (every downlink frame, concatenated) into
/// the IR, through the protocol kernel's own state machine so a streamed and
/// a buffered answer never disagree.
///
/// A Run that failed (an error end frame, an empty reply, an unreadable
/// frame) is [`ProtocolError::InvalidUpstreamResponse`] or the mapped error
/// of its end frame; one cut off mid-text is delivered with
/// [`IrStop::Length`]; a tool step is delivered with [`IrStop::ToolUse`].
pub fn response_to_ir(
    raw: &[u8],
    _context_window: Option<u64>,
) -> Result<IrResponse, ProtocolError> {
    let mut decoder = crate::protocol::cursor::response::aggregate(raw)?;
    let truncated = match decoder.finish() {
        crate::protocol::Terminal::Completed => false,
        crate::protocol::Terminal::Incomplete => true,
        crate::protocol::Terminal::Failed | crate::protocol::Terminal::Cancelled => {
            return Err(ProtocolError::InvalidUpstreamResponse);
        }
    };
    let usage = decoder.usage();
    let reasoning = decoder.take_reasoning();
    let text = decoder.take_text();
    let mut content = Vec::new();
    if !reasoning.is_empty() {
        content.push(IrPart::Thinking { text: reasoning });
    }
    if !text.is_empty() {
        content.push(IrPart::Text(text));
    }
    for call in decoder.tool_calls() {
        let args: Value = serde_json::from_str(&call.arguments)
            .map_err(|_| ProtocolError::InvalidUpstreamResponse)?;
        if !args.is_object() {
            return Err(ProtocolError::InvalidUpstreamResponse);
        }
        content.push(IrPart::ToolCall {
            id: Some(call.id.clone()),
            name: call.name.clone(),
            args,
        });
    }
    if content.is_empty() {
        return Err(ProtocolError::InvalidUpstreamResponse);
    }
    let stop = if truncated {
        IrStop::Length
    } else if decoder.called_tools() {
        IrStop::ToolUse
    } else {
        IrStop::Stop
    };
    Ok(IrResponse {
        // Cursor's updates carry no model identity; the relay fills the
        // client body with the requested target.
        model: String::new(),
        content,
        stop,
        usage,
    })
}

/// Cursor has no inbound wire: nothing is ever parsed *from* a Cursor client.
pub fn to_ir(_body: &Value, _ceiling: u64) -> super::Parsed<IrRequest> {
    Err(ProtocolError::UnsupportedApi)
}

/// Cursor has no inbound wire: nothing is ever rendered *for* a Cursor client.
pub fn emit_response_json(_response: &IrResponse) -> Result<Vec<u8>, ProtocolError> {
    Err(ProtocolError::UnsupportedApi)
}
