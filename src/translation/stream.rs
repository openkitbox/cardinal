//! Cross-protocol stream transcoding.
//!
//! The upstream stream is observed through the upstream kernel's decoder; the
//! emitted [`StreamEvent`]s drive synthesis of the client protocol's frames.
//! This is an additive path: same-protocol streams keep forwarding raw bytes
//! unchanged, so nothing here can regress passthrough fidelity.

use crate::protocol::sse::RawFrame;
use crate::protocol::usage::UsageCounts;
use crate::protocol::{ProtocolId, StreamEvent, Terminal};
use bytes::Bytes;
use serde::{Serialize, Serializer};
use serde_json::{Map, Value};
use std::fmt;

/// Synthesizes client frames from upstream stream events.
///
/// One instance per client dialect. The state machine is dialect-neutral;
/// only the emitted frames differ. The synthetic ids a Responses client sees
/// live entirely on the emission side (response/message/function_call), so
/// the client protocol — not the upstream — is captured at construction.
pub struct StreamTranslator {
    client: ProtocolId,
    model: String,
    request_id: String,
    state: State,
}

enum State {
    /// Frames before the first content: the client envelope on first event.
    Open,
    /// Content is flowing; Chat deltas and Anthropic content_block_delta.
    /// `usage` keeps the last full usage record (Responses terminal frames
    /// report its details); the bare token fields serve the Chat/Anthropic arms.
    Content {
        blocks: Vec<Block>,
        input_tokens: Option<u64>,
        output_tokens: u64,
        usage: Option<Box<UsageCounts>>,
        finish: Option<String>,
    },
    /// The client stream is complete; nothing more is emitted.
    Closed,
}

/// One upstream content block. Text/arguments accumulate so the Responses
/// arm can emit full payloads in its close-time `.done` lifecycle events;
/// the Chat/Anthropic arms only read the kind.
struct Block {
    /// Responses lifecycle flag: the block's `.done` events were emitted (a
    /// block closes when the next one opens or the stream terminates).
    closed: bool,
    kind: BlockKind,
}

enum BlockKind {
    Text {
        text: String,
    },
    Thinking {
        text: String,
    },
    /// A tool call, indexed by the upstream delta's `index`; `call_id`/`name`/
    /// `arguments` are the identity and accumulated arguments the Responses
    /// `.done` payloads must echo in full.
    Tool {
        index: u32,
        call_id: String,
        name: String,
        arguments: String,
    },
}

/// Clients whose translated streams this layer can synthesize. Single source
/// of truth for the streaming gate: a translated stream for any other client
/// would emit Chat-shaped frames the client cannot read, so the pipeline
/// refuses the combination before any send instead of mis-speaking the wire.
///
/// The Responses arm synthesizes its event vocabulary from the same deltas —
/// reasoning degrades to summary text there (a chat upstream carries no
/// reasoning signatures, so a full reasoning item can never come back).
pub fn supports_translated_stream(client: ProtocolId) -> bool {
    matches!(
        client,
        ProtocolId::OpenAiChat | ProtocolId::AnthropicMessages | ProtocolId::OpenAiResponses
    )
}

impl StreamTranslator {
    /// Returns `None` for clients this layer cannot synthesize streams for;
    /// callers must have consulted [`supports_translated_stream`] first.
    pub fn new(client: ProtocolId, model: &str, request_id: &str) -> Option<Self> {
        if !supports_translated_stream(client) {
            return None;
        }
        Some(Self {
            client,
            model: model.to_owned(),
            request_id: request_id.to_owned(),
            state: State::Open,
        })
    }

    /// Feed one batch of upstream events, receiving client frames to forward.
    pub fn translate(
        &mut self,
        events: Vec<StreamEvent>,
    ) -> Result<Vec<RawFrame>, crate::protocol::ProtocolError> {
        let mut out = Vec::new();
        for event in events {
            match &mut self.state {
                State::Open => match event {
                    StreamEvent::Usage(usage) => {
                        let input = usage.input_tokens;
                        let output = usage.output_tokens;
                        self.state = content_state(Some(input));
                        if let State::Content {
                            usage: latest,
                            output_tokens,
                            ..
                        } = &mut self.state
                        {
                            *latest = Some(Box::new(usage.clone()));
                            // A usage event carries both counts; the close frame
                            // must not report a fabricated output of 0.
                            *output_tokens = output;
                        }
                        self.open_frames(&mut out, Some(usage));
                    }
                    StreamEvent::TextDelta(_)
                    | StreamEvent::ReasoningDelta(_)
                    | StreamEvent::ToolCallDelta { .. } => {
                        self.state = content_state(None);
                        self.open_frames(&mut out, None);
                        self.step(event, &mut out)?;
                    }
                    StreamEvent::Finish { reason } => {
                        self.state = content_state(None);
                        self.open_frames(&mut out, None);
                        self.close(&mut out, &StreamEvent::Finish { reason }, None)?;
                    }
                },
                State::Content { .. } => self.step(event, &mut out)?,
                State::Closed => {}
            }
        }
        Ok(out)
    }

    /// The stream ended without a `Finish` event (upstream EOF).
    pub fn close_after_eof(
        &mut self,
        terminal: Terminal,
    ) -> Result<Vec<RawFrame>, crate::protocol::ProtocolError> {
        self.close_after_eof_with(terminal, None)
    }

    /// The upstream reported an explicit output-ceiling terminal (Kiro's benign
    /// `ContentLengthExceededException`). The stream is truncated but
    /// legitimate, so it closes with the dialect's length reason instead of the
    /// generic truncation marker (which a Chat client would read as a null
    /// `finish_reason`).
    pub fn close_after_limit(&mut self) -> Result<Vec<RawFrame>, crate::protocol::ProtocolError> {
        self.close_after_eof_with(Terminal::Incomplete, Some("length"))
    }

    fn close_after_eof_with(
        &mut self,
        terminal: Terminal,
        explicit_reason: Option<&str>,
    ) -> Result<Vec<RawFrame>, crate::protocol::ProtocolError> {
        let mut out = Vec::new();
        if !matches!(self.state, State::Closed) {
            if matches!(self.state, State::Open) {
                self.state = content_state(None);
                self.open_frames(&mut out, None);
            }
            // Only a completed upstream stream may end the client stream with a
            // success stop; a truncated one closes honestly: Anthropic clients get
            // max_tokens (the stream really did stop mid-output), Chat clients get
            // a null finish_reason so no client reads it as a clean stop, and
            // Responses clients get the terminal event that matches the verdict —
            // their vocabulary has distinct completed/incomplete/failed frames.
            // An explicit ceiling is the one truncation whose reason is known.
            let reason = match explicit_reason {
                Some(reason) => reason.to_owned(),
                None if matches!(terminal, Terminal::Completed) => "stop".to_owned(),
                None => "max_tokens_truncated".to_owned(),
            };
            self.close(&mut out, &StreamEvent::Finish { reason }, Some(terminal))?;
        }
        Ok(out)
    }

    fn open_frames(&mut self, out: &mut Vec<RawFrame>, usage: Option<UsageCounts>) {
        match self.client {
            ProtocolId::AnthropicMessages => {
                let input = usage.as_ref().map(|usage| usage.input_tokens).unwrap_or(0);
                out.push(frame(
                    Some("message_start"),
                    serde_json::json!({
                      "type": "message_start",
                      "message": {
                        "id": format!("msg_{}", self.request_id),
                        "type": "message",
                        "role": "assistant",
                        "model": self.model,
                        "content": [],
                        "stop_reason": Value::Null,
                        "stop_sequence": Value::Null,
                        "usage": {"input_tokens": input, "output_tokens": 0},
                      }
                    }),
                ));
            }
            ProtocolId::OpenAiResponses => {
                // The Responses envelope announces the response object up front.
                // `sequence_number` is deliberately omitted on every synthesized
                // event: a partial sequence is worse than none (clients that validate
                // monotonicity tolerate absence, not gaps).
                out.push(responses_frame(
          "response.created",
          serde_json::json!({
            "type": "response.created",
            "response": {"id": format!("resp_{}", self.request_id), "object": "response", "status": "in_progress", "model": self.model},
          }),
        ));
            }
            ProtocolId::OpenAiChat => {
                // Chat has no envelope frame; chunks carry everything.
                out.push(chat_chunk(
                    &self.model,
                    serde_json::json!({"role": "assistant", "content": ""}),
                    Value::Null,
                    usage.as_ref().map(|usage| usage.input_tokens),
                    None,
                    None,
                ));
            }
            ProtocolId::Gemini
            | ProtocolId::OpenAiEmbeddings
            | ProtocolId::Kiro
            | ProtocolId::Cursor => {
                // Kiro and Cursor are upstream-only targets: never a
                // translating client.
                unreachable!("only the three chat protocols are translation clients")
            }
        }
    }

    fn step(
        &mut self,
        event: StreamEvent,
        out: &mut Vec<RawFrame>,
    ) -> Result<(), crate::protocol::ProtocolError> {
        match event {
            StreamEvent::TextDelta(delta) => {
                let State::Content { blocks, .. } = &mut self.state else {
                    return Ok(());
                };
                match self.client {
                    ProtocolId::AnthropicMessages => {
                        let index = block_index(
                            out,
                            blocks,
                            BlockKind::Text {
                                text: String::new(),
                            },
                        );
                        out.push(content_block_delta(index, AnthropicDelta::Text(&delta)));
                    }
                    ProtocolId::OpenAiResponses => {
                        let position = match blocks.last() {
                            Some(Block {
                                kind: BlockKind::Text { .. },
                                ..
                            }) => blocks.len() - 1,
                            _ => {
                                // The trailing open item closes when the text item opens.
                                close_responses_block(out, blocks, &self.request_id);
                                blocks.push(Block {
                                    closed: false,
                                    kind: BlockKind::Text {
                                        text: String::new(),
                                    },
                                });
                                let position = blocks.len() - 1;
                                out.push(responses_frame(
                                    "response.output_item.added",
                                    message_item_payload(&self.request_id, position),
                                ));
                                out.push(responses_frame(
                                    "response.content_part.added",
                                    serde_json::json!({
                                      "item_id": message_item_id(&self.request_id, position),
                                      "output_index": position,
                                      "content_index": 0,
                                      "part": {"type": "output_text", "text": ""},
                                    }),
                                ));
                                position
                            }
                        };
                        // Accumulate for the close-time `output_text.done` payload.
                        if let Some(Block {
                            kind: BlockKind::Text { text },
                            ..
                        }) = blocks.get_mut(position)
                        {
                            text.push_str(&delta);
                        }
                        out.push(responses_delta(ResponsesDelta {
                            content_index: Some(0),
                            delta: &delta,
                            item_id: message_item_id(&self.request_id, position),
                            output_index: position,
                            summary_index: None,
                            kind: "response.output_text.delta",
                        }));
                    }
                    ProtocolId::OpenAiChat => {
                        out.push(chat_delta_chunk(&self.model, ChatDelta::Content(&delta)));
                    }
                    ProtocolId::Gemini
                    | ProtocolId::OpenAiEmbeddings
                    | ProtocolId::Kiro
                    | ProtocolId::Cursor => {
                        unreachable!("only the three chat protocols are translation clients")
                    }
                }
            }
            StreamEvent::ReasoningDelta(delta) => {
                let State::Content { blocks, .. } = &mut self.state else {
                    return Ok(());
                };
                match self.client {
                    ProtocolId::AnthropicMessages => {
                        let index = block_index(
                            out,
                            blocks,
                            BlockKind::Thinking {
                                text: String::new(),
                            },
                        );
                        out.push(content_block_delta(index, AnthropicDelta::Thinking(&delta)));
                    }
                    ProtocolId::OpenAiResponses => {
                        // Reasoning rides its own output item, summarized (not signed):
                        // a chat upstream's reasoning carries no signature, so a full
                        // replayable reasoning item can never be synthesized — the
                        // summary_text delta vocabulary is the lossy approximation.
                        let position = match blocks.last() {
                            Some(Block {
                                kind: BlockKind::Thinking { .. },
                                ..
                            }) => blocks.len() - 1,
                            _ => {
                                close_responses_block(out, blocks, &self.request_id);
                                blocks.push(Block {
                                    closed: false,
                                    kind: BlockKind::Thinking {
                                        text: String::new(),
                                    },
                                });
                                let position = blocks.len() - 1;
                                out.push(responses_frame(
                                    "response.output_item.added",
                                    reasoning_item_payload(&self.request_id, position),
                                ));
                                out.push(responses_frame(
                                    "response.reasoning_summary_part.added",
                                    serde_json::json!({
                                      "item_id": reasoning_item_id(&self.request_id, position),
                                      "output_index": position,
                                      "summary_index": 0,
                                      "part": {"type": "summary_text", "text": ""},
                                    }),
                                ));
                                position
                            }
                        };
                        if let Some(Block {
                            kind: BlockKind::Thinking { text },
                            ..
                        }) = blocks.get_mut(position)
                        {
                            text.push_str(&delta);
                        }
                        out.push(responses_delta(ResponsesDelta {
                            content_index: None,
                            delta: &delta,
                            item_id: reasoning_item_id(&self.request_id, position),
                            output_index: position,
                            summary_index: Some(0),
                            kind: "response.reasoning_summary_text.delta",
                        }));
                    }
                    ProtocolId::OpenAiChat => {
                        out.push(chat_delta_chunk(&self.model, ChatDelta::Reasoning(&delta)));
                    }
                    ProtocolId::Gemini
                    | ProtocolId::OpenAiEmbeddings
                    | ProtocolId::Kiro
                    | ProtocolId::Cursor => {
                        unreachable!("only the three chat protocols are translation clients")
                    }
                }
            }
            StreamEvent::ToolCallDelta {
                index,
                id,
                name,
                arguments,
            } => {
                let State::Content { blocks, .. } = &mut self.state else {
                    return Ok(());
                };
                match self.client {
                    ProtocolId::OpenAiResponses => {
                        let position = blocks.iter().position(|block| matches!(&block.kind, BlockKind::Tool { index: tool, .. } if *tool == index));
                        let position = match position {
                            Some(position) => position,
                            None => {
                                // The trailing open item closes when the next call opens.
                                close_responses_block(out, blocks, &self.request_id);
                                let position = blocks.len();
                                // A delta without an id (some chat upstreams stream
                                // arguments-only) gets a deterministic synthetic call_id so
                                // the `.added`/`.done` frames of the item agree.
                                let call_id = id
                                    .filter(|id| !id.is_empty())
                                    .unwrap_or_else(|| format!("call_{position}"));
                                let name = name.unwrap_or_default();
                                blocks.push(Block {
                                    closed: false,
                                    kind: BlockKind::Tool {
                                        index,
                                        call_id: call_id.clone(),
                                        name: name.clone(),
                                        arguments: String::new(),
                                    },
                                });
                                out.push(responses_frame(
                                    "response.output_item.added",
                                    function_call_item_payload(
                                        &self.request_id,
                                        position,
                                        &call_id,
                                        &name,
                                    ),
                                ));
                                position
                            }
                        };
                        if !arguments.is_empty() {
                            if let Some(Block {
                                kind:
                                    BlockKind::Tool {
                                        arguments: accumulated,
                                        ..
                                    },
                                ..
                            }) = blocks.get_mut(position)
                            {
                                accumulated.push_str(&arguments);
                            }
                            out.push(responses_delta(ResponsesDelta {
                                content_index: None,
                                delta: &arguments,
                                item_id: function_call_item_id(&self.request_id, position),
                                output_index: position,
                                summary_index: None,
                                kind: "response.function_call_arguments.delta",
                            }));
                        }
                    }
                    ProtocolId::AnthropicMessages => {
                        // Anthropic streams tool input as partial JSON inside one block.
                        let block_index =
              match blocks.iter().position(|block| matches!(&block.kind, BlockKind::Tool { index: tool, .. } if *tool == index)) {
                Some(position) => u32::try_from(position).unwrap_or(u32::MAX),
                None => {
                  if !blocks.is_empty() {
                    let last_index = u32::try_from(blocks.len().saturating_sub(1)).unwrap_or(u32::MAX);
                    out.push(frame(Some("content_block_stop"), serde_json::json!({"type": "content_block_stop", "index": last_index})));
                  }
                  let block_index = u32::try_from(blocks.len()).unwrap_or(u32::MAX);
                  let call_id = id.unwrap_or_else(|| format!("toolu_{index:024x}"));
                  let name = name.unwrap_or_default();
                  blocks.push(Block {
                    closed: false,
                    kind: BlockKind::Tool { index, call_id: call_id.clone(), name: name.clone(), arguments: String::new() },
                  });
                  let mut content_block = Map::new();
                  content_block.insert("type".to_owned(), Value::from("tool_use"));
                  content_block.insert("id".to_owned(), Value::String(call_id));
                  content_block.insert("name".to_owned(), Value::String(name));
                  content_block.insert("input".to_owned(), Value::Object(Map::new()));
                  out.push(content_block_start(block_index, Value::Object(content_block)));
                  block_index
                }
              };
                        if !arguments.is_empty() {
                            out.push(content_block_delta(
                                block_index,
                                AnthropicDelta::InputJson(&arguments),
                            ));
                        }
                    }
                    ProtocolId::OpenAiChat => {
                        // SH-04: emit the tool identity only on the first delta for this
                        // call. Repeating id/name every frame breaks naive clients that
                        // concatenate function arguments verbatim (native OpenAI streams
                        // carry identity once, then arguments-only deltas).
                        let known = blocks.iter().any(|block| matches!(&block.kind, BlockKind::Tool { index: tool_index, .. } if *tool_index == index));
                        if !known {
                            blocks.push(Block {
                                closed: false,
                                kind: BlockKind::Tool {
                                    index,
                                    call_id: String::new(),
                                    name: String::new(),
                                    arguments: String::new(),
                                },
                            });
                        }
                        let (id, name) = if known { (None, None) } else { (id, name) };
                        out.push(chat_delta_chunk(
                            &self.model,
                            ChatDelta::ToolCall(ChatToolCall {
                                function: ChatFunction {
                                    arguments: &arguments,
                                    name: name.as_deref(),
                                },
                                id: id.as_deref(),
                                index,
                                kind: "function",
                            }),
                        ));
                    }
                    ProtocolId::Gemini
                    | ProtocolId::OpenAiEmbeddings
                    | ProtocolId::Kiro
                    | ProtocolId::Cursor => {
                        unreachable!("only the three chat protocols are translation clients")
                    }
                }
            }
            StreamEvent::Usage(usage) => {
                let State::Content {
                    input_tokens,
                    output_tokens,
                    usage: latest,
                    ..
                } = &mut self.state
                else {
                    return Ok(());
                };
                *input_tokens = Some(usage.input_tokens);
                *output_tokens = usage.output_tokens;
                *latest = Some(Box::new(usage));
            }
            StreamEvent::Finish { reason } => {
                self.close(out, &StreamEvent::Finish { reason }, None)?
            }
        }
        Ok(())
    }

    fn close(
        &mut self,
        out: &mut Vec<RawFrame>,
        finish: &StreamEvent,
        eof: Option<Terminal>,
    ) -> Result<(), crate::protocol::ProtocolError> {
        let State::Content {
            input_tokens,
            output_tokens,
            usage,
            finish: pending,
            blocks,
            ..
        } = &mut self.state
        else {
            self.state = State::Closed;
            return Ok(());
        };
        if let StreamEvent::Finish { reason } = finish {
            *pending = Some(reason.clone());
        }
        let reason = pending.clone().unwrap_or_else(|| "stop".to_owned());
        match self.client {
            ProtocolId::OpenAiResponses => {
                // Every open item gets its lifecycle close: the `.done` events carry
                // the FULL item (accumulated text / arguments), because materializing
                // clients (codex et al.) rebuild history from them, not from deltas.
                close_responses_block(out, blocks, &self.request_id);
                // The terminal `response` object replays the items in final form.
                let output: Vec<Value> = blocks
                    .iter()
                    .enumerate()
                    .map(|(index, block)| final_item_payload(&self.request_id, index, &block.kind))
                    .collect();
                let input = input_tokens.unwrap_or(0);
                let output_tokens = *output_tokens;
                // Terminal honesty: an EOF verdict wins over the synthesized reason
                // (Responses has the vocabulary for it — unlike Chat/Anthropic, whose
                // arms keep their historical null-finish/max_tokens conventions).
                let failed = matches!(eof, Some(Terminal::Failed));
                let truncated = !failed
                    && (matches!(
                        reason.as_str(),
                        "length" | "max_tokens" | "max_tokens_truncated" | "truncated"
                    ) || matches!(eof, Some(Terminal::Incomplete)));
                let (event, status) = if failed {
                    ("response.failed", "failed")
                } else if truncated {
                    ("response.incomplete", "incomplete")
                } else {
                    ("response.completed", "completed")
                };
                // Details objects appear only when a real value was observed upstream
                // — a fabricated zero is worse than absence (the non-streaming arm
                // applies the same rule).
                let mut usage_json = serde_json::json!({
                  "input_tokens": input,
                  "output_tokens": output_tokens,
                  "total_tokens": input.saturating_add(output_tokens),
                });
                if let Some(usage) = usage.as_deref() {
                    if let Some(cached) = usage.cached_input_tokens {
                        usage_json["input_tokens_details"] =
                            serde_json::json!({"cached_tokens": cached});
                    }
                    if let Some(reasoning) = usage.reasoning_output_tokens {
                        usage_json["output_tokens_details"] =
                            serde_json::json!({"reasoning_tokens": reasoning});
                    }
                }
                // Owned `output`/`usage` move into the maps; `json!` would deep-copy
                // every accumulated item a second time.
                let mut response = Map::new();
                response.insert(
                    "id".to_owned(),
                    Value::String(format!("resp_{}", self.request_id)),
                );
                response.insert("object".to_owned(), Value::from("response"));
                response.insert("status".to_owned(), Value::from(status));
                response.insert("model".to_owned(), Value::String(self.model.clone()));
                response.insert("output".to_owned(), Value::Array(output));
                response.insert("usage".to_owned(), usage_json);
                if truncated {
                    response.insert(
                        "incomplete_details".to_owned(),
                        serde_json::json!({"reason": "max_output_tokens"}),
                    );
                }
                if failed {
                    response.insert(
                        "error".to_owned(),
                        serde_json::json!({"code": "upstream_error"}),
                    );
                }
                let mut payload = Map::new();
                payload.insert("response".to_owned(), Value::Object(response));
                out.push(responses_frame(event, Value::Object(payload)));
            }
            ProtocolId::AnthropicMessages => {
                // Every announced block gets its stop before the message envelope.
                let last_index = u32::try_from(blocks.len().saturating_sub(1)).unwrap_or(u32::MAX);
                if !blocks.is_empty() {
                    out.push(frame(
                        Some("content_block_stop"),
                        serde_json::json!({"type": "content_block_stop", "index": last_index}),
                    ));
                }
                out.push(frame(
          Some("message_delta"),
          serde_json::json!({
            "type": "message_delta",
            "delta": {"stop_reason": stop_anthropic_name(&reason), "stop_sequence": Value::Null},
            "usage": {"output_tokens": *output_tokens},
          }),
        ));
                out.push(frame(
                    Some("message_stop"),
                    serde_json::json!({"type": "message_stop"}),
                ));
            }
            ProtocolId::OpenAiChat => {
                let finish_reason = stop_chat_name(&reason);
                let finish_reason = if finish_reason.is_empty() {
                    Value::Null
                } else {
                    serde_json::json!(finish_reason)
                };
                // Usage is evidence, not a shape to fill: only a Usage event
                // licenses a usage object. Kiro's estimate is licensed by the
                // pump injecting it ahead of `Finish` (`usage_before_finish`);
                // with no estimate the field is still omitted entirely —
                // `{"completion_tokens":0}` reads as a measured free request
                // and mis-bills it.
                let usage_seen = usage.is_some() || input_tokens.is_some();
                out.push(chat_chunk(
                    &self.model,
                    Value::Null,
                    finish_reason,
                    if usage_seen { *input_tokens } else { None },
                    if usage_seen {
                        Some(*output_tokens)
                    } else {
                        None
                    },
                    usage.as_ref().and_then(|usage| usage.cached_input_tokens),
                ));
                // SH-02: `[DONE]` is an SSE framing marker, not JSON — the wire must
                // carry `data: [DONE]` (no quotes). JSON-serializing a string value
                // produced `data: "[DONE]"`, which Chat clients reject.
                out.push(RawFrame {
                    event: None,
                    id: None,
                    data: Bytes::from_static(b"[DONE]"),
                });
            }
            ProtocolId::Gemini
            | ProtocolId::OpenAiEmbeddings
            | ProtocolId::Kiro
            | ProtocolId::Cursor => {
                unreachable!("only the three chat protocols are translation clients")
            }
        }
        self.state = State::Closed;
        Ok(())
    }
}

fn content_state(input_tokens: Option<u64>) -> State {
    State::Content {
        blocks: Vec::new(),
        input_tokens,
        output_tokens: 0,
        usage: None,
        finish: None,
    }
}

/// Resolve the index for `kind`, emitting a `content_block_start` when the
/// block is new or the previous block of a different kind must be closed.
fn block_index(out: &mut Vec<RawFrame>, blocks: &mut Vec<Block>, kind: BlockKind) -> u32 {
    if matches!(blocks.last(), Some(existing) if std::mem::discriminant(&existing.kind) == std::mem::discriminant(&kind))
    {
        return u32::try_from(blocks.len().saturating_sub(1)).unwrap_or(0);
    }
    // Switching kinds closes the previous block first: interleaved
    // reasoning and text each get their own well-formed block run.
    if !blocks.is_empty() {
        let index = u32::try_from(blocks.len().saturating_sub(1)).unwrap_or(u32::MAX);
        out.push(frame(
            Some("content_block_stop"),
            serde_json::json!({"type": "content_block_stop", "index": index}),
        ));
    }
    let index = u32::try_from(blocks.len()).unwrap_or(u32::MAX);
    let content_block = match &kind {
        BlockKind::Text { .. } => serde_json::json!({"type": "text", "text": ""}),
        BlockKind::Thinking { .. } => serde_json::json!({"type": "thinking", "thinking": ""}),
        BlockKind::Tool { .. } => {
            serde_json::json!({"type": "tool_use", "id": "", "name": "", "input": {}})
        }
    };
    blocks.push(Block {
        closed: false,
        kind,
    });
    out.push(content_block_start(index, content_block));
    index
}

/// Anthropic `content_block_start`; the owned block moves into the payload.
fn content_block_start(index: u32, content_block: Value) -> RawFrame {
    let mut payload = Map::new();
    payload.insert("type".to_owned(), Value::from("content_block_start"));
    payload.insert("index".to_owned(), Value::from(index));
    payload.insert("content_block".to_owned(), content_block);
    frame(Some("content_block_start"), Value::Object(payload))
}

fn frame(event: Option<&str>, data: serde_json::Value) -> RawFrame {
    RawFrame {
        event: event.map(str::to_owned),
        id: None,
        data: Bytes::from(serde_json::to_string(&data).unwrap_or_default()),
    }
}

/// Serializes a borrowed per-delta payload straight into the frame bytes, so
/// the delta text is copied once (into the output buffer). Same fallback as
/// [`frame`]: an unserializable payload yields an empty data field.
fn serialized_frame(event: Option<&str>, data: &impl Serialize) -> RawFrame {
    RawFrame {
        event: event.map(str::to_owned),
        id: None,
        data: Bytes::from(serde_json::to_vec(data).unwrap_or_default()),
    }
}

// Per-delta hot frames. `serde_json` is built without `preserve_order`, so the
// `json!` objects these replace serialized their keys in sorted order: every
// struct below declares its fields in that order, keeping the bytes identical.

/// Anthropic `content_block_delta`: `{"delta":..,"index":..,"type":..}`.
#[derive(Serialize)]
struct ContentBlockDelta<'a> {
    delta: AnthropicDelta<'a>,
    index: u32,
    #[serde(rename = "type")]
    kind: &'static str,
}

/// The inner Anthropic delta: one payload key plus `type` (every payload key
/// sorts before `type`).
enum AnthropicDelta<'a> {
    Text(&'a str),
    Thinking(&'a str),
    InputJson(&'a str),
}

impl Serialize for AnthropicDelta<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let (key, value, kind) = match self {
            Self::Text(text) => ("text", text, "text_delta"),
            Self::Thinking(text) => ("thinking", text, "thinking_delta"),
            Self::InputJson(text) => ("partial_json", text, "input_json_delta"),
        };
        let mut map = serializer.serialize_map(Some(2))?;
        map.serialize_entry(key, value)?;
        map.serialize_entry("type", kind)?;
        map.end()
    }
}

fn content_block_delta(index: u32, delta: AnthropicDelta<'_>) -> RawFrame {
    serialized_frame(
        Some("content_block_delta"),
        &ContentBlockDelta {
            delta,
            index,
            kind: "content_block_delta",
        },
    )
}

/// Responses `*.delta` payload; `type` mirrors the SSE event name, as
/// [`responses_frame`] writes it.
#[derive(Serialize)]
struct ResponsesDelta<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    content_index: Option<u8>,
    delta: &'a str,
    item_id: ItemId<'a>,
    output_index: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    summary_index: Option<u8>,
    #[serde(rename = "type")]
    kind: &'static str,
}

fn responses_delta(payload: ResponsesDelta<'_>) -> RawFrame {
    serialized_frame(Some(payload.kind), &payload)
}

/// Chat `chat.completion.chunk` carrying one delta and no usage.
#[derive(Serialize)]
struct ChatDeltaChunk<'a> {
    choices: [ChatChoice<'a>; 1],
    id: &'static str,
    model: &'a str,
    object: &'static str,
}

#[derive(Serialize)]
struct ChatChoice<'a> {
    delta: ChatDelta<'a>,
    /// Always `null` on a delta chunk.
    finish_reason: Option<&'static str>,
    index: u8,
}

/// The Chat `delta` object: a single key.
enum ChatDelta<'a> {
    Content(&'a str),
    Reasoning(&'a str),
    ToolCall(ChatToolCall<'a>),
}

impl Serialize for ChatDelta<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(1))?;
        match self {
            Self::Content(text) => map.serialize_entry("content", text)?,
            Self::Reasoning(text) => map.serialize_entry("reasoning_content", text)?,
            Self::ToolCall(call) => {
                map.serialize_entry("tool_calls", std::slice::from_ref(call))?
            }
        }
        map.end()
    }
}

/// `{"function":{..},"id":..,"index":..,"type":"function"}`; an absent
/// identity serializes as `null`, as the `json!` form did.
#[derive(Serialize)]
struct ChatToolCall<'a> {
    function: ChatFunction<'a>,
    id: Option<&'a str>,
    index: u32,
    #[serde(rename = "type")]
    kind: &'static str,
}

#[derive(Serialize)]
struct ChatFunction<'a> {
    arguments: &'a str,
    name: Option<&'a str>,
}

fn chat_delta_chunk<'a>(model: &'a str, delta: ChatDelta<'a>) -> RawFrame {
    serialized_frame(
        None,
        &ChatDeltaChunk {
            choices: [ChatChoice {
                delta,
                finish_reason: None,
                index: 0,
            }],
            id: "chatcmpl-xh",
            model,
            object: "chat.completion.chunk",
        },
    )
}

/// Responses emission: the payload carries its own `type` (mirroring the SSE
/// event name), as native Responses streams do.
fn responses_frame(event: &str, mut payload: Value) -> RawFrame {
    payload["type"] = Value::String(event.to_owned());
    frame(Some(event), payload)
}

/// Responses emission: emit the closing lifecycle events for a trailing open
/// item — text/summary/arguments `.done` plus `output_item.done`, each with
/// the FULL accumulated payload. Materializing clients (codex et al.) rebuild
/// history from these frames, so they are load-bearing, not ceremonial.
/// Only trailing state can be open, so a superseded block closes exactly once.
fn close_responses_block(out: &mut Vec<RawFrame>, blocks: &mut [Block], request_id: &str) {
    if blocks.last().is_none_or(|block| block.closed) {
        return;
    }
    let output_index = blocks.len() - 1;
    let Some(block) = blocks.last_mut() else {
        return;
    };
    block.closed = true;
    match &block.kind {
        BlockKind::Text { text } => {
            let item_id = message_item_id(request_id, output_index);
            out.push(responses_frame(
        "response.output_text.done",
        serde_json::json!({"item_id": item_id, "output_index": output_index, "content_index": 0, "text": text}),
      ));
            out.push(responses_frame(
        "response.content_part.done",
        serde_json::json!({"item_id": item_id, "output_index": output_index, "content_index": 0, "part": {"type": "output_text", "text": text}}),
      ));
            out.push(responses_frame(
        "response.output_item.done",
        serde_json::json!({
          "output_index": output_index,
          "item": {"id": item_id, "type": "message", "status": "completed", "role": "assistant", "content": [{"type": "output_text", "text": text}]},
        }),
      ));
        }
        BlockKind::Thinking { text } => {
            let item_id = reasoning_item_id(request_id, output_index);
            out.push(responses_frame(
        "response.reasoning_summary_text.done",
        serde_json::json!({"item_id": item_id, "output_index": output_index, "summary_index": 0, "text": text}),
      ));
            out.push(responses_frame(
        "response.output_item.done",
        serde_json::json!({
          "output_index": output_index,
          "item": {"id": item_id, "type": "reasoning", "summary": [{"type": "summary_text", "text": text}]},
        }),
      ));
        }
        BlockKind::Tool {
            call_id,
            name,
            arguments,
            ..
        } => {
            let item_id = function_call_item_id(request_id, output_index);
            out.push(responses_frame(
        "response.function_call_arguments.done",
        serde_json::json!({"item_id": item_id, "output_index": output_index, "arguments": arguments}),
      ));
            out.push(responses_frame(
        "response.output_item.done",
        serde_json::json!({
          "output_index": output_index,
          "item": {"id": item_id, "type": "function_call", "status": "completed", "call_id": call_id, "name": name, "arguments": arguments},
        }),
      ));
        }
    }
}

/// The final form of one output item, as replayed in the terminal
/// `response.completed`/`incomplete`/`failed` object's `output` array.
fn final_item_payload(request_id: &str, output_index: usize, kind: &BlockKind) -> Value {
    match kind {
        BlockKind::Text { text } => serde_json::json!({
          "id": message_item_id(request_id, output_index),
          "type": "message",
          "status": "completed",
          "role": "assistant",
          "content": [{"type": "output_text", "text": text}],
        }),
        BlockKind::Thinking { text } => serde_json::json!({
          "id": reasoning_item_id(request_id, output_index),
          "type": "reasoning",
          "summary": [{"type": "summary_text", "text": text}],
        }),
        BlockKind::Tool {
            call_id,
            name,
            arguments,
            ..
        } => serde_json::json!({
          "id": function_call_item_id(request_id, output_index),
          "type": "function_call",
          "status": "completed",
          "call_id": call_id,
          "name": name,
          "arguments": arguments,
        }),
    }
}

/// Synthetic item ids are deterministic in (response, output index) so the
/// `.added`/`.delta`/`.done` frames of one item agree with each other.
fn message_item_id(request_id: &str, output_index: usize) -> ItemId<'_> {
    ItemId {
        prefix: "msg",
        request_id,
        output_index,
    }
}

fn reasoning_item_id(request_id: &str, output_index: usize) -> ItemId<'_> {
    ItemId {
        prefix: "rs",
        request_id,
        output_index,
    }
}

fn function_call_item_id(request_id: &str, output_index: usize) -> ItemId<'_> {
    ItemId {
        prefix: "fc",
        request_id,
        output_index,
    }
}

/// `{prefix}_{request_id}_{output_index}`, rendered at serialization time so
/// a delta frame does not allocate the id first.
struct ItemId<'a> {
    prefix: &'static str,
    request_id: &'a str,
    output_index: usize,
}

impl fmt::Display for ItemId<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}_{}_{}",
            self.prefix, self.request_id, self.output_index
        )
    }
}

impl Serialize for ItemId<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

fn message_item_payload(request_id: &str, output_index: usize) -> Value {
    serde_json::json!({
      "output_index": output_index,
      "item": {"id": message_item_id(request_id, output_index), "type": "message", "status": "in_progress", "role": "assistant", "content": []},
    })
}

fn reasoning_item_payload(request_id: &str, output_index: usize) -> Value {
    serde_json::json!({
      "output_index": output_index,
      "item": {"id": reasoning_item_id(request_id, output_index), "type": "reasoning", "summary": []},
    })
}

fn function_call_item_payload(
    request_id: &str,
    output_index: usize,
    call_id: &str,
    name: &str,
) -> Value {
    serde_json::json!({
      "output_index": output_index,
      "item": {
        "id": function_call_item_id(request_id, output_index),
        "type": "function_call",
        "status": "in_progress",
        "call_id": call_id,
        "name": name,
        "arguments": "",
      },
    })
}

fn chat_chunk(
    model: &str,
    delta: serde_json::Value,
    finish_reason: serde_json::Value,
    input: Option<u64>,
    output: Option<u64>,
    cached: Option<u64>,
) -> RawFrame {
    let mut usage = serde_json::json!({});
    if let Some(input) = input {
        usage["prompt_tokens"] = serde_json::json!(input);
    }
    if let Some(output) = output {
        usage["completion_tokens"] = serde_json::json!(output);
    }
    if let Some(cached) = cached {
        usage["prompt_tokens_details"] = serde_json::json!({"cached_tokens": cached});
    }
    let chunk = serde_json::json!({
      "id": "chatcmpl-xh",
      "object": "chat.completion.chunk",
      "model": model,
      "choices": [
        {"index": 0, "delta": delta, "finish_reason": finish_reason}
      ],
    });
    let mut chunk = chunk;
    if usage.as_object().is_some_and(|usage| !usage.is_empty()) {
        chunk["usage"] = usage;
    }
    frame(None, chunk)
}

fn stop_anthropic_name(reason: &str) -> &'static str {
    match reason {
        "max_tokens" | "length" | "max_tokens_truncated" => "max_tokens",
        "tool_calls" | "tool_use" | "function_call" => "tool_use",
        _ => "end_turn",
    }
}

/// The truncation marker keeps the finish_reason null on the wire: a Chat
/// client must not read a truncated upstream as a clean stop.
fn stop_chat_name(reason: &str) -> &'static str {
    match reason {
        "max_tokens" | "length" => "length",
        "tool_calls" | "tool_use" | "function_call" => "tool_calls",
        "max_tokens_truncated" => "",
        _ => "stop",
    }
}

/// Places `usage` immediately before the first `Finish` of a batch.
///
/// A Kiro (KAS) upstream reports its usage estimate only after the terminal
/// event, so the translator would close the client stream (finish chunk and
/// `[DONE]`) before any `Usage` exists. Moving the estimate in front of the
/// `Finish` lets the close frame carry it. See
/// `2026-10-30-kiro-stream-usage-to-client.md` in the plans directory.
///
/// Unchanged when `usage` is `None`, when the batch already holds a `Usage`,
/// or when it holds no `Finish`.
pub(crate) fn usage_before_finish(
    mut events: Vec<StreamEvent>,
    usage: Option<UsageCounts>,
) -> Vec<StreamEvent> {
    let Some(usage) = usage else {
        return events;
    };
    if events.iter().any(|e| matches!(e, StreamEvent::Usage(_))) {
        return events;
    }
    if let Some(at) = events
        .iter()
        .position(|e| matches!(e, StreamEvent::Finish { .. }))
    {
        events.insert(at, StreamEvent::Usage(usage));
    }
    events
}
