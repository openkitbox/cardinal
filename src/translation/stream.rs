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
use serde_json::Value;

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
                ));
            }
            ProtocolId::Gemini | ProtocolId::OpenAiEmbeddings | ProtocolId::Kiro => {
                // Kiro is an upstream-only target: it is never a translating
                // client.
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
                        out.push(frame(
              Some("content_block_delta"),
              serde_json::json!({"type": "content_block_delta", "index": index, "delta": {"type": "text_delta", "text": delta}}),
            ));
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
                        out.push(responses_frame(
                            "response.output_text.delta",
                            serde_json::json!({
                              "item_id": message_item_id(&self.request_id, position),
                              "output_index": position,
                              "content_index": 0,
                              "delta": delta,
                            }),
                        ));
                    }
                    ProtocolId::OpenAiChat => {
                        out.push(chat_chunk(
                            &self.model,
                            serde_json::json!({"content": delta}),
                            Value::Null,
                            None,
                            None,
                        ));
                    }
                    ProtocolId::Gemini | ProtocolId::OpenAiEmbeddings | ProtocolId::Kiro => {
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
                        out.push(frame(
              Some("content_block_delta"),
              serde_json::json!({"type": "content_block_delta", "index": index, "delta": {"type": "thinking_delta", "thinking": delta}}),
            ));
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
                        out.push(responses_frame(
                            "response.reasoning_summary_text.delta",
                            serde_json::json!({
                              "item_id": reasoning_item_id(&self.request_id, position),
                              "output_index": position,
                              "summary_index": 0,
                              "delta": delta,
                            }),
                        ));
                    }
                    ProtocolId::OpenAiChat => {
                        out.push(chat_chunk(
                            &self.model,
                            serde_json::json!({"reasoning_content": delta}),
                            Value::Null,
                            None,
                            None,
                        ));
                    }
                    ProtocolId::Gemini | ProtocolId::OpenAiEmbeddings | ProtocolId::Kiro => {
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
                            out.push(responses_frame(
                                "response.function_call_arguments.delta",
                                serde_json::json!({
                                  "item_id": function_call_item_id(&self.request_id, position),
                                  "output_index": position,
                                  "delta": arguments,
                                }),
                            ));
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
                  let call_id = id.clone().unwrap_or_else(|| format!("toolu_{index:024x}"));
                  let name = name.clone().unwrap_or_default();
                  blocks.push(Block {
                    closed: false,
                    kind: BlockKind::Tool { index, call_id: call_id.clone(), name: name.clone(), arguments: String::new() },
                  });
                  out.push(frame(
                    Some("content_block_start"),
                    serde_json::json!({
                      "type": "content_block_start", "index": block_index,
                      "content_block": {"type": "tool_use", "id": call_id, "name": name, "input": {}}
                    }),
                  ));
                  block_index
                }
              };
                        if !arguments.is_empty() {
                            out.push(frame(
                Some("content_block_delta"),
                serde_json::json!({"type": "content_block_delta", "index": block_index, "delta": {"type": "input_json_delta", "partial_json": arguments}}),
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
                        out.push(chat_chunk(
              &self.model,
              serde_json::json!({
                "tool_calls": [
                  {"index": index, "id": id, "type": "function", "function": {"name": name, "arguments": arguments}}
                ]
              }),
              Value::Null,
              None,
              None,
            ));
                    }
                    ProtocolId::Gemini | ProtocolId::OpenAiEmbeddings | ProtocolId::Kiro => {
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
                let mut response = serde_json::json!({
                  "id": format!("resp_{}", self.request_id),
                  "object": "response",
                  "status": status,
                  "model": self.model,
                  "output": output,
                  "usage": usage_json,
                });
                if truncated {
                    response["incomplete_details"] =
                        serde_json::json!({"reason": "max_output_tokens"});
                }
                if failed {
                    response["error"] = serde_json::json!({"code": "upstream_error"});
                }
                out.push(responses_frame(
                    event,
                    serde_json::json!({"response": response}),
                ));
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
            ProtocolId::Gemini | ProtocolId::OpenAiEmbeddings | ProtocolId::Kiro => {
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
    out.push(frame(
    Some("content_block_start"),
    serde_json::json!({"type": "content_block_start", "index": index, "content_block": content_block}),
  ));
    index
}

fn frame(event: Option<&str>, data: serde_json::Value) -> RawFrame {
    RawFrame {
        event: event.map(str::to_owned),
        id: None,
        data: Bytes::from(serde_json::to_string(&data).unwrap_or_default()),
    }
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
fn message_item_id(request_id: &str, output_index: usize) -> String {
    format!("msg_{request_id}_{output_index}")
}

fn reasoning_item_id(request_id: &str, output_index: usize) -> String {
    format!("rs_{request_id}_{output_index}")
}

fn function_call_item_id(request_id: &str, output_index: usize) -> String {
    format!("fc_{request_id}_{output_index}")
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
) -> RawFrame {
    let mut usage = serde_json::json!({});
    if let Some(input) = input {
        usage["prompt_tokens"] = serde_json::json!(input);
    }
    if let Some(output) = output {
        usage["completion_tokens"] = serde_json::json!(output);
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

#[cfg(test)]
mod tests {
    use super::*;

    fn usage(input: u64, output: u64) -> UsageCounts {
        UsageCounts {
            input_tokens: input,
            output_tokens: output,
            ..Default::default()
        }
    }

    fn text(s: &str) -> StreamEvent {
        StreamEvent::TextDelta(s.to_owned())
    }

    fn finish() -> StreamEvent {
        StreamEvent::Finish {
            reason: "stop".to_owned(),
        }
    }

    #[test]
    fn no_usage_leaves_events_unchanged() {
        let events = vec![text("hi"), finish()];
        assert_eq!(usage_before_finish(events.clone(), None), events);
    }

    #[test]
    fn existing_usage_is_never_duplicated() {
        let events = vec![text("hi"), StreamEvent::Usage(usage(5, 6)), finish()];
        assert_eq!(
            usage_before_finish(events.clone(), Some(usage(1200, 3))),
            events
        );
    }

    #[test]
    fn usage_lands_immediately_before_finish() {
        let out = usage_before_finish(vec![text("hi"), finish()], Some(usage(1200, 3)));
        assert_eq!(
            out,
            vec![text("hi"), StreamEvent::Usage(usage(1200, 3)), finish()]
        );
    }

    #[test]
    fn usage_lands_before_the_first_of_two_finishes() {
        let out = usage_before_finish(
            vec![text("a"), text("b"), finish(), finish()],
            Some(usage(7, 8)),
        );
        assert_eq!(
            out,
            vec![
                text("a"),
                text("b"),
                StreamEvent::Usage(usage(7, 8)),
                finish(),
                finish()
            ]
        );
    }

    #[test]
    fn batch_without_finish_is_unchanged() {
        let events = vec![text("hi")];
        assert_eq!(
            usage_before_finish(events.clone(), Some(usage(1, 2))),
            events
        );
    }

    fn json_frames(frames: &[RawFrame]) -> Vec<Value> {
        frames
            .iter()
            .filter(|f| f.data.as_ref() != b"[DONE]")
            .map(|f| serde_json::from_slice(&f.data).expect("frame is JSON"))
            .collect()
    }

    fn chat_frames(events: Vec<StreamEvent>) -> Vec<RawFrame> {
        let mut t = StreamTranslator::new(ProtocolId::OpenAiChat, "m", "req").unwrap();
        t.translate(events).unwrap()
    }

    #[test]
    fn chat_finish_chunk_carries_usage_when_placed_before_finish() {
        let frames = chat_frames(usage_before_finish(
            vec![text("hi"), finish()],
            Some(usage(1200, 3)),
        ));
        assert_eq!(frames.last().unwrap().data.as_ref(), b"[DONE]");
        let chunks = json_frames(&frames);
        let finish_chunk = chunks.last().unwrap();
        assert_eq!(finish_chunk["choices"][0]["finish_reason"], "stop");
        assert_eq!(finish_chunk["usage"]["prompt_tokens"], 1200);
        assert_eq!(finish_chunk["usage"]["completion_tokens"], 3);
    }

    #[test]
    fn chat_finish_chunk_has_no_usage_key_without_evidence() {
        let frames = chat_frames(vec![text("hi"), finish()]);
        assert_eq!(frames.last().unwrap().data.as_ref(), b"[DONE]");
        let chunks = json_frames(&frames);
        let finish_chunk = chunks.last().unwrap();
        assert_eq!(finish_chunk["choices"][0]["finish_reason"], "stop");
        assert!(finish_chunk.get("usage").is_none(), "{finish_chunk}");
    }

    #[test]
    fn anthropic_message_delta_carries_output_tokens() {
        let mut t = StreamTranslator::new(ProtocolId::AnthropicMessages, "m", "req").unwrap();
        let frames = t
            .translate(usage_before_finish(
                vec![text("hi"), finish()],
                Some(usage(1200, 3)),
            ))
            .unwrap();
        let delta = frames
            .iter()
            .find(|f| f.event.as_deref() == Some("message_delta"))
            .expect("message_delta frame");
        let body: Value = serde_json::from_slice(&delta.data).unwrap();
        assert_eq!(body["usage"]["output_tokens"], 3);
    }
}
