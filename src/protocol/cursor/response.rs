//! The Cursor downlink: `AgentServerMessage` frames → [`StreamEvent`]s, usage
//! and the Run's terminal verdict.
//!
//! Each reader of a Run has a [`StreamDecoder`] of its own: the translated
//! relay pump (`Decoder::Cursor`), which turns the frames into the events the
//! client sees; the Run driver (`upstream::cursor_run`), which needs to know
//! when the Run is over so it can close both HTTP legs and report the sizes
//! it produced; and [`aggregate`], which decodes a whole buffered body for the
//! non-streaming path. The pump and the driver read the same live frames
//! through two instances rather than one shared decoder deliberately: the
//! driver must reach its verdict whether or not anyone is still reading, and
//! the two have different lifetimes. Both see the same bytes, so both reach
//! the same verdict. Only the pump reads events; the driver's decoder and
//! [`aggregate`]'s run under [`Emission::Silent`], which keeps the state and
//! skips the events.
//!
//! A stateless Run (plan D2) ends in exactly one of these ways:
//!
//! * `turn_ended` (`InteractionUpdate#14`) with no tool call in the step —
//!   the model answered; the update carries the only inline usage Cursor
//!   ever sends;
//! * the step's tool calls are complete: Cursor lists how many calls the step
//!   makes (`#27`) before or after sending them as `exec_server_message#11`,
//!   and once every listed call has either come as an exec, been answered
//!   here (an MCP catalogue or environment query, a refused built-in) or been
//!   completed by Cursor itself, the step is done and the caller runs the
//!   tools. There is no inline usage for such a step (plan §2.8);
//! * a checkpoint (`#3`) whose `pending_tool_calls` are exactly the calls
//!   handed out, after the count — Cursor is waiting on the caller;
//! * the Connect end frame: `{}` is a clean end (an empty one when nothing
//!   was said is an error — the model produced nothing), `{"error": …}` is
//!   mapped to a [`ProtocolError`] by [`map_failure`].
//!
//! Everything unknown is skipped: a new field or update kind must not break
//! the stream (plan §4 invariant). A malformed frame is terminal, as it is for
//! the AWS wire: the length prefix just proved untrustworthy.

use std::collections::HashSet;

use serde_json::Value;

use super::connect::Frame;
use super::pb::{self, FieldValue, Reader};
use super::{CursorError, msg};
use crate::protocol::usage::UsageCounts;
use crate::protocol::{ProtocolError, StreamEvent, Terminal};

/// Whether a [`StreamDecoder`] keeps the accumulated text and reasoning.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Retention {
    /// Streamed: content leaves as delta events; only counts are kept.
    #[default]
    CountsOnly,
    /// Buffered ([`aggregate`]): the text and reasoning are kept for the IR.
    Full,
}

/// Whether a [`StreamDecoder`] builds the [`StreamEvent`]s its state implies.
///
/// A reader that consults only the decoder's state — whether the Run is over,
/// how it failed, what it counted and collected — would otherwise allocate a
/// `String` per text and reasoning delta, and copies per tool call, and drop
/// them unread. Under [`Emission::Silent`] no event is built: the counters,
/// the retained content, the tool tracking and every state transition happen
/// as they do under [`Emission::Events`], and [`StreamDecoder::observe`]
/// returns no events.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Emission {
    /// The events are read (the relay pump turns them into client frames).
    #[default]
    Events,
    /// Only the decoder's state is read: no event is built.
    Silent,
}

/// One tool call the model made: a `CallDynamicTool` exec, decoded to the
/// caller's tool name and its JSON arguments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToolCall {
    pub id: String,
    pub name: String,
    /// The arguments as one serialized JSON object.
    pub arguments: String,
}

/// How a Run's end frame failed, already reduced to the platform's taxonomy
/// plus the vendor's words for the attempt log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Failure {
    pub error: ProtocolError,
    /// The HTTP status the reference implementation maps the failure to; the
    /// relay's failover reads it like an upstream status.
    pub status: u16,
    /// The vendor's message, bounded. Never a token: Cursor's error bodies
    /// carry codes and prose.
    pub message: String,
}

/// Longest vendor message kept from an end frame.
const MAX_FAILURE_MESSAGE: usize = 400;

/// What one exec ask was, as the decoder classifies it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExecKind {
    /// `mcp_args` — a call of the caller's tools.
    ToolCall,
    /// Something the uplink answers in full (the MCP tool list, a refused
    /// built-in). Cursor counts such a call toward the step's total.
    Answered,
    /// `request_context_args` — an environment query. Cursor does **not**
    /// count it as a call.
    Context,
}

/// The Run state machine: one instance per Run.
#[derive(Debug, Default)]
pub struct StreamDecoder {
    retention: Retention,
    emission: Emission,
    text: String,
    reasoning: String,
    text_chars: usize,
    reasoning_chars: usize,
    tools: Vec<ToolCall>,
    /// Characters of tool arguments, for the output estimate.
    argument_chars: usize,
    /// `#27`: how many calls the step makes. `None` until Cursor says.
    listed: Option<u64>,
    /// Whether `#27` came after the latest call update or exec: a checkpoint
    /// that waits on exactly our calls then ends the step.
    listed_after: bool,
    /// Calls answered by the uplink (never handed to the caller).
    answered: u64,
    /// Calls the model wrote (`#7`) in this step, by id.
    partial: HashSet<String>,
    /// Calls that started on the client side (`#2`), by id.
    started: HashSet<String>,
    /// Ids seen inside an exec's args: an exec'd call is never "completed by
    /// Cursor" even when `#3` arrives before its exec.
    exec_ids: HashSet<String>,
    /// Calls completed by Cursor itself (`#3` with no exec and no start).
    by_cursor: HashSet<String>,
    turn_ended: bool,
    /// `#14`: the turn's total, and the only inline usage Cursor sends.
    turn_usage: Option<UsageCounts>,
    /// The step is over (any of the module-level terminal conditions).
    done: bool,
    /// The end frame arrived cleanly after (or as) the terminal.
    end_seen: bool,
    failure: Option<Failure>,
    /// A frame could not be read: every later frame is refused.
    broken: bool,
}

impl StreamDecoder {
    #[must_use]
    pub fn new(retention: Retention) -> Self {
        Self {
            retention,
            ..Self::default()
        }
    }

    /// A decoder for a reader that only consults the state: the Run driver
    /// (the terminal verdict, the failure, the report's counts) and
    /// [`aggregate`] (the buffered body's content, tool calls and usage).
    /// Neither looks at an event.
    #[must_use]
    pub fn silent(retention: Retention) -> Self {
        Self {
            retention,
            emission: Emission::Silent,
            ..Self::default()
        }
    }

    /// Whether this decoder builds events at all.
    fn emits(&self) -> bool {
        self.emission == Emission::Events
    }

    /// Observe one Connect frame.
    ///
    /// After the Run is [`Self::done`], further content frames are ignored (a
    /// stateless Run is closed by the client; Cursor may still send a
    /// checkpoint or a heartbeat before it notices). A malformed frame or a
    /// failing end frame is an error and marks the decoder broken.
    pub fn observe(&mut self, frame: &Frame) -> Result<Vec<StreamEvent>, ProtocolError> {
        if self.broken {
            return Err(ProtocolError::InvalidUpstreamResponse);
        }
        if frame.is_end() {
            return self.observe_end(&frame.payload);
        }
        if self.done {
            return Ok(Vec::new());
        }
        match self.observe_message(&frame.payload) {
            Ok(events) => {
                if let Some(failure) = &self.failure {
                    // An empty reply noticed mid-stream (`turn_ended` with
                    // nothing said and nothing called).
                    self.broken = true;
                    return Err(failure.error);
                }
                Ok(events)
            }
            Err(error) => {
                self.broken = true;
                tracing::warn!(%error, "Cursor server message could not be read");
                Err(ProtocolError::InvalidUpstreamResponse)
            }
        }
    }

    /// The Connect end frame: `{}` or `{"error": {...}}`.
    fn observe_end(&mut self, payload: &[u8]) -> Result<Vec<StreamEvent>, ProtocolError> {
        self.end_seen = true;
        if let Some(failure) = parse_end_frame(payload) {
            self.broken = true;
            let error = failure.error;
            self.failure = Some(failure);
            return Err(error);
        }
        if self.done {
            return Ok(Vec::new());
        }
        // A clean end before any terminal: Cursor ended the stream itself. With
        // text or calls it is a finished turn; with nothing (thinking alone
        // included) it is an empty reply, which the caller must ask again for.
        if self.empty_reply() {
            self.broken = true;
            self.failure = Some(Failure {
                error: ProtocolError::UpstreamError,
                status: 502,
                message: "an empty reply: the Run ended with no text and no tool call".to_owned(),
            });
            return Err(ProtocolError::UpstreamError);
        }
        Ok(self.finish_step())
    }

    /// Nothing the caller could use: no text and no tool call (reasoning alone
    /// is not an answer).
    fn empty_reply(&self) -> bool {
        self.text_chars == 0 && self.tools.is_empty()
    }

    fn observe_message(&mut self, payload: &[u8]) -> Result<Vec<StreamEvent>, CursorError> {
        let mut events = Vec::new();
        for field in Reader::new(payload) {
            let field = field?;
            let FieldValue::Bytes(body) = field.value else {
                continue;
            };
            match field.number {
                msg::SERVER_INTERACTION_UPDATE => self.observe_update(body, &mut events)?,
                msg::SERVER_EXEC => self.observe_exec(body, &mut events)?,
                msg::SERVER_CHECKPOINT => self.observe_checkpoint(body, &mut events)?,
                // KV, exec control, interaction queries, ttft: the uplink
                // answers what needs answering; nothing here is content.
                _ => {}
            }
            if self.done {
                break;
            }
        }
        Ok(events)
    }

    fn observe_update(
        &mut self,
        body: &[u8],
        events: &mut Vec<StreamEvent>,
    ) -> Result<(), CursorError> {
        for field in Reader::new(body) {
            let field = field?;
            let FieldValue::Bytes(update) = field.value else {
                continue;
            };
            match field.number {
                msg::UPDATE_TEXT_DELTA => {
                    let text = first_string(update, msg::DELTA_TEXT)?;
                    if !text.is_empty() {
                        self.text_chars += text.chars().count();
                        if self.retention == Retention::Full {
                            self.text.push_str(text);
                        }
                        if self.emits() {
                            events.push(StreamEvent::TextDelta(text.to_owned()));
                        }
                    }
                }
                msg::UPDATE_THINKING_DELTA => {
                    let text = first_string(update, msg::DELTA_TEXT)?;
                    if !text.is_empty() {
                        self.reasoning_chars += text.chars().count();
                        if self.retention == Retention::Full {
                            self.reasoning.push_str(text);
                        }
                        if self.emits() {
                            events.push(StreamEvent::ReasoningDelta(text.to_owned()));
                        }
                    }
                }
                msg::UPDATE_TURN_ENDED => {
                    // A turn that ends without counters leaves `turn_usage`
                    // unset, so the dashboard (or an estimate) still speaks
                    // for the Run.
                    if let Some(usage) = decode_turn_usage(update)? {
                        self.turn_usage = Some(usage);
                    }
                    self.turn_ended = true;
                    if self.tools.is_empty() {
                        if self.empty_reply() {
                            // Nothing written and nothing called: an empty
                            // reply, not a finished turn.
                            self.failure = Some(Failure {
                                error: ProtocolError::UpstreamError,
                                status: 502,
                                message: "an empty reply: Cursor ended the turn with no text and no tool call".to_owned(),
                            });
                            return Ok(());
                        }
                        events.extend(self.finish_step());
                        return Ok(());
                    }
                }
                msg::UPDATE_TOOL_REQUESTS_LISTED => {
                    self.listed = Some(first_varint(update, msg::LISTED_CALL_COUNT)?);
                    self.listed_after = true;
                    if self.step_done() {
                        events.extend(self.finish_step());
                        return Ok(());
                    }
                }
                msg::UPDATE_TOOL_CALL_STARTED
                | msg::UPDATE_TOOL_CALL_COMPLETED
                | msg::UPDATE_PARTIAL_TOOL_CALL => {
                    self.listed_after = false;
                    let id = first_string(update, msg::TOOL_CALL_ID)?;
                    if self.note_call_update(field.number, id) && self.step_done() {
                        events.extend(self.finish_step());
                        return Ok(());
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Track one tool-call lifecycle update; `true` when Cursor completed a
    /// call of this step by itself (a call the model wrote, completed with no
    /// client start and no exec), which counts toward the listed total.
    fn note_call_update(&mut self, kind: u32, id: &str) -> bool {
        if id.is_empty() {
            return false;
        }
        match kind {
            msg::UPDATE_TOOL_CALL_STARTED => {
                self.started.insert(id.to_owned());
                false
            }
            msg::UPDATE_PARTIAL_TOOL_CALL => {
                // One update per streamed argument chunk: own the id once.
                if !self.partial.contains(id) {
                    self.partial.insert(id.to_owned());
                }
                false
            }
            _ => {
                if !self.partial.contains(id)
                    || self.started.contains(id)
                    || self.exec_ids.contains(id)
                    || self.by_cursor.contains(id)
                {
                    return false;
                }
                self.by_cursor.insert(id.to_owned());
                true
            }
        }
    }

    fn observe_exec(
        &mut self,
        body: &[u8],
        events: &mut Vec<StreamEvent>,
    ) -> Result<(), CursorError> {
        self.listed_after = false;
        let mut kind = ExecKind::Answered;
        let mut call: Option<ToolCall> = None;
        for field in Reader::new(body) {
            let field = field?;
            let FieldValue::Bytes(args) = field.value else {
                // The exec id (`#1`, uint32) and the like: the uplink's business.
                continue;
            };
            match field.number {
                msg::EXEC_CLIENT_EXEC_ID | msg::EXEC_SPAN_CONTEXT => continue,
                msg::EXEC_MCP_ARGS => {
                    call = Some(decode_mcp_call(args)?);
                    kind = ExecKind::ToolCall;
                }
                msg::EXEC_REQUEST_CONTEXT_ARGS => kind = ExecKind::Context,
                _ => {}
            }
            // Every exec kind keeps its tool_call_id in a string field of its
            // own (ShellArgs 4, ReadArgs 2, McpArgs 3); remembering every
            // short string of the args is what keeps a `#3` that raced its
            // exec from counting as "completed by Cursor".
            for id in short_strings(args)? {
                self.by_cursor.remove(id);
                self.exec_ids.insert(id.to_owned());
            }
        }
        match kind {
            ExecKind::ToolCall => {
                let call = call.ok_or(CursorError::Malformed)?;
                let index = u32::try_from(self.tools.len()).map_err(|_| CursorError::Malformed)?;
                self.argument_chars += call.arguments.chars().count();
                if self.emits() {
                    events.push(StreamEvent::ToolCallDelta {
                        index,
                        id: Some(call.id.clone()),
                        name: Some(call.name.clone()),
                        arguments: call.arguments.clone(),
                    });
                }
                self.tools.push(call);
            }
            ExecKind::Answered => self.answered += 1,
            ExecKind::Context => {}
        }
        if self.step_done() {
            events.extend(self.finish_step());
        }
        Ok(())
    }

    fn observe_checkpoint(
        &mut self,
        body: &[u8],
        events: &mut Vec<StreamEvent>,
    ) -> Result<(), CursorError> {
        if self.listed.is_none() || !self.listed_after || self.tools.is_empty() {
            return Ok(());
        }
        let mut pending = 0usize;
        for field in Reader::new(body) {
            let field = field?;
            if field.number == msg::CHECKPOINT_PENDING_TOOL_CALLS {
                pending += 1;
            }
        }
        if pending == self.tools.len() {
            events.extend(self.finish_step());
        }
        Ok(())
    }

    /// Whether every call the step listed has come. A step whose calls were
    /// all answered by the uplink goes on on Cursor's side under a fresh count.
    fn step_done(&mut self) -> bool {
        let Some(listed) = self.listed else {
            return false;
        };
        let calls = self.tools.len() as u64;
        let completed = self.by_cursor.len() as u64;
        if calls + self.answered + completed < listed {
            return false;
        }
        if calls > 0 {
            return true;
        }
        self.listed = None;
        self.listed_after = false;
        self.answered = 0;
        self.partial.clear();
        self.by_cursor.clear();
        false
    }

    /// Mark the Run done and produce its finish event, preceded by the
    /// turn's inline usage (`#14`) when the turn ended with counters. Under
    /// [`Emission::Silent`] the step is marked done just the same and no
    /// event is built.
    fn finish_step(&mut self) -> Vec<StreamEvent> {
        if self.done {
            return Vec::new();
        }
        self.done = true;
        if !self.emits() {
            return Vec::new();
        }
        let mut events = Vec::with_capacity(2);
        if let Some(usage) = self.usage() {
            events.push(StreamEvent::Usage(usage));
        }
        events.push(StreamEvent::Finish {
            reason: self.finish_reason().to_owned(),
        });
        events
    }

    /// Whether the Run reached its terminal (the driver closes both legs).
    #[must_use]
    pub fn done(&self) -> bool {
        self.done || self.broken
    }

    /// The failure the end frame (or an empty reply) carried, if any.
    #[must_use]
    pub fn failure(&self) -> Option<&Failure> {
        self.failure.as_ref()
    }

    /// The client-facing finish reason.
    #[must_use]
    pub fn finish_reason(&self) -> &'static str {
        if self.tools.is_empty() {
            "stop"
        } else {
            "tool_calls"
        }
    }

    /// How the response ended. A Run cut off after its tool calls came is a
    /// finished step (the reference's EOF-with-calls rule); one cut off
    /// mid-text is truncated; one cut off with nothing is a failure.
    #[must_use]
    pub fn finish(&self) -> Terminal {
        if self.broken {
            Terminal::Failed
        } else if self.done || !self.tools.is_empty() {
            Terminal::Completed
        } else if self.content_seen() {
            Terminal::Incomplete
        } else {
            Terminal::Failed
        }
    }

    /// Whether Cursor has said how many calls the step makes.
    #[must_use]
    pub fn listed(&self) -> bool {
        self.listed.is_some()
    }

    /// Calls the model wrote (`#7`) that are neither started on the client,
    /// sent as an exec, nor completed by Cursor: still being written, or one
    /// of Cursor's own still running. The driver's count-wait holds while any.
    #[must_use]
    pub fn writing(&self) -> usize {
        self.partial
            .iter()
            .filter(|id| {
                !self.started.contains(*id)
                    && !self.exec_ids.contains(*id)
                    && !self.by_cursor.contains(*id)
            })
            .count()
    }

    /// The inline usage of a turn that ended with counters; `None` for a tool
    /// step and for a counter-less turn (the dashboard, or an estimate, then
    /// stands in — never this).
    #[must_use]
    pub fn usage(&self) -> Option<UsageCounts> {
        self.turn_usage.clone()
    }

    #[must_use]
    pub fn terminal_seen(&self) -> bool {
        self.done
    }

    /// Whether real content (text, reasoning or a tool call) was observed.
    #[must_use]
    pub fn content_seen(&self) -> bool {
        self.text_chars > 0 || self.reasoning_chars > 0 || !self.tools.is_empty()
    }

    /// Characters the model produced (text, reasoning, tool arguments): the
    /// basis of the output estimate when Cursor reported no usage.
    #[must_use]
    pub fn output_chars(&self) -> usize {
        self.text_chars + self.reasoning_chars + self.argument_chars
    }

    /// Whether the model called tools this step.
    #[must_use]
    pub fn called_tools(&self) -> bool {
        !self.tools.is_empty()
    }

    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    #[must_use]
    pub fn reasoning(&self) -> &str {
        &self.reasoning
    }

    /// Move the accumulated text out (see the Kiro kernel's caveat: read
    /// [`Self::output_chars`] first).
    pub fn take_text(&mut self) -> String {
        self.text_chars = 0;
        std::mem::take(&mut self.text)
    }

    pub fn take_reasoning(&mut self) -> String {
        self.reasoning_chars = 0;
        std::mem::take(&mut self.reasoning)
    }

    #[must_use]
    pub fn tool_calls(&self) -> &[ToolCall] {
        &self.tools
    }
}

/// Whether a frame carries nothing but heartbeats (`InteractionUpdate#13`):
/// the driver's silence clock ignores such frames.
#[must_use]
pub fn is_heartbeat(frame: &Frame) -> bool {
    if frame.is_end() || frame.payload.is_empty() {
        return false;
    }
    let mut any = false;
    for field in Reader::new(&frame.payload) {
        let Ok(field) = field else {
            return false;
        };
        let (msg::SERVER_INTERACTION_UPDATE, FieldValue::Bytes(update)) =
            (field.number, field.value)
        else {
            return false;
        };
        for inner in Reader::new(update) {
            match inner {
                Ok(inner) if inner.number == msg::UPDATE_HEARTBEAT => any = true,
                _ => return false,
            }
        }
    }
    any
}

/// `TurnEndedUpdate` → usage. `input_tokens` is Cursor's whole prompt, the
/// cache read and the cache write included — exactly the kernel's prompt
/// total; the two cache quantities are listed beside it and never subtracted
/// (the price splits the total). Reasoning is a sub-item of output.
///
/// `None` unless the update reports a billable total. `input_tokens` and
/// `output_tokens` are what the ledger prices (`ModelPrice::cost_split`);
/// every field is `optional` in the schema, and a turn that ends without
/// both of them reports nothing rather than zero — the vendor CLI skips its
/// own usage record on exactly this condition. A zero total would read as
/// "observed, and free", which charges nothing *and* hides the Run from the
/// dashboard and the estimate, so a turn carrying only a cache or reasoning
/// counter is reconciled rather than believed. A counter the update omits
/// beside a real total stays `None`: the ledger records "not reported",
/// never a measured zero (`protocol::usage`).
fn decode_turn_usage(body: &[u8]) -> Result<Option<UsageCounts>, CursorError> {
    let mut input = None;
    let mut output = None;
    let mut cache_read = None;
    let mut cache_write = None;
    let mut reasoning = None;
    for field in Reader::new(body) {
        let field = field?;
        let FieldValue::Varint(value) = field.value else {
            continue;
        };
        match field.number {
            msg::TURN_INPUT => input = Some(value),
            msg::TURN_OUTPUT => output = Some(value),
            msg::TURN_CACHE_READ => cache_read = Some(value),
            msg::TURN_CACHE_WRITE => cache_write = Some(value),
            msg::TURN_REASONING => reasoning = Some(value),
            _ => {}
        }
    }
    if input.is_none() && output.is_none() {
        return Ok(None);
    }
    // `TurnEndedUpdate.input` already counts the cache read and the cache
    // write, which is exactly the kernel's prompt total; the two cache parts
    // are listed beside it, never subtracted (the price splits the total).
    Ok(Some(UsageCounts {
        input_tokens: input.unwrap_or(0),
        output_tokens: output.unwrap_or(0),
        cached_input_tokens: cache_read,
        cache_creation_input_tokens: cache_write,
        reasoning_output_tokens: reasoning,
        ..UsageCounts::default()
    }))
}

/// `McpArgs` → the caller's tool call. The model calls `CallDynamicTool`
/// (`{namespace, toolName, arguments}`), which Cursor hands over as
/// `tool_name` (`#5`) or `name` (`#1`, possibly namespaced `tools-<name>`) with
/// the arguments as a `map<string, Value>`. Rarely Cursor echoes the envelope
/// back unchanged — the name is `CallDynamicTool` itself and the real call
/// sits in the args map — which is unwrapped here, or refused.
fn decode_mcp_call(body: &[u8]) -> Result<ToolCall, CursorError> {
    let mut name = "";
    let mut tool_name = "";
    let mut call_id = String::new();
    let mut args = serde_json::Map::new();
    for field in Reader::new(body) {
        let field = field?;
        let FieldValue::Bytes(value) = field.value else {
            continue;
        };
        match field.number {
            msg::MCP_NAME => name = pb::text(value)?,
            msg::MCP_ARGS_ENTRY => {
                let (key, item) = decode_map_entry(value)?;
                args.insert(key, item);
            }
            msg::MCP_TOOL_CALL_ID => call_id = pb::text(value)?.to_owned(),
            msg::MCP_TOOL_NAME => tool_name = pb::text(value)?,
            _ => {}
        }
    }
    let name = if tool_name.is_empty() {
        name.strip_prefix(&format!("{}-", msg::NAMESPACE))
            .unwrap_or(name)
    } else {
        tool_name
    };
    if name.is_empty() {
        return Err(CursorError::Malformed);
    }
    // Cursor sometimes hands the envelope back unchanged: the name is the
    // synthetic tool itself and the real call rides in its arguments.
    let (name, args) = if name == msg::CALL_TOOL {
        unwrap_envelope(args)?
    } else {
        (name.to_owned(), args)
    };
    // An OpenAI-style call id can carry a newline between its two halves
    // (`call_…\nfc_…`), which no Chat client accepts: the reference replaces
    // it on the way out and restores it when the result comes back.
    let id = if call_id.is_empty() {
        format!("call_{}", uuid::Uuid::new_v4().simple())
    } else {
        call_id.replace('\n', "__")
    };
    let arguments =
        serde_json::to_string(&Value::Object(args)).map_err(|_| CursorError::Malformed)?;
    Ok(ToolCall {
        id,
        name,
        arguments,
    })
}

/// The caller's call inside an echoed `CallDynamicTool` envelope, or
/// [`CursorError::Malformed`] — the shell is not a tool the caller has, so a
/// shape that cannot be unwrapped is refused rather than passed on.
fn unwrap_envelope(
    mut args: serde_json::Map<String, Value>,
) -> Result<(String, serde_json::Map<String, Value>), CursorError> {
    let Some(Value::String(name)) = args.remove("toolName") else {
        return Err(CursorError::Malformed);
    };
    if name.is_empty() {
        return Err(CursorError::Malformed);
    }
    // A tool that takes no arguments can echo back without the entry at all,
    // or with the empty value this decoder reads as `Null`; one of the wrong
    // shape is still a refusal.
    let args = match args.remove("arguments") {
        Some(Value::Object(args)) => args,
        None | Some(Value::Null) => serde_json::Map::new(),
        Some(_) => return Err(CursorError::Malformed),
    };
    Ok((name, args))
}

/// One `map<string, google.protobuf.Value>` entry: `1` key, `2` value.
fn decode_map_entry(body: &[u8]) -> Result<(String, Value), CursorError> {
    let mut key: Option<String> = None;
    let mut item = Value::Null;
    for field in Reader::new(body) {
        let field = field?;
        match (field.number, field.value) {
            (1, FieldValue::Bytes(bytes)) => key = Some(pb::text(bytes)?.to_owned()),
            (2, FieldValue::Bytes(bytes)) => item = pb::decode_value(bytes)?,
            _ => {}
        }
    }
    Ok((key.ok_or(CursorError::Malformed)?, item))
}

/// Every short (≤ 512 bytes) UTF-8 string field of one exec's args.
fn short_strings(body: &[u8]) -> Result<Vec<&str>, CursorError> {
    let mut out = Vec::new();
    for field in Reader::new(body) {
        let field = field?;
        if let FieldValue::Bytes(bytes) = field.value
            && !bytes.is_empty()
            && bytes.len() <= 512
            && let Ok(text) = std::str::from_utf8(bytes)
        {
            out.push(text);
        }
    }
    Ok(out)
}

/// The first string value of `field` in a message body, `""` when absent.
fn first_string(body: &[u8], field: u32) -> Result<&str, CursorError> {
    for item in Reader::new(body) {
        let item = item?;
        if item.number == field
            && let FieldValue::Bytes(bytes) = item.value
        {
            return pb::text(bytes);
        }
    }
    Ok("")
}

/// The first varint value of `field` in a message body, `0` when absent.
fn first_varint(body: &[u8], field: u32) -> Result<u64, CursorError> {
    for item in Reader::new(body) {
        let item = item?;
        if item.number == field
            && let FieldValue::Varint(value) = item.value
        {
            return Ok(value);
        }
    }
    Ok(0)
}

/// Read an end frame's JSON: `None` for a clean end, the mapped failure
/// otherwise. Only a Connect `code` makes a failure (the reference's
/// `failure(200, …)`): a body that is not JSON, or JSON without a code, is a
/// stream that ended well with a note.
fn parse_end_frame(payload: &[u8]) -> Option<Failure> {
    let text = std::str::from_utf8(payload).ok()?.trim();
    if text.is_empty() || text == "{}" {
        return None;
    }
    let parsed = serde_json::from_str::<Value>(text).ok()?;
    let error = parsed
        .get("error")
        .filter(|error| error.is_object())
        .unwrap_or(&parsed);
    let code = error.get("code").and_then(Value::as_str).unwrap_or("");
    let mut message = error
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    // Connect error details can carry the human-readable title/detail pair.
    if let Some(details) = error.get("details").and_then(Value::as_array) {
        for detail in details {
            let debug = detail.get("debug").and_then(|debug| debug.get("details"));
            let title = debug
                .and_then(|debug| debug.get("title"))
                .and_then(Value::as_str)
                .unwrap_or("");
            let text = debug
                .and_then(|debug| debug.get("detail"))
                .and_then(Value::as_str)
                .unwrap_or("");
            let joined = format!("{title}: {text}");
            let joined = joined
                .trim_matches(|character: char| character == ':' || character.is_whitespace());
            if !joined.is_empty() {
                message = joined.to_owned();
            }
        }
    }
    if message.is_empty() || message == "Error" {
        message = code.to_owned();
    }
    if code.is_empty() {
        // No Connect code: the stream ended well, with a note.
        return None;
    }
    Some(map_failure(200, code, &message))
}

/// Reduce a Connect error (or an HTTP failure of the Run endpoints) to the
/// platform's error and the status the reference maps it to.
///
/// The order mirrors the reference `statusOf`: a regional refusal and
/// `permission_denied` are 403; `unauthenticated`, an HTTP 401 or any "expired"
/// is 401; `resource_exhausted` and quota/rate/usage-limit words are 429;
/// context-length words and `invalid_argument` are 400; `unavailable` is 503;
/// any other Connect code is 502; no code keeps the HTTP status.
#[must_use]
pub fn map_failure(status: u16, code: &str, message: &str) -> Failure {
    let message: String = message.chars().take(MAX_FAILURE_MESSAGE).collect();
    let lower = message.to_ascii_lowercase();
    let (status, error) = if lower.contains("region") || code == "permission_denied" {
        (403, ProtocolError::PermissionDenied)
    } else if code == "unauthenticated" || status == 401 || lower.contains("expired") {
        (401, ProtocolError::UpstreamAuthenticationFailed)
    } else if code == "resource_exhausted"
        || lower.contains("quota")
        || lower.contains("rate limit")
        || lower.contains("usage limit")
    {
        (429, ProtocolError::UpstreamRateLimited)
    } else if lower.contains("too long")
        || lower.contains("context length")
        || lower.contains("too many tokens")
        || code == "invalid_argument"
    {
        (400, ProtocolError::InvalidRequest)
    } else if code == "unavailable" {
        (503, ProtocolError::PlatformUnavailable)
    } else if !code.is_empty() {
        (502, ProtocolError::UpstreamError)
    } else {
        (status, status_error(status))
    };
    Failure {
        error,
        status,
        message,
    }
}

/// The platform error for a bare HTTP status from a Run endpoint.
fn status_error(status: u16) -> ProtocolError {
    match status {
        401 => ProtocolError::UpstreamAuthenticationFailed,
        403 => ProtocolError::PermissionDenied,
        429 => ProtocolError::UpstreamRateLimited,
        400 => ProtocolError::InvalidRequest,
        503 => ProtocolError::PlatformUnavailable,
        _ => ProtocolError::UpstreamError,
    }
}

/// Frame and decode one complete Run body (every downlink frame, concatenated)
/// into its terminal decoder state, for the non-streaming path.
pub fn aggregate(body: &[u8]) -> Result<StreamDecoder, ProtocolError> {
    let mut framer = super::connect::Framer::new();
    let frames = framer.push(body)?;
    framer.finish()?;
    let mut decoder = StreamDecoder::silent(Retention::Full);
    for frame in &frames {
        decoder.observe(frame)?;
    }
    Ok(decoder)
}
