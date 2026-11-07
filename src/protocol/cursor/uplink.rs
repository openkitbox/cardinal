//! What cardinal sends up a Run after the `run_request`: the answers Cursor's
//! server asks for while it works.
//!
//! Cursor's agent host keeps the conversation as content-addressed blobs and
//! asks for them back over the KV channel (`KvServerMessage.get`); it also
//! hands the client its own records to keep (`set`), asks the client for the
//! MCP tool list (`get_mcp_tools_args`) and the environment
//! (`request_context_args`), and asks it to run things — the caller's tools
//! (`mcp_args`, which the decoder turns into a tool call the caller runs) and
//! Cursor's own built-ins (shell, file reads, edits), which cardinal never
//! runs: they are refused with "not available", and the model carries on.
//!
//! [`Uplink::react`] is a pure function of one downlink frame: it returns the
//! client messages to send, each flagged with whether it may overlap the
//! appends before it (plan rule: KV replies may, everything else goes alone).
//! Timers, sequencing and the HTTP legs live in `upstream::cursor_run`.

use std::collections::HashMap;

use bytes::Bytes;

use super::CursorError;
use super::connect::Frame;
use super::msg;
use super::pb::{FieldValue, Reader, Writer};

/// One client message to append to the Run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outbound {
    /// The encoded `AgentClientMessage` (not Connect-framed).
    pub bytes: Bytes,
    /// Whether this append may be in flight alongside earlier ones. KV
    /// replies are independent lookups; an exec answer or control message
    /// must land after everything before it.
    pub overlaps: bool,
}

/// The Run's answer book: its blobs by id and its tool definitions.
#[derive(Debug)]
pub struct Uplink {
    blobs: HashMap<Vec<u8>, Bytes>,
    /// Pre-encoded `McpToolDefinition`s, in the order the request listed them.
    tool_defs: Vec<Bytes>,
    /// The environment the request declared (`RequestContext.env`, encoded).
    env: Bytes,
}

impl Uplink {
    /// `blobs` are `(sha256 id, content)` pairs; `tool_defs` the encoded tool
    /// definitions the `run_request` sent; `env` the encoded environment.
    #[must_use]
    pub fn new(blobs: &[(Vec<u8>, Bytes)], tool_defs: Vec<Bytes>, env: Bytes) -> Self {
        Self {
            blobs: blobs.iter().cloned().collect(),
            tool_defs,
            env,
        }
    }

    /// The messages one downlink frame calls for. Content frames and the end
    /// frame call for nothing; a malformed frame is an error.
    pub fn react(&self, frame: &Frame) -> Result<Vec<Outbound>, CursorError> {
        let mut out = Vec::new();
        if frame.is_end() {
            return Ok(out);
        }
        for field in Reader::new(&frame.payload) {
            let field = field?;
            let FieldValue::Bytes(body) = field.value else {
                continue;
            };
            match field.number {
                msg::SERVER_KV => self.react_kv(body, &mut out)?,
                msg::SERVER_EXEC => self.react_exec(body, &mut out)?,
                _ => {}
            }
        }
        Ok(out)
    }

    fn react_kv(&self, body: &[u8], out: &mut Vec<Outbound>) -> Result<(), CursorError> {
        let mut id = 0u64;
        let mut asks: Vec<(u32, &[u8])> = Vec::new();
        for field in Reader::new(body) {
            let field = field?;
            match (field.number, field.value) {
                (1, FieldValue::Varint(value)) => id = value,
                (msg::KV_SERVER_GET | msg::KV_SERVER_SET, FieldValue::Bytes(ask)) => {
                    asks.push((field.number, ask));
                }
                _ => {}
            }
        }
        for (kind, ask) in asks {
            let mut response = Writer::new();
            response.varint(msg::KV_RESPONSE_BLOB_ID, id);
            if kind == msg::KV_SERVER_GET {
                let wanted = first_bytes(ask, msg::KV_BLOB_ID)?;
                let mut result = Writer::new();
                match self.blobs.get(wanted) {
                    Some(blob) => result.bytes(msg::KV_GET_FOUND, blob),
                    None => {
                        let mut missing = Writer::new();
                        missing.string(1, "blob not found");
                        result.message(msg::KV_GET_NOT_FOUND, missing);
                    }
                }
                response.message(msg::KV_RESPONSE_GET, result);
            } else {
                // The server's own record of the turn: acknowledged, not kept.
                response.message(msg::KV_RESPONSE_SET, Writer::new());
            }
            let mut message = Writer::new();
            message.message(msg::CLIENT_KV, response);
            out.push(Outbound {
                bytes: message.into_bytes(),
                overlaps: true,
            });
        }
        Ok(())
    }

    fn react_exec(&self, body: &[u8], out: &mut Vec<Outbound>) -> Result<(), CursorError> {
        let mut id = 0u64;
        let mut exec_id = "";
        let mut kind: Option<u32> = None;
        for field in Reader::new(body) {
            let field = field?;
            match (field.number, field.value) {
                (msg::EXEC_ID, FieldValue::Varint(value)) => id = value,
                (msg::EXEC_CLIENT_EXEC_ID, FieldValue::Bytes(text)) => {
                    exec_id = super::pb::text(text)?;
                }
                (number, FieldValue::Bytes(_)) if number != msg::EXEC_SPAN_CONTEXT => {
                    kind.get_or_insert(number);
                }
                _ => {}
            }
        }
        match kind {
            // A call of the caller's tools: the decoder hands it out; nothing
            // goes up until the caller answers in its next request.
            Some(msg::EXEC_MCP_ARGS) => {}
            Some(msg::EXEC_MCP_STATE_ARGS) => {
                // McpServerState{1 name, 2 identifier, 5 tools…, 7 "connected"}
                let mut server = Writer::new();
                server.string(1, msg::NAMESPACE);
                server.string(2, msg::NAMESPACE);
                for def in &self.tool_defs {
                    server.bytes(5, def);
                }
                server.string(7, "connected");
                let mut state = Writer::new();
                state.message(1, server);
                let mut result = Writer::new();
                result.message(1, state);
                out.push(self.answer(id, exec_id, msg::EXEC_MCP_STATE_ARGS, result));
                out.push(close_exec(id));
            }
            Some(msg::EXEC_REQUEST_CONTEXT_ARGS) => {
                let mut context = Writer::new();
                context.bytes(4, &self.env);
                let mut inner = Writer::new();
                inner.message(1, context);
                let mut result = Writer::new();
                result.message(1, inner);
                out.push(self.answer(id, exec_id, msg::EXEC_REQUEST_CONTEXT_ARGS, result));
                out.push(close_exec(id));
            }
            // A shell, a file read, an edit of Cursor's own — never run.
            _ => {
                let mut refusal = Writer::new();
                refusal.varint(1, id);
                refusal.string(2, "not available");
                let mut control = Writer::new();
                control.message(2, refusal);
                let mut message = Writer::new();
                message.message(msg::CLIENT_EXEC_CONTROL, control);
                out.push(Outbound {
                    bytes: message.into_bytes(),
                    overlaps: false,
                });
                out.push(close_exec(id));
            }
        }
        Ok(())
    }

    /// `ExecClientMessage{1 id, 15 exec_id, <kind> result}`.
    fn answer(&self, id: u64, exec_id: &str, kind: u32, result: Writer) -> Outbound {
        let mut exec = Writer::new();
        exec.varint(msg::EXEC_ID, id);
        exec.string(msg::EXEC_CLIENT_EXEC_ID, exec_id);
        exec.message(kind, result);
        let mut message = Writer::new();
        message.message(msg::CLIENT_EXEC, exec);
        Outbound {
            bytes: message.into_bytes(),
            overlaps: false,
        }
    }
}

/// `ExecClientControlMessage.close{1 id}`.
fn close_exec(id: u64) -> Outbound {
    let mut close = Writer::new();
    close.varint(1, id);
    let mut control = Writer::new();
    control.message(1, close);
    let mut message = Writer::new();
    message.message(msg::CLIENT_EXEC_CONTROL, control);
    Outbound {
        bytes: message.into_bytes(),
        overlaps: false,
    }
}

/// `AgentClientMessage.client_heartbeat{}` — sent every few seconds so the
/// server knows the client is still there.
#[must_use]
pub fn heartbeat() -> Outbound {
    let mut message = Writer::new();
    message.message(msg::CLIENT_HEARTBEAT, Writer::new());
    Outbound {
        bytes: message.into_bytes(),
        overlaps: true,
    }
}

/// The first length-delimited value of `field`, empty when absent.
fn first_bytes(body: &[u8], field: u32) -> Result<&[u8], CursorError> {
    for item in Reader::new(body) {
        let item = item?;
        if item.number == field
            && let FieldValue::Bytes(bytes) = item.value
        {
            return Ok(bytes);
        }
    }
    Ok(&[])
}
