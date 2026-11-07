//! Field numbers of the `agent.v1` messages cardinal reads and writes.
//!
//! One place for every number, so the request encoder, the response decoder
//! and the uplink agree by construction. The names follow the schema recovered
//! in `.ox/plans/2026-11-06-cursor-proto-local-extract.md`; a number not
//! listed here is unknown to cardinal and skipped on the wire.

/// The MCP namespace cardinal lists the caller's tools under, and the tool
/// the model calls to reach them.
pub const NAMESPACE: &str = "tools";
pub const CALL_TOOL: &str = "CallDynamicTool";
pub const LIST_TOOLS: &str = "GetDynamicTools";

// ---- AgentClientMessage ------------------------------------------------------

pub const CLIENT_RUN_REQUEST: u32 = 1;
pub const CLIENT_EXEC: u32 = 2;
pub const CLIENT_KV: u32 = 3;
pub const CLIENT_EXEC_CONTROL: u32 = 5;
pub const CLIENT_HEARTBEAT: u32 = 7;

// ---- AgentServerMessage ------------------------------------------------------

pub const SERVER_INTERACTION_UPDATE: u32 = 1;
pub const SERVER_EXEC: u32 = 2;
pub const SERVER_CHECKPOINT: u32 = 3;
pub const SERVER_KV: u32 = 4;

/// `ConversationStateStructure.pending_tool_calls` (repeated string).
pub const CHECKPOINT_PENDING_TOOL_CALLS: u32 = 4;

// ---- InteractionUpdate -------------------------------------------------------

pub const UPDATE_TEXT_DELTA: u32 = 1;
pub const UPDATE_TOOL_CALL_STARTED: u32 = 2;
pub const UPDATE_TOOL_CALL_COMPLETED: u32 = 3;
pub const UPDATE_THINKING_DELTA: u32 = 4;
pub const UPDATE_PARTIAL_TOOL_CALL: u32 = 7;
pub const UPDATE_HEARTBEAT: u32 = 13;
pub const UPDATE_TURN_ENDED: u32 = 14;
pub const UPDATE_TOOL_REQUESTS_LISTED: u32 = 27;

/// `TextDeltaUpdate.text` / `ThinkingDeltaUpdate.text`.
pub const DELTA_TEXT: u32 = 1;
/// The call id at field 1 of every tool-call lifecycle update.
pub const TOOL_CALL_ID: u32 = 1;
/// `ToolRequestsListedUpdate.call_count`.
pub const LISTED_CALL_COUNT: u32 = 1;

/// `TurnEndedUpdate` counters.
pub const TURN_INPUT: u32 = 1;
pub const TURN_OUTPUT: u32 = 2;
pub const TURN_CACHE_READ: u32 = 3;
pub const TURN_CACHE_WRITE: u32 = 4;
pub const TURN_REASONING: u32 = 5;

// ---- ExecServerMessage / ExecClientMessage ----------------------------------

/// Both directions: the exec id (uint32) at field 1.
pub const EXEC_ID: u32 = 1;
/// `ExecServerMessage.span_context` — tracing metadata whose strings are
/// never a call id (skipped by the tracker).
pub const EXEC_SPAN_CONTEXT: u32 = 19;
/// `ExecServerMessage.request_context_args` — an environment query.
pub const EXEC_REQUEST_CONTEXT_ARGS: u32 = 10;
/// `ExecServerMessage.mcp_args` — a call of the caller's tools.
pub const EXEC_MCP_ARGS: u32 = 11;
/// `ExecServerMessage.mcp_state_exec_args` — Cursor asking for the MCP
/// server state (servers and their tools); answered with
/// `McpStateExecResult.success{servers}`.
pub const EXEC_MCP_STATE_ARGS: u32 = 36;
/// `ExecClientMessage.exec_id` (string) at field 15.
pub const EXEC_CLIENT_EXEC_ID: u32 = 15;

/// `McpArgs` fields.
pub const MCP_NAME: u32 = 1;
pub const MCP_ARGS_ENTRY: u32 = 2;
pub const MCP_TOOL_CALL_ID: u32 = 3;
pub const MCP_PROVIDER: u32 = 4;
pub const MCP_TOOL_NAME: u32 = 5;

// ---- KvServerMessage / KvClientMessage -------------------------------------

/// `KvServerMessage.get` — `{1: blob_id}`.
pub const KV_SERVER_GET: u32 = 2;
/// `KvServerMessage.set` — `{1: blob_id, 2: data}`.
pub const KV_SERVER_SET: u32 = 3;
/// `KvClientMessage.response` — `{1: blob_id, 2: get_result | 3: set_ok}`.
pub const KV_CLIENT_RESPONSE: u32 = 3;
pub const KV_RESPONSE_BLOB_ID: u32 = 1;
pub const KV_RESPONSE_GET: u32 = 2;
pub const KV_RESPONSE_SET: u32 = 3;
/// `GetResult.found{1: data}` / `GetResult.not_found{1: message}`.
pub const KV_GET_FOUND: u32 = 1;
pub const KV_GET_NOT_FOUND: u32 = 2;
pub const KV_BLOB_ID: u32 = 1;

// ---- BidiAppendRequest -------------------------------------------------------

pub const BIDI_REQUEST_ID: u32 = 2;
pub const BIDI_SEQNO: u32 = 3;
pub const BIDI_DATA: u32 = 4;
/// `RequestId.id` (string).
pub const BIDI_REQUEST_ID_VALUE: u32 = 1;

// ---- RunSSE request ----------------------------------------------------------

/// `RunSSERequest.request_id` (string).
pub const RUN_SSE_REQUEST_ID: u32 = 1;
