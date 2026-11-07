//! The Cursor `run_request`: the dialect body → the Run's opening message,
//! its blobs and the HTTP request that opens the downlink.
//!
//! The dialect body is the JSON `translation::cursor::from_ir` emits — not a
//! vendor wire shape (Cursor has none in JSON) but cardinal's own staging
//! format, so the IR layer stays protobuf-free and this kernel stays
//! IR-free:
//!
//! ```json
//! {
//!   "model": "<legacy slug Cursor accepts>",
//!   "params": [{"id": "effort", "value": "high"}],
//!   "messages": [ <AI SDK messages, one blob each> ],
//!   "last_user": "<the last user message's first text>",
//!   "tools": [{"name": "…", "description": "…", "schema": {…}}],
//!   "conversation_id": "<uuid or empty>",
//!   "prompt_chars": 1234
//! }
//! ```
//!
//! Three of those fields are the contract and a body missing one of them is
//! refused: `model` (non-empty), `messages`, and `prompt_chars`.
//! `prompt_chars` is required because it is the sole basis of the usage
//! estimate a Run whose usage the backend never reports is billed by —
//! treating an absent count as zero would bill the whole request as having
//! had no input, and say nothing. The rest are tolerated when absent:
//! `params` and `tools` empty, `last_user` a lone `.`, and an absent or
//! empty `conversation_id` mints a fresh one.
//!
//! One optional field is not `from_ir`'s to emit: `max_mode`. Whether a Run
//! asks for Max Mode is a per-attempt decision — the relay learns the model
//! needs it from Cursor's refusal and repeats the attempt with the flag set —
//! so the relay is the field's only writer and only ever writes `true`.
//! Absence is the ordinary case and means off, which is what the
//! `unwrap_or(false)` below stands for.
//!
//! The body is read field by field off a borrowed [`Value`] rather than
//! deserialized into a struct: [`prepare`] is handed a `&Value`, so
//! `serde_json::from_value` would have to own it and deep-copy the entire
//! conversation — every message and every blob — once per request. Reading
//! through [`Value::get`] borrows it in place, and only what reaches the
//! wire is copied.
//!
//! [`prepare`] renders the `AgentRunRequest` (plan §2.4), content-addresses
//! every message blob (`sha256`), and returns a [`Prepared`] addressed at the
//! bidi `Run` (the IDE's path: one HTTP/2 stream on [`super::AGENT_ORIGIN`],
//! whose body the Run driver streams) and whose [`Prepared::cursor`] carries
//! everything the driver needs afterwards: the first uplink message, the
//! blobs, the tool definitions, the environment — and the split transport's
//! addresses (`RunSSE` + `BidiAppend` on the provider's origin) for the
//! HTTP/1.1 fallback.

use std::sync::Arc;

use bytes::Bytes;
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::CursorError;
use super::connect::encode_frame;
use super::msg;
use super::pb::{self, Writer};
use super::uplink::Uplink;
use crate::protocol::{Prepared, ProtocolError, ProtocolId, TargetView};

/// Connect's protocol version header value.
pub const CONNECT_PROTOCOL_VERSION: &str = "1";
/// The content type of a Connect stream: the bidi `Run` in both directions,
/// the `RunSSE` request and its response stream.
pub const CONNECT_PROTO: &str = "application/connect+proto";
/// The content type of a `BidiAppend` request.
pub const PROTO: &str = "application/proto";
/// The client form Cursor's own headless agent host declares (plan D7).
pub const CLIENT_TYPE: &str = "cli";
/// The tools the Run may use: the caller's MCP tools and the tool list, none
/// of Cursor's own.
pub const ALLOWED_TOOLS: &str = "mcp_tool_call,get_mcp_tools_tool_call";
/// Bidi `Run` path under the agent-stream origin ([`super::AGENT_ORIGIN`]).
pub const RUN_PATH: &str = "agent.v1.AgentService/Run";
/// `RunSSE` path under the agent API origin.
pub const RUN_SSE_PATH: &str = "agent.v1.AgentService/RunSSE";
/// `BidiAppend` path under the agent API origin.
pub const BIDI_APPEND_PATH: &str = "aiserver.v1.BidiService/BidiAppend";
/// `GetUsableModels` path under the agent API origin (unary, JSON).
pub const USABLE_MODELS_PATH: &str = "agent.v1.AgentService/GetUsableModels";

/// Everything one Run needs beyond the opening HTTP request. Lives in
/// [`Prepared::cursor`]; the Run driver (`upstream::cursor_run`) consumes it.
pub struct RunPlan {
    /// The `x-request-id` of the Run: names the downlink to the uplink on the
    /// split transport; the stream's id on the bidi one.
    pub request_id: String,
    /// The `conversation_id` the request carried (dashboard reconciliation).
    pub conversation_id: String,
    /// `AgentClientMessage{run_request}` — the stream's first message (append
    /// seqno 0 on the split transport).
    pub run_request: Bytes,
    /// Blob lookups, tool list and environment answers.
    pub uplink: Uplink,
    /// The split transport's downlink: the `RunSSE` URL on the provider's
    /// origin and the one Connect frame it takes (`{1: request_id}`).
    pub sse_url: String,
    pub sse_body: Bytes,
    /// The split transport's uplink: the `BidiAppend` URL on the same origin
    /// as the `RunSSE` URL.
    pub append_url: String,
    /// Characters of the rendered prompt, for the usage estimate.
    pub prompt_chars: u64,
}

impl std::fmt::Debug for RunPlan {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RunPlan")
            .field("request_id", &self.request_id)
            .field("conversation_id", &self.conversation_id)
            .field("run_request_len", &self.run_request.len())
            .field("sse_url", &self.sse_url)
            .field("prompt_chars", &self.prompt_chars)
            .finish_non_exhaustive()
    }
}

/// The Cursor CLI release this gateway identifies as: `<build date>-<commit>`,
/// the directory name under `~/.local/share/cursor-agent/versions/` of the
/// release the wire path was verified against (E2E 2026-11-07).
///
/// Not `-agent-host`: that suffix (the plan's §2.1.1, taken from the IDE
/// extract) names the Grok Build host, and the backend answers a Run bearing
/// it with "Grok Build isn't available for this account yet" for a Cursor
/// account. The reference implementation sends the installed CLI's release id
/// for the same reason.
pub const CLIENT_RELEASE: &str = "2026.11.05-86047df";

/// The `x-cursor-client-version` the Cursor CLI sends: `cli-<release>`.
/// `CARDINAL_CURSOR_CLIENT_RELEASE` overrides the release id (plan D7: the
/// version is configurable) when the pinned one stops being accepted.
#[must_use]
pub fn client_version() -> String {
    let release = std::env::var("CARDINAL_CURSOR_CLIENT_RELEASE")
        .ok()
        .filter(|value| {
            let (date, hash) = value.split_once('-').unwrap_or((value, ""));
            date.len() == 10
                && date
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || byte == b'.')
                && !hash.is_empty()
                && hash.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
        .unwrap_or_else(|| CLIENT_RELEASE.to_owned());
    format!("cli-{release}")
}

/// One unary Connect call in JSON (`GetUsableModels`, the dashboard reads):
/// the request shell for `path` (relative to [`super::API_ORIGIN`]) with
/// `body` as its JSON payload. The protocol tag is a placeholder — the
/// transport reads it only to frame a stream, which a unary call never is.
#[must_use]
pub fn unary_json(path: &str, body: Bytes) -> Prepared {
    Prepared {
        protocol: ProtocolId::OpenAiChat,
        url: format!("{}/{path}", super::API_ORIGIN),
        content_type: "application/json",
        body,
        stream: false,
        headers: Vec::new(),
        cursor: None,
    }
}

/// The headers a unary call authenticates and identifies itself with: the
/// Connect version, the CLI identity, ghost mode, the bearer and — for a team
/// login — the team id. `access_token` is a secret: the vector carries it,
/// so it must not be logged.
#[must_use]
pub fn unary_headers(access_token: &str, team_id: Option<&str>) -> Vec<(&'static str, String)> {
    let mut headers = vec![
        (
            "connect-protocol-version",
            CONNECT_PROTOCOL_VERSION.to_owned(),
        ),
        ("x-cursor-client-version", client_version()),
        ("x-cursor-client-type", CLIENT_TYPE.to_owned()),
        ("x-ghost-mode", "true".to_owned()),
        ("authorization", format!("Bearer {access_token}")),
    ];
    if let Some(team_id) = team_id {
        headers.push(("x-cursor-team-id", team_id.to_owned()));
    }
    headers
}

/// Non-secret headers every Run endpoint takes (the bearer and the team id
/// are the relay's to add).
#[must_use]
pub fn run_headers(request_id: &str) -> Vec<(&'static str, String)> {
    vec![
        (
            "connect-protocol-version",
            CONNECT_PROTOCOL_VERSION.to_owned(),
        ),
        ("x-cursor-client-version", client_version()),
        ("x-cursor-client-type", CLIENT_TYPE.to_owned()),
        ("x-ghost-mode", "true".to_owned()),
        ("x-request-id", request_id.to_owned()),
        ("x-cursor-agent-allowed-tools", ALLOWED_TOOLS.to_owned()),
        // No response compression on either transport: the frame splitter
        // reads the wire as sent (no `connect-accept-encoding` either, so a
        // Connect peer may not compress a message).
        ("accept-encoding", "identity".to_owned()),
        ("x-cursor-streaming", "true".to_owned()),
    ]
}

/// Build the Run from the dialect body. `stream` is accepted for the
/// kernel signature's sake: every Cursor Run is a stream, and the relay
/// aggregates for a non-streaming client.
pub fn prepare(
    body: &Value,
    target: &TargetView<'_>,
    _stream: bool,
) -> Result<Prepared, ProtocolError> {
    let model = body
        .get("model")
        .and_then(Value::as_str)
        .filter(|model| !model.is_empty())
        .ok_or(ProtocolError::InvalidRequest)?;
    let messages = body
        .get("messages")
        .and_then(Value::as_array)
        .ok_or(ProtocolError::InvalidRequest)?;
    let last_user = body.get("last_user").and_then(Value::as_str).unwrap_or(".");
    let tools = body
        .get("tools")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let max_mode = body
        .get("max_mode")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let params = body
        .get("params")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let conversation_id = body
        .get("conversation_id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let prompt_chars = body
        .get("prompt_chars")
        .and_then(Value::as_u64)
        .ok_or(ProtocolError::InvalidRequest)?;

    let mut blobs: Vec<(Vec<u8>, Bytes)> = Vec::with_capacity(messages.len() + 2);
    let mut put = |content: Vec<u8>| -> Vec<u8> {
        let id = Sha256::digest(&content).to_vec();
        blobs.push((id.clone(), Bytes::from(content)));
        id
    };

    // ConversationState: one blob per message, the turn, the client form.
    let mut state = Writer::new();
    for message in messages {
        let blob = serde_json::to_vec(message).map_err(|_| ProtocolError::InvalidRequest)?;
        state.bytes(1, &put(blob));
    }
    let message_id = uuid::Uuid::new_v4().to_string();
    let mut user = Writer::new();
    user.string(1, last_user);
    user.string(2, &message_id);
    user.varint(4, 1); // mode: agent
    let user_id = put(user.into_bytes().to_vec());
    let mut turn_inner = Writer::new();
    turn_inner.bytes(1, &user_id);
    turn_inner.string(10, &message_id);
    let mut turn = Writer::new();
    turn.message(1, turn_inner);
    state.bytes(8, &put(turn.into_bytes().to_vec()));
    state.varint(10, 1);
    state.string(22, CLIENT_TYPE);

    // Tool definitions, the environment, the resume action.
    let tool_defs = tools
        .iter()
        .map(tool_definition)
        .collect::<Result<Vec<Bytes>, ProtocolError>>()?;
    let env = environment();
    let mut request_context = Writer::new();
    request_context.bytes(4, &env);
    let mut mcp_tools = Writer::new();
    for def in &tool_defs {
        request_context.bytes(7, def);
        mcp_tools.bytes(1, def);
    }
    let mut resume = Writer::new();
    resume.message(2, request_context);
    let mut action = Writer::new();
    action.message(2, resume);

    // ModelDetails and RequestedModel.
    let mut details = Writer::new();
    details.string(1, model);
    details.string(3, model);
    details.string(4, model);
    let mut requested = Writer::new();
    requested.string(1, model);
    if max_mode {
        details.varint(7, 1);
        requested.varint(2, 1);
    }
    for param in params {
        let (Some(id), Some(value)) = (
            param.get("id").and_then(Value::as_str),
            param.get("value").and_then(Value::as_str),
        ) else {
            return Err(ProtocolError::InvalidRequest);
        };
        let mut pair = Writer::new();
        pair.string(1, id);
        pair.string(2, value);
        requested.message(3, pair);
    }

    let mut run_request = Writer::new();
    run_request.message(1, state);
    run_request.message(2, action);
    run_request.message(3, details);
    run_request.message(4, mcp_tools);
    run_request.string(5, &conversation_id);
    run_request.message(9, requested);
    run_request.varint(msg::RUN_CLIENT_SUPPORTS_INLINE_IMAGES, 1);
    let mut first = Writer::new();
    first.message(msg::CLIENT_RUN_REQUEST, run_request);
    let run_request = first.into_bytes();

    let request_id = uuid::Uuid::new_v4().to_string();
    let mut open = Writer::new();
    open.string(msg::RUN_SSE_REQUEST_ID, &request_id);
    let sse_body = encode_frame(&open.into_bytes()).map_err(|_| ProtocolError::InvalidRequest)?;

    // The bidi stream dials the agent-stream origin; the split fallback dials
    // the provider's (api2), as the IDE's own HTTP/1.1 rewrite does.
    let origin = target.endpoint.trim_end_matches('/');
    let url = format!("{}/{RUN_PATH}", super::AGENT_ORIGIN);
    let sse_url = format!("{origin}/{RUN_SSE_PATH}");
    let append_url = format!("{origin}/{BIDI_APPEND_PATH}");
    let headers = run_headers(&request_id);
    let plan = RunPlan {
        request_id,
        conversation_id,
        run_request,
        uplink: Uplink::new(&blobs, tool_defs, env),
        sse_url,
        sse_body,
        append_url,
        prompt_chars,
    };
    Ok(Prepared {
        protocol: ProtocolId::Cursor,
        url,
        content_type: CONNECT_PROTO,
        // The bidi request body is the message stream the driver writes; the
        // prepared body is empty. The split fallback's opening frame lives in
        // the plan.
        body: Bytes::new(),
        stream: true,
        headers,
        cursor: Some(Arc::new(plan)),
    })
}

/// `McpToolDefinition{1 name, 2 description, 3 schema(Value), 4 server,
/// 5 tool name, 6 schema text}`.
fn tool_definition(tool: &Value) -> Result<Bytes, ProtocolError> {
    let name = tool
        .get("name")
        .and_then(Value::as_str)
        .filter(|name| !name.is_empty())
        .ok_or(ProtocolError::InvalidRequest)?;
    let description = tool
        .get("description")
        .and_then(Value::as_str)
        .unwrap_or("");
    let schema = tool
        .get("schema")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let schema_text = serde_json::to_string(&schema).map_err(|_| ProtocolError::InvalidRequest)?;
    let mut def = Writer::new();
    def.string(1, name);
    if !description.is_empty() {
        def.string(2, description);
    }
    pb::write_value(&mut def, 3, &schema).map_err(|error: CursorError| {
        tracing::warn!(%error, "tool schema cannot be rendered as a protobuf Value");
        ProtocolError::InvalidRequest
    })?;
    def.string(4, msg::NAMESPACE);
    def.string(5, name);
    def.string(6, &schema_text);
    Ok(def.into_bytes())
}

/// `RequestContextEnv{1 os_version, 3 shell, 10 time_zone}` — a fixed,
/// minimal description. No real path or host detail leaves the gateway.
///
/// Per the CLI's own schema (2026.11.05): field 2 is `workspace_paths`, not
/// a tmpdir — the reference implementation wrote its tmpdir there, which told
/// the model its workspace was `/tmp`. The gateway has no workspace, so the
/// field is left empty.
fn environment() -> Bytes {
    let os = match std::env::consts::OS {
        "macos" => "darwin",
        other => other,
    };
    let mut env = Writer::new();
    env.string(1, os);
    env.string(3, "sh");
    env.string(10, "UTC");
    env.into_bytes()
}
