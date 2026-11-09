//! Thin relay ring: model resolution (direct `provider/model` or route alias) → ordered attempts
//! (same-protocol passthrough / cross-protocol translation) → response.
//! Gateway auth is an HTTP-surface hoop and lives in `api`, not here.

mod candidates;
pub mod capabilities;
mod dialects;
pub mod dispatcher;
mod failover;
pub mod ledger_writer;
pub(crate) mod optional;
mod price_cache;
mod prompt_cache;
mod rest_cache;
mod rotate;
mod route_cache;
mod smart;
pub mod smart_cache;
mod streaming;
pub mod trace;

pub use dispatcher::{
    Assignment, CandidateCaps, CandidateState, DispatchDecision, DispatchEvent, DispatchRequest,
    SlotGuard, SlotKey,
};
// The one dialect predicate read outside this module: the OpenCode login flow
// refuses a provider whose host the console's tokens could not be minted for.
pub(crate) use dialects::is_opencode_upstream;
pub use failover::Failover;
pub use ledger_writer::{LedgerWriter, LedgerWriterHandle};
pub use price_cache::{PriceCache, PriceInput};
pub use prompt_cache::PromptCache;
pub use rest_cache::RestCache;
pub use rotate::RotateCursors;
pub use route_cache::RouteCache;
pub use smart::SmartVerdict;
pub use smart_cache::SmartCache;
pub use trace::{CandidateTrace, DispatchTrace, SkipReason, TraceRing};
// Constructing a public RelayRequest requires naming this type — re-export it
// so downstream callers (and tests) don't need their own `llm` dependency.
pub use crate::protocol::ProtocolId;

use secrecy::{ExposeSecret as _, SecretString};
use serde_json::Value;

use crate::activity::{ActivitySink, EndMetrics, EndStatus};
use crate::billing;
use crate::body_log::{BodyLog, CapturedBodies, CapturedBody};
use crate::credentials::KeyCredential;
use crate::metering::UsageCertainty;
use crate::opencode::OpencodeOAuth;
use crate::protocol::{self, ProtocolError, TargetView};
use crate::store::{self, AttemptLog};
use crate::translation;
use crate::translation::ir::Effort;
use crate::upstream::cursor_run;
use crate::upstream::cursor_tokens::{CursorBearer, CursorTokenError, CursorTokens};
use crate::upstream::cursor_usage::CursorUsage;
use crate::upstream::kiro_tokens::{self, KiroCallContext, KiroTokens};
use crate::upstream::openai_tokens::OpenaiTokens;
use crate::upstream::opencode_tokens::OpencodeTokens;
use crate::upstream::transport::{self, Transport};

use std::sync::atomic::{AtomicU64, Ordering};

/// Monotonic, process-local id for dispatcher events (assignment requests
/// and their timeout tracking). Not the request's idempotency key: it resets
/// on restart, so the persisted request id is a UUID (see [`dispatch`]).
static DISPATCH_EVENT_ID: AtomicU64 = AtomicU64::new(0);

fn next_dispatch_event_id() -> u64 {
    DISPATCH_EVENT_ID.fetch_add(1, Ordering::Relaxed)
}

use dialects::{
    ChatFixups, conversation_seed, fill_missing_reasoning, fill_missing_reasoning_pending,
    is_deepseek_model, is_glm_upstream, join_split_tool_call_turns,
    join_split_tool_call_turns_pending, opencode_headers, vendor_thinking_off_fields,
};
use streaming::{
    AttemptSuccess, CursorHandle, HoldSignal, OnClientGone, PumpSide, RelayOutcome, StreamFrames,
    StreamPump, StreamUsage, spawn_stream_pump,
};

/// Full context of one client request.
pub struct RelayRequest {
    pub protocol: ProtocolId,
    pub body: Value,
    pub stream: bool,
    /// Mirror request/response payloads into the log (target `gateway::payload`).
    pub payload_log: bool,
    /// The caller the HTTP auth hoop verified (gateway key + owning user +
    /// group). None only for in-process calls that never pass HTTP auth (the
    /// admin chat facade, test hosts); every `/v1*` request carries one.
    pub principal: Option<store::Principal>,
    /// Which client the request's User-Agent names; None
    /// when the header is absent or the call is in-process.
    pub agent: Option<String>,
}

/// Payload logs are truncated: bodies can carry whole conversations.
const MAX_PAYLOAD_LOG_BYTES: usize = 64 * 1024;

/// The reasoning effort the client asked for, read straight off the request
/// body (read-only — nothing is rewritten). The matrix: chat reads
/// `reasoning_effort` with `thinking.effort` (Kimi Code 2.x) as fallback;
/// responses reads `reasoning.effort`; anthropic maps
/// `thinking.budget_tokens` to a level (thinking must be enabled/adaptive — a
/// title request with effort but no thinking stays effortless) and lets
/// `output_config.effort` override it.
/// Levels normalize to low/medium/high/xhigh/max, explicit off to `off`;
/// None = no effort named.
pub fn extract_effort(protocol: ProtocolId, body: &Value) -> Option<String> {
    let name = |raw: &str| {
        Effort::parse_name(raw).map(|effort| match effort {
            Effort::None => "off".to_owned(),
            named => named.chat_name().to_owned(),
        })
    };
    match protocol {
        ProtocolId::OpenAiChat => body
            .get("reasoning_effort")
            .and_then(Value::as_str)
            .and_then(name)
            .or_else(|| {
                body.get("thinking")
                    .and_then(|t| t.get("effort"))
                    .and_then(Value::as_str)
                    .and_then(name)
            }),
        ProtocolId::OpenAiResponses => body
            .get("reasoning")
            .and_then(|r| r.get("effort"))
            .and_then(Value::as_str)
            .and_then(name),
        ProtocolId::AnthropicMessages => {
            let thinking = body.get("thinking")?;
            let kind = thinking.get("type").and_then(Value::as_str)?;
            if kind != "enabled" && kind != "adaptive" {
                return None;
            }
            let budgeted = thinking
                .get("budget_tokens")
                .and_then(Value::as_u64)
                .and_then(Effort::from_budget)
                .map(|effort| effort.chat_name().to_owned());
            // output_config (request-level or per-message) overrides the budget.
            let configured = body
                .get("output_config")
                .and_then(|oc| oc.get("effort"))
                .and_then(Value::as_str)
                .and_then(name)
                .or_else(|| {
                    body.get("messages")?
                        .as_array()?
                        .iter()
                        .rev()
                        .find_map(|message| {
                            message
                                .get("output_config")?
                                .get("effort")
                                .and_then(Value::as_str)
                                .and_then(name)
                        })
                });
            configured.or(budgeted)
        }
        // Neither carries an effort dial: Gemini's effort lives in
        // `generationConfig`, and a retrieval call generates nothing at all.
        // Kiro and Cursor never arrive inbound — translation targets only.
        ProtocolId::Gemini
        | ProtocolId::OpenAiEmbeddings
        | ProtocolId::Kiro
        | ProtocolId::Cursor => None,
    }
}

/// The tracing target for payload logs — RUST_LOG can tune it independently
/// (`gateway::payload=off` silences bodies without hiding the relay's warns).
const PAYLOAD_TARGET: &str = "gateway::payload";

/// Tracing target for effort-clamp decisions (one info line per clamped attempt).
const EFFORT_TARGET: &str = "cardinal::relay::effort";

/// Char-boundary-safe truncation (slicing a multibyte char would panic).
/// Payload-log rendering cap: one small slack above body_log's capture limit,
/// so the capture's own boundary-accurate cut still sees the same bytes an
/// unbounded render would have given it.
const PAYLOAD_RENDER_LIMIT: usize = crate::body_log::CALL_BODY_LIMIT + 4;

/// A bounded rendering of a JSON body for payload logging: `text` stops at
/// [`PAYLOAD_RENDER_LIMIT`] bytes while `total_bytes` keeps the true size for
/// the log line. A long-context body costs the capped buffer plus a counter —
/// never a second full copy of itself.
struct RenderedPayload {
    text: String,
    total_bytes: usize,
}

/// A `Vec<u8>` sink that retains only the first `cap` bytes yet counts every
/// byte written, so the caller learns the full size without holding it.
struct BoundedWriter {
    buf: Vec<u8>,
    cap: usize,
    total: usize,
}

impl BoundedWriter {
    fn new(cap: usize) -> Self {
        Self {
            buf: Vec::new(),
            cap,
            total: 0,
        }
    }
}

impl std::io::Write for BoundedWriter {
    fn write(&mut self, chunk: &[u8]) -> std::io::Result<usize> {
        self.total = self.total.saturating_add(chunk.len());
        let room = self.cap.saturating_sub(self.buf.len());
        self.buf.extend_from_slice(&chunk[..chunk.len().min(room)]);
        Ok(chunk.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Render a JSON body for payload logging, bounded (see [`RenderedPayload`]).
/// Serializing a `Value` into this always-OK writer cannot fail, so the
/// discarded `Result` is unreachable.
fn render_payload_bounded(body: &Value) -> RenderedPayload {
    let mut writer = BoundedWriter::new(PAYLOAD_RENDER_LIMIT);
    let _ = serde_json::to_writer(&mut writer, body);
    // A cut can land inside a UTF-8 character; lossy decoding repairs the tail
    // (a stray U+FFFD in a diagnostic capture, never anything on the wire).
    let text = String::from_utf8_lossy(&writer.buf).into_owned();
    RenderedPayload {
        text,
        total_bytes: writer.total,
    }
}

/// Cut a rendered payload down to the log-line cap. `total_bytes` is the FULL
/// body size — the caller may have rendered a bounded prefix (see
/// [`render_payload_bounded`]) while still owing the log the true total.
fn truncate_payload(text: &str, total_bytes: usize) -> String {
    if text.len() <= MAX_PAYLOAD_LOG_BYTES {
        return text.to_string();
    }
    let mut end = MAX_PAYLOAD_LOG_BYTES;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}… [truncated, {} bytes total]", &text[..end], total_bytes)
}

/// Diagnostic body capture of one in-flight request: the
/// client body is snapshotted at dispatch entry; the response side lands when
/// the attempt settles. Carried through the attempt loop and consumed by
/// whichever terminal path persists the final row.
pub(crate) struct RequestCapture {
    request_text: String,
    request_truncated: bool,
    streaming: bool,
    started: chrono::DateTime<chrono::Utc>,
}

/// Ask the vendor's own quota endpoint when a quota-refused key's window
/// resets (the `quota.rs` per-vendor source, previously admin-plane only).
/// The binding constraint is the latest-stated reset among the windows — a
/// monthly exhaustion outlasts the weekly one. `None` = no source, probe
/// failure, or no forward-looking reset; the caller then rests the default.
async fn probe_quota_reset(
    provider_name: &str,
    base_url: &str,
    api_key: Option<&str>,
    dns: crate::upstream::Dns,
    transport: &crate::upstream::transport::Transport,
) -> Option<chrono::DateTime<chrono::Utc>> {
    let api_key = api_key?;
    let quota =
        crate::quota::fetch_quota(provider_name, base_url, api_key, None, dns, transport).await?;
    let now = chrono::Utc::now();
    let reset = quota
        .windows
        .iter()
        .filter_map(|w| w.resets_at)
        .filter(|t| *t > now)
        .max()?;
    tracing::info!(provider = provider_name, %reset, "quota refused: resting until the vendor's stated window reset");
    Some(reset)
}

/// Attach the captured bodies to the settling dispatch, keyed by its request
/// id (`req_<uuid>`): the ledger writer batches inserts, so no DB row id exists
/// at capture time. Failover writes one row per attempt, and only the settled
/// request carries bodies (intermediate failures stay uncaptured on purpose).
fn push_capture(
    body_log: &BodyLog,
    request_id: &str,
    capture: RequestCapture,
    response: Option<(String, bool)>,
) {
    let (response, response_truncated) = match response {
        Some((text, truncated)) => (Some(text), truncated),
        None => (None, false),
    };
    // Credentials can ride inside the captured bodies (auth translations,
    // upstream error echoes): the payload log is operator-readable, so mask
    // secrets before they ever hit disk.
    let request = crate::body_log::mask_secrets(&capture.request_text);
    let response = response.map(|text| crate::body_log::mask_secrets(&text));
    body_log.push(
        request_id,
        CapturedBodies {
            request,
            response,
            request_truncated: capture.request_truncated,
            response_truncated,
            streaming: capture.streaming,
            captured_at: capture.started,
        },
    );
}

/// Execute one relay attempt (non-streaming and streaming share preparation and send; streaming only takes response headers).
async fn attempt(
    ctx: &AttemptContext<'_>,
    target_model: &str,
    request: &RelayRequest,
    client_ir: &mut ClientIr,
    request_id: &str,
    deadline: std::time::Instant,
) -> Result<RelayOutcome, failover::AttemptError> {
    if !request.stream {
        attempt_json(ctx, target_model, request, client_ir, deadline).await
    } else {
        attempt_stream(ctx, target_model, request, client_ir, request_id, deadline).await
    }
}

/// Everything the Kiro token plane needs for one candidate: the key row (its
/// stored bundle seeds the manager and its id keys the per-key lock), the
/// gateway database (rereads and write-backs), the manager itself, and the
/// simulated prompt cache (KAS reports no cached-token split).
///
/// Bundled as one optional field so every non-Kiro candidate pays nothing for
/// it — and so the credential path reads as one thing at the construction site.
#[derive(Clone, Copy)]
struct KiroDeps<'a> {
    key: &'a crate::store::ProviderKeyRow,
    pool: &'a sqlx::PgPool,
    tokens: &'a KiroTokens,
    prompt_cache: &'a PromptCache,
    /// The gateway key that called, when this candidate takes part in the
    /// simulated cache: a cached prefix is only ever read back by the caller
    /// that sent it. `None` disables the cache (in-process calls, or a model
    /// with no cache-read price, whose hit would bill as free input).
    cache_caller_key_id: Option<i64>,
}

/// Everything the OpenCode token plane needs for one candidate: the key's id
/// (the cache and gate key), the gateway database (rereads and the CAS
/// write-back), and the manager itself.
///
/// Selected by the key's `auth_kind`, never by the upstream protocol: one
/// account serves chat, messages and responses. Bundled as one optional field so
/// a static candidate pays nothing for it.
#[derive(Clone, Copy)]
struct OpencodeDeps<'a> {
    tokens: &'a OpencodeTokens,
    pool: &'a sqlx::PgPool,
    key_id: i64,
}

/// Everything the OpenAI Codex token plane needs for one candidate: the key's
/// id (the cache and gate key), the gateway database (rereads and the CAS
/// write-back) and the manager itself.
///
/// Selected by the key's `auth_kind`, like [`OpencodeDeps`]. Bundled as one
/// optional field so a static candidate pays nothing for it.
#[derive(Clone, Copy)]
struct OpenaiDeps<'a> {
    tokens: &'a OpenaiTokens,
    pool: &'a sqlx::PgPool,
    key_id: i64,
}

/// Everything the Cursor credential plane needs for one candidate: the
/// manager, the gateway database (bundle rereads and write-back), the key's id
/// and the credential the row holds — a browser-login bundle, or a static API
/// key the manager exchanges for a bearer. Selected by the upstream protocol:
/// every Cursor Run authenticates through the manager, never with the row's
/// secret on the wire.
#[derive(Clone, Copy)]
struct CursorDeps<'a> {
    tokens: &'a CursorTokens,
    pool: &'a sqlx::PgPool,
    key_id: i64,
    credential: &'a KeyCredential<'a>,
    /// The usage reconciler the settlement reads the dashboard with.
    usage: &'a std::sync::Arc<CursorUsage>,
    dns: crate::upstream::Dns,
}

/// The unchanging surroundings of one dispatch attempt: transport, the chosen
/// upstream capability, credential material, the learned-refusal registry, the
/// vendor fixup fields this candidate's upstream must never see, and — for
/// OpenCode upstreams — the conversation seed computed once per dispatch.
/// Bundled so the attempt functions stay under clippy's argument ceiling.
struct AttemptContext<'a> {
    transport: &'a Transport,
    capability: &'a capabilities::Capability,
    credential: &'a crate::providers::AuthSchemeMaterial<'a>,
    unfit: &'a optional::Unfit,
    provider_id: i64,
    dns: crate::upstream::Dns,
    vendor_skip: &'a [&'static str],
    /// The conversation seed (the serialized first user message), computed once
    /// per dispatch; `None` when no OpenCode or Codex upstream is in play.
    /// OpenCode derives `x-opencode-session` from it, Codex its session headers.
    session_seed: Option<&'a str>,
    /// This candidate's Chat-body adaptations (none for the common request).
    fixups: ChatFixups,
    /// This candidate model's supported effort levels (ascending, named only);
    /// `None` = unconstrained.
    supported_efforts: Option<&'a [Effort]>,
    /// The vendor-declared default level, used to repair names outside the
    /// closed vocabulary.
    default_effort: Option<Effort>,
    /// The candidate model's declared context window. `None` = unknown, so the
    /// response decoder must omit usage rather than invent it.
    context_window: Option<u64>,
    /// 路由层固定 effort 档位;`None` = 直连或 legacy 路由(快照 clamp)。
    route_efforts: Option<&'a [Effort]>,
    /// 当前候选 (provider, model family) 的 effort 方言。
    dial: capabilities::EffortDial,
    /// Kiro only: this candidate's token plumbing. `None` for every non-Kiro
    /// protocol, which therefore never touches the token manager or PG.
    kiro: Option<KiroDeps<'a>>,
    /// OpenCode account rows only: this candidate's bearer plumbing. `None` for
    /// every static key, so those never touch the token manager or PG.
    opencode: Option<OpencodeDeps<'a>>,
    /// OpenAI Codex account rows only: this candidate's bearer plumbing. `None`
    /// for every static key. Its presence also selects the Codex body
    /// adaptation (forced `store`/`stream`, defaulted `instructions`).
    openai: Option<OpenaiDeps<'a>>,
    /// Cursor upstreams only: this candidate's bearer plumbing. `None` for
    /// every other protocol.
    cursor: Option<CursorDeps<'a>>,
}

/// The Cursor Run's auth headers: the resolved bearer plus, for a team
/// account, the team the console bound the login to.
fn cursor_auth_headers(bearer: &CursorBearer) -> Vec<(&'static str, String)> {
    let mut headers = vec![("authorization", format!("Bearer {}", bearer.access_token()))];
    if let Some(team_id) = bearer.team_id() {
        headers.push(("x-cursor-team-id", team_id.to_owned()));
    }
    headers
}

/// Whether Cursor refused the Run because the model needs Max Mode (the
/// reference retries once with the flag set).
fn cursor_requires_max_mode(body: &[u8]) -> bool {
    let text = String::from_utf8_lossy(body).to_ascii_lowercase();
    [
        "max mode required",
        "max_mode_required",
        "max mode_required",
        "max_mode required",
    ]
    .iter()
    .any(|needle| text.contains(needle))
        || text.contains("requires max mode")
}

/// The OpenCode account's auth headers: the resolved bearer plus, for an
/// organization-scoped login, the workspace the console bound the token to.
///
/// Built here rather than through [`crate::providers::AuthSchemeMaterial`]
/// because the material is a rotating bundle, not the row's static credential;
/// every other header on the request is unaffected.
fn opencode_auth_headers(bundle: &OpencodeOAuth) -> Vec<(&'static str, String)> {
    let mut headers = vec![("authorization", format!("Bearer {}", bundle.access_token))];
    if let Some(org_id) = bundle.org_id.as_deref() {
        headers.push(("x-opencode-org-id", org_id.to_owned()));
    }
    headers
}

/// Shared send for both attempt flavors: prepare (passthrough or translated),
/// send, and status validation. The returned response is finished by the
/// caller (stream reader vs bounded body read).
///
/// A strict upstream that 400/422s on an optional request field it doesn't
/// know (Mistral's extra_forbidden for OpenCode's `store`) is
/// asked again without the fields it named, and the refusal is remembered in
/// `unfit` so later requests pre-strip instead of paying the round-trip.
async fn send_attempt(
    ctx: &AttemptContext<'_>,
    target_model: &str,
    request: &RelayRequest,
    client_ir: &mut ClientIr,
    stream: bool,
    deadline: std::time::Instant,
) -> Result<Sent, failover::AttemptError> {
    let AttemptContext {
        transport,
        capability,
        credential,
        unfit,
        provider_id,
        dns,
        vendor_skip,
        session_seed,
        fixups,
        supported_efforts,
        default_effort,
        // Only the response decoders read the window; the request path never needs it.
        context_window: _,
        route_efforts,
        dial,
        kiro,
        opencode,
        openai,
        cursor,
    } = *ctx;
    // The selected capability IS the upstream protocol: passthrough when it
    // matches the client protocol, translation target otherwise.
    let protocol = capability.protocol;
    // A Cursor Run authenticates with a bearer the manager produced from the
    // row's credential (a login bundle refreshed under the key's gate, or an
    // API key exchanged once and cached); the row's own secret never goes on
    // the wire. A missing plumbing for a Cursor upstream is a wiring fault,
    // reported as a missing credential rather than sent unauthenticated.
    let cursor_bearer = match (protocol, cursor) {
        (ProtocolId::Cursor, Some(deps)) => Some(
            deps.tokens
                .resolve(deps.pool, deps.key_id, deps.credential, dns)
                .await
                .map_err(failover::AttemptError::CursorTokenError)?,
        ),
        (ProtocolId::Cursor, None) => {
            return Err(failover::AttemptError::CursorTokenError(
                CursorTokenError::Missing,
            ));
        }
        _ => None,
    };
    // Kiro: one logical call per dispatch attempt (the reference's one
    // `execute()`). The invocation id and attempt counter live here, outside
    // the send/re-prepare loop, so an optional-field strip re-prepare advances
    // the attempt instead of presenting the upstream with an invocation it has
    // never seen. A failover to the next candidate enters this function again
    // and therefore starts a new logical call.
    let kas_call = (protocol == ProtocolId::Kiro).then(crate::kiro::KasCall::default);
    // Kiro's bearer rotates, so it is resolved per attempt. A still-fresh token
    // costs one lock acquisition and no I/O; a stale one refreshes under the
    // key's lock (single-flight) and persists the rotated bundle. The KAS
    // body's `profileArn` comes from the same live bundle, so a refresh that
    // moved the account identity is reflected before the body is prepared.
    let mut kiro_call: Option<KiroCallContext> = match (protocol, kiro) {
        (ProtocolId::Kiro, Some(deps)) => {
            // The manager pins the destination to the credential's own runtime
            // host before and after resolving it; fail closed on a mismatch.
            let call = deps
                .tokens
                .access_token_for_endpoint(deps.pool, deps.key, &capability.endpoint, dns)
                .await
                .map_err(failover::AttemptError::KiroTokenError)?;
            Some(call)
        }
        (ProtocolId::Kiro, None) => {
            return Err(failover::AttemptError::KiroTokenError(
                kiro_tokens::KiroTokenError::MissingCredential,
            ));
        }
        _ => None,
    };
    // The account identity the prepared body carries (updated if a 401 refresh
    // rotates it mid-attempt). Owned: the call context it came from is replaced
    // by the refresh, while the strip round still prepares from this copy.
    let mut kiro_profile_arn = kiro_call.as_ref().and_then(|call| call.profile_arn.clone());
    // An OpenCode account bearer rotates on the console's schedule, so it is
    // resolved per attempt: one cache lookup while the bundle is fresh, a
    // single-flight refresh otherwise. The row's own credential never carries it
    // (an `opencode_oauth` row's `api_key` is NULL).
    let mut opencode_bundle = match opencode {
        Some(deps) => Some(
            deps.tokens
                .resolve(deps.pool, deps.key_id)
                .await
                .map_err(failover::AttemptError::OpencodeTokenError)?,
        ),
        None => None,
    };
    // An OpenAI Codex account bearer is resolved per attempt the same way.
    let mut openai_bundle = match openai {
        Some(deps) => Some(
            deps.tokens
                .resolve(deps.pool, deps.key_id)
                .await
                .map_err(failover::AttemptError::OpenaiTokenError)?,
        ),
        None => None,
    };
    let target = TargetView {
        protocol,
        endpoint: &capability.endpoint,
        stream_endpoint: capability.stream_endpoint.as_deref(),
        upstream_model: target_model,
        kas_call: kas_call.as_ref(),
        forced: if openai.is_some() {
            capabilities::codex::FORCED_FIELDS
        } else {
            &[]
        },
        required: if openai.is_some() {
            capabilities::codex::REQUIRED_FIELDS
        } else {
            &[]
        },
    };

    // Fields the wire must not carry, all known before the send: the vendor
    // fixup's (GLM always-thinking `thinking`) plus every optional field this
    // upstream is already known to refuse. Prepare
    // omits them while it builds the body — no parse/re-serialize strip
    // round-trip — and kernel-injected fields (chat's `stream_options`,
    // responses' `store` pin) honor the skip the same way the old
    // strip-after-prepare did.
    let mut skip: Vec<&'static str> = vendor_skip.to_vec();
    skip.extend(unfit.refused_fields(provider_id, protocol));
    // Per-candidate Chat-body adaptations:
    //   GLM: the client's inline images (passthrough) or the ones the emitter
    //   re-encodes (translated) arrive as data URIs, which GLM rejects. That
    //   strip is a pure string rewrite, so it rides the wire render
    //   (protocol::prepare's strip_images) and never copies the tree.
    //   DeepSeek: a calling assistant turn must be followed by its tool
    //   results, and a mixed reasoning history must be levelled. Both edits
    //   are structural, so they are detected read-only first and materialized
    //   as ONE owned copy only when either has real work; the edits then land
    //   in place.
    let mut adapted_body: Option<std::borrow::Cow<'_, Value>> = None;
    if fixups.deepseek_dialect
        && (join_split_tool_call_turns_pending(&request.body)
            || fill_missing_reasoning_pending(&request.body))
    {
        let body = adapted_body
            .get_or_insert(std::borrow::Cow::Borrowed(&request.body))
            .to_mut();
        join_split_tool_call_turns(body);
        fill_missing_reasoning(body);
    }
    // Passthrough carries the client's own wire shape — no IR to normalize.
    // Even without a snapshot, the dial is scrubbed against the closed
    // vocabulary: aliases become canonical names and unknown/off values are
    // repaired to the vendor's own markers, so a strict upstream never sees a
    // name it would 400 on. Plan read-only first and materialize one owned
    // copy only when a rewrite is due (same Cow discipline as the fixups).
    let mut clamp_note: Option<(String, String)> = None;
    if request.protocol == protocol {
        let current: &Value = adapted_body
            .as_ref()
            .map_or(&request.body, std::borrow::Cow::as_ref);
        let effort_target = translation::effort_clamp::EffortTarget {
            route: route_efforts,
            snapshot: supported_efforts.unwrap_or(&[]),
            default: default_effort.unwrap_or(Effort::Medium),
            dial,
        };
        let rewrites = translation::effort_clamp::plan(protocol, current, &effort_target);
        if !rewrites.is_empty() {
            let body = adapted_body
                .get_or_insert(std::borrow::Cow::Borrowed(&request.body))
                .to_mut();
            clamp_note = translation::effort_clamp::apply(body, &rewrites);
        }
    }
    if let Some((from, to)) = &clamp_note {
        tracing::info!(
            target: EFFORT_TARGET,
            model = target_model,
            provider_id,
            from,
            to,
            "effort normalized for upstream"
        );
    }
    let passthrough_body: &Value = adapted_body
        .as_ref()
        .map_or(&request.body, std::borrow::Cow::as_ref);
    // Kiro: the scope a simulated cache read is confined to (account, caller,
    // upstream model); `None` keeps every other attempt out of the cache.
    let prompt_scope = kiro.and_then(|deps| {
        deps.cache_caller_key_id
            .map(|caller_key_id| prompt_cache::Scope {
                account_key_id: deps.key.id,
                caller_key_id,
                model: target_model,
            })
    });
    // Only the first preparation digests the prompt: a re-prepare strips
    // optional fields or rotates the profile, neither of which is prompt, so it
    // passes no scope and skips the hashing.
    let mut prepare = |fields: &[&str],
                       profile_arn: Option<&str>,
                       prompt_scope: Option<prompt_cache::Scope<'_>>,
                       cursor_max_mode: bool| {
        if request.protocol == protocol {
            protocol::prepare(
                protocol,
                passthrough_body,
                &target,
                stream,
                fields,
                fixups.strip_glm_images,
            )
            .map(|prepared| PreparedBody {
                prepared,
                prompt_prefix: None,
            })
        } else {
            prepare_translated(
                &request.body,
                client_ir,
                request.protocol,
                protocol,
                &target,
                stream,
                WireTweaks {
                    skip: fields,
                    fixups,
                    supported_efforts,
                    route_efforts,
                    dial,
                    kiro_profile_arn: profile_arn,
                    prompt_scope,
                    cursor_max_mode,
                },
            )
        }
    };
    let PreparedBody {
        mut prepared,
        prompt_prefix,
    } = prepare(&skip, kiro_profile_arn.as_deref(), prompt_scope, false)
        .map_err(failover::AttemptError::Protocol)?;
    // Cursor: two HTTP legs driven as one Run, with its own retry rules (no
    // optional-field strips — the body is protobuf the kernel wrote), so it
    // leaves the HTTP loop below.
    if let (Some(bearer), Some(deps)) = (cursor_bearer, cursor) {
        return send_cursor(
            transport,
            dns,
            deps,
            bearer,
            prepared,
            |max_mode| {
                prepare(&skip, None, None, max_mode)
                    .map(|body| body.prepared)
                    .map_err(failover::AttemptError::Protocol)
            },
            deadline,
        )
        .await;
    }
    // OpenCode's gateway (Zen or Go) refuses requests that name no conversation
    // (400 MissingSessionID), so its header family rides beside the credential.
    // The session seed derives from the first user message — top-level field
    // strips never move it — and was computed once per dispatch.
    // Kiro's Authorization is the call-context bearer; the row's own credential
    // (the static-scheme placeholder, or a secret an operator typed on a Kiro
    // row) never goes upstream. The same holds for an OpenCode account row, whose
    // bearer is the resolved bundle's access token.
    let mut headers = match (&kiro_call, &opencode_bundle, &openai_bundle) {
        (_, _, Some(bundle)) => capabilities::codex::headers(bundle, session_seed),
        (_, Some(bundle), None) => opencode_auth_headers(bundle),
        (Some(call), None, None) => {
            vec![("authorization", format!("Bearer {}", call.bearer()))]
        }
        (None, None, None) => credential.headers(),
    };
    if let Some(seed) = session_seed
        && is_opencode_upstream(&capability.endpoint)
    {
        headers.extend(opencode_headers(seed));
    }
    let query_pairs = if kiro_call.is_some() || opencode_bundle.is_some() || openai_bundle.is_some()
    {
        Vec::new()
    } else {
        credential.query_pairs()
    };

    let mut rounds = 0u32;
    let mut kiro_retried = false;
    let mut opencode_retried = false;
    let mut openai_retried = false;
    loop {
        let response = transport
            .send_with_headers(&prepared, dns, &headers, &query_pairs, deadline)
            .await
            .map_err(failover::AttemptError::Transport)?;
        let status = response.status().as_u16();
        // Only 2xx is a success. Redirects are never followed (the credential
        // must not reach another authority), so a 3xx is a failed attempt too.
        if (200..300).contains(&status) {
            // The vendor accepted this prompt; the cache is read and written
            // only once the attempt completes (the caller settles it).
            let cache_read = match (kiro, prompt_prefix) {
                (Some(deps), Some(prefix)) => {
                    Some(prompt_cache::PendingRead::new(deps.prompt_cache, prefix))
                }
                _ => None,
            };
            return Ok(Sent {
                status,
                upstream: Upstream::Http(response),
                protocol,
                cache_read,
            });
        }
        // Capture the vendor's error body (bounded, best-effort: an unreadable body
        // still yields the Status error, just without evidence) so the relay can
        // classify the failure and the attempt log shows the vendor's own words.
        let response_headers = response.headers().clone();
        let body = transport
            .read_body(response, transport::MAX_ERROR_BODY, deadline)
            .await
            .unwrap_or_default();
        // OpenCode: the gateway's own 401 licences exactly one refresh-and-resend
        // of this same call. The wire body carries no bearer, so only the headers
        // are rebuilt — same request, one attempt later. Concurrent requests that
        // presented the same stale bearer de-duplicate on the key's gate, and a
        // 401 raised after another request already rotated the bundle adopts that
        // bundle instead of rotating it a second time.
        if !opencode_retried
            && status == 401
            && let Some(deps) = opencode
            && let Some(presented) = opencode_bundle.as_deref()
        {
            opencode_retried = true;
            let bundle = deps
                .tokens
                .resolve_forced(deps.pool, deps.key_id, &presented.access_token)
                .await
                .map_err(failover::AttemptError::OpencodeTokenError)?;
            headers = opencode_auth_headers(&bundle);
            if let Some(seed) = session_seed {
                headers.extend(opencode_headers(seed));
            }
            opencode_bundle = Some(bundle);
            tracing::warn!(
                key_id = deps.key_id,
                status,
                "OpenCode rejected the bearer; refreshed once, resending the same call"
            );
            continue;
        }
        // OpenAI Codex: same contract as OpenCode above, one refresh-and-resend
        // after a 401.
        if !openai_retried
            && status == 401
            && let Some(deps) = openai
            && let Some(presented) = openai_bundle.as_deref()
        {
            openai_retried = true;
            let bundle = deps
                .tokens
                .resolve_forced(deps.pool, deps.key_id, &presented.access_token)
                .await
                .map_err(failover::AttemptError::OpenaiTokenError)?;
            headers = capabilities::codex::headers(&bundle, session_seed);
            openai_bundle = Some(bundle);
            tracing::warn!(
                key_id = deps.key_id,
                status,
                "Codex backend rejected the bearer; refreshed once, resending the same call"
            );
            continue;
        }
        // Kiro: the runtime's own invalidation signal licenses exactly one
        // refresh-and-resend of this SAME invocation (same invocation id, the
        // wire re-prepared with the refreshed identity, attempt advanced).
        // Any other 401/403 — or a second rejection
        // after the refresh — falls through to the ordinary failure path.
        if !kiro_retried
            && kiro_tokens::bearer_token_invalid(status, &body)
            && let (Some(deps), Some(call)) = (kiro, &kiro_call)
        {
            kiro_retried = true;
            // Concurrent requests that presented the same stale bearer
            // de-duplicate in the manager: one CreateToken, everyone reuses.
            let recovered = deps
                .tokens
                .recover_invalidated_for_endpoint(
                    deps.pool,
                    deps.key,
                    &capability.endpoint,
                    call.bearer(),
                    dns,
                )
                .await
                .map_err(failover::AttemptError::KiroTokenError)?;
            kiro_profile_arn = recovered.profile_arn.clone();
            headers = vec![("authorization", format!("Bearer {}", recovered.bearer()))];
            kiro_call = Some(recovered);
            // Cold path, at most once per attempt: rebuild the wire through the
            // one preparation path. The refresh may have moved the account
            // identity (`profileArn`), and `prepare` advances the shared
            // `KasCall` itself, so the retry headers are replaced wholesale —
            // same invocation id, one attempt later — with no second writer.
            prepared = prepare(&skip, kiro_profile_arn.as_deref(), None, false)
                .map_err(failover::AttemptError::Protocol)?
                .prepared;
            tracing::warn!(
                key_id = deps.key.id,
                status,
                "Kiro runtime rejected the bearer; refreshed once, resending the same call"
            );
            continue;
        }
        // Refusal detection skips Anthropic upstreams (its API never names
        // request fields in errors).
        // Both refusal readers answer nothing outside 400/422, so any other
        // status skips the parse of the sent body.
        if protocol != ProtocolId::AnthropicMessages
            && rounds < optional::MAX_STRIP_ROUNDS
            && (status == 400 || status == 422)
            && let Ok(sent) = serde_json::from_slice::<Value>(&prepared.body)
        {
            let refused = optional::refused_optional(status, &body, &sent);
            if !refused.is_empty() {
                // Extend the skip list and rebuild the wire from the still-available
                // client tree — cheaper than parsing and re-serializing the wire
                // body, and it covers kernel-injected fields identically.
                skip.extend(refused.iter().copied());
                if let Ok(PreparedBody {
                    prepared: retried, ..
                }) = prepare(&skip, kiro_profile_arn.as_deref(), None, false)
                {
                    for field in &refused {
                        unfit.record(provider_id, protocol, field);
                    }
                    tracing::info!(
                        provider_id,
                        protocol = protocol.as_str(),
                        ?refused,
                        "upstream refused optional fields; stripped, retrying"
                    );
                    prepared = retried;
                    rounds += 1;
                    continue;
                }
            } else if optional::carries_json_object(&sent)
                && optional::refuses_json_mode(status, &body)
            {
                // A node without JSON output mode names no field. Ask once more
                // without the mode; not learned, because the next request may
                // land on a node that has it (see `optional::refuses_json_mode`).
                skip.push(optional::JSON_MODE_FIELD);
                if let Ok(PreparedBody {
                    prepared: retried, ..
                }) = prepare(&skip, kiro_profile_arn.as_deref(), None, false)
                {
                    tracing::info!(
                        provider_id,
                        protocol = protocol.as_str(),
                        "upstream refused JSON output mode; dropped response_format, retrying"
                    );
                    prepared = retried;
                    rounds += 1;
                    continue;
                }
            }
        }
        // A vendor error body can echo the credential it just rejected; excise it
        // before the body becomes the attempt's error — that error is what the
        // caller reads, what the attempt log prints, and what the request row keeps.
        let account_token = opencode_bundle
            .as_deref()
            .map(|bundle| bundle.access_token.as_str())
            .or_else(|| {
                openai_bundle
                    .as_deref()
                    .map(|bundle| bundle.access_token.as_str())
            });
        let redacted = match (&kiro_call, account_token) {
            (_, Some(token)) => crate::providers::AuthSchemeMaterial::new(
                crate::providers::AuthScheme::Bearer,
                token,
            )
            .redact(&body),
            (Some(call), None) => crate::providers::AuthSchemeMaterial::new(
                crate::providers::AuthScheme::Bearer,
                call.bearer(),
            )
            .redact(&body),
            (None, None) => credential.redact(&body),
        };
        let body = match redacted {
            Some(redacted) => bytes::Bytes::from(redacted),
            None => bytes::Bytes::from(body),
        };
        return Err(
            match transport::status_error(status, &response_headers, body) {
                Some(error) => failover::AttemptError::Transport(error),
                // Unreachable (a non-2xx status always classifies), kept total without panicking.
                None => failover::AttemptError::Transport(transport::TransportError::InvalidBody),
            },
        );
    }
}

/// The Cursor leg of [`send_attempt`]: open the Run and apply the two retries
/// the reference allows — one refresh-and-resend after Cursor rejects the
/// bearer (401, either as the downlink's status or as the Run's first frame),
/// and one re-prepare with Max Mode when the model demands it. Every other
/// refusal is the attempt's error, with the bearer excised from Cursor's words.
async fn send_cursor(
    transport: &Transport,
    dns: crate::upstream::Dns,
    deps: CursorDeps<'_>,
    mut bearer: std::sync::Arc<CursorBearer>,
    mut prepared: protocol::Prepared,
    mut reprepare: impl FnMut(bool) -> Result<protocol::Prepared, failover::AttemptError>,
    deadline: std::time::Instant,
) -> Result<Sent, failover::AttemptError> {
    let mut headers = cursor_auth_headers(&bearer);
    let mut refreshed = false;
    let mut max_mode = false;
    loop {
        let error = match cursor_run::open(transport, dns, &prepared, &headers, deadline).await {
            Ok(run) => {
                return Ok(Sent {
                    status: run.status,
                    upstream: Upstream::Cursor {
                        run: Box::new(run),
                        bearer: std::sync::Arc::clone(&bearer),
                    },
                    protocol: ProtocolId::Cursor,
                    cache_read: None,
                });
            }
            Err(error) => error,
        };
        let transport::TransportError::Status { status, body, .. } = &error else {
            return Err(failover::AttemptError::Transport(error));
        };
        if !refreshed && *status == 401 {
            refreshed = true;
            bearer = deps
                .tokens
                .resolve_forced(
                    deps.pool,
                    deps.key_id,
                    deps.credential,
                    bearer.access_token(),
                    dns,
                )
                .await
                .map_err(failover::AttemptError::CursorTokenError)?;
            headers = cursor_auth_headers(&bearer);
            tracing::warn!(
                key_id = deps.key_id,
                "Cursor rejected the bearer; refreshed once, opening the Run again"
            );
            continue;
        }
        if !max_mode && cursor_requires_max_mode(body) {
            max_mode = true;
            prepared = reprepare(true)?;
            tracing::info!(
                key_id = deps.key_id,
                "Cursor requires Max Mode for this model; asking again with it"
            );
            continue;
        }
        // Cursor's words may echo the bearer it rejected; excise it before the
        // body becomes the attempt's error.
        let redacted = crate::providers::AuthSchemeMaterial::new(
            crate::providers::AuthScheme::Bearer,
            bearer.access_token(),
        )
        .redact(body);
        return Err(failover::AttemptError::Transport(match redacted {
            Some(redacted) => transport::TransportError::Status {
                status: *status,
                retry_after: None,
                reset_header: None,
                body: bytes::Bytes::from(redacted),
            },
            None => error,
        }));
    }
}

// Price per request is computed at the attempt sites; the model-level price
// row carries every unit the formula needs (see store::ModelPrice::cost_split).

/// Streaming attempt: send prepared, validate the status, then return the StreamReader and pump.
async fn attempt_stream(
    ctx: &AttemptContext<'_>,
    target_model: &str,
    request: &RelayRequest,
    client_ir: &mut ClientIr,
    request_id: &str,
    deadline: std::time::Instant,
) -> Result<RelayOutcome, failover::AttemptError> {
    let Sent {
        status,
        upstream,
        protocol,
        cache_read,
    } = send_attempt(ctx, target_model, request, client_ir, true, deadline).await?;
    let (reader, cursor) = match upstream {
        Upstream::Http(response) => (ctx.transport.stream(response, deadline, protocol), None),
        // The Run's driver already split the downlink into frames; the reader
        // takes them with the same idle/total bounds as an HTTP body.
        Upstream::Cursor { run, bearer } => {
            let cursor_run::Run { frames, report, .. } = *run;
            (
                ctx.transport.stream_frames(frames, deadline),
                cursor_handle(ctx, report, bearer),
            )
        }
    };
    let reader = Box::new(reader);

    let pump = if request.protocol == protocol {
        StreamPump::PassThrough {
            decoder: protocol::Decoder::new(protocol, ctx.context_window),
        }
    } else {
        // Translation: synthesize frames in the client protocol.
        let translator =
            translation::stream::StreamTranslator::new(request.protocol, target_model, request_id)
                .ok_or(failover::AttemptError::Protocol(
                    ProtocolError::UnsupportedApi,
                ))?;
        StreamPump::Translated {
            upstream: protocol,
            translator,
            context_window: ctx.context_window,
            cache_read,
        }
    };
    Ok(RelayOutcome::Stream {
        status,
        reader,
        pump,
        cursor,
    })
}

/// The settlement handle of a Cursor Run, from the attempt's plumbing.
fn cursor_handle(
    ctx: &AttemptContext<'_>,
    report: tokio::sync::oneshot::Receiver<cursor_run::RunReport>,
    bearer: std::sync::Arc<CursorBearer>,
) -> Option<CursorHandle> {
    let deps = ctx.cursor?;
    Some(CursorHandle {
        report,
        bearer,
        usage: std::sync::Arc::clone(deps.usage),
        key_id: deps.key_id,
        dns: deps.dns,
    })
}

/// Execute one relay attempt (non-streaming). Same protocol passes through; cross-protocol translates.
async fn attempt_json(
    ctx: &AttemptContext<'_>,
    target_model: &str,
    request: &RelayRequest,
    client_ir: &mut ClientIr,
    deadline: std::time::Instant,
) -> Result<RelayOutcome, failover::AttemptError> {
    let Sent {
        status,
        upstream,
        protocol,
        cache_read,
    } = send_attempt(ctx, target_model, request, client_ir, false, deadline).await?;
    let limit = ctx.transport.limits().max_json_bytes;
    let (body, cursor) = match upstream {
        Upstream::Http(response) => (
            ctx.transport
                .read_body(response, limit, deadline)
                .await
                .map_err(failover::AttemptError::Transport)?,
            None,
        ),
        // The whole Run as one Connect-framed body: the kernel's aggregate
        // decode reads it exactly as it would read a streamed one.
        Upstream::Cursor { mut run, bearer } => {
            let body = run
                .collect(limit, deadline)
                .await
                .map_err(failover::AttemptError::Transport)?;
            (body, cursor_handle(ctx, run.report, bearer))
        }
    };

    let mut observed = if request.protocol == protocol {
        // Passthrough: observe per the target protocol.
        protocol::parse_json(protocol, &body, ctx.context_window)
            .map_err(failover::AttemptError::Protocol)?
    } else {
        // Translation: upstream response → IR → source-protocol shape.
        let upstream_dialect =
            translation::dialect(protocol).map_err(failover::AttemptError::Protocol)?;
        let source_dialect =
            translation::dialect(request.protocol).map_err(failover::AttemptError::Protocol)?;
        let mut ir = (upstream_dialect.response_to_ir)(&body, ctx.context_window)
            .map_err(failover::AttemptError::Protocol)?;
        // Kiro reports no model identity. The client body must still carry a
        // sensible model, so fill an empty one with the model this attempt
        // actually requested (never an invented id). The ledger keeps the
        // evidence honest: an absent upstream model stays `None` there and
        // falls back to the requested target (AttemptLog::from_observed).
        let reported_model = !ir.model.is_empty();
        if !reported_model {
            ir.model = target_model.to_owned();
        }
        // A Cursor Run that reported no usage inline (a tool step, or a turn
        // that ended without counters): the dashboard's count
        // (or the estimate) goes into the client body and the ledger alike.
        if ir.usage.is_none()
            && let Some(handle) = cursor
        {
            ir.usage = handle.settle().await;
        }
        // The body parsed, so the attempt completed: settle the simulated
        // cache read. The client body and the ledger read the same split.
        let cache_hit = cache_read.and_then(prompt_cache::PendingRead::settle);
        ir.usage = prompt_cache::with_hit(ir.usage.take(), cache_hit);
        let bytes =
            (source_dialect.emit_response_json)(&ir).map_err(failover::AttemptError::Protocol)?;
        if request.payload_log {
            tracing::debug!(target: PAYLOAD_TARGET, direction = "upstream_response", translated = true, body = %truncate_payload(&String::from_utf8_lossy(&bytes), bytes.len()));
        }
        let terminal = match ir.stop {
            translation::ir::IrStop::Length => protocol::Terminal::Incomplete,
            _ => protocol::Terminal::Completed,
        };
        return Ok(RelayOutcome::Json {
            status,
            body: bytes,
            observed: protocol::ObservedResponse {
                // A translated upstream that reported no token usage stays
                // unknown; the ledger must not record fabricated zeroes. The
                // same value is already in the client body (Kiro: an estimate).
                usage: ir.usage,
                terminal,
                upstream_model: reported_model.then_some(ir.model),
            },
        });
    };
    if observed.usage.is_none()
        && let Some(handle) = cursor
    {
        observed.usage = handle.settle().await;
    }
    if request.payload_log {
        tracing::debug!(target: PAYLOAD_TARGET, direction = "upstream_response", translated = false, body = %truncate_payload(&String::from_utf8_lossy(&body), body.len()));
    }
    Ok(RelayOutcome::Json {
        status,
        body,
        observed,
    })
}

/// Candidate-specific wire adjustments for the translation path.
#[derive(Clone, Copy)]
struct WireTweaks<'a> {
    /// Optional fields the upstream is known to refuse.
    skip: &'a [&'a str],
    /// Vendor Chat-body adaptations.
    fixups: ChatFixups,
    /// The target model's supported effort levels; `None` = unconstrained.
    supported_efforts: Option<&'a [Effort]>,
    /// 路由层固定 effort 档位;`None` = legacy(快照 clamp)。
    route_efforts: Option<&'a [Effort]>,
    /// 当前候选的 effort 方言。
    dial: capabilities::EffortDial,
    /// Kiro only: the KAS body's `profileArn` — the live bundle's account
    /// identity, resolved by the token manager before preparing (a refresh may
    /// have rotated it). `None` for every other target, and also when this
    /// login carried no profile.
    kiro_profile_arn: Option<&'a str>,
    /// Kiro only: digest the translated prompt for the simulated cache.
    prompt_scope: Option<prompt_cache::Scope<'a>>,
    /// Cursor only: ask for Max Mode (set on the one retry after Cursor said
    /// the model requires it).
    cursor_max_mode: bool,
}

/// A send the upstream accepted (2xx), still unread.
struct Sent {
    status: u16,
    upstream: Upstream,
    protocol: ProtocolId,
    /// Kiro only: the simulated cache read, settled once the attempt completes.
    cache_read: Option<prompt_cache::PendingRead>,
}

/// The accepted upstream, in the shape its protocol delivers it: one HTTP
/// response body for every protocol but Cursor, whose Run hands over the
/// downlink frames (and a report for the settlement) instead.
enum Upstream {
    Http(reqwest::Response),
    Cursor {
        run: Box<cursor_run::Run>,
        /// The bearer the Run opened with: the settlement reads the
        /// dashboard as the same account.
        bearer: std::sync::Arc<CursorBearer>,
    },
}

/// One prepared upstream body.
struct PreparedBody {
    prepared: protocol::Prepared,
    /// Kiro only: the prompt's prefix digest, when a cache scope was given.
    prompt_prefix: Option<prompt_cache::Prefix>,
}

/// The client body's IR, translated at most once per dispatch.
///
/// The client body never changes during a dispatch and `to_ir` is a pure
/// function of it, so every translated preparation (each candidate, each
/// optional-field strip round, the Kiro 401 re-prepare) reads the same IR. The
/// slot stays empty on a passthrough-only dispatch. A translation error is
/// kept too: the same body fails the same way for every candidate.
#[derive(Default)]
struct ClientIr(Option<Result<translation::ir::IrRequest, ProtocolError>>);

impl ClientIr {
    /// The IR of `body`, translated with `dialect` on first use.
    fn get_or_translate(
        &mut self,
        dialect: &translation::Dialect,
        body: &Value,
    ) -> Result<&mut translation::ir::IrRequest, ProtocolError> {
        let slot = self.0.get_or_insert_with(|| {
            (dialect.to_ir)(body, translation::ir::NO_DECLARED_LIMIT).map(|(ir, _)| ir)
        });
        match slot {
            Ok(ir) => Ok(ir),
            Err(error) => Err(*error),
        }
    }
}

/// Request preparation for the translation path: source to_ir → target from_ir → target prepare.
/// The source IR comes from `client_ir` (translated once per dispatch); the
/// per-candidate effort clamp is applied for this preparation only and undone
/// before returning, so the next candidate starts from the client's own level.
/// `skip` passes through to the target kernel (learned refusals, vendor fixups).
/// `fixups` are the vendor Chat-body adaptations (see [`ChatFixups`]).
/// With a `prompt_scope`, the IR prompt's prefix digest comes back too.
fn prepare_translated(
    source_body: &Value,
    client_ir: &mut ClientIr,
    source: ProtocolId,
    upstream: ProtocolId,
    target: &TargetView<'_>,
    stream: bool,
    tweaks: WireTweaks<'_>,
) -> Result<PreparedBody, ProtocolError> {
    let source_dialect = translation::dialect(source)?;
    let upstream_dialect = translation::dialect(upstream)?;
    let ir = client_ir.get_or_translate(&source_dialect, source_body)?;
    let client_effort = ir.effort;
    // 与 passthrough 同一套归一:路由列表(已配置)或 legacy 快照 → 方言
    // 可接受集。显式 off 不在此 clamp——它在下方按厂商标记注入。
    if let Some(effort) = ir.effort {
        let effort_target = translation::effort_clamp::EffortTarget {
            route: tweaks.route_efforts,
            snapshot: tweaks.supported_efforts.unwrap_or(&[]),
            // IR 路径无原始字符串,修复值用不到;占位即可。
            default: Effort::Medium,
            dial: tweaks.dial,
        };
        let resolved = translation::effort_clamp::resolve_level(effort, &effort_target);
        if resolved != effort {
            tracing::info!(
                target: EFFORT_TARGET,
                model = target.upstream_model,
                from = ?effort,
                to = ?resolved,
                "effort clamped to upstream model support"
            );
            ir.effort = Some(resolved);
        }
    }
    // Emit and digest against the clamped IR, then undo the clamp (it belongs
    // to this candidate only) before any early return.
    let emitted = (upstream_dialect.from_ir)(ir, target.upstream_model).map(|(value, _)| {
        let prompt_prefix = tweaks
            .prompt_scope
            .map(|scope| prompt_cache::Prefix::of(scope, ir));
        (value, prompt_prefix)
    });
    let effort_off = matches!(ir.effort, Some(Effort::None));
    ir.effort = client_effort;
    let (mut upstream_value, prompt_prefix) = emitted?;
    // Chat 发射器对显式 off 省略字段;按厂商方言注入 off 标记,让"关思考"
    // 在翻译路径真正生效(纯思考模型由方言降级为最低档)。
    if upstream == ProtocolId::OpenAiChat && effort_off {
        upstream_value["reasoning_effort"] =
            Value::String(translation::effort_clamp::off_wire_name(tweaks.dial).to_owned());
    }
    // Same for a Responses upstream, where the dial lives under `reasoning`;
    // `from_ir` already wrote `summary` when it wrote an effort, and an off
    // request carries neither, so the nested object is created here.
    if upstream == ProtocolId::OpenAiResponses && effort_off {
        upstream_value["reasoning"] = serde_json::json!({
            "effort": translation::effort_clamp::off_wire_name(tweaks.dial),
        });
    }
    // The rebuilt tree is already owned, so the DeepSeek dialect edits land in
    // place: a calling assistant turn must be followed straight away by its
    // tool results, and a partially-reasoning history still needs the gaps
    // backfilled (the emitter only writes `reasoning_content` for turns whose
    // IR carried thinking). The GLM image strip needs nothing here — it rides
    // the wire render below.
    if tweaks.fixups.deepseek_dialect {
        join_split_tool_call_turns(&mut upstream_value);
        fill_missing_reasoning(&mut upstream_value);
    }
    if upstream == ProtocolId::Kiro {
        // A KAS request body has no `stream` field at all: whether the client
        // asked to stream is cardinal's reading of the AWS event-stream
        // response, not a request knob. Injecting the Chat field here would
        // hand KAS a body shape it never sends.
        if let Some(profile_arn) = tweaks.kiro_profile_arn {
            // The candidate's own login is the only profile identity — there is
            // no provider-level cache to read (two keys of one provider are two
            // accounts).
            upstream_value["profileArn"] = Value::String(profile_arn.to_owned());
        }
        if upstream_value.get("stream").is_some() {
            return Err(ProtocolError::InvalidRequest);
        }
    } else if upstream == ProtocolId::Cursor {
        // A Cursor Run is always a stream on the wire (the relay aggregates
        // for a non-streaming client), so the Chat `stream` field is never
        // injected; the Max Mode flag is the only per-attempt knob.
        //
        // This is Max Mode's only writer: the retry loop decides to ask for
        // it when Cursor refuses a model without it, `from_ir` leaves the
        // field out of the staged body, and the kernel's `unwrap_or(false)`
        // reads that absence as off, so the default needs no writing.
        if tweaks.cursor_max_mode {
            upstream_value["max_mode"] = Value::Bool(true);
        }
    } else if stream {
        // The IR has no stream concept, so `from_ir` never emits it; the client
        // asked for a stream, and both kernels whitelist the field — inject it
        // here or the upstream answers with one non-streaming JSON blob.
        upstream_value["stream"] = Value::Bool(true);
    }
    protocol::prepare(
        upstream,
        &upstream_value,
        target,
        stream,
        tweaks.skip,
        tweaks.fixups.strip_glm_images,
    )
    .map(|prepared| PreparedBody {
        prepared,
        prompt_prefix,
    })
}

/// Model resolution: the client-supplied model string picks the candidate set.
///
/// Two ways to call:
/// - `"<provider_name>/<upstream_model>"` whose prefix names an ENABLED provider → that provider's
///   enabled keys in global (position, id) order, all serving the suffix model (direct path);
/// - otherwise the string is looked up as a route alias → one candidate per
///   entry in the route's STORED order (the user-arranged GUI order), each
///   entry carrying its own account and upstream model (route path).
enum Resolution {
    /// alias = Some(route) on the route path, None on the direct path.
    /// `window_skipped` counts route entries filtered out by their active
    /// window — it shapes the error when nothing at all is triable.
    /// `secret_skipped` counts keys dropped from candidacy because their secret
    /// could not be read (logged per key; it never shapes a new status code —
    /// an emptied candidate set still takes the existing 404/503 paths).
    /// `excluded` carries candidates filtered during expansion (disabled keys,
    /// window-denied entries, model-not-allowed) with their skip reasons.
    Candidates {
        alias: Option<String>,
        /// The route's strategy on the route path: it orders the candidate list
        /// (one candidate per entry). Direct `provider/model` resolution is
        /// always Smart, a deliberate exception (plan D5): its keys are
        /// interchangeable routes to one model, so ranking them by quota beats
        /// always taking the first account by position.
        strategy: store::RouteStrategy,
        candidates: Vec<candidates::Candidate>,
        /// Candidates excluded during expansion, with the reason.
        excluded: Vec<(candidates::Candidate, trace::SkipReason)>,
        window_skipped: usize,
        secret_skipped: usize,
        /// 路由层固定 effort 档位(升序,解析自 `RouteRow.efforts`):
        /// `Some` = 路由已配置(含显式空表 = 不 clamp),`None` = 直连路径
        /// 或 legacy 路由(快照 clamp)。每次请求解析一次,各 attempt 共享引用。
        efforts: Option<Box<[Effort]>>,
    },
    /// `"provider/"` — the direct path with an empty upstream model.
    EmptySuffix,
    /// Neither an enabled-provider prefix nor a route alias.
    NoRoute,
}

/// Credentials now ride on the key rows themselves (0013). The branch is on
/// `auth_kind` before the `api_key` emptiness check, because the two shapes are
/// disjoint by construction:
///
/// * `static` — the row's plaintext key is the credential (unchanged);
/// * `kiro_oidc` — the row's OAuth bundle is the credential and `api_key` is
///   NULL. The access token inside that bundle rotates, so it is resolved per
///   attempt by [`crate::upstream::KiroTokens`], not carried in the candidate:
///   the candidate's placeholder secret is empty and never reaches the wire;
/// * `opencode_oauth` — the same shape, resolved per attempt by
///   [`crate::upstream::OpencodeTokens`];
/// * `openai_oauth` — the same shape, resolved per attempt by
///   [`crate::upstream::OpenaiTokens`];
/// * `cursor_oauth` — the same shape, resolved per attempt by
///   [`crate::upstream::CursorTokens`] (a `static` key on a Cursor provider is
///   exchanged for a bearer by the same manager).
///
/// A row missing the credential its `auth_kind` requires is dropped from
/// candidacy with a warning — never cooled, since a missing credential is not an
/// upstream failure.
///
/// Inactive rows (disabled or archived) are deliberately NOT dropped here: the
/// expansion decides that, so a route entry naming a disabled account is
/// reported as `SkipReason::Disabled` instead of vanishing as a dangling entry.
fn fetch_key_secrets(
    keys: Vec<std::sync::Arc<crate::store::ProviderKeyRow>>,
) -> (
    Vec<(std::sync::Arc<crate::store::ProviderKeyRow>, SecretString)>,
    usize,
) {
    let mut resolved = Vec::with_capacity(keys.len());
    let mut skipped = 0usize;
    for key in keys {
        if key.auth_kind == "kiro_oidc" {
            if key.kiro_oauth().is_some() {
                resolved.push((key, SecretString::from(String::new())));
            } else {
                skipped += 1;
                tracing::warn!(
                    key_id = key.id,
                    "Kiro provider key has no OAuth bundle; skipped"
                );
            }
            continue;
        }
        if key.auth_kind == "opencode_oauth" {
            if key.opencode_oauth().is_some() {
                resolved.push((key, SecretString::from(String::new())));
            } else {
                skipped += 1;
                tracing::warn!(
                    key_id = key.id,
                    "OpenCode provider key has no OAuth bundle; skipped"
                );
            }
            continue;
        }
        if key.auth_kind == "openai_oauth" {
            if key.openai_oauth().is_some() {
                resolved.push((key, SecretString::from(String::new())));
            } else {
                skipped += 1;
                tracing::warn!(
                    key_id = key.id,
                    "OpenAI provider key has no OAuth bundle; skipped"
                );
            }
            continue;
        }
        if key.auth_kind == "cursor_oauth" {
            if key.cursor_oauth().is_some() {
                resolved.push((key, SecretString::from(String::new())));
            } else {
                skipped += 1;
                tracing::warn!(
                    key_id = key.id,
                    "Cursor provider key has no OAuth bundle; skipped"
                );
            }
            continue;
        }
        match key.api_key.clone() {
            Some(api_key) => resolved.push((key, SecretString::from(api_key))),
            None => {
                skipped += 1;
                tracing::warn!(key_id = key.id, "provider key has no api_key; skipped");
            }
        }
    }
    (resolved, skipped)
}

fn resolve(
    route_cache: &route_cache::RouteCache,
    model: &str,
    now: chrono::DateTime<chrono::Local>,
) -> anyhow::Result<Resolution> {
    if let Some((prefix, upstream_model)) = model.split_once('/') {
        if upstream_model.is_empty() {
            return Ok(Resolution::EmptySuffix);
        }
        if let Some(provider) = route_cache.provider_by_name(prefix)
            && provider.enabled
        {
            let keys = route_cache.keys_for_provider(provider.id);
            let (keys, secret_skipped) = fetch_key_secrets(keys);
            let (candidates, excluded) = candidates::expand_direct(provider, keys, upstream_model);
            return Ok(Resolution::Candidates {
                alias: None,
                // Deliberate (plan D5): direct `provider/model` stays
                // quota-ranked even though route entries are per account
                // again. These keys are interchangeable routes to ONE model,
                // so stored position ordering would pin a multi-account
                // provider to its first account forever; position only breaks
                // quota ties inside `smart::order`.
                strategy: store::RouteStrategy::Smart,
                candidates,
                excluded,
                window_skipped: 0,
                secret_skipped,
                efforts: None,
            });
        }
        // No enabled provider with this name: fall through to the route lookup
        // (a route alias may itself contain `/`).
    }
    match route_cache.route_by_alias(model) {
        Some(route) => {
            // One candidate per entry: each entry names its own account, so
            // the key set is just the entries' key ids (dangling ids drop out).
            // Deduped: one account serving several models on this route is the
            // normal case, and the cache would share its row and clone its
            // secret once per entry before expansion discards all but one.
            let mut key_ids: Vec<i64> = route.entries.iter().map(|entry| entry.key_id).collect();
            key_ids.sort_unstable();
            key_ids.dedup();
            let keys = route_cache.keys_by_ids(&key_ids);
            let (keys, secret_skipped) = fetch_key_secrets(keys);
            let mut provider_ids: Vec<i64> = keys.iter().map(|(key, _)| key.provider_id).collect();
            provider_ids.sort_unstable();
            provider_ids.dedup();
            let providers = route_cache
                .providers_by_ids(&provider_ids)
                .into_iter()
                .map(|provider| (provider.id, provider))
                .collect();
            // The active window is judged against `now` (the request's local-time
            // read), not a fresh clock read inside expansion.
            let expansion = candidates::expand_route(&route.entries, keys, &providers, now);
            let mut candidates = expansion.candidates;
            let excluded = expansion.excluded;
            for candidate in &mut candidates {
                candidate.route_alias = Some(route.alias.clone());
            }
            // 读路径宽容:store 写时已归一化;这里防御性解析,坏名跳过。
            let efforts = route.efforts.as_deref().map(|names| {
                names
                    .iter()
                    .filter_map(|name| Effort::parse_name(name))
                    .filter(|level| !matches!(level, Effort::None))
                    .collect::<Vec<_>>()
                    .into_boxed_slice()
            });
            Ok(Resolution::Candidates {
                alias: Some(route.alias),
                strategy: route.strategy,
                candidates,
                excluded,
                window_skipped: expansion.window_skipped,
                secret_skipped,
                efforts,
            })
        }
        None => Ok(Resolution::NoRoute),
    }
}

impl AttemptLog {
    /// Record of a non-streaming success. `model` is the client-supplied string; `served_model` is
    /// the upstream model (self-reported when the response says so, otherwise the requested target).
    fn from_observed(
        (protocol, alias, provider_id, provider_key_id, model, target_model): (
            ProtocolId,
            Option<&str>,
            i64,
            i64,
            &str,
            &str,
        ),
        status: u16,
        observed: &protocol::ObservedResponse,
        price: Option<&crate::store::ModelPrice>,
        started: std::time::Instant,
    ) -> Self {
        let usage = observed.usage.clone();
        let cost_usd = price.map(|price| {
            let (input, output, cached, written, written_1h) = usage
                .as_ref()
                .map(|u| {
                    (
                        u.input_tokens as i64,
                        u.output_tokens as i64,
                        u.cached_input_tokens.unwrap_or(0) as i64,
                        u.cache_creation_input_tokens.unwrap_or(0) as i64,
                        u.cache_creation_1h_input_tokens.unwrap_or(0) as i64,
                    )
                })
                .unwrap_or_default();
            price.cost_split(input, output, cached, written, written_1h)
        });
        Self {
            protocol,
            client_protocol: None,
            effort: None,
            alias: alias.map(str::to_owned),
            provider_id,
            provider_key_id,
            model: model.to_owned(),
            served_model: observed
                .upstream_model
                .clone()
                .or_else(|| Some(target_model.to_owned())),
            status,
            input_tokens: usage.as_ref().map(|u| u.input_tokens as i64),
            output_tokens: usage.as_ref().map(|u| u.output_tokens as i64),
            cached_input_tokens: usage
                .as_ref()
                .and_then(|u| u.cached_input_tokens)
                .map(|v| v as i64),
            cache_creation_input_tokens: usage
                .as_ref()
                .and_then(|u| u.cache_creation_input_tokens)
                .map(|v| v as i64),
            total_ms: started.elapsed().as_millis().min(i32::MAX as u128) as i32,
            ttft_ms: None,
            cost_usd,
            error: None,
            caller_key: None,
            user_id: None,
            gateway_key_id: None,
            agent: None,
            request_id: None,
            charged_microus: None,
            rate_bp: None,
        }
    }

    /// Record of a failed attempt.
    fn from_error(
        protocol: ProtocolId,
        alias: Option<&str>,
        provider_id: i64,
        provider_key_id: i64,
        model: &str,
        error: &failover::AttemptError,
        started: std::time::Instant,
    ) -> Self {
        Self {
            protocol,
            client_protocol: None,
            effort: None,
            alias: alias.map(str::to_owned),
            provider_id,
            provider_key_id,
            model: model.to_owned(),
            served_model: None,
            status: error.ledger_status(),
            input_tokens: None,
            output_tokens: None,
            cached_input_tokens: None,
            cache_creation_input_tokens: None,
            total_ms: started.elapsed().as_millis().min(i32::MAX as u128) as i32,
            ttft_ms: None,
            cost_usd: None,
            error: Some(error.message()),
            caller_key: None,
            user_id: None,
            gateway_key_id: None,
            agent: None,
            request_id: None,
            charged_microus: None,
            rate_bp: None,
        }
    }

    /// Stamp the caller identity — key label, owning user and key id (one per
    /// dispatch, shared by every attempt row of the request — the
    /// constructors leave it empty).
    fn with_caller(mut self, principal: Option<&store::Principal>) -> Self {
        if let Some(principal) = principal {
            self.caller_key = Some(principal.key_label.clone());
            self.user_id = Some(principal.user_id);
            self.gateway_key_id = Some(principal.key_id);
            self.rate_bp = Some(billing::rate_bp(principal));
        }
        self
    }

    /// Price a successful attempt: the debit derived from its cost, the
    /// usage certainty and the caller's rate (stamped by
    /// [`Self::with_caller`]; None — an in-process call — is never charged).
    /// A billed caller's success with unknown usage is served free and
    /// warned about: unknown is never treated as zero.
    fn with_charge(mut self, certainty: UsageCertainty) -> Self {
        let Some(rate_bp) = self.rate_bp else {
            return self;
        };
        if rate_bp > 0 && certainty == UsageCertainty::Unknown {
            tracing::warn!(
                request_id = self.request_id.as_deref().unwrap_or(""),
                user_id = self.user_id,
                model = self.model.as_str(),
                "billed request succeeded without usage; not charged"
            );
        }
        self.charged_microus = billing::attempt_charge(self.cost_usd, certainty, rate_bp);
        self
    }

    /// Stamp the client identity (the User-Agent's name; same one-per-dispatch
    /// sharing as [`Self::with_caller`]).
    fn with_agent(mut self, agent: Option<&str>) -> Self {
        self.agent = agent.map(str::to_owned);
        self
    }

    /// Stamp the client-facing protocol (the protocol the request arrived as;
    /// same one-per-dispatch sharing as [`Self::with_caller`]).
    fn with_client_protocol(mut self, protocol: ProtocolId) -> Self {
        self.client_protocol = Some(protocol);
        self
    }

    /// Stamp the reasoning effort the client asked for (same one-per-dispatch
    /// sharing as [`Self::with_caller`]).
    fn with_effort(mut self, effort: Option<&str>) -> Self {
        self.effort = effort.map(str::to_owned);
        self
    }

    /// Stamp the dispatch request id (the `req_<uuid>` string the trace ring and
    /// upstream header share; same one-per-dispatch sharing as
    /// [`Self::with_caller`]).
    fn with_request_id(mut self, request_id: &str) -> Self {
        self.request_id = Some(request_id.to_owned());
        self
    }

    /// Stamp the upstream model a failed attempt requested ([`Self::from_error`]
    /// leaves it empty), so the model split counts the failure under its model.
    fn with_served_model(mut self, served_model: &str) -> Self {
        self.served_model = Some(served_model.to_owned());
        self
    }

    /// The ledger numbers the attempt's End reports ([`EndMetrics`]) so a settled
    /// feed row shows the same duration/decode-window speed as the 请求 page
    /// without a ledger read — taken from the very row about to be inserted.
    fn end_metrics(&self) -> EndMetrics {
        EndMetrics {
            output_tokens: self.output_tokens,
            total_ms: Some(self.total_ms),
            ttft_ms: self.ttft_ms,
            input_tokens: self.input_tokens,
            cached_input_tokens: self.cached_input_tokens,
            http_status: Some(self.status),
        }
    }
}

/// Records the attempt the client walked away from.
///
/// A disconnect makes hyper drop the handler future: no error is produced, no
/// ledger row is queued, no access-log line is written, and the live-activity
/// row never ends — the request simply vanishes while the GUI still shows it
/// "connecting". The guard is armed for exactly the in-flight attempt and
/// disarmed the moment it resolves; a `Drop` while still armed is that case.
/// It records the client-closed row (499) and one WARN with the attempt's
/// identity and elapsed time.
struct AbandonGuard<'a> {
    request_id: &'a str,
    provider: &'a str,
    key: &'a str,
    model: &'a str,
    /// The upstream model the in-flight attempt requested.
    served_model: &'a str,
    alias: Option<&'a str>,
    protocol: ProtocolId,
    client_protocol: ProtocolId,
    effort: Option<&'a str>,
    provider_id: i64,
    provider_key_id: i64,
    principal: Option<&'a store::Principal>,
    agent: Option<&'a str>,
    started: std::time::Instant,
    ledger: &'a LedgerWriter,
    activity: &'a ActivitySink,
    seq: u64,
    armed: bool,
}

impl AbandonGuard<'_> {
    /// The attempt settled on its own (any outcome): dropping it now must not
    /// fabricate a client-closed row.
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for AbandonGuard<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let error = failover::AttemptError::Transport(transport::TransportError::ClientGone);
        let row = AttemptLog::from_error(
            self.protocol,
            self.alias,
            self.provider_id,
            self.provider_key_id,
            self.model,
            &error,
            self.started,
        )
        .with_caller(self.principal)
        .with_agent(self.agent)
        .with_client_protocol(self.client_protocol)
        .with_effort(self.effort)
        .with_request_id(self.request_id)
        .with_served_model(self.served_model);
        let metrics = row.end_metrics();
        tracing::warn!(
            request_id = self.request_id,
            provider = self.provider,
            key = self.key,
            model = self.model,
            elapsed_ms = row.total_ms,
            "client closed before the attempt settled"
        );
        self.ledger.push(vec![row]);
        self.activity.end(self.seq, EndStatus::Error, metrics);
    }
}

// ---------- dispatch: orchestration core shared by all three entry points ----------

/// Final result of dispatch. The HTTP handler renders it into a response.
pub enum DispatchOutcome {
    /// Non-streaming success: upstream JSON bytes (already in the client protocol).
    Json { status: u16, body: Vec<u8> },
    /// Streaming success: client-protocol SSE frame stream plus a completion signal for post-processing (usage accounting and persistence run in a background task).
    Stream {
        status: u16,
        frames: StreamFrames,
        finalize: tokio::sync::oneshot::Receiver<()>,
    },
    /// Request-level failure (no route / no enabled key / all attempts failed): carries the status and message the client should get, plus a Retry-After hint (seconds) when waiting is the documented remedy (gateway-side saturation).
    Failed {
        status: u16,
        message: String,
        retry_after_secs: Option<u64>,
    },
}

/// In-place retries of the last candidate never pause longer than this.
const MAX_RETRY_PAUSE: std::time::Duration = std::time::Duration::from_secs(8);

/// Whole-call budget for a retrieval request. The transport's `total` is an
/// hour, sized for a long SSE stream; a retrieval call has no stream, a much
/// shorter natural ceiling (a vendor answers in seconds, a long batch in a
/// minute or two), and no reason to buy the relay's full retry ladder on a
/// silent upstream. Thirty seconds short of three minutes leaves the last
/// retry a usable slice of its opening deadline rather than starting an
/// attempt the budget would have to cut.
const EMBEDDINGS_BUDGET: std::time::Duration = std::time::Duration::from_secs(150);

/// The dispatch budget for one client protocol: the shared transport budget,
/// except for the protocols whose call shape is bounded more tightly. The
/// relay's retry-pause check reads the same deadline, so the budget also ends
/// the retry ladder — a stuck retrieval fails as a recorded 504 instead of
/// spending an hour of attempts.
fn call_budget(protocol: ProtocolId, limits: &transport::Limits) -> std::time::Duration {
    match protocol {
        ProtocolId::OpenAiEmbeddings => EMBEDDINGS_BUDGET.min(limits.total),
        _ => limits.total,
    }
}

/// Acquire a slot for the remaining failover candidates. The returned index is
/// absolute in the original candidate vector, and the guard belongs to exactly
/// that candidate.
struct DispatchTimeoutGuard {
    dispatcher: tokio::sync::mpsc::UnboundedSender<dispatcher::DispatchEvent>,
    request_id: u64,
    armed: bool,
}

impl DispatchTimeoutGuard {
    fn new(
        dispatcher: tokio::sync::mpsc::UnboundedSender<dispatcher::DispatchEvent>,
        request_id: u64,
    ) -> Self {
        Self {
            dispatcher,
            request_id,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for DispatchTimeoutGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.dispatcher.send(dispatcher::DispatchEvent::Timeout {
                request_id: self.request_id,
            });
        }
    }
}

async fn acquire_remaining_candidate_slot(
    dispatcher: tokio::sync::mpsc::UnboundedSender<dispatcher::DispatchEvent>,
    queue_timeout: std::time::Duration,
    start_index: usize,
    slot_keys: &[(SlotKey, Option<SlotKey>)],
    caps: &[CandidateCaps],
    cap_generation: u64,
) -> Result<Option<(usize, SlotGuard)>, ()> {
    if start_index >= slot_keys.len() {
        return Ok(None);
    }
    let request_id = next_dispatch_event_id();
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    dispatcher
        .send(DispatchEvent::Request(DispatchRequest {
            id: request_id,
            slot_keys: slot_keys[start_index..].to_vec(),
            order: (0..slot_keys.len() - start_index).collect(),
            caps: caps[start_index..].to_vec(),
            cap_generation,
            reply: reply_tx,
        }))
        .map_err(|_| ())?;
    let mut timeout_guard = DispatchTimeoutGuard::new(dispatcher, request_id);
    match tokio::time::timeout(queue_timeout, reply_rx).await {
        Ok(Ok(Some(assignment))) => {
            timeout_guard.disarm();
            Ok(Some((start_index + assignment.index, assignment.slot)))
        }
        Ok(Ok(None)) | Err(_) => Ok(None),
        Ok(Err(_)) => Err(()),
    }
}

/// The observability sidecars every dispatch threads through: the body
/// capture ring and the live-activity feed. Bundled because they always
/// travel together; both are fail-open by design.
pub struct Observability<'a> {
    pub body_log: &'a BodyLog,
    pub activity: &'a ActivitySink,
}

/// The shared dependencies every dispatch threads through: the upstream
/// transport, dispatcher queue wait, failover state and the provider-key
/// secret store (the relay resolves credentials from it at resolve time).
/// Bundled because they always travel together.
///
/// `pool` is the one deliberate PG touch on the request path, and only the
/// rotating-credential candidates reach it: a Kiro OIDC access token expires
/// hourly and an OpenCode account bearer rotates on the console's schedule, so
/// the credential plane must reread the row (another process may have rotated
/// it) and persist the rotated bundle. Every other candidate still reads cached
/// state only, and every other write still goes through `ledger`.
pub struct DispatchDeps<'a> {
    pub pool: &'a sqlx::PgPool,
    pub transport: &'a Transport,
    pub queue_timeout: std::time::Duration,
    pub dispatcher: &'a tokio::sync::mpsc::UnboundedSender<dispatcher::DispatchEvent>,
    pub failover: &'a std::sync::Arc<Failover>,
    /// Per-user outstanding-request counts. `Arc` (not a plain reference) for
    /// the same reason as `failover`: the streaming settlement task outlives
    /// this call, and that task is what frees the user's slot.
    pub exposure: &'a std::sync::Arc<crate::exposure::Exposure>,
    /// Per-key Kiro OIDC token manager (lazy refresh, single-flight, write-back).
    pub kiro_tokens: &'a KiroTokens,
    /// Simulated Kiro prompt cache: remembered prompt prefixes per account and
    /// caller (KAS reports no cached-token split of its own).
    pub prompt_cache: &'a PromptCache,
    /// Per-key OpenCode account bearer manager (lazy refresh, single-flight, CAS
    /// write-back). The same instance backs model and quota probing.
    pub opencode_tokens: &'a OpencodeTokens,
    /// Per-key OpenAI Codex account bearer manager (lazy refresh, single-flight,
    /// CAS write-back).
    pub openai_tokens: &'a OpenaiTokens,
    /// Per-key Cursor bearer manager (login-bundle refresh or API-key exchange,
    /// single-flight, write-back). The same instance backs model probing.
    pub cursor_tokens: &'a CursorTokens,
    /// The Cursor usage reconciler (dashboard events, claimed-event table,
    /// unreadable accounts). `Arc`: the streaming settlement task outlives
    /// this call.
    pub cursor_usage: &'a std::sync::Arc<CursorUsage>,
    /// Routing trace ring: each dispatch pushes its decision record here.
    pub trace_ring: &'a trace::TraceRing,
    /// In-memory quota snapshots for Smart ordering — no PG read on the
    /// request path.
    pub smart_cache: &'a smart_cache::SmartCache,
    /// Per-alias round-robin cursors for Rotate ordering — one atomic
    /// increment on the request path, no lock, no allocation.
    pub rotate_cursors: &'a rotate::RotateCursors,
    /// In-memory route/provider/key cache — no PG read on the request path.
    pub route_cache: &'a route_cache::RouteCache,
    /// In-memory cooldown cache — no PG read on the request path.
    pub rest_cache: &'a rest_cache::RestCache,
    /// In-memory price cache — no PG read on the request path.
    pub price_cache: &'a price_cache::PriceCache,
    /// Batch ledger writer: attempt rows are queued here and flushed to PG by
    /// a background task — the request path never blocks on the INSERT.
    pub ledger: &'a LedgerWriter,
    /// Cancelled once graceful shutdown has stopped the HTTP surface; each
    /// stream pump selects on it to settle instead of draining for usage.
    pub server_stopped: &'a tokio_util::sync::CancellationToken,
}

/// The verdict reason per READY candidate, position-aligned with the ordered
/// ready list the dispatch loop walks (the resting tail is chained after it, so
/// a resting candidate lands past the end and reads as "no reason", never as
/// its ready sibling's verdict). Position, not key id, is the identity: a route
/// may hang several models on one account, and each entry is its own candidate
/// with its own verdict.
type VerdictReasons = Vec<String>;

/// Order the ready partition per the route's strategy and compute each
/// candidate's verdict reason:
/// - `Ordered` keeps the stored order (the user-arranged GUI order);
/// - `Rotate` moves the whole list around the per-alias cursor — a no-op below
///   two ready candidates, and a no-op must not consume a tick;
/// - `Smart` ranks the whole list by quota surplus (`smart::order`).
///
/// The snapshot cache is read once and only BORROWED (`with_snapshots`, no
/// clone); an empty cache degrades to the stored order with a debug log —
/// dispatch must NEVER fail because of quota lookups.
///
/// Every strategy reports the quota reason of each candidate, because the feed
/// shows it: `Smart` gets the reasons from its ranking (computed once, moved
/// alongside), the stored-order strategies get the same verdicts in their final
/// order (`smart::verdicts`, no ranking side effect).
fn order_ready(
    smart_cache: &smart_cache::SmartCache,
    rotate_cursors: &rotate::RotateCursors,
    strategy: store::RouteStrategy,
    alias: Option<&str>,
    ready: Vec<candidates::Candidate>,
    now: chrono::DateTime<chrono::Utc>,
) -> (Vec<candidates::Candidate>, VerdictReasons) {
    smart_cache.with_snapshots(|quotas| {
        if quotas.is_empty() {
            // Not a warning: the prober may not have run yet, and many healthy
            // keys legitimately carry no snapshot.
            tracing::debug!(
                route = alias.unwrap_or(""),
                "no quota snapshots yet; no quota verdict this dispatch"
            );
        }
        let (ready, ranked_reasons) = match strategy {
            store::RouteStrategy::Smart if !quotas.is_empty() => {
                let (ordered, reasons): (Vec<_>, VerdictReasons) = smart::order(ready, quotas, now)
                    .into_iter()
                    .map(|(candidate, verdict)| (candidate, verdict.reason))
                    .unzip();
                (ordered, Some(reasons))
            }
            store::RouteStrategy::Rotate => (rotate_ready(ready, rotate_cursors, alias), None),
            // Ordered, and Smart with no snapshot to rank by.
            _ => (ready, None),
        };
        let reasons = match ranked_reasons {
            Some(reasons) => reasons,
            // Nothing to report without snapshots; an empty list reads as "no
            // verdict", never as a stale sibling's reason.
            None if quotas.is_empty() => VerdictReasons::new(),
            None => smart::verdicts(&ready, quotas, now),
        };
        (ready, reasons)
    })
}

/// Rotate: start the ready list after the candidate that served last. A no-op
/// below two candidates must not advance the cursor (it would only cause a skip
/// once a second candidate becomes ready again). Pure apart from the cursor's
/// `fetch_add`.
fn rotate_ready(
    mut ready: Vec<candidates::Candidate>,
    rotate_cursors: &rotate::RotateCursors,
    alias: Option<&str>,
) -> Vec<candidates::Candidate> {
    // Direct `provider/model` has no alias and is never Rotate; the guard keeps
    // this total.
    let Some(alias) = alias else {
        return ready;
    };
    let len = ready.len();
    if len < 2 {
        return ready;
    }
    let start = rotate_cursors.next(alias) % len;
    ready.rotate_left(start);
    ready
}

/// Orchestration core: model resolution → candidate expansion (ready first, resting last) → strategy ordering
/// (the route's strategy orders the ready candidates; Smart ranks them by quota) → ordered
/// attempts → accounting and persistence.
///
/// Shared by the /v1/chat/completions, /v1/messages and /v1/responses HTTP handlers.
/// This function touches no HTTP types; gateway auth is an HTTP-surface hoop,
/// so there is no auth here.
///
/// `failover` is `Arc` (not a plain reference) because the streaming post-processing
/// task outlives this call and clears the key's failure counter from there.
pub async fn dispatch(
    deps: &DispatchDeps<'_>,
    observability: &Observability<'_>,
    request: RelayRequest,
) -> DispatchOutcome {
    dispatch_at(deps, observability, request, chrono::Local::now()).await
}

/// Test affordance: dispatch with an explicit local time so route active
/// windows (time-of-day AND weekday) can be exercised deterministically.
/// Production calls use [`dispatch`], which reads the clock once per request.
#[doc(hidden)]
pub async fn dispatch_at(
    deps: &DispatchDeps<'_>,
    observability: &Observability<'_>,
    request: RelayRequest,
    now: chrono::DateTime<chrono::Local>,
) -> DispatchOutcome {
    let &DispatchDeps {
        pool,
        transport,
        queue_timeout,
        dispatcher,
        failover,
        exposure,
        kiro_tokens,
        prompt_cache,
        opencode_tokens,
        openai_tokens,
        cursor_tokens,
        cursor_usage,
        trace_ring,
        smart_cache,
        rotate_cursors,
        route_cache,
        rest_cache,
        price_cache,
        ledger,
        server_stopped,
    } = deps;
    let body_log = observability.body_log;
    let activity = observability.activity;
    let protocol = request.protocol;
    let Some(model) = request
        .body
        .get("model")
        .and_then(Value::as_str)
        .map(str::to_owned)
    else {
        return DispatchOutcome::Failed {
            status: 400,
            message: "missing model".into(),
            retry_after_secs: None,
        };
    };
    // One caller identity per request: shared by every attempt row it writes.
    let principal = request.principal.as_ref();
    // Admission before any routing work: a refused caller costs no candidate
    // expansion, slot or ledger row. In-process calls (no principal) are not
    // subject to billing.
    if let Some(principal) = principal
        && let Err(deny) = billing::admit(principal, &model)
    {
        return DispatchOutcome::Failed {
            status: deny.status(),
            message: deny.message(&principal.key_label),
            retry_after_secs: None,
        };
    }
    // Exposure gate: how many requests a billed caller may have in flight is
    // bounded by the user's `max_concurrent`, because admission reads the
    // balance from the authentication snapshot while the debit only lands on
    // the next ledger flush — inside that window a small balance could go
    // arbitrarily negative. Free callers (rate 0) and in-process calls take no
    // slot: their traffic creates no receivable.
    //
    // The slot frees itself on `Drop`, so every early return below balances it
    // without another line of code, and so does the non-streaming success (it
    // queues its attempt rows before returning). Only the streaming arm moves
    // the slot into the settlement task, where the charge is still in flight
    // until those rows are queued.
    let mut exposure_slot = match principal {
        Some(principal) if billing::is_billed(principal) => {
            match exposure.try_acquire(principal.user_id, principal.max_concurrent) {
                Some(slot) => Some(slot),
                None => {
                    tracing::debug!(
                        user_id = principal.user_id,
                        limit = principal.max_concurrent,
                        in_flight = exposure.in_flight(principal.user_id),
                        "refusing dispatch: the user is at max_concurrent requests in flight"
                    );
                    return DispatchOutcome::Failed {
                        status: 429,
                        message: "too many concurrent requests for this account; retry shortly"
                            .into(),
                        retry_after_secs: Some(1),
                    };
                }
            }
        }
        _ => None,
    };
    // The caller's rate multiplier, `Copy` so the streaming accounting task
    // captures it without holding the principal.
    let rate_bp = principal.map(billing::rate_bp);
    let caller_key = principal.map(|principal| principal.key_label.as_str());
    let effort = extract_effort(request.protocol, &request.body);
    let agent = request.agent.as_deref();
    // Serialize the body at most once (payloads on): the tracing line and the
    // capture snapshot share the same bounded rendering, so a long-context
    // body costs the capped buffer plus a byte count, never a full copy.
    let rendered = request
        .payload_log
        .then(|| render_payload_bounded(&request.body));
    if let Some(rendered) = &rendered {
        tracing::debug!(
          target: PAYLOAD_TARGET,
          direction = "client_request",
          protocol = protocol.as_str(),
          model = model.as_str(),
          caller = caller_key.unwrap_or(""),
          body = %truncate_payload(&rendered.text, rendered.total_bytes),
        );
    }

    // Diagnostic body capture, gated by the same payloads
    // flag: the client body is snapshotted now; the response side lands when
    // the final attempt settles, correlated by the dispatch's request id.
    let capture = rendered.as_ref().map(|rendered| {
        let (request_text, request_truncated) = crate::body_log::capture_text(&rendered.text);
        // The render itself may have been the cut — report truncation either way.
        let request_truncated = request_truncated || rendered.total_bytes > rendered.text.len();
        RequestCapture {
            request_text,
            request_truncated,
            streaming: request.stream,
            started: chrono::Utc::now(),
        }
    });

    // Model resolution: direct `provider/model` first, then the route table.
    // `now` (one read per request) is what route active windows are judged against.
    let (alias, strategy, mut expanded, excluded, window_skipped, secret_skipped, efforts) =
        match resolve(route_cache, &model, now) {
            Ok(Resolution::Candidates {
                alias,
                strategy,
                candidates,
                excluded,
                window_skipped,
                secret_skipped,
                efforts,
            }) => (
                alias,
                strategy,
                candidates,
                excluded,
                window_skipped,
                secret_skipped,
                efforts,
            ),
            Ok(Resolution::EmptySuffix) => {
                return DispatchOutcome::Failed {
                    status: 400,
                    message: format!("missing upstream model after the provider prefix in {model}"),
                    retry_after_secs: None,
                };
            }
            Ok(Resolution::NoRoute) => {
                return DispatchOutcome::Failed {
                    status: 404,
                    message: format!("no route for model {model}"),
                    retry_after_secs: None,
                };
            }
            Err(error) => {
                tracing::warn!("model resolution failed: {error}");
                return DispatchOutcome::Failed {
                    status: 500,
                    message: "model resolution failed".into(),
                    retry_after_secs: None,
                };
            }
        };
    if secret_skipped > 0 {
        tracing::warn!(
            model = model.as_str(),
            secret_skipped,
            "candidates dropped: secrets unreadable in the secret store"
        );
    }
    // Fail closed on pricing: a billed caller is only ever served by a
    // candidate whose model has a price, so every success can be charged.
    // Free callers and in-process calls keep every candidate. An empty
    // resolution falls through to the window/no-key answers below.
    if billing::needs_price(principal) && !expanded.is_empty() {
        expanded.retain(|candidate| {
            let priced = price_cache.contains(candidate.provider.id, &candidate.upstream_model);
            if !priced {
                // May be new to models.dev: nudge the catalog keeper (6h-throttled).
                crate::prices::missing(&candidate.upstream_model);
            }
            priced
        });
        if expanded.is_empty() {
            tracing::warn!(
                model = model.as_str(),
                user_id = principal.map(|principal| principal.user_id),
                "no priced candidate for a billed caller; refusing"
            );
            return DispatchOutcome::Failed {
                status: 503,
                message: format!("model {model} is not priced yet; try again later"),
                retry_after_secs: None,
            };
        }
    }
    if expanded.is_empty() {
        // All entries filtered by their time window is a temporary state, not a
        // missing route — say so plainly instead of the generic 404.
        if window_skipped > 0 {
            return DispatchOutcome::Failed {
                status: 503,
                message: format!(
                    "route {model} has no active entry at this time ({window_skipped} outside their time window)"
                ),
                retry_after_secs: None,
            };
        }
        // Resolution succeeded but nothing in it is usable (no enabled key of an enabled provider).
        return DispatchOutcome::Failed {
            status: 404,
            message: format!("no enabled key for model {model}"),
            retry_after_secs: None,
        };
    }

    let deadline = std::time::Instant::now() + call_budget(protocol, &transport.limits());
    let mut attempts: Vec<AttemptLog> = Vec::new();
    // The last busy-gate verdict's queue wait (None once any real attempt
    // fails): the Retry-After for the terminal verdict when busy is the end.
    let mut retry_after_hint: Option<u64> = None;
    let mut terminal_concurrency_busy = false;

    // restLast: a resting candidate is not skipped but deferred behind the ready
    // ones — a lone resting candidate is still tried, and its fresh error is what
    // the client gets when everything fails. The match is model-aware: a row
    // rests the candidate when it is a whole-key row (model NULL) or names the
    // candidate's own upstream model — a (key, m1) cooldown never defers (key, m2).
    let rest_rows = rest_cache.active_rows();
    let is_resting = |candidate: &candidates::Candidate| {
        rest_rows.iter().any(|row| {
            row.key_id == candidate.rest_key()
                && row
                    .model
                    .as_deref()
                    .is_none_or(|model| model == candidate.upstream_model)
        })
    };

    let (ready, resting): (Vec<_>, Vec<_>) = expanded
        .into_iter()
        .partition(|candidate| !is_resting(candidate));
    for candidate in &resting {
        // Per-request bookkeeping for every rested candidate: steady noise on
        // a resting provider (one line per request per rested key) — DEBUG.
        tracing::debug!(
            provider = candidate.provider.name.as_str(),
            key = candidate.key.label.as_str(),
            "candidate resting, deferred behind ready keys"
        );
    }
    // Order the READY partition by the route's strategy (one candidate per
    // entry). Dispatch must never fail because of a quota lookup: when no
    // snapshots exist yet (or the cache lock is poisoned) the candidates keep
    // their stored order for this request — `order_ready` logs the empty cache
    // at debug, and the cache warns on a poisoned lock.
    let (ready, reasons) = order_ready(
        smart_cache,
        rotate_cursors,
        strategy,
        alias.as_deref(),
        ready,
        chrono::Utc::now(),
    );
    debug_assert!(
        reasons.is_empty() || reasons.len() == ready.len(),
        "verdict reasons must be position-aligned with the ready list: {} reasons for {} ready",
        reasons.len(),
        ready.len()
    );
    // Rest-first invariant: rest overrides strategy order BY CONSTRUCTION —
    // the partition above ran BEFORE this ordering, so a resting candidate can
    // only ever trail the Smart (or stored) order of the ready set. Rest is
    // judged once per request here, exactly as on an ordered route: a
    // candidate that starts resting while the quota read below runs is still
    // tried this request (the ledger's post-failure rest takes effect on the
    // NEXT request, when its row shows up in the partition).
    let candidates: Vec<_> = ready.into_iter().chain(resting).collect();

    // Set when at least one candidate was skipped because none of its
    // capabilities can serve the client protocol (shapes the final error).
    let mut unserved = false;
    // Set when a streaming-only candidate (the Codex backend) was skipped for a
    // non-streaming request (shapes the final error like `unserved`).
    let mut stream_required = false;
    // Set when a billed caller's candidate lost its price after admission
    // (shapes the final error like the admission refusal).
    let mut unpriced = false;
    // Conversation identity for OpenCode and Codex session headers: derived
    // from the request body alone, so it is computed at most once per dispatch
    // and reused by every attempt (the input must stay byte-identical — both
    // upstreams' cache affinity depends on its stability across attempts and
    // processes). `None` while neither upstream has appeared.
    let mut session_seed: Option<String> = None;
    // The client body's IR, shared by every translated attempt of this
    // dispatch (see [`ClientIr`]).
    let mut client_ir = ClientIr::default();

    // === Dispatcher integration: centralized slot assignment ===
    // Instead of acquiring semaphores per-candidate, submit a DispatchRequest
    // to the dispatcher task and wait for an assignment. The dispatcher owns
    // all slot state and the pending queue.

    // Build CandidateCaps for all candidates (computed once per dispatch).
    // is_resting is judged per candidate HERE, on the final vector — flags
    // captured before the partition/Smart reorder would misalign with the
    // positions below (a rest flag from stored order would land on a
    // different candidate).
    let candidate_caps: Vec<CandidateCaps> = candidates
        .iter()
        .map(|c| CandidateCaps {
            key_cap: c.key.max_concurrency.map(|n| n as usize),
            entry_cap: c.entry_cap.map(|n| n as usize),
            rested: is_resting(c),
        })
        .collect();

    // The dispatcher's walk order (indices into the candidates vector). The
    // vector is already in dispatch order — `order_ready` ranked the ready
    // set and the resting tail trails it — so the walk is the identity.
    let order: Vec<usize> = (0..candidates.len()).collect();

    // Precompute the dispatcher's slot keys: the dispatcher only needs the
    // key id and the route-entry identity, so it never holds the candidates
    // (an Arc<[Candidate]> here would deep-clone every SecretString into the
    // pending queue). The entry-slot hash mirrors the route entry identity:
    // key id + upstream model + route alias — one slot per account, route and
    // model.
    let slot_keys: Vec<(SlotKey, Option<SlotKey>)> = candidates
        .iter()
        .map(|c| {
            let key_slot = SlotKey::Key(c.key.id as u64);
            let entry_slot = c
                .route_alias
                .as_deref()
                .map(|alias| dispatcher::entry_slot_key(alias, c.key.id, &c.upstream_model));
            (key_slot, entry_slot)
        })
        .collect();

    // One request id per dispatch, shared by the trace, the ledger rows, the
    // captured bodies and the billing charge. A UUID, not a counter: the
    // billing idempotency index keys on it, so it must stay unique across
    // restarts. The dispatcher keeps its own process-local numeric event id.
    let request_id = format!("req_{}", uuid::Uuid::new_v4().simple());
    let dispatch_event_id = next_dispatch_event_id();

    // Create a reply channel for this request.
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();

    // Submit the dispatch request.
    let dispatch_req = DispatchRequest {
        id: dispatch_event_id,
        slot_keys: slot_keys.clone(),
        order,
        caps: candidate_caps.clone(),
        cap_generation: route_cache.generation(),
        reply: reply_tx,
    };

    if dispatcher
        .send(DispatchEvent::Request(dispatch_req))
        .is_err()
    {
        // Dispatcher died — this is a fatal error.
        return DispatchOutcome::Failed {
            status: 500,
            message: "dispatcher unavailable".into(),
            retry_after_secs: None,
        };
    }

    let mut timeout_guard = DispatchTimeoutGuard::new(dispatcher.clone(), dispatch_event_id);

    // Wait for assignment with timeout.
    let assignment = match tokio::time::timeout(queue_timeout, reply_rx).await {
        Ok(Ok(Some(assignment))) => {
            timeout_guard.disarm();
            assignment
        }
        Ok(Ok(None)) | Err(_) => {
            retry_after_hint = Some(queue_timeout.as_secs());
            return DispatchOutcome::Failed {
                status: 429,
                message: format!("all candidates busy after {queue_timeout:?}"),
                retry_after_secs: retry_after_hint,
            };
        }
        Ok(Err(_)) => {
            // Reply channel closed (dispatcher died).
            return DispatchOutcome::Failed {
                status: 500,
                message: "dispatcher unavailable".into(),
                retry_after_secs: None,
            };
        }
    };

    // Get the assigned candidate index and start the loop from there.
    let start_index = assignment.index;
    let mut slot = Some(assignment.slot); // SlotGuard — drop to release

    // Build trace from the dispatcher's decision and record it in the ring.
    let trace = build_trace(TraceInputs {
        request_id: &request_id,
        model: &model,
        alias: alias.as_deref(),
        strategy: &strategy,
        candidates: &candidates,
        excluded: &excluded,
        decision: &assignment.decision,
        reasons: &reasons,
    });
    trace_ring.push(trace);

    let mut index = start_index;
    'candidates: loop {
        if slot.is_none() {
            match acquire_remaining_candidate_slot(
                dispatcher.clone(),
                queue_timeout,
                index,
                &slot_keys,
                &candidate_caps,
                route_cache.generation(),
            )
            .await
            {
                Ok(Some((assigned_index, candidate_slot))) => {
                    debug_assert!(assigned_index >= index);
                    index = assigned_index;
                    slot = Some(candidate_slot);
                }
                Ok(None) => {
                    terminal_concurrency_busy = true;
                    retry_after_hint = Some(queue_timeout.as_secs());
                    break;
                }
                Err(()) => {
                    return DispatchOutcome::Failed {
                        status: 500,
                        message: "dispatcher unavailable".into(),
                        retry_after_secs: None,
                    };
                }
            }
        }
        let Some(candidate) = candidates.get(index) else {
            break;
        };
        let is_last = index + 1 == candidates.len();
        let provider = &candidate.provider;
        let target_model = candidate.upstream_model.as_str();
        // Per-candidate protocol selection, passthrough-first: an exact protocol
        // match relays natively at the capability's endpoint; otherwise the
        // capability table's preferred translation target (a candidate that can
        // do neither is skipped — translation makes a candidate usable, never
        // reorders them). Anthropic rows carrying `claude_only` (aggregator
        // vendors) additionally gate on Claude model ids.
        let caps = capabilities::capabilities(
            &provider.name,
            &provider.protocol,
            &provider.base_url,
            &provider.auth_scheme,
        );
        let Some(capability) = capabilities::select(&caps, protocol, target_model) else {
            if caps.is_empty() {
                tracing::warn!(
                    "provider {} has an invalid protocol or credential scheme; skipping candidate",
                    provider.name
                );
            } else {
                unserved = true;
                tracing::info!(
                    provider = provider.name.as_str(),
                    key = candidate.key.label.as_str(),
                    "no capability serves the {} protocol; skipping candidate",
                    protocol.as_str()
                );
            }
            drop(slot.take()); // Release the slot before failing over.
            index += 1;
            continue 'candidates;
        };
        // Gemini bakes the upstream model into the URL; substitute the pattern's
        // `{model}` placeholder now that the candidate's target model is known.
        let capability = capabilities::resolve_for_model(capability, target_model);
        let capability = &capability;
        // A ChatGPT Codex account's key kind decides (one provider row can hold
        // many accounts). The backend only streams, and the gateway does not
        // aggregate its SSE into a JSON reply: a non-streaming client cannot be
        // served here, so this candidate is skipped like any unservable one.
        let codex = candidate.key.auth_kind == "openai_oauth";
        if codex && !request.stream {
            stream_required = true;
            tracing::info!(
                provider = provider.name.as_str(),
                key = candidate.key.label.as_str(),
                "the Codex backend only streams; skipping candidate for a non-streaming request"
            );
            drop(slot.take()); // Release the slot before failing over.
            index += 1;
            continue 'candidates;
        }
        if codex && !capabilities::codex::is_backend_endpoint(&capability.endpoint) {
            // Fail closed: the bearer is minted for ChatGPT and goes nowhere else.
            tracing::warn!(
                provider = provider.name.as_str(),
                key = candidate.key.label.as_str(),
                "an OpenAI OAuth key is attached to a provider outside the ChatGPT backend; skipping candidate"
            );
            unserved = true;
            drop(slot.take()); // Release the slot before failing over.
            index += 1;
            continue 'candidates;
        }
        if session_seed.is_none() && (codex || is_opencode_upstream(&capability.endpoint)) {
            session_seed = Some(conversation_seed(&request.body));
        }
        // The secret is exposed only here, at the injection point; AuthSchemeMaterial
        // never logs it.
        let credential = crate::providers::AuthSchemeMaterial::new(
            capability.auth_scheme,
            candidate.credential().expose_secret(),
        );
        // A Cursor candidate's credential in the shape the bearer manager
        // takes: the row's login bundle, or its API key for the exchange.
        let cursor_credential =
            (capability.protocol == ProtocolId::Cursor).then(|| {
                match candidate.key.cursor_oauth() {
                    Some(bundle) => KeyCredential::CursorOauth(bundle),
                    None => KeyCredential::Static(candidate.credential().expose_secret()),
                }
            });
        let key_id = candidate.rest_key();
        let price = match price_cache.get(provider.id, target_model) {
            Some(price) => Some(price),
            None => {
                // A priceless model may be new to models.dev: nudge the catalog
                // keeper (6h-throttled, no-op when no keeper runs).
                crate::prices::missing(target_model);
                // The admission filter saw a price, but it vanished since (a
                // catalog reload): a billed caller must never be served
                // unpriced, so skip this candidate like an unservable one.
                if billing::needs_price(principal) {
                    tracing::warn!(
                        request_id = %request_id,
                        provider = provider.name.as_str(),
                        model = target_model,
                        "price vanished after admission; skipping candidate for a billed caller"
                    );
                    unpriced = true;
                    drop(slot.take()); // Release the slot before failing over.
                    index += 1;
                    continue 'candidates;
                }
                None
            }
        };
        // In-place retries (last candidate: Rate ×3, Other ×2; a 429 不冷却
        // account: Rate ×3 anywhere) run inside this loop; the dispatcher slot
        // guard is held across them.
        let mut retried = 0u32;
        // Zhipu GLM passthrough fixup: the 5.x always-thinking models reject
        // `thinking: {"type": "disabled"}` (HTTP 400, code 1210 — "该模型始终思考，
        // 不支持关闭思考；请使用 low、high 或 max"). The field never reaches the
        // wire: prepare omits it for this candidate via the skip list (no body
        // copy). Per candidate: a later non-glm candidate must see the client's
        // original body — it does; the tree is never touched.
        let vendor_skip = if codex {
            // The Codex backend refuses sampling controls and output caps.
            capabilities::codex::SKIP_FIELDS
        } else {
            vendor_thinking_off_fields(
                &provider.name,
                &provider.base_url,
                target_model,
                protocol,
                capability.protocol,
                &request.body,
            )
        };
        if !vendor_skip.is_empty() {
            tracing::info!(
                provider = provider.name.as_str(),
                model = target_model,
                "always-thinking upstream: stripped thinking field"
            );
        }
        // Chat upstreams only (the native anthropic surface's behavior is
        // unverified, so it keeps the client's encoding), and candidate-scoped: a
        // non-GLM, non-DeepSeek sibling in the same route sees the client's original
        // body untouched.
        let fixups = ChatFixups {
            strip_glm_images: capability.protocol == ProtocolId::OpenAiChat
                && is_glm_upstream(&provider.name, &provider.base_url),
            // Any candidate serving a DeepSeek model — the official API, OpenCode
            // Go/Zen, Command Code, a later reseller — obeys the same thinking dialect
            // (see [`is_deepseek_model`]).
            deepseek_dialect: capability.protocol == ProtocolId::OpenAiChat
                && is_deepseek_model(target_model),
        };
        let request = &request;
        loop {
            let started = std::time::Instant::now();
            // Live-activity feed: one Start per attempt (each retry is its own
            // ledger row, so it gets its own seq). Published fire-and-forget;
            // nothing here can stall the request.
            let seq = activity.start(crate::activity::AttemptStart {
                client_model: &model,
                route: alias.as_deref(),
                account: Some(candidate.key.label.as_str()),
                served_model: target_model,
                protocol: protocol.as_str(),
                client_protocol: Some(request.protocol.as_str()),
                effort: effort.as_deref(),
                caller: caller_key,
                caller_key_id: principal.map(|principal| principal.key_id),
                caller_user_id: principal.map(|principal| principal.user_id),
                agent: request.agent.as_deref(),
                key_id: Some(candidate.key.id),
                stream: request.stream,
            });
            // The client-closed watchdog covers the in-flight attempt only: once
            // `attempt` returns, the pump owns client-gone (pre-commit via its own
            // hold verdict, post-commit via the stream) and the arm below writes
            // the row. Scoped to this block so the borrows end before `effort` /
            // `request_id` move into the streaming accounting task.
            let settled = {
                let mut watchdog = AbandonGuard {
                    request_id: &request_id,
                    provider: provider.name.as_str(),
                    key: candidate.key.label.as_str(),
                    model: &model,
                    served_model: target_model,
                    alias: alias.as_deref(),
                    protocol: capability.protocol,
                    client_protocol: request.protocol,
                    effort: effort.as_deref(),
                    provider_id: provider.id,
                    provider_key_id: key_id,
                    principal,
                    agent,
                    started,
                    ledger,
                    activity,
                    seq,
                    armed: true,
                };
                let settled = attempt(
                    &AttemptContext {
                        transport,
                        capability,
                        credential: &credential,
                        unfit: failover.unfit(),
                        provider_id: provider.id,
                        dns: provider.dns,
                        vendor_skip,
                        session_seed: session_seed.as_deref(),
                        fixups,
                        supported_efforts: candidate.supported_efforts.as_deref(),
                        default_effort: candidate.default_effort,
                        context_window: candidate.context_window,
                        route_efforts: efforts.as_deref(),
                        dial: capabilities::effort_dial(&provider.name, target_model),
                        // Only a Kiro candidate touches token state or PG.
                        kiro: (capability.protocol == ProtocolId::Kiro).then_some(KiroDeps {
                            key: &candidate.key,
                            pool,
                            tokens: kiro_tokens,
                            prompt_cache,
                            cache_caller_key_id: request
                                .principal
                                .as_ref()
                                .filter(|_| prompt_cache::prices_cache_reads(price.as_ref()))
                                .map(|principal| principal.key_id),
                        }),
                        // An OpenCode account row authenticates per attempt. The
                        // key's `auth_kind` decides, not the protocol: one
                        // account serves chat, messages and responses.
                        opencode: (candidate.key.auth_kind == "opencode_oauth").then_some(
                            OpencodeDeps {
                                tokens: opencode_tokens,
                                pool,
                                key_id: candidate.key.id,
                            },
                        ),
                        // An OpenAI Codex account authenticates per attempt too.
                        openai: codex.then_some(OpenaiDeps {
                            tokens: openai_tokens,
                            pool,
                            key_id: candidate.key.id,
                        }),
                        // Every Cursor Run authenticates through the manager.
                        cursor: cursor_credential.as_ref().map(|credential| CursorDeps {
                            tokens: cursor_tokens,
                            pool,
                            key_id: candidate.key.id,
                            credential,
                            usage: cursor_usage,
                            dns: candidate.provider.dns,
                        }),
                    },
                    target_model,
                    request,
                    &mut client_ir,
                    &request_id,
                    deadline,
                )
                .await;
                watchdog.disarm();
                settled
            };
            // Streaming hold: a streaming attempt counts as
            // successful only past the pump's commit point — the 200 headers alone
            // no longer lock the attempt in. Before the commit point, an upstream
            // death is an ordinary transferable failure and the client never saw a
            // byte; the dispatcher slot guards stay here through the failure path (so
            // a last-candidate retry keeps holding them) and move to the pump only
            // on commit.
            let outcome: Result<AttemptSuccess, failover::AttemptError> = match settled {
                Ok(RelayOutcome::Json {
                    status,
                    body,
                    observed,
                }) => Ok(AttemptSuccess::Json {
                    status,
                    body,
                    observed,
                }),
                Ok(RelayOutcome::Stream {
                    status,
                    reader,
                    pump,
                    cursor,
                }) => {
                    let (usage_tx, usage_rx) = tokio::sync::oneshot::channel();
                    let (commit_tx, commit_rx) = tokio::sync::oneshot::channel();
                    // The slot moves into the pump only on commit: until then a
                    // failed attempt still holds it here for failover.
                    let (slot_tx, slot_rx) = tokio::sync::oneshot::channel();
                    // Response-body accumulator, one per streaming attempt (an
                    // aborted attempt's buffer is dropped unread with the outcome).
                    let captured = capture.as_ref().map(|_| CapturedBody::new());
                    let frames = spawn_stream_pump(
                        reader,
                        pump,
                        usage_tx,
                        commit_tx,
                        slot_rx,
                        PumpSide {
                            payload_log: request.payload_log,
                            captured,
                            activity: Some((activity.clone(), seq)),
                            started,
                            request_id: request_id.clone(),
                            // A billed caller is charged for what the upstream
                            // generated, even past a client hang-up.
                            on_client_gone: if billing::needs_price(principal) {
                                OnClientGone::DrainUsage
                            } else {
                                OnClientGone::Stop
                            },
                            server_stopped: server_stopped.clone(),
                        },
                    );
                    match commit_rx.await {
                        Ok(HoldSignal::Committed) => {
                            // Locked in: the pump now owns the slot and releases it
                            // when the upstream read ends, not when the client's
                            // response body is dropped. A failed send (the pump
                            // task already died) returns the guard, which drops
                            // here and releases the slot.
                            if let Some(guard) = slot.take() {
                                let _ = slot_tx.send(guard);
                            }
                            Ok(AttemptSuccess::Stream {
                                status,
                                frames,
                                usage_rx,
                                cursor,
                            })
                        }
                        // A dropped verdict channel means the pump panicked: nothing
                        // reached the client either way, so it reads as an abort.
                        Ok(HoldSignal::Aborted) | Err(_) => {
                            Err(failover::AttemptError::AbortedStream)
                        }
                        Ok(HoldSignal::UpstreamTerminal(terminal)) => {
                            Err(failover::AttemptError::UpstreamTerminal(terminal))
                        }
                        Ok(HoldSignal::ClientGone) => Err(failover::AttemptError::Transport(
                            transport::TransportError::ClientGone,
                        )),
                    }
                }
                Err(error) => Err(error),
            };
            match outcome {
                Ok(AttemptSuccess::Json {
                    status,
                    body,
                    observed,
                }) => {
                    // Release the slots before the accounting writes below: a queued waiter
                    // must not time out on the predecessor's DB round-trips.
                    drop(slot);
                    let attempt = AttemptLog::from_observed(
                        (
                            capability.protocol,
                            alias.as_deref(),
                            provider.id,
                            key_id,
                            model.as_str(),
                            target_model,
                        ),
                        status,
                        &observed,
                        price.as_ref(),
                        started,
                    )
                    .with_caller(principal)
                    .with_agent(agent)
                    .with_client_protocol(request.protocol)
                    .with_effort(effort.as_deref())
                    .with_request_id(&request_id)
                    .with_charge(billing::certainty(
                        observed.usage.is_some(),
                        capability.protocol,
                    ));
                    let metrics = attempt.end_metrics();
                    attempts.push(attempt);
                    // Success resets the failure counter and clears this model's rest
                    // (other (key, model) rows stand — they are about other models).
                    failover.failures().clear(key_id);
                    let _ = rest_cache.clear_for_model(key_id, target_model).await;
                    // Queue the attempt rows for the batched ledger write — the
                    // request path no longer blocks on the INSERT (the Persisted
                    // activity event fires from the flush task, per batch).
                    ledger.push(std::mem::take(&mut attempts));
                    activity.end(seq, EndStatus::Ok, metrics);
                    if let Some(capture) = capture {
                        // The settled request's response body (lossy for readability,
                        // like the streaming capture — the body log is a diagnostic aid).
                        let response =
                            crate::body_log::capture_text(&String::from_utf8_lossy(&body));
                        push_capture(body_log, &request_id, capture, Some(response));
                    }
                    return DispatchOutcome::Json { status, body };
                }
                Ok(AttemptSuccess::Stream {
                    status,
                    frames,
                    usage_rx,
                    cursor,
                }) => {
                    let (finalize_tx, finalize_rx) = tokio::sync::oneshot::channel();
                    // Streaming post-processing: after the pump ends, take usage → account → clear the rest → queue the ledger rows, all in a background task,
                    // so neither the HTTP nor the in-process entry has to duplicate this.
                    //
                    // The exposure slot travels with the rows: until this task
                    // queues them the charge is still in flight, so the user's
                    // slot must not be freed when dispatch returns.
                    let exposure_claim = exposure_slot.take();
                    let failover = std::sync::Arc::clone(failover);
                    let body_log = body_log.clone();
                    let ledger = ledger.clone();
                    let rest_cache = rest_cache.clone();
                    let attempt_protocol = capability.protocol;
                    let provider_id = provider.id;
                    let alias = alias.clone();
                    let model = model.clone();
                    let served_model = candidate.upstream_model.clone();
                    let caller_key = caller_key.map(str::to_owned);
                    let user_id = principal.map(|principal| principal.user_id);
                    let gateway_key_id = principal.map(|principal| principal.key_id);
                    let agent = agent.map(str::to_owned);
                    let client_protocol = request.protocol;
                    let activity = activity.clone();
                    let stream_request_id = request_id.clone();
                    let mut attempts = std::mem::take(&mut attempts);
                    let settlement_ledger = ledger.clone();
                    settlement_ledger.spawn_settlement(async move {
                        // Held until this block ends, i.e. past `ledger.push`
                        // below: the user's slot must cover the charge until
                        // the attempt rows are queued, and no longer.
                        let _exposure_claim = exposure_claim;
                        let outcome = usage_rx.await.ok();
                        let ttft_ms = outcome.as_ref().and_then(|outcome| outcome.ttft_ms);
                        let mut usage = outcome.as_ref().and_then(|outcome| outcome.usage);
                        // A Cursor Run that carried no usage inline (a tool
                        // step, or a turn with no counters): wait for the
                        // dashboard's count (≤6s), else estimate (D9). The
                        // client's stream is already over; this is the ledger's.
                        if usage.is_none()
                            && let Some(handle) = cursor
                        {
                            usage = handle.settle().await.map(StreamUsage::from);
                        }
                        let cost_usd = price.as_ref().map(|price| {
                            let (input, output, cached, written, written_1h) = usage
                                .map(|u| {
                                    (
                                        u.input_tokens,
                                        u.output_tokens,
                                        u.cached_input_tokens.unwrap_or(0),
                                        u.cache_creation_input_tokens.unwrap_or(0),
                                        u.cache_creation_1h_input_tokens.unwrap_or(0),
                                    )
                                })
                                .unwrap_or_default();
                            price.cost_split(input, output, cached, written, written_1h)
                        });
                        let interrupted = outcome
                            .as_ref()
                            .and_then(|outcome| outcome.interrupted.clone());
                        let attempt = AttemptLog {
                            protocol: attempt_protocol,
                            client_protocol: Some(client_protocol),
                            effort,
                            alias,
                            provider_id,
                            provider_key_id: key_id,
                            model,
                            served_model: Some(served_model.clone()),
                            status,
                            input_tokens: usage.as_ref().map(|u| u.input_tokens),
                            output_tokens: usage.as_ref().map(|u| u.output_tokens),
                            cached_input_tokens: usage.as_ref().and_then(|u| u.cached_input_tokens),
                            cache_creation_input_tokens: usage
                                .as_ref()
                                .and_then(|u| u.cache_creation_input_tokens),
                            total_ms: started.elapsed().as_millis().min(i32::MAX as u128) as i32,
                            ttft_ms,
                            cost_usd,
                            error: interrupted,
                            caller_key,
                            user_id,
                            gateway_key_id,
                            agent,
                            request_id: Some(stream_request_id),
                            charged_microus: None,
                            rate_bp,
                        }
                        .with_charge(billing::certainty(usage.is_some(), attempt_protocol));
                        let metrics = attempt.end_metrics();
                        attempts.push(attempt);
                        // Success resets the failure counter and clears this model's rest
                        // (other (key, model) rows stand — they are about other models).
                        failover.failures().clear(key_id);
                        let _ = rest_cache.clear_for_model(key_id, &served_model).await;
                        // Queue the attempt rows for the batched ledger write; the
                        // Persisted event fires from the flush task, per batch.
                        ledger.push(std::mem::take(&mut attempts));
                        activity.end(seq, EndStatus::Ok, metrics);
                        if let Some(capture) = capture {
                            let response = outcome
                                .and_then(|outcome| outcome.captured)
                                .map(CapturedBody::finish);
                            push_capture(&body_log, &request_id, capture, response);
                        }
                        let _ = finalize_tx.send(());
                    });
                    return DispatchOutcome::Stream {
                        status,
                        frames: StreamFrames::new(frames),
                        finalize: finalize_rx,
                    };
                }
                Err(error) => {
                    terminal_concurrency_busy = false;
                    retry_after_hint = None;
                    let attempt = AttemptLog::from_error(
                        capability.protocol,
                        alias.as_deref(),
                        provider.id,
                        key_id,
                        &model,
                        &error,
                        started,
                    )
                    .with_caller(principal)
                    .with_agent(agent)
                    .with_client_protocol(request.protocol)
                    .with_effort(effort.as_deref())
                    .with_request_id(&request_id)
                    .with_served_model(target_model);
                    let metrics = attempt.end_metrics();
                    attempts.push(attempt);
                    // The attempt resolved in failure: drop its live row (the row it
                    // just pushed is persisted at the terminal insert below).
                    activity.end(seq, EndStatus::Error, metrics);
                    // The client disappeared: record the row for the ledger and stop —
                    // never classify, cool the key, bump the counter, fail over, or
                    // retry in place (a reconnect replays the whole request anyway).
                    if matches!(
                        &error,
                        failover::AttemptError::Transport(transport::TransportError::ClientGone)
                    ) {
                        drop(slot.take()); // accounting must not hold the slots
                        ledger.push(std::mem::take(&mut attempts));
                        // No response ever arrived (the client left): capture the request
                        // side with an empty response.
                        if let Some(capture) = capture {
                            push_capture(body_log, &request_id, capture, None);
                        }
                        return DispatchOutcome::Failed {
                            status: error.ledger_status(),
                            message: error.message(),
                            retry_after_secs: None,
                        };
                    }
                    let failure = match failover::classify(&error) {
                        // A quota refusal with no word of when: ask the vendor's own
                        // quota endpoint (quota.rs knows each vendor's usage source)
                        // whether a window reports its reset — rest to that instead of
                        // re-probing every 15 minutes for the rest of the month.
                        failover::Failure::Quota { reset_until: None } => {
                            failover::Failure::Quota {
                                reset_until: probe_quota_reset(
                                    provider.name.as_str(),
                                    provider.base_url.as_str(),
                                    candidate.key.api_key.as_deref(),
                                    provider.dns,
                                    transport,
                                )
                                .await,
                            }
                        }
                        failure => failure,
                    };
                    // The request itself is at fault: no failover, no rest — hand the
                    // upstream's own status and words back (a mapped 5xx would mislead).
                    if !failure.transferable() {
                        drop(slot.take()); // accounting must not hold the slots
                        ledger.push(std::mem::take(&mut attempts));
                        if let Some(capture) = capture {
                            push_capture(body_log, &request_id, capture, None);
                        }
                        return DispatchOutcome::Failed {
                            status: error.client_status(),
                            message: error.message(),
                            retry_after_secs: None,
                        };
                    }
                    // In-place retry: the last candidate retries Rate (up to 3) and
                    // Other (up to 2) before the request fails; an account set to
                    // 429 不冷却 (`rest_on_429 = false`) retries Rate at any position
                    // (`Failure::in_place_retries`). Pause: doubling backoff from `retry_pause`,
                    // overridden by Retry-After when present, never beyond 8s or the
                    // request budget. Each try is its own attempt row; the rest and the
                    // counter bump happen once, after the final failure. The permit is
                    // held across the sleeps — releasing it would break FIFO fairness,
                    // at the cost of a queued waiter on a saturated key possibly timing
                    // out (and logging a spurious Timeout row) during the pause.
                    let rate_policy = if candidate.key.rest_on_429 {
                        failover::RateLimitPolicy::Rest
                    } else {
                        failover::RateLimitPolicy::RetryInPlace
                    };
                    let retries_left = failure.in_place_retries(is_last, rate_policy);
                    if retried < retries_left {
                        // Total over both failure families: a Kiro OIDC 429
                        // carries its own Retry-After, and the token error's
                        // variant is not the transport one.
                        let retry_after = error.retry_after_duration();
                        let pause = retry_after.unwrap_or_else(|| {
                            failover.retry_pause().saturating_mul(1u32 << retried)
                        });
                        let remaining =
                            deadline.saturating_duration_since(std::time::Instant::now());
                        if pause <= MAX_RETRY_PAUSE && pause <= remaining {
                            retried += 1;
                            tracing::info!(
                                request_id = %request_id,
                                provider = provider.name.as_str(),
                                key = candidate.key.label.as_str(),
                                model = target_model,
                                elapsed_ms = started.elapsed().as_millis() as u64,
                                "attempt failed ({}), retrying the same account in {}ms ({retried}/{retries_left})",
                                error.message(),
                                pause.as_millis()
                            );
                            tokio::time::sleep(pause).await;
                            continue;
                        }
                    }
                    drop(slot.take()); // accounting must not hold the slots
                    // Neither the key nor the model is at fault (request shape / channel
                    // refusal): fail over without resting anyone, and don't bump the
                    // failure counter.
                    if matches!(failure, failover::Failure::Blameless) {
                        tracing::warn!(
                            request_id = %request_id,
                            provider = provider.name.as_str(),
                            key = candidate.key.label.as_str(),
                            model = target_model,
                            elapsed_ms = started.elapsed().as_millis() as u64,
                            "attempt failed without blaming the key, failing over: {}",
                            error.message()
                        );
                        index += 1;
                        continue 'candidates;
                    }
                    // An `Other` failure bumps the key's consecutive-failure counter once
                    // (after any in-place retries) and drives the backoff; the named
                    // classes (Credit/Quota/Rate/Unserved) have fixed durations and don't count.
                    let consecutive = if matches!(failure, failover::Failure::Other) {
                        failover.failures().bump(key_id)
                    } else {
                        1
                    };
                    let Some(rest_target) =
                        failure.rest_target(rate_policy, consecutive, chrono::Utc::now())
                    else {
                        // Nobody rests: either the class says so (Credit/Quota/Rate all
                        // rest; Blameless and Request never reach here) or this account's
                        // 429 switch suppressed its own rate-limit cooldown. Name the
                        // latter, so the log explains the extra attempts and failover
                        // instead of reading like a cooldown that got lost.
                        if matches!(failure, failover::Failure::Rate { .. }) {
                            tracing::info!(
                                request_id = %request_id,
                                provider = provider.name.as_str(),
                                key = candidate.key.label.as_str(),
                                model = target_model,
                                elapsed_ms = started.elapsed().as_millis() as u64,
                                "429: account is set to not cool down, failing over un-rested: {}",
                                error.message()
                            );
                        }
                        index += 1;
                        continue 'candidates;
                    };
                    let (duration, rest_model) = match rest_target {
                        failover::RestTarget::Key(duration) => (duration, None),
                        failover::RestTarget::KeyModel(duration) => (duration, Some(target_model)),
                    };
                    let until = chrono::Utc::now() + duration;
                    let _ = rest_cache
                        .insert(key_id, rest_model, until, error.code())
                        .await;
                    tracing::warn!(
                        request_id = %request_id,
                        provider = provider.name.as_str(),
                        key = candidate.key.label.as_str(),
                        model = target_model,
                        elapsed_ms = started.elapsed().as_millis() as u64,
                        "attempt failed, failing over: {} (resting until {until})",
                        error.message()
                    );
                    index += 1;
                    continue 'candidates;
                }
            }
        }
    }
    // Queue whatever attempts accumulated for the batched ledger write (the
    // Persisted event fires from the flush task). Unserved/all-invalid paths
    // leave attempts empty — the push is then a no-op and no Persisted fires,
    // same as the old per-request guard. The outcome fields are lifted first
    // so the push can take ownership (no clone of the attempt rows).
    let outcome = if terminal_concurrency_busy {
        Some((
            429,
            format!("all candidates busy after {queue_timeout:?}"),
            retry_after_hint,
        ))
    } else {
        attempts.last().map(|last| {
            (
                last.status,
                last.error
                    .clone()
                    .unwrap_or_else(|| "upstream failed".into()),
                retry_after_hint,
            )
        })
    };
    ledger.push(attempts);
    match outcome {
        Some((status, message, retry_after_secs)) => {
            // The request settled in failure: capture the request side (the error
            // lives on the row; there is no response body).
            if let Some(capture) = capture {
                push_capture(body_log, &request_id, capture, None);
            }
            DispatchOutcome::Failed {
                status,
                message,
                retry_after_secs,
            }
        }
        // No attempt ran and at least one candidate was skipped for capability
        // reasons: nobody can serve this protocol (e.g. an Anthropic client with
        // only Responses-capable candidates — that pair is not translatable).
        None if unpriced => DispatchOutcome::Failed {
            status: 503,
            message: format!("model {model} is not priced yet; try again later"),
            retry_after_secs: None,
        },
        None if stream_required && !unserved => DispatchOutcome::Failed {
            status: 400,
            message: "this model is served by a ChatGPT Codex account, which only streams; \
                      set \"stream\": true"
                .into(),
            retry_after_secs: None,
        },
        None if unserved => DispatchOutcome::Failed {
            status: 501,
            message: format!("no candidate can serve the {} protocol", protocol.as_str()),
            retry_after_secs: None,
        },
        // All candidates had invalid rows (skipped via continue); no real attempt was made.
        None => DispatchOutcome::Failed {
            status: 500,
            message: "no usable provider credential".into(),
            retry_after_secs: None,
        },
    }
}

/// Everything [`build_trace`] needs to render one dispatch: identity, route
/// metadata, the candidates the dispatcher saw, and its decision record.
struct TraceInputs<'a> {
    request_id: &'a str,
    model: &'a str,
    alias: Option<&'a str>,
    strategy: &'a store::RouteStrategy,
    candidates: &'a [candidates::Candidate],
    excluded: &'a [(candidates::Candidate, trace::SkipReason)],
    decision: &'a DispatchDecision,
    /// Verdict reasons, indexed by candidate index (empty when no quota
    /// snapshots were available; absent for the resting tail).
    reasons: &'a [String],
}

/// Build a routing trace from the dispatcher's decision record.
///
/// The trace shows every candidate with its final state: skipped (with
/// reason), ready, full, rested, or selected. Excluded candidates appear
/// first (they weren't in the ordered list), followed by the ordered
/// candidates in dispatch order.
fn build_trace(inputs: TraceInputs<'_>) -> trace::DispatchTrace {
    let TraceInputs {
        request_id,
        model,
        alias,
        strategy,
        candidates,
        excluded,
        decision,
        reasons,
    } = inputs;
    let mut trace_candidates = Vec::new();

    // Add excluded candidates first (they weren't in the ordered list).
    for (candidate, reason) in excluded {
        trace_candidates.push(trace::CandidateTrace {
            key_label: candidate.key.label.clone(),
            provider_name: candidate.provider.name.clone(),
            model: candidate.upstream_model.clone(),
            skipped: Some(reason.clone()),
            smart_reason: String::new(), // excluded candidates don't have smart reasons
        });
    }

    // Add ordered candidates (from the dispatcher's decision).
    // decision.candidates is indexed by candidate index, matching `candidates`.
    for (index, state) in decision.candidates.iter().enumerate() {
        let candidate = &candidates[index];
        let smart_reason = reasons.get(index).cloned().unwrap_or_default();

        let skipped = match state {
            dispatcher::CandidateState::Selected | dispatcher::CandidateState::Ready => None,
            dispatcher::CandidateState::Full => Some(trace::SkipReason::ConcurrencyFull),
            dispatcher::CandidateState::Rested => Some(trace::SkipReason::Resting),
        };

        trace_candidates.push(trace::CandidateTrace {
            key_label: candidate.key.label.clone(),
            provider_name: candidate.provider.name.clone(),
            model: candidate.upstream_model.clone(),
            skipped,
            smart_reason,
        });
    }

    trace::DispatchTrace {
        request_id: request_id.to_owned(),
        model: model.to_owned(),
        alias: alias.map(str::to_owned),
        strategy: format!("{strategy:?}").to_lowercase(),
        candidates: trace_candidates,
        ts: chrono::Utc::now(),
    }
}
