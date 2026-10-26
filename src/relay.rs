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
pub use failover::Failover;
pub use ledger_writer::{LedgerWriter, LedgerWriterHandle};
pub use price_cache::{PriceCache, PriceInput};
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
use crate::body_log::{BodyLog, CapturedBodies, CapturedBody};
use crate::protocol::{self, ProtocolError, TargetView};
use crate::store::{self, AttemptLog};
use crate::translation;
use crate::translation::ir::Effort;
use crate::upstream::kiro_tokens::{self, KiroCallContext, KiroTokens};
use crate::upstream::transport::{self, Transport};

use std::sync::atomic::{AtomicU64, Ordering};

/// Monotonic request ID for dispatcher timeout tracking.
static REQUEST_ID: AtomicU64 = AtomicU64::new(0);

fn next_request_id() -> u64 {
    REQUEST_ID.fetch_add(1, Ordering::Relaxed)
}

use dialects::{
    ChatFixups, conversation_seed, fill_missing_reasoning, fill_missing_reasoning_pending,
    is_deepseek_model, is_glm_upstream, is_opencode_upstream, join_split_tool_call_turns,
    join_split_tool_call_turns_pending, opencode_headers, vendor_thinking_off_fields,
};
use streaming::{
    AttemptSuccess, HoldSignal, PumpSide, RelayOutcome, StreamPump, spawn_stream_pump,
};

/// Full context of one client request.
pub struct RelayRequest {
    pub protocol: ProtocolId,
    pub body: Value,
    pub stream: bool,
    /// Mirror request/response payloads into the log (target `gateway::payload`).
    pub payload_log: bool,
    /// The caller's identity (the gateway key's label), verified by the HTTP
    /// auth hoop; None for a local unidentified caller or an in-process call.
    pub caller_key: Option<String>,
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
        // Kiro never arrives inbound — it is a translation target only.
        ProtocolId::Gemini | ProtocolId::OpenAiEmbeddings | ProtocolId::Kiro => None,
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
) -> Option<chrono::DateTime<chrono::Utc>> {
    let api_key = api_key?;
    let quota = crate::quota::fetch_quota(provider_name, base_url, api_key).await?;
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
/// id (`req_{n}`): the ledger writer batches inserts, so no DB row id exists
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
    request_id: &str,
    deadline: std::time::Instant,
) -> Result<RelayOutcome, failover::AttemptError> {
    if !request.stream {
        attempt_json(ctx, target_model, request, deadline).await
    } else {
        attempt_stream(ctx, target_model, request, request_id, deadline).await
    }
}

/// Everything the Kiro token plane needs for one candidate: the key row (its
/// stored bundle seeds the manager and its id keys the per-key lock), the
/// gateway database (rereads and write-backs), and the manager itself.
///
/// Bundled as one optional field so every non-Kiro candidate pays nothing for
/// it — and so the credential path reads as one thing at the construction site.
#[derive(Clone, Copy)]
struct KiroDeps<'a> {
    key: &'a crate::store::ProviderKeyRow,
    pool: &'a sqlx::PgPool,
    tokens: &'a KiroTokens,
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
    vendor_skip: &'a [&'static str],
    /// The OpenCode session seed (the serialized first user message), computed
    /// once per dispatch; `None` when no OpenCode upstream is in play.
    opencode_seed: Option<&'a str>,
    /// This candidate's Chat-body adaptations (none for the common request).
    fixups: ChatFixups,
    /// This candidate model's supported effort levels (ascending, named only);
    /// `None` = unconstrained.
    supported_efforts: Option<&'a [Effort]>,
    /// The vendor-declared default level, used to repair names outside the
    /// closed vocabulary.
    default_effort: Option<Effort>,
    /// 路由层固定 effort 档位;`None` = 直连或 legacy 路由(快照 clamp)。
    route_efforts: Option<&'a [Effort]>,
    /// 当前候选 (provider, model family) 的 effort 方言。
    dial: capabilities::EffortDial,
    /// Kiro only: this candidate's token plumbing. `None` for every non-Kiro
    /// protocol, which therefore never touches the token manager or PG.
    kiro: Option<KiroDeps<'a>>,
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
    stream: bool,
    deadline: std::time::Instant,
) -> Result<(u16, reqwest::Response, ProtocolId), failover::AttemptError> {
    let AttemptContext {
        transport,
        capability,
        credential,
        unfit,
        provider_id,
        vendor_skip,
        opencode_seed,
        fixups,
        supported_efforts,
        default_effort,
        route_efforts,
        dial,
        kiro,
    } = *ctx;
    // The selected capability IS the upstream protocol: passthrough when it
    // matches the client protocol, translation target otherwise.
    let protocol = capability.protocol;
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
            // Pin the destination BEFORE resolving a credential: a bearer must
            // only ever travel to the credential's own runtime host, never to
            // an operator-editable `base_url`. Fail closed on a mismatch.
            let api_region = deps
                .key
                .oauth
                .as_ref()
                .map(|oauth| oauth.api_region.as_str())
                .ok_or(failover::AttemptError::KiroTokenError(
                    kiro_tokens::KiroTokenError::MissingCredential,
                ))?;
            if !kiro_tokens::kas_endpoint_matches(&capability.endpoint, api_region) {
                tracing::warn!(
                    provider_id = deps.key.provider_id,
                    key_id = deps.key.id,
                    "Kiro runtime endpoint contradicts the credential's API region; refusing to send the bearer"
                );
                return Err(failover::AttemptError::KiroTokenError(
                    kiro_tokens::KiroTokenError::EndpointMismatch,
                ));
            }
            let call = deps
                .tokens
                .access_token(deps.pool, deps.key)
                .await
                .map_err(failover::AttemptError::KiroTokenError)?;
            // Reassert against the RESOLVED bundle: the pre-check read the
            // route cache's copy, which can lag a region move. The bearer must
            // only ever travel to its own credential's runtime host.
            if !kiro_tokens::kas_endpoint_matches(&capability.endpoint, &call.api_region) {
                tracing::warn!(
                    provider_id = deps.key.provider_id,
                    key_id = deps.key.id,
                    "Kiro credential's API region contradicts the runtime endpoint after token resolution; refusing to send the bearer"
                );
                return Err(failover::AttemptError::KiroTokenError(
                    kiro_tokens::KiroTokenError::EndpointMismatch,
                ));
            }
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
    let target = TargetView {
        protocol,
        endpoint: &capability.endpoint,
        stream_endpoint: capability.stream_endpoint.as_deref(),
        upstream_model: target_model,
        kas_call: kas_call.as_ref(),
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
    let prepare = |fields: &[&str], profile_arn: Option<&str>| {
        if request.protocol == protocol {
            protocol::prepare(
                protocol,
                passthrough_body,
                &target,
                stream,
                fields,
                fixups.strip_glm_images,
            )
        } else {
            prepare_translated(
                &request.body,
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
                },
            )
        }
    };
    let mut prepared =
        prepare(&skip, kiro_profile_arn.as_deref()).map_err(failover::AttemptError::Protocol)?;
    // OpenCode's gateway (Zen or Go) refuses requests that name no conversation
    // (400 MissingSessionID), so its header family rides beside the credential.
    // The session seed derives from the first user message — top-level field
    // strips never move it — and was computed once per dispatch.
    // Kiro's Authorization is the call-context bearer; the row's own credential
    // (the static-scheme placeholder, or a secret an operator typed on a Kiro
    // row) never goes upstream.
    let mut headers = match &kiro_call {
        Some(call) => vec![("authorization", format!("Bearer {}", call.bearer()))],
        None => credential.headers(),
    };
    if let Some(seed) = opencode_seed {
        headers.extend(opencode_headers(seed));
    }
    let query_pairs = if kiro_call.is_some() {
        Vec::new()
    } else {
        credential.query_pairs()
    };

    let mut rounds = 0u32;
    let mut kiro_retried = false;
    loop {
        let response = transport
            .send_with_headers(&prepared, &headers, &query_pairs, deadline)
            .await
            .map_err(failover::AttemptError::Transport)?;
        let status = response.status().as_u16();
        if status < 400 {
            return Ok((status, response, protocol));
        }
        // Capture the vendor's error body (bounded, best-effort: an unreadable body
        // still yields the Status error, just without evidence) so the relay can
        // classify the failure and the attempt log shows the vendor's own words.
        let response_headers = response.headers().clone();
        let body = transport
            .read_body(response, transport::MAX_ERROR_BODY, deadline)
            .await
            .unwrap_or_default();
        // Kiro: the runtime's own invalidation signal licenses exactly one
        // refresh-and-resend of this SAME invocation (same URL, same body,
        // attempt advanced in place). Any other 401/403 — or a second rejection
        // after the refresh — falls through to the ordinary failure path.
        if !kiro_retried
            && kiro_tokens::bearer_token_invalid(status, &body)
            && let (Some(deps), Some(call)) = (kiro, &kiro_call)
        {
            kiro_retried = true;
            let old_bearer = call.bearer().to_owned();
            let old_profile_arn = call.profile_arn.clone();
            // Concurrent requests that presented the same stale bearer
            // de-duplicate in the manager: one CreateToken, everyone reuses.
            let recovered = deps
                .tokens
                .recover_invalidated(deps.pool, deps.key, &old_bearer)
                .await
                .map_err(failover::AttemptError::KiroTokenError)?;
            // The refreshed bundle may have moved to another API region (an
            // operator rotation): reassert before resending this bearer.
            if !kiro_tokens::kas_endpoint_matches(&capability.endpoint, &recovered.api_region) {
                tracing::warn!(
                    provider_id = deps.key.provider_id,
                    key_id = deps.key.id,
                    "recovered Kiro credential's API region no longer matches the runtime endpoint; refusing to resend the bearer"
                );
                return Err(failover::AttemptError::KiroTokenError(
                    kiro_tokens::KiroTokenError::EndpointMismatch,
                ));
            }
            if recovered.profile_arn != old_profile_arn
                && let Some(profile_arn) = recovered.profile_arn.as_deref()
            {
                // Cold path: the account identity moved, so the already-built
                // KAS body must name the new profile or the call is rejected.
                set_profile_arn(&mut prepared, profile_arn);
            }
            kiro_profile_arn = recovered.profile_arn.clone();
            headers = vec![("authorization", format!("Bearer {}", recovered.bearer()))];
            kiro_call = Some(recovered);
            // Same logical call, one attempt later: REPLACE the retry headers in
            // place. The transport appends a caller's header list, so appending
            // a second triple would send duplicate, contradictory values.
            if let Some(call) = &kas_call {
                let attempt = call.next_attempt();
                crate::kiro::profile::replace_retry_headers(
                    &mut prepared.headers,
                    call.invocation(),
                    attempt,
                    crate::kiro::profile::KIRO_MAX_ATTEMPTS,
                    chrono::Utc::now(),
                );
            }
            tracing::warn!(
                key_id = deps.key.id,
                status,
                "Kiro runtime rejected the bearer; refreshed once, resending the same call"
            );
            continue;
        }
        // Refusal detection skips Anthropic upstreams (its API never names
        // request fields in errors).
        if protocol != ProtocolId::AnthropicMessages
            && rounds < optional::MAX_STRIP_ROUNDS
            && let Ok(sent) = serde_json::from_slice::<Value>(&prepared.body)
        {
            let refused = optional::refused_optional(status, &body, &sent);
            if !refused.is_empty() {
                // Extend the skip list and rebuild the wire from the still-available
                // client tree — cheaper than parsing and re-serializing the wire
                // body, and it covers kernel-injected fields identically.
                skip.extend(refused.iter().copied());
                if let Ok(retried) = prepare(&skip, kiro_profile_arn.as_deref()) {
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
            }
        }
        // A vendor error body can echo the credential it just rejected; excise it
        // before the body becomes the attempt's error — that error is what the
        // caller reads, what the attempt log prints, and what the request row keeps.
        let redacted = match &kiro_call {
            Some(call) => crate::providers::AuthSchemeMaterial::new(
                crate::providers::AuthScheme::Bearer,
                call.bearer(),
            )
            .redact(&body),
            None => credential.redact(&body),
        };
        let body = match redacted {
            Some(redacted) => bytes::Bytes::from(redacted),
            None => bytes::Bytes::from(body),
        };
        return Err(
            match transport::status_error(status, &response_headers, body) {
                Some(error) => failover::AttemptError::Transport(error),
                // Unreachable (status >= 400 always classifies), kept total without panicking.
                None => failover::AttemptError::Transport(transport::TransportError::InvalidBody),
            },
        );
    }
}

/// Point an already-prepared KAS body at a rotated account identity.
///
/// One cold-path parse/re-render, taken at most once per attempt: the body was
/// built from the bundle the token manager knew before the 401, and a refresh
/// that returned a new `profileArn` invalidates that copy. A body that cannot
/// be parsed is left untouched (the resend then fails upstream like any other
/// malformed request, which is the honest outcome).
fn set_profile_arn(prepared: &mut protocol::Prepared, profile_arn: &str) {
    let Ok(mut body) = serde_json::from_slice::<Value>(&prepared.body) else {
        return;
    };
    let Some(object) = body.as_object_mut() else {
        return;
    };
    if object.get("profileArn").and_then(Value::as_str) == Some(profile_arn) {
        return;
    }
    object.insert(
        "profileArn".to_owned(),
        Value::String(profile_arn.to_owned()),
    );
    match serde_json::to_vec(&body) {
        Ok(rendered) => prepared.body = bytes::Bytes::from(rendered),
        Err(_) => tracing::warn!("Kiro profileArn update could not re-render the prepared body"),
    }
}

// Price per request is computed at the attempt sites; the model-level price
// row carries every unit the formula needs (see store::ModelPrice::cost_split).

/// Streaming attempt: send prepared, validate the status, then return the StreamReader and pump.
async fn attempt_stream(
    ctx: &AttemptContext<'_>,
    target_model: &str,
    request: &RelayRequest,
    request_id: &str,
    deadline: std::time::Instant,
) -> Result<RelayOutcome, failover::AttemptError> {
    let (status, response, protocol) =
        send_attempt(ctx, target_model, request, true, deadline).await?;
    let reader = Box::new(ctx.transport.stream(response, deadline, protocol));

    let pump = if request.protocol == protocol {
        StreamPump::PassThrough {
            decoder: protocol::Decoder::new(protocol),
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
        }
    };
    Ok(RelayOutcome::Stream {
        status,
        reader,
        pump,
    })
}

/// Execute one relay attempt (non-streaming). Same protocol passes through; cross-protocol translates.
async fn attempt_json(
    ctx: &AttemptContext<'_>,
    target_model: &str,
    request: &RelayRequest,
    deadline: std::time::Instant,
) -> Result<RelayOutcome, failover::AttemptError> {
    let (status, response, protocol) =
        send_attempt(ctx, target_model, request, false, deadline).await?;
    let body = ctx
        .transport
        .read_body(response, ctx.transport.limits().max_json_bytes, deadline)
        .await
        .map_err(failover::AttemptError::Transport)?;

    let observed = if request.protocol == protocol {
        // Passthrough: observe per the target protocol.
        protocol::parse_json(protocol, &body).map_err(failover::AttemptError::Protocol)?
    } else {
        // Translation: upstream response → IR → source-protocol shape.
        let upstream_dialect =
            translation::dialect(protocol).map_err(failover::AttemptError::Protocol)?;
        let source_dialect =
            translation::dialect(request.protocol).map_err(failover::AttemptError::Protocol)?;
        let mut ir =
            (upstream_dialect.response_to_ir)(&body).map_err(failover::AttemptError::Protocol)?;
        // Kiro reports no model identity. The client body must still carry a
        // sensible model, so fill an empty one with the model this attempt
        // actually requested (never an invented id). The ledger keeps the
        // evidence honest: an absent upstream model stays `None` there and
        // falls back to the requested target (AttemptLog::from_observed).
        let reported_model = !ir.model.is_empty();
        if !reported_model {
            ir.model = target_model.to_owned();
        }
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
                // unknown; the ledger must not record fabricated zeroes.
                usage: ir.usage,
                terminal,
                upstream_model: reported_model.then_some(ir.model),
            },
        });
    };
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
}

/// Request preparation for the translation path: source to_ir → target from_ir → target prepare.
/// `skip` passes through to the target kernel (learned refusals, vendor fixups).
/// `fixups` are the vendor Chat-body adaptations (see [`ChatFixups`]).
fn prepare_translated(
    source_body: &Value,
    source: ProtocolId,
    upstream: ProtocolId,
    target: &TargetView<'_>,
    stream: bool,
    tweaks: WireTweaks<'_>,
) -> Result<protocol::Prepared, ProtocolError> {
    let source_dialect = translation::dialect(source)?;
    let upstream_dialect = translation::dialect(upstream)?;
    let (mut ir, _) = (source_dialect.to_ir)(source_body, translation::ir::NO_DECLARED_LIMIT)?;
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
    let (mut upstream_value, _) = (upstream_dialect.from_ir)(&ir, target.upstream_model)?;
    // Chat 发射器对显式 off 省略字段;按厂商方言注入 off 标记,让"关思考"
    // 在翻译路径真正生效(纯思考模型由方言降级为最低档)。
    if upstream == ProtocolId::OpenAiChat && matches!(ir.effort, Some(Effort::None)) {
        upstream_value["reasoning_effort"] =
            Value::String(translation::effort_clamp::off_wire_name(tweaks.dial).to_owned());
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
}

/// Model resolution: the client-supplied model string picks the candidate set.
///
/// Two ways to call:
/// - `"<provider_name>/<upstream_model>"` whose prefix names an ENABLED provider → that provider's
///   enabled keys in global (position, id) order, all serving the suffix model (direct path);
/// - otherwise the string is looked up as a route alias → one candidate per
///   entry in the route's STORED order (the user-arranged GUI order), each
///   entry carrying its own upstream model (route path).
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
        /// Smart only applies on the route path; direct `provider/model`
        /// resolution keeps its stored key order (Ordered).
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
///   the candidate's placeholder secret is empty and never reaches the wire.
///
/// A row missing the credential its `auth_kind` requires is dropped from
/// candidacy with a warning — never cooled, since a missing credential is not an
/// upstream failure.
fn fetch_key_secrets(
    keys: Vec<crate::store::ProviderKeyRow>,
) -> (Vec<(crate::store::ProviderKeyRow, SecretString)>, usize) {
    let mut resolved = Vec::with_capacity(keys.len());
    let mut skipped = 0usize;
    for key in keys.into_iter().filter(|key| key.enabled) {
        if key.auth_kind == "kiro_oidc" {
            if key.oauth.is_some() {
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
                strategy: store::RouteStrategy::Ordered,
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
            let key_ids: Vec<i64> = route.entries.iter().map(|entry| entry.key_id).collect();
            let keys = route_cache.keys_by_ids(&key_ids);
            let (keys, secret_skipped) = fetch_key_secrets(keys);
            let provider_ids: Vec<i64> = keys.iter().map(|(key, _)| key.provider_id).collect();
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
            agent: None,
            request_id: None,
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
            agent: None,
            request_id: None,
        }
    }

    /// Stamp the caller identity (one per dispatch, shared by every attempt row
    /// of the request — the constructors leave it empty).
    fn with_caller(mut self, caller_key: Option<&str>) -> Self {
        self.caller_key = caller_key.map(str::to_owned);
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

    /// Stamp the dispatch request id (the `req_{n}` string the trace ring and
    /// upstream header share; same one-per-dispatch sharing as
    /// [`Self::with_caller`]).
    fn with_request_id(mut self, request_id: &str) -> Self {
        self.request_id = Some(request_id.to_owned());
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
    alias: Option<&'a str>,
    protocol: ProtocolId,
    client_protocol: ProtocolId,
    effort: Option<&'a str>,
    provider_id: i64,
    provider_key_id: i64,
    caller_key: Option<&'a str>,
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
        .with_caller(self.caller_key)
        .with_agent(self.agent)
        .with_client_protocol(self.client_protocol)
        .with_effort(self.effort)
        .with_request_id(self.request_id);
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
        frames: tokio::sync::mpsc::Receiver<Result<bytes::Bytes, std::io::Error>>,
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
/// `pool` is the one deliberate PG touch on the request path, and only Kiro
/// candidates reach it: an OIDC access token expires hourly, so the credential
/// plane must reread the row (another process may have rotated it) and persist
/// the rotated bundle. Every other candidate still reads cached state only, and
/// every other write still goes through `ledger`.
pub struct DispatchDeps<'a> {
    pub pool: &'a sqlx::PgPool,
    pub transport: &'a Transport,
    pub queue_timeout: std::time::Duration,
    pub dispatcher: &'a tokio::sync::mpsc::UnboundedSender<dispatcher::DispatchEvent>,
    pub failover: &'a std::sync::Arc<Failover>,
    /// Per-key Kiro OIDC token manager (lazy refresh, single-flight, write-back).
    pub kiro_tokens: &'a KiroTokens,
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
}

/// The Smart verdict reason per READY candidate, position-aligned with the
/// ordered ready list the dispatch loop walks (the resting tail is chained
/// after it, so a resting candidate lands past the end and reads as "no
/// reason", never as its ready sibling's verdict). Position, not key id, is
/// the identity: a route may hang several models on one key, and each entry
/// is its own candidate with its own verdict.
type VerdictReasons = Vec<String>;

/// Order the ready partition per the route's strategy and compute each
/// candidate's verdict reason. Ordered routes keep the stored order with an
/// empty reason list. Smart routes read the in-memory snapshot cache (no PG
/// round-trip); an empty cache degrades to stored order with a debug log —
/// dispatch must NEVER fail because of quota lookups.
fn order_ready(
    smart_cache: &smart_cache::SmartCache,
    rotate_cursors: &rotate::RotateCursors,
    strategy: store::RouteStrategy,
    alias: Option<&str>,
    ready: Vec<candidates::Candidate>,
    now: chrono::DateTime<chrono::Utc>,
) -> (Vec<candidates::Candidate>, VerdictReasons) {
    match strategy {
        store::RouteStrategy::Smart => {
            // Direct `provider/model` resolution always resolves as Ordered, so a
            // Smart strategy here implies a route alias; the guard keeps the
            // helper total all the same.
            let Some(alias) = alias else {
                return return_ordered(ready);
            };
            if smart_cache.is_empty() {
                // Not a warning: the prober may not have run yet, and many healthy
                // keys legitimately carry no snapshot.
                tracing::debug!(route = %alias, "smart route has no quota snapshots yet; dispatching in stored route order");
                return return_ordered(ready);
            }
            let quotas = smart_cache.snapshots();
            let ordered = smart::order(ready, &quotas, now);
            // The verdict reason is computed here, at dispatch-prep time, and MOVED
            // alongside the candidate — never cloned, never recomputed later.
            ordered
                .into_iter()
                .map(|(candidate, verdict)| (candidate, verdict.reason))
                .unzip()
        }
        store::RouteStrategy::Rotate => {
            let Some(alias) = alias else {
                return return_ordered(ready);
            };
            let len = ready.len();
            if len < 2 {
                // Fewer than 2 ready candidates: rotation is a no-op, and
                // advancing the cursor would only cause a skip when the
                // second candidate comes back.
                return return_ordered(ready);
            }
            let start = rotate_cursors.next(alias) % len;
            let mut ready = ready;
            ready.rotate_left(start);
            (ready, VerdictReasons::new())
        }
        store::RouteStrategy::Ordered => return_ordered(ready),
    }
}

/// Smart fallback shape: the stored (ordered) candidate order with no verdict
/// reasons — exactly what an Ordered route produces.
fn return_ordered(
    ready: Vec<candidates::Candidate>,
) -> (Vec<candidates::Candidate>, VerdictReasons) {
    (ready, VerdictReasons::new())
}

/// Orchestration core: model resolution → candidate expansion (ready first, resting last) → strategy ordering
/// (Smart routes reorder the ready partition by quota snapshots; Ordered routes keep the stored order) → ordered
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
        kiro_tokens,
        trace_ring,
        smart_cache,
        rotate_cursors,
        route_cache,
        rest_cache,
        price_cache,
        ledger,
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
    let caller_key = request.caller_key.as_deref();
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
    let (alias, strategy, expanded, excluded, window_skipped, secret_skipped, efforts) =
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
    // Smart routes order the READY partition by the latest quota snapshots.
    // Dispatch must never fail because of a quota lookup: when the snapshot
    // read fails (or no snapshots exist yet) the route degrades to ordered
    // behavior for this request — the warn log is the signal something is off.
    let (ready, reasons) = order_ready(
        smart_cache,
        rotate_cursors,
        strategy,
        alias.as_deref(),
        ready,
        chrono::Utc::now(),
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
    // OpenCode session identity: derived from the request body alone, so it is
    // computed at most once per dispatch and reused by every attempt (the
    // sha256 input must stay byte-identical — opencode's session headers depend
    // on its stability across attempts and processes). `None` while no OpenCode
    // upstream has appeared.
    let mut opencode_seed: Option<String> = None;

    // === Dispatcher integration: centralized slot assignment ===
    // Instead of acquiring semaphores per-candidate, submit a DispatchRequest
    // to the dispatcher task and wait for an assignment. The dispatcher owns
    // all slot state and the pending queue.

    // Build CandidateCaps for all candidates (computed once per dispatch).
    // is_resting is judged per candidate HERE, on the final vector — flags
    // captured before the partition/Smart reorder would misalign with the
    // positions below (a rest flag from stored order would land on a
    // different candidate).
    let caps: Vec<CandidateCaps> = candidates
        .iter()
        .map(|c| CandidateCaps {
            key_cap: c.key.max_concurrency.map(|n| n as usize),
            entry_cap: c.entry_cap.map(|n| n as usize),
            rested: is_resting(c),
        })
        .collect();

    // Build the smart-sorted order (indices into the candidates vector).
    // The candidates vector is already in the correct order (ready first, resting last),
    // so order is just 0..len for now. In the future, smart::order could reorder.
    let order: Vec<usize> = (0..candidates.len()).collect();

    // Precompute the dispatcher's slot keys: the dispatcher only needs the
    // key id and the route-entry identity, so it never holds the candidates
    // (an Arc<[Candidate]> here would deep-clone every SecretString into the
    // pending queue). The entry-slot hash mirrors the route entry identity:
    // key id + upstream model + route alias.
    let slot_keys: Vec<(SlotKey, Option<SlotKey>)> = candidates
        .iter()
        .map(|c| {
            let key_slot = SlotKey::Key(c.key.id as u64);
            let entry_slot = c.entry_cap.map(|_| {
                use std::hash::{Hash, Hasher};
                let mut hasher = std::collections::hash_map::DefaultHasher::new();
                c.key.id.hash(&mut hasher);
                c.upstream_model.hash(&mut hasher);
                if let Some(alias) = &c.route_alias {
                    alias.hash(&mut hasher);
                }
                SlotKey::Entry(hasher.finish())
            });
            (key_slot, entry_slot)
        })
        .collect();

    // One request id per dispatch: the dispatcher's timeout-tracking id, the
    // trace's request_id, and the upstream header all share it.
    let request_num = next_request_id();
    let request_id = format!("req_{request_num}");

    // Create a reply channel for this request.
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();

    // Submit the dispatch request.
    let dispatch_req = DispatchRequest {
        id: request_num,
        slot_keys,
        order,
        caps,
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

    // Wait for assignment with timeout.
    let assignment = match tokio::time::timeout(queue_timeout, reply_rx).await {
        Ok(Ok(Some(assignment))) => assignment,
        Ok(Ok(None)) | Err(_) => {
            // All candidates busy: either the dispatcher answered None (its own
            // Timeout event raced us) or our wait timed out — tell the dispatcher
            // to drop the pending entry so the queue doesn't leak.
            let _ = dispatcher.send(DispatchEvent::Timeout {
                request_id: request_num,
            });
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

    'candidates: for (index, candidate) in candidates.iter().enumerate().skip(start_index) {
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
            continue 'candidates;
        };
        // Gemini bakes the upstream model into the URL; substitute the pattern's
        // `{model}` placeholder now that the candidate's target model is known.
        let capability = capabilities::resolve_for_model(capability, target_model);
        let capability = &capability;
        if opencode_seed.is_none() && is_opencode_upstream(&capability.endpoint) {
            opencode_seed = Some(conversation_seed(&request.body));
        }
        // The secret is exposed only here, at the injection point; AuthSchemeMaterial
        // never logs it.
        let credential = crate::providers::AuthSchemeMaterial::new(
            capability.auth_scheme,
            candidate.credential().expose_secret(),
        );
        let key_id = candidate.rest_key();
        let price = match price_cache.get(provider.id, target_model) {
            Some(price) => Some(price),
            None => {
                // A priceless model may be new to models.dev: nudge the catalog
                // keeper (6h-throttled, no-op when no keeper runs).
                crate::prices::missing(target_model);
                None
            }
        };
        // In-place retries of the last candidate (Rate ×3, Other ×2) run inside
        // this loop; the dispatcher slot guard is held across them.
        let mut retried = 0u32;
        // Zhipu GLM passthrough fixup: the 5.x always-thinking models reject
        // `thinking: {"type": "disabled"}` (HTTP 400, code 1210 — "该模型始终思考，
        // 不支持关闭思考；请使用 low、high 或 max"). The field never reaches the
        // wire: prepare omits it for this candidate via the skip list (no body
        // copy). Per candidate: a later non-glm candidate must see the client's
        // original body — it does; the tree is never touched.
        let vendor_skip = vendor_thinking_off_fields(
            &provider.name,
            &provider.base_url,
            target_model,
            protocol,
            capability.protocol,
            &request.body,
        );
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
                caller: request.caller_key.as_deref(),
                agent: request.agent.as_deref(),
                // The Smart verdict computed at dispatch-prep time, read by POSITION in
                // the dispatch order (empty for ordered routes and the resting tail —
                // serialized as null on the wire). Never recomputed here, and never
                // inherited from a ready sibling of the same key: the ready list is a
                // prefix of the dispatch order, so a resting candidate reads past the
                // end and has nothing to inherit.
                reason: reasons.get(index).map_or("", String::as_str),
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
                    alias: alias.as_deref(),
                    protocol: capability.protocol,
                    client_protocol: request.protocol,
                    effort: effort.as_deref(),
                    provider_id: provider.id,
                    provider_key_id: key_id,
                    caller_key,
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
                        vendor_skip,
                        opencode_seed: opencode_seed.as_deref(),
                        fixups,
                        supported_efforts: candidate.supported_efforts.as_deref(),
                        default_effort: candidate.default_effort,
                        route_efforts: efforts.as_deref(),
                        dial: capabilities::effort_dial(&provider.name, target_model),
                        // Only a Kiro candidate touches token state or PG.
                        kiro: (capability.protocol == ProtocolId::Kiro).then_some(KiroDeps {
                            key: &candidate.key,
                            pool,
                            tokens: kiro_tokens,
                        }),
                    },
                    target_model,
                    request,
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
                }) => {
                    let (usage_tx, usage_rx) = tokio::sync::oneshot::channel();
                    let (commit_tx, commit_rx) = tokio::sync::oneshot::channel();
                    let (permit_tx, permit_rx) = tokio::sync::oneshot::channel();
                    // Response-body accumulator, one per streaming attempt (an
                    // aborted attempt's buffer is dropped unread with the outcome).
                    let captured = capture.as_ref().map(|_| CapturedBody::new());
                    let frames = spawn_stream_pump(
                        reader,
                        pump,
                        usage_tx,
                        commit_tx,
                        permit_rx,
                        PumpSide {
                            payload_log: request.payload_log,
                            captured,
                            activity: Some((activity.clone(), seq)),
                            started,
                            request_id: request_id.clone(),
                        },
                    );
                    match commit_rx.await {
                        Ok(HoldSignal::Committed) => {
                            // Locked in: the pump guards the slot for the stream's life.
                            if let Some(slot) = slot.take() {
                                let _ = permit_tx.send(slot);
                            }
                            Ok(AttemptSuccess::Stream {
                                status,
                                frames,
                                usage_rx,
                            })
                        }
                        // A dropped verdict channel means the pump panicked: nothing
                        // reached the client either way, so it reads as an abort.
                        Ok(HoldSignal::Aborted) | Err(_) => {
                            Err(failover::AttemptError::AbortedStream)
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
                    .with_caller(caller_key)
                    .with_agent(agent)
                    .with_client_protocol(request.protocol)
                    .with_effort(effort.as_deref())
                    .with_request_id(&request_id);
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
                }) => {
                    let (finalize_tx, finalize_rx) = tokio::sync::oneshot::channel();
                    // Streaming post-processing: after the pump ends, take usage → account → clear the rest → queue the ledger rows, all in a background task,
                    // so neither the HTTP nor the in-process entry has to duplicate this.
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
                    let agent = agent.map(str::to_owned);
                    let client_protocol = request.protocol;
                    let activity = activity.clone();
                    let stream_request_id = request_id.clone();
                    let mut attempts = std::mem::take(&mut attempts);
                    tokio::spawn(async move {
                        let outcome = usage_rx.await.ok();
                        let ttft_ms = outcome.as_ref().and_then(|outcome| outcome.ttft_ms);
                        let usage = outcome.as_ref().and_then(|outcome| outcome.usage);
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
                            agent,
                            request_id: Some(stream_request_id),
                        };
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
                        frames,
                        finalize: finalize_rx,
                    };
                }
                Err(error) => {
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
                    .with_caller(caller_key)
                    .with_agent(agent)
                    .with_client_protocol(request.protocol)
                    .with_effort(effort.as_deref())
                    .with_request_id(&request_id);
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
                    // Last-candidate in-place retry: the final key in
                    // the chain retries on Rate (up to 3) and Other (up to 2) before the
                    // request fails. Pause: doubling backoff from `retry_pause`,
                    // overridden by Retry-After when present, never beyond 8s or the
                    // request budget. Each try is its own attempt row; the rest and the
                    // counter bump happen once, after the final failure. The permit is
                    // held across the sleeps — releasing it would break FIFO fairness,
                    // at the cost of a queued waiter on a saturated key possibly timing
                    // out (and logging a spurious Timeout row) during the pause.
                    let retries_left = match (failure, is_last) {
                        (failover::Failure::Rate { .. }, true) => 3,
                        (failover::Failure::Other, true) => 2,
                        _ => 0,
                    };
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
                                "last candidate failed ({}), retrying in {}ms ({retried}/{retries_left})",
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
                    let Some(rest_target) = failure.rest_target(consecutive, chrono::Utc::now())
                    else {
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
    let outcome = attempts.last().map(|last| {
        (
            last.status,
            last.error
                .clone()
                .unwrap_or_else(|| "upstream failed".into()),
            retry_after_hint,
        )
    });
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
        // reasons: nobody can serve this protocol (e.g. a responses client with
        // only chat-capable candidates — responses has no translation path).
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
    /// Smart verdict reasons, indexed by candidate index (empty for ordered routes).
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
