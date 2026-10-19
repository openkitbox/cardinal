//! HTTP surface: /health, /v1/messages, /v1/chat/completions, /v1/responses (M4 adds /api/*).

use std::sync::Arc;
use std::time::Instant;

use salvo::affix_state;
use salvo::http::{ParseError, StatusCode, header};
use salvo::prelude::*;
use serde_json::Value;

use crate::protocol::ProtocolId;
use crate::relay::{self, RelayRequest};
use crate::store::GatewayKeyInfo;
use crate::upstream::transport;

/// Shared in-process state.
pub struct AppState {
    pub pool: sqlx::PgPool,
    pub transport: transport::Transport,
    /// Wait for a dispatcher slot assignment before answering 429
    /// ([gateway].queue_timeout_secs; at least one second).
    pub queue_timeout: std::time::Duration,
    /// Failover state: consecutive-failure counters + the last-candidate retry pause.
    pub failover: Arc<relay::Failover>,
    /// Centralized dispatcher for slot assignment.
    pub dispatcher: tokio::sync::mpsc::UnboundedSender<crate::relay::dispatcher::DispatchEvent>,
    /// Routing trace ring (last N dispatches), shared with relay dispatch and
    /// the admin surface.
    pub trace_ring: Arc<relay::trace::TraceRing>,
    /// Diagnostic body ring (shared with relay dispatch and the admin surface).
    pub body_log: crate::body_log::BodyLog,
    /// Live-activity publisher (shared with relay dispatch).
    pub activity: crate::activity::ActivitySink,
    /// In-memory quota snapshots for Smart ordering.
    pub smart_cache: relay::SmartCache,
    /// Per-alias round-robin cursors for Rotate ordering.
    pub rotate_cursors: relay::RotateCursors,
    /// In-memory route/provider/key cache.
    pub route_cache: relay::RouteCache,
    /// In-memory cooldown cache.
    pub rest_cache: relay::RestCache,
    /// In-memory price cache.
    pub price_cache: relay::PriceCache,
    /// Batch ledger writer: relay dispatch queues attempt rows here.
    pub ledger: relay::LedgerWriter,
    /// `[gateway].payloads`: relay mirrors request/response bodies into the log.
    pub payload_log: bool,
    /// `[gateway.privacy]`: masking policy for outbound bodies.
    pub privacy: crate::config::PrivacyConfig,
}

#[handler]
async fn health() -> &'static str {
    "ok"
}

/// `GET /v1/models`: one full standard model object per route (the model ids
/// clients may call), enriched with the attributes derivable from the member
/// keys' model-list snapshots — context window, output cap, input modalities,
/// reasoning effort levels (see [`crate::models`]). Model pickers in clients
/// like omp/opencode can pull it directly.
#[handler]
async fn list_models(depot: &mut Depot, response: &mut Response) {
    let state = depot.get_typed::<Arc<AppState>>().expect("state");
    let routes = state.route_cache.all_routes();
    let keys = state.route_cache.all_key_models();
    let data: Vec<Value> = routes
        .iter()
        .map(|route| crate::models::route_model_object(route, &keys))
        .collect();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/json"),
    );
    let _ = response.body(
        serde_json::to_vec(&serde_json::json!({"object": "list", "data": data}))
            .unwrap_or_default(),
    );
}

fn stream_of(body: &Value) -> bool {
    body.get("stream").and_then(Value::as_bool).unwrap_or(false)
}

/// Common entry point for gateway auth + relay.
///
/// `endpoint_protocol` is determined by the route: /v1/messages = Anthropic, /v1/chat/completions = Chat,
/// /v1/responses = Responses. The handler only does HTTP parsing and rendering; all orchestration lives in
/// The outcome of a bounded request-body read, split so each endpoint can map
/// it onto its own wire dialect (relay uses bare statuses, Gemini a JSON error).
enum BodyRead {
    Ok(Value),
    TooLarge,
    Invalid,
    /// The client did not finish sending the body within `Limits::body_read`.
    Timeout,
}

/// Read the inbound JSON body under two bounds: `max_json_bytes` (size, via
/// salvo's secure max) and `Limits::body_read` (time, via a timeout). The time
/// bound is the guard against a slow or stalled client holding the connection
/// open forever while the request never dispatches — observed on prod behind a
/// tunnel as a request sitting "connecting" for minutes with zero dispatch.
async fn read_json_body(request: &mut Request, state: &AppState) -> BodyRead {
    let limits = state.transport.limits();
    request.set_secure_max_size(limits.max_json_bytes);
    let start = Instant::now();
    match tokio::time::timeout(limits.body_read, request.parse_json::<Value>()).await {
        Ok(Ok(value)) => BodyRead::Ok(value),
        Ok(Err(ParseError::PayloadTooLarge)) => BodyRead::TooLarge,
        Ok(Err(_)) => BodyRead::Invalid,
        Err(_elapsed) => {
            tracing::warn!(
                remote = %request.remote_addr(),
                path = request.uri().path(),
                waited_ms = start.elapsed().as_millis() as u64,
                "request body read timed out; client never finished sending it"
            );
            BodyRead::Timeout
        }
    }
}

/// [`relay::dispatch`].
async fn relay_endpoint(
    request: &mut Request,
    response: &mut Response,
    depot: &mut Depot,
    protocol: ProtocolId,
) {
    let state = depot.get_typed::<Arc<AppState>>().expect("state");
    let body: Value = match read_json_body(request, state.as_ref()).await {
        BodyRead::Ok(value) => value,
        BodyRead::TooLarge => {
            response.status_code(StatusCode::PAYLOAD_TOO_LARGE);
            let _ = response.body("request body too large");
            return;
        }
        BodyRead::Invalid => {
            response.status_code(StatusCode::BAD_REQUEST);
            let _ = response.body("invalid JSON body");
            return;
        }
        BodyRead::Timeout => {
            response.status_code(StatusCode::REQUEST_TIMEOUT);
            let _ = response.body("request body not received in time");
            return;
        }
    };
    relay_dispatch(response, depot, protocol, body, caller_agent(request)).await;
}

/// Which client the request's User-Agent names; None
/// when the header is absent or empty.
fn caller_agent(request: &Request) -> Option<String> {
    let ua = request
        .headers()
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    crate::client::agent_of(ua)
}

/// The parsed-body half of [`relay_endpoint`], shared with the Gemini route
/// (whose model and stream flag arrive in the URL and are folded into the
/// body before dispatch).
async fn relay_dispatch(
    response: &mut Response,
    depot: &mut Depot,
    protocol: ProtocolId,
    body: Value,
    agent: Option<String>,
) {
    let state = depot.get_typed::<Arc<AppState>>().expect("state");
    // The caller identity the gateway_auth hoop verified (absent for a local
    // unidentified caller — the ledger row then records caller_key NULL).
    let caller_key = depot.get::<String>(CALLER_KEY).ok().cloned();
    let request = RelayRequest {
        protocol,
        stream: stream_of(&body),
        body,
        payload_log: state.payload_log,
        caller_key,
        agent,
    };

    let observability = relay::Observability {
        body_log: &state.body_log,
        activity: &state.activity,
    };
    let privacy = state.privacy.policy();
    let deps = relay::DispatchDeps {
        transport: &state.transport,
        queue_timeout: state.queue_timeout,
        dispatcher: &state.dispatcher,
        failover: &state.failover,
        trace_ring: &state.trace_ring,
        smart_cache: &state.smart_cache,
        rotate_cursors: &state.rotate_cursors,
        route_cache: &state.route_cache,
        rest_cache: &state.rest_cache,
        price_cache: &state.price_cache,
        ledger: &state.ledger,
        privacy: &privacy,
    };
    match relay::dispatch(&deps, &observability, request).await {
        relay::DispatchOutcome::Json { status, body } => {
            response.status_code(
                StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            );
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                header::HeaderValue::from_static("application/json"),
            );
            let _ = response.body(body);
        }
        relay::DispatchOutcome::Stream {
            status,
            frames,
            finalize: _,
        } => {
            response.status_code(
                StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            );
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                header::HeaderValue::from_static("text/event-stream"),
            );
            response.headers_mut().insert(
                header::CACHE_CONTROL,
                header::HeaderValue::from_static("no-cache"),
            );
            response.stream(tokio_stream::wrappers::ReceiverStream::new(frames));
            // Return immediately after installing the stream: salvo only hands the
            // Response to hyper once the handler future completes, so awaiting
            // `finalize` here would buffer the whole stream and deadlock the pump
            // once the frame channel (capacity 32) fills up. Usage accounting and
            // persistence run in the pump's trailing background task.
        }
        relay::DispatchOutcome::Failed {
            status,
            message,
            retry_after_secs,
        } => {
            response.status_code(
                StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            );
            if let Some(secs) = retry_after_secs
                && let Ok(value) = header::HeaderValue::from_str(&secs.to_string())
            {
                response.headers_mut().insert(header::RETRY_AFTER, value);
            }
            let _ = response.body(message);
        }
    }
}

#[handler]
async fn messages(request: &mut Request, response: &mut Response, depot: &mut Depot) {
    relay_endpoint(request, response, depot, ProtocolId::AnthropicMessages).await;
}

#[handler]
async fn chat_completions(request: &mut Request, response: &mut Response, depot: &mut Depot) {
    relay_endpoint(request, response, depot, ProtocolId::OpenAiChat).await;
}

#[handler]
async fn responses(request: &mut Request, response: &mut Response, depot: &mut Depot) {
    relay_endpoint(request, response, depot, ProtocolId::OpenAiResponses).await;
}

// ---------- Google Gemini surface (`/v1beta/*`) ----------
//
// Gemini keeps the model and the streaming choice in the URL
// (…/models/{model}:generateContent vs …:streamGenerateContent); the handler
// folds both into the body so the shared relay sees one shape.
// Gemini-shaped errors
// ({"error":{"code","message","status"}}) answer the failures the route
// itself detects.

/// One Gemini-shaped error response (Google's `google.rpc.Status` JSON).
fn gemini_error(
    response: &mut Response,
    status: StatusCode,
    status_name: &str,
    message: impl Into<String>,
) {
    response.status_code(status);
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/json"),
    );
    let body = serde_json::json!({"error": {"code": status.as_u16(), "message": message.into(), "status": status_name}});
    let _ = response.body(serde_json::to_vec(&body).unwrap_or_default());
}

/// `POST /v1beta/models/{**call}` where call = `{model}:{method}`. Model ids
/// may hold a colon, methods never do — the split is at the LAST colon.
/// Unsupported methods (countTokens included — this
/// gateway holds no prompt state to count) are 404, never a guessed answer.
#[handler]
async fn gemini_generate(request: &mut Request, response: &mut Response, depot: &mut Depot) {
    let call = request.param::<String>("call").unwrap_or_default();
    let Some((model, method)) = call.rsplit_once(':') else {
        return gemini_error(
            response,
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "expected /v1beta/models/{model}:generateContent",
        );
    };
    let stream = match method {
        "generateContent" => false,
        "streamGenerateContent" => true,
        other => {
            return gemini_error(
                response,
                StatusCode::NOT_FOUND,
                "NOT_FOUND",
                format!("unknown method {other}"),
            );
        }
    };
    // salvo delivers path params percent-decoded; the `models/` prefix is the
    // resource spelling some clients send whole.
    let model = model.strip_prefix("models/").unwrap_or(model).trim();
    if model.is_empty() {
        return gemini_error(
            response,
            StatusCode::BAD_REQUEST,
            "INVALID_ARGUMENT",
            "model must be a nonempty string",
        );
    }
    let state = depot.get_typed::<Arc<AppState>>().expect("state");
    let mut body: Value = match read_json_body(request, state.as_ref()).await {
        BodyRead::Ok(value) => value,
        BodyRead::TooLarge => {
            return gemini_error(
                response,
                StatusCode::PAYLOAD_TOO_LARGE,
                "INVALID_ARGUMENT",
                "request body too large",
            );
        }
        BodyRead::Invalid => {
            return gemini_error(
                response,
                StatusCode::BAD_REQUEST,
                "INVALID_ARGUMENT",
                "invalid JSON body",
            );
        }
        BodyRead::Timeout => {
            return gemini_error(
                response,
                StatusCode::REQUEST_TIMEOUT,
                "DEADLINE_EXCEEDED",
                "request body not received in time",
            );
        }
    };
    let Some(object) = body.as_object_mut() else {
        return gemini_error(
            response,
            StatusCode::BAD_REQUEST,
            "INVALID_ARGUMENT",
            "expected a JSON object",
        );
    };
    object.insert("model".to_owned(), Value::String(model.to_owned()));
    object.insert("stream".to_owned(), Value::Bool(stream));
    relay_dispatch(
        response,
        depot,
        ProtocolId::Gemini,
        body,
        caller_agent(request),
    )
    .await;
}

/// `GET /v1beta/models`: the route catalog in Google's shape — one entry per
/// route alias, with the token limits derivable from the member keys' model
/// snapshots (same derivation as `/v1/models`; omitted when not derivable).
#[handler]
async fn list_gemini_models(depot: &mut Depot, response: &mut Response) {
    let state = depot.get_typed::<Arc<AppState>>().expect("state");
    let routes = state.route_cache.all_routes();
    let keys = state.route_cache.all_key_models();
    let data: Vec<Value> = routes
        .iter()
        .map(|route| crate::models::gemini_model_object(route, &keys))
        .collect();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/json"),
    );
    let _ =
        response.body(serde_json::to_vec(&serde_json::json!({"models": data})).unwrap_or_default());
}

// ---------- Gateway auth hoop (`/v1/*`) ----------
//
// Gateway auth is an HTTP-surface concern: it reads salvo request headers and
// short-circuits the request, so it lives here, not in the relay layer. The
// caller-key model: multi-source credential extraction, loopback
// leniency, and refusal messages that tell a missing key apart from a wrong
// one — adapted to our hash-at-rest storage (SHA-256 lookup).

/// The depot key under which the hoop stores the caller's identity (the
/// gateway key's label) for the relay handler.
const CALLER_KEY: &str = "caller_key";

/// Headers a proxy or tunnel on this machine adds to a request it passes on:
/// cloudflared (Cf-Connecting-IP, and X-Forwarded-For beside it), ngrok,
/// Tailscale serve/funnel, frp's and Caddy's and nginx's HTTP proxies. An
/// agent calling the gateway directly sends none of them.
const FORWARD_HEADERS: [&str; 6] = [
    "forwarded",
    "x-forwarded-for",
    "x-real-ip",
    "cf-connecting-ip",
    "true-client-ip",
    "tailscale-user-login",
];

/// The API keys a request carries, in read order: Authorization's bearer
/// token, x-api-key, x-goog-api-key, ?key=. A header
/// that carries none ("Authorization: Bearer ", sent beside an x-api-key by a
/// client with no token set) is passed over, and every candidate is tried in
/// turn: a client that sends two different values — a stale or placeholder
/// token in Authorization, the real key in x-api-key — is let in by whichever
/// is a gateway key.
fn caller_keys(request: &Request) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut add = |value: &str| {
        let value = value.trim();
        if !value.is_empty() && !out.iter().any(|key| key == value) {
            out.push(value.to_owned());
        }
    };
    let authorization = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .trim();
    // A bare "Bearer" header value counts as empty; a non-bearer value counts
    // whole. The byte-prefix check guarantees byte 7 is a char
    // boundary before slicing.
    let bytes = authorization.as_bytes();
    let token = if bytes.len() >= 7 && bytes[..7].eq_ignore_ascii_case(b"Bearer ") {
        &authorization[7..]
    } else if authorization.eq_ignore_ascii_case("Bearer") {
        ""
    } else {
        authorization
    };
    add(token);
    for name in ["x-api-key", "x-goog-api-key"] {
        if let Some(value) = request
            .headers()
            .get(name)
            .and_then(|value| value.to_str().ok())
        {
            add(value);
        }
    }
    if let Some(value) = request.queries().get("key") {
        add(value);
    }
    out
}

/// OX_TRUST_PROXY=1: a proxy on this machine authenticates its clients
/// itself, so what it forwards stays local.
fn trust_proxy() -> bool {
    let Ok(value) = std::env::var("OX_TRUST_PROXY") else {
        return false;
    };
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "t" | "true"
    )
}

/// A request from this computer: one that reached the
/// gateway on loopback and was NOT passed on by a proxy or tunnel running
/// here — a forwarding header makes it someone else's, from wherever the
/// proxy reaches (#1022: a Cloudflare Tunnel to 127.0.0.1), so it is treated
/// as remote. OX_TRUST_PROXY disables the forwarding-header check.
///
/// Also the admin surface's gate: `/api/*` is loopback-only (see admin.rs).
pub(crate) fn is_local(request: &Request) -> bool {
    // A non-IP peer (a unix socket) is never loopback: treated as remote.
    // to_canonical unmaps IPv4-mapped IPv6 (::ffff:127.0.0.1) so a dual-stack
    // listener still recognizes a genuinely local client.
    if !request
        .remote_addr()
        .ip()
        .is_some_and(|ip| ip.to_canonical().is_loopback())
    {
        return false;
    }
    trust_proxy()
        || !FORWARD_HEADERS.iter().any(|name| {
            request
                .headers()
                .get(*name)
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| !value.is_empty())
        })
}

/// Authenticate one candidate key: plaintext against gateway_keys.
async fn authenticate(pool: &sqlx::PgPool, key: &str) -> anyhow::Result<Option<GatewayKeyInfo>> {
    crate::store::gateway_key_info(pool, key).await
}

/// Why a caller was turned away: no credential
/// came, or the one that came is no gateway key — named by its last four
/// characters, and only when long enough that naming it doesn't give most of
/// it away. A value containing a space is a whole non-Bearer Authorization
/// header (e.g. `Basic dXNlcg==`) — it stays a candidate (a
/// bare key in Authorization works), but its tail is never named, since that
/// tail belongs to another scheme's credential. When several candidates came
/// and all failed, the first is named.
fn refused_key(key: Option<&str>) -> String {
    let Some(key) = key else {
        return "no API key was sent: send a gateway key as Authorization: Bearer <key> (or x-api-key)".to_owned();
    };
    if key.chars().count() >= 12 && !key.contains(' ') {
        let tail: String = key
            .chars()
            .rev()
            .take(4)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        format!("the API key ending in …{tail} is not a gateway key: it was removed or mistyped")
    } else {
        "the API key sent is not a gateway key: it was removed or mistyped".to_owned()
    }
}

/// Caller-key verification: every credential
/// candidate is tried against gateway_keys and the FIRST match wins (a stale
/// Authorization beside a correct x-api-key still gets in).
///
/// Caller identity ("the client a request came from is the one its token
/// names"): a key whose VALUE carries the `cardinal-` prefix
/// self-names its client (`cardinal-cherry` → the request is cherry's) — a
/// name is presentation, not access, so it attaches wherever the request is
/// allowed: a registered key passes and self-names when its value has the
/// prefix (else falls back to its stored label); an unregistered loopback
/// request passes and may self-name the same way; a remote or proxied one
/// gets a 401 regardless of what it calls itself — naming never opens a
/// door. A DB failure is not an auth failure: 503, so monitoring can tell
/// the two apart.
#[handler]
async fn gateway_auth(
    request: &mut Request,
    response: &mut Response,
    depot: &mut Depot,
    ctrl: &mut FlowCtrl,
) {
    let state = depot.get_typed::<Arc<AppState>>().expect("state");
    let pool = state.pool.clone();
    let candidates = caller_keys(request);
    let mut info: Option<GatewayKeyInfo> = None;
    for candidate in &candidates {
        match authenticate(&pool, candidate).await {
            Ok(found) => {
                info = found;
                if info.is_some() {
                    break;
                }
            }
            Err(error) => {
                tracing::warn!("gateway key lookup failed: {error}");
                response.status_code(StatusCode::SERVICE_UNAVAILABLE);
                let _ = response.body("gateway key lookup failed");
                ctrl.skip_rest();
                return;
            }
        }
    }

    // User-Agent agent — read for the caller-identity fallback below; the
    // ledger/feed `agent` column is filled separately at dispatch time.
    let agent = caller_agent(request);

    if let Some(info) = info {
        if !info.enabled {
            let reason = format!("the API key '{}' is disabled", info.label);
            tracing::info!(
                "refused {} {} from {}: {reason}",
                request.method(),
                request.uri().path(),
                request.remote_addr()
            );
            response.status_code(StatusCode::UNAUTHORIZED);
            let _ = response.body(reason);
            ctrl.skip_rest();
            return;
        }
        // Registered key: the caller is its label (chosen by the owner) —
        // never the raw key value.
        depot.insert(CALLER_KEY, info.label.clone());
        // Fire-and-forget: update last_used_at.
        let pool = pool.clone();
        let id = info.id;
        tokio::spawn(async move {
            crate::store::touch_gateway_key(&pool, id).await;
        });
        return;
    }
    // Loopback without a proxy's forwarding headers is this computer itself:
    // let it through — carrying its self-asserted name when the key value
    // offered one (`cardinal-alma` → `alma`), else the client name, else
    // without identity (normal operation, not logged).
    if is_local(request) {
        let named = candidates
            .iter()
            .find_map(|candidate| candidate.strip_prefix("cardinal-"))
            .filter(|rest| !rest.is_empty());
        if let Some(name) = named {
            depot.insert(CALLER_KEY, name.to_string());
        } else if let Some(agent) = agent {
            depot.insert(CALLER_KEY, agent);
        }
        return;
    }
    let reason = refused_key(candidates.first().map(String::as_str));
    // The access Logger already logs the request line; this adds WHY it was refused.
    tracing::info!(
        "refused {} {} from {}: {reason}",
        request.method(),
        request.uri().path(),
        request.remote_addr()
    );
    response.status_code(StatusCode::UNAUTHORIZED);
    let _ = response.body(reason);
    ctrl.skip_rest();
}

pub fn router(
    state: Arc<AppState>,
    admin_key: Arc<crate::admin::AdminKey>,
    admin_remote: Arc<crate::admin::AdminRemote>,
) -> Router {
    Router::new()
        .hoop(crate::access_log::AccessLog)
        .push(Router::with_path("health").get(health))
        .push(
            Router::with_path("v1")
                .hoop(gateway_auth)
                .push(Router::with_path("models").get(list_models))
                .push(Router::with_path("messages").post(messages))
                .push(Router::with_path("chat/completions").post(chat_completions))
                .push(Router::with_path("responses").post(responses)),
        )
        .push(
            Router::with_path("v1beta")
                .hoop(gateway_auth)
                .push(Router::with_path("models").get(list_gemini_models))
                .push(Router::with_path("models/{**call}").post(gemini_generate)),
        )
        .push(crate::admin::router(admin_key, admin_remote))
        .hoop(affix_state::inject(state))
}
