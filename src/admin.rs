//! Admin API: `/api/*`, authenticated with the admin key (SHA-256 of config.gateway_key).
//!
//! Endpoints:
//! - `GET/POST /api/providers`, `GET/PATCH/DELETE /api/providers/:id` — provider = protocol + endpoint (+ auth scheme), no credential
//! - `GET/POST /api/providers/:id/keys`, `PATCH/DELETE /api/providers/:id/keys/:key_id` — every credential is a named key
//! - `GET /api/providers/:id/keys/:key_id/reveal` — the full KeyView, plaintext credential included (the ONLY
//!   plaintext-serving endpoint; the list shape stays masked)
//! - `PUT /api/keys/order` `{ids: [..]}` — assign global positions sequentially in array order (one transaction)
//! - `POST /api/keys/validate` `{name, protocol, base_url, auth_scheme?, enabled?, api_key}` — probe a not-yet-saved credential
//! - `GET/PUT /api/keys/:id/models` — a key's model list: GET re-probes the provider, PUT persists a list as the snapshot
//! - `GET /api/routes`, `GET/PUT/DELETE /api/routes/:alias` — route = named key subset exposed to clients as a model id;
//!   PUT body `{entries: [{key_id, model}], context_window?, strategy?}` (`strategy` = `ordered`|`smart`|`rotate`, absent = `ordered`;
//!   400 when the body is malformed or a referenced key does not exist). PUT is a full
//!   replace: a strategy-preserving client MUST send it back, or the save resets to `ordered`
//! - `GET /api/rests`, `DELETE /api/rests/keys/:key_id`, `DELETE /api/rests/providers/:provider_id` — cooldowns, identity = key
//! - `GET /api/usage?days=N` (aggregated by day × alias; `caller` restricts to one caller identity, `caller=null` = unidentified)
//! - `GET /api/usage/trend?since&until&split&offset_seconds` (bucket × category aggregates for the trend chart; `caller` as above)
//! - `GET /api/usage/window?since&until` (whole-window aggregate behind the KPI cards; `caller` as above)
//! - `GET /api/requests?limit=N` (recent requests)
//! - `GET /api/requests/:id/bodies` (captured request/response bodies from the hourly payload files)
//! - `GET /api/chat-models` (the chat picker's model list: route aliases + probed direct entries)
//! - `GET /api/concurrency` (per-key live occupancy for concurrency-capped keys)
//! - `GET /api/quotas` (LIVE per-key vendor quota probing — outbound side effect) / `GET /api/quota-snapshots` (the stored readings)
//! - `GET /api/bootstrap` — every parameterless read the status pages render from, as one document (also the activity stream's connect frame)
//! - `GET /api/activity` (SSE live attempt feed: ActivityEvent frames + keep-alive)
//! - `GET /api/traces`, `GET /api/traces/:request_id` — recent routing traces from the dispatch trace ring
//!   (newest first, capped at the ring's capacity; transient — nothing is persisted)

use std::sync::Arc;

use salvo::affix_state;
use salvo::http::{StatusCode, header};
use salvo::prelude::*;
use salvo::sse::SseEvent;
use serde::Deserialize;
use serde_json::json;

use crate::agent;
use crate::store::{self, ProviderInput, RouteEntry, RouteStrategy};

/// Admin key SHA-256 (shared in-process, injected by main from config).
pub struct AdminKey(pub String);

/// Whether the admin API accepts non-loopback requests.
pub struct AdminRemote(pub bool);

/// Admin locality gate (P1-4): the management surface is loopback-only unless
/// `[gateway].admin_remote` is set. Post-split the GUI is the primary HTTP
/// client of these endpoints (over loopback), alongside same-machine
/// scripting. Handing a relay key to a third-party agent must not hand them
/// the admin plane, so a request that isn't local (loopback with no
/// forwarding headers) is refused before the key is even
/// looked at — unless the operator explicitly opted into remote admin.
#[handler]
async fn admin_local_only(
    request: &mut Request,
    response: &mut Response,
    depot: &mut Depot,
    ctrl: &mut FlowCtrl,
) {
    let remote = depot
        .get_typed::<Arc<AdminRemote>>()
        .map(|r| r.0)
        .unwrap_or(false);
    if remote || crate::api::is_local(request) {
        return;
    }
    response.status_code(StatusCode::FORBIDDEN);
    let _ = response.body(
        "admin API is loopback-only (set [gateway].admin_remote = true to allow remote access)",
    );
    ctrl.skip_rest();
}

/// Admin auth: `Authorization: Bearer <gateway_key>` with constant-time comparison.
#[handler]
async fn admin_auth(
    request: &mut Request,
    response: &mut Response,
    depot: &mut Depot,
    ctrl: &mut FlowCtrl,
) {
    let Ok(key) = depot.get_typed::<Arc<AdminKey>>() else {
        response.status_code(StatusCode::INTERNAL_SERVER_ERROR);
        let _ = response.body("admin key not configured");
        ctrl.skip_rest();
        return;
    };
    let expected = key.0.clone();
    let provided = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim)
        .unwrap_or_default();
    if provided.is_empty() {
        response.status_code(StatusCode::UNAUTHORIZED);
        let _ = response.body("missing admin key");
        ctrl.skip_rest();
        return;
    }
    // Both sides hashed with SHA-256 so the comparison is constant-time.
    if constant_time_eq(
        &crate::db::sha256_hex(provided),
        &crate::db::sha256_hex(&expected),
    ) {
        return;
    }
    response.status_code(StatusCode::UNAUTHORIZED);
    let _ = response.body("invalid admin key");
    ctrl.skip_rest();
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes()
        .zip(b.bytes())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

fn state(depot: &Depot) -> &Arc<crate::api::AppState> {
    depot
        .get_typed::<Arc<crate::api::AppState>>()
        .expect("app state injected")
}

fn state_pool(depot: &Depot) -> &sqlx::PgPool {
    &state(depot).pool
}

/// Assemble the facade from the shared AppState: the registries are the live
/// relay's own, so occupancy reads live values and clearing a rest forgives
/// the live streak. The facade is cheap to construct (a pool clone plus Arc
/// bumps), so handlers build it per request.
fn admin(depot: &Depot) -> crate::admin_ops::Admin {
    // TODO: same as state_pool; change the hot-path expect to returning 500 later.
    let state = depot
        .get_typed::<Arc<crate::api::AppState>>()
        .expect("app state injected");
    crate::admin_ops::Admin::new(
        state.pool.clone(),
        state.transport.limits().allow_private_destinations,
        Arc::clone(&state.failover),
        state.smart_cache.clone(),
        state.route_cache.clone(),
        state.rest_cache.clone(),
        state.activity.clone(),
    )
    .with_dispatcher(state.dispatcher.clone())
}

/// Save-time endpoint validation: same source as the send-time policy (`Transport`'s limits);
/// obviously invalid or internal base_urls are rejected before persistence.
/// Hardcoded-capability vendors additionally keep their base_url contract
/// (version root, never a protocol leaf — see relay::capabilities).
fn validate_base_url(depot: &Depot, name: &str, base_url: &str, response: &mut Response) -> bool {
    // TODO: same as state_pool; change the hot-path expect to returning 500 later.
    let state = depot
        .get_typed::<Arc<crate::api::AppState>>()
        .expect("app state injected");
    let allow_private = state.transport.limits().allow_private_destinations;
    let result = crate::upstream::transport::validate_saved_endpoint(base_url, allow_private)
        .and_then(|()| crate::relay::capabilities::validate_base_url(name, base_url));
    match result {
        Ok(()) => true,
        Err(error) => {
            response.status_code(StatusCode::BAD_REQUEST);
            let _ = response.body(format!("{error:#}"));
            false
        }
    }
}

fn json_response<T: serde::Serialize>(response: &mut Response, value: &T) {
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/json"),
    );
    let _ = response.body(serde_json::to_vec(value).unwrap_or_default());
}

// ---------- providers ----------

/// The catalog-spec fields shared by the provider create/update body and the
/// key-validate body (a provider's protocol + endpoint + auth shape, before
/// any credential). Flattened into both.
#[derive(Deserialize)]
struct ProviderSpecBody {
    name: String,
    protocol: String,
    base_url: String,
    #[serde(default)]
    auth_scheme: Option<String>,
    #[serde(default = "default_true")]
    enabled: bool,
}

impl ProviderSpecBody {
    fn input(&self) -> ProviderInput<'_> {
        ProviderInput {
            name: &self.name,
            protocol: &self.protocol,
            base_url: &self.base_url,
            auth_scheme: self.auth_scheme.as_deref(),
            enabled: self.enabled,
        }
    }
}

#[derive(Deserialize)]
struct ProviderBody {
    #[serde(flatten)]
    spec: ProviderSpecBody,
}

fn default_true() -> bool {
    true
}

#[handler]
async fn list_providers(depot: &mut Depot, response: &mut Response) {
    let pool = state_pool(depot);
    match store::list_providers(pool).await {
        Ok(rows) => json_response(response, &rows),
        Err(error) => internal(response, error),
    }
}

#[handler]
async fn create_provider(request: &mut Request, depot: &mut Depot, response: &mut Response) {
    let pool = state_pool(depot);
    let Ok(body) = request.parse_json::<ProviderBody>().await else {
        response.status_code(StatusCode::BAD_REQUEST);
        let _ = response.body("invalid provider body");
        return;
    };
    if !validate_base_url(depot, &body.spec.name, &body.spec.base_url, response) {
        return;
    }
    match store::insert_provider(pool, &body.spec.input()).await {
        Ok(id) => {
            let _ = state(depot).route_cache.refresh(pool).await;
            response.status_code(StatusCode::CREATED);
            json_response(response, &json!({"id": id}));
        }
        Err(error) => bad_request(response, error),
    }
}

#[handler]
async fn get_provider(request: &mut Request, depot: &mut Depot, response: &mut Response) {
    let pool = state_pool(depot);
    let Some(id) = request.param::<i64>("id") else {
        response.status_code(StatusCode::BAD_REQUEST);
        let _ = response.body("bad id");
        return;
    };
    match store::get_provider(pool, id).await {
        Ok(Some(row)) => json_response(response, &row),
        Ok(None) => not_found(response, "provider"),
        Err(error) => internal(response, error),
    }
}

#[handler]
async fn update_provider(request: &mut Request, depot: &mut Depot, response: &mut Response) {
    let pool = state_pool(depot);
    let Some(id) = request.param::<i64>("id") else {
        response.status_code(StatusCode::BAD_REQUEST);
        let _ = response.body("bad id");
        return;
    };
    let Ok(body) = request.parse_json::<ProviderBody>().await else {
        response.status_code(StatusCode::BAD_REQUEST);
        let _ = response.body("invalid provider body");
        return;
    };
    if !validate_base_url(depot, &body.spec.name, &body.spec.base_url, response) {
        return;
    }
    match store::update_provider(pool, id, &body.spec.input()).await {
        Ok(true) => {
            let _ = state(depot).route_cache.refresh(pool).await;
            json_response(response, &json!({"ok": true}))
        }
        Ok(false) => not_found(response, "provider"),
        Err(error) => bad_request(response, error),
    }
}

#[handler]
async fn delete_provider(request: &mut Request, depot: &mut Depot, response: &mut Response) {
    let pool = state_pool(depot);
    let Some(id) = request.param::<i64>("id") else {
        response.status_code(StatusCode::BAD_REQUEST);
        let _ = response.body("bad id");
        return;
    };
    match store::delete_provider(pool, id).await {
        Ok(true) => {
            let _ = state(depot).route_cache.refresh(pool).await;
            json_response(response, &json!({"ok": true}))
        }
        Ok(false) => not_found(response, "provider"),
        Err(error) => internal(response, error),
    }
}

// ---------- routes ----------

#[derive(Deserialize)]
struct RouteBody {
    entries: Vec<RouteEntry>,
    #[serde(default)]
    context_window: Option<i64>,
    /// Old clients omitting the field apply the `ordered` default — re-saving
    /// a smart route from an old client resets it to ordered (fixed when the
    /// GUI learns the field).
    #[serde(default)]
    strategy: RouteStrategy,
    /// Admin-facing display note; absent/empty on old clients clears it.
    #[serde(default)]
    note: Option<String>,
}

/// The 400 body for a malformed `PUT /api/routes/{alias}`. An unknown
/// `strategy` string fails [`RouteBody`]'s typed deserialization (serde
/// rejects any variant but `ordered`/`smart`), so the message names the
/// accepted values — same posture as `usage_trend`'s split hint. Kept as a
/// const so the test that pins this exact body
/// (`route_api_tests::unknown_strategy_is_rejected_with_400`) shares one
/// source of truth — the only extracted 400 message in this file.
const INVALID_ROUTE_BODY: &str = "invalid route body (expected {entries: [...], context_window?, strategy? = ordered, smart, or rotate})";

#[handler]
async fn list_routes(depot: &mut Depot, response: &mut Response) {
    let pool = state_pool(depot);
    match store::list_routes(pool).await {
        Ok(rows) => json_response(response, &rows),
        Err(error) => internal(response, error),
    }
}

#[handler]
async fn get_route(request: &mut Request, depot: &mut Depot, response: &mut Response) {
    let pool = state_pool(depot);
    let alias = request.param::<String>("alias").unwrap_or_default();
    match store::get_route(pool, &alias).await {
        Ok(Some(row)) => json_response(response, &row),
        Ok(None) => not_found(response, "route"),
        Err(error) => internal(response, error),
    }
}

#[handler]
async fn put_route(request: &mut Request, depot: &mut Depot, response: &mut Response) {
    let pool = state_pool(depot);
    let alias = request.param::<String>("alias").unwrap_or_default();
    let Ok(body) = request.parse_json::<RouteBody>().await else {
        response.status_code(StatusCode::BAD_REQUEST);
        let _ = response.body(INVALID_ROUTE_BODY);
        return;
    };
    match store::put_route(
        pool,
        &alias,
        &body.entries,
        body.context_window,
        body.strategy,
        body.note,
    )
    .await
    {
        Ok(()) => {
            let _ = state(depot).route_cache.refresh(pool).await;
            json_response(response, &json!({"ok": true}))
        }
        Err(error) => bad_request(response, error),
    }
}

#[handler]
async fn delete_route(request: &mut Request, depot: &mut Depot, response: &mut Response) {
    let pool = state_pool(depot);
    let alias = request.param::<String>("alias").unwrap_or_default();
    match store::delete_route(pool, &alias).await {
        Ok(true) => {
            let _ = state(depot).route_cache.refresh(pool).await;
            json_response(response, &json!({"ok": true}))
        }
        Ok(false) => not_found(response, "route"),
        Err(error) => internal(response, error),
    }
}

// ---------- usage / requests ----------

#[derive(Deserialize)]
struct UsageQuery {
    #[serde(default = "default_days")]
    days: i32,
    #[serde(default)]
    caller: Option<String>,
}

fn default_days() -> i32 {
    7
}

/// Usage aggregated by day × alias.
#[handler]
async fn usage(request: &mut Request, depot: &mut Depot, response: &mut Response) {
    let pool = state_pool(depot);
    let query = request.parse_queries::<UsageQuery>().unwrap_or(UsageQuery {
        days: default_days(),
        caller: None,
    });
    let days = query.days.clamp(1, 365);
    let caller = caller_filter(query.caller);
    match store::usage_by_day(pool, days, caller_ref(&caller)).await {
        Ok(rows) => json_response(response, &json!({ "days": days, "items": rows })),
        Err(error) => internal(response, error),
    }
}

/// Resolve the shared window bounds of the usage aggregations: RFC3339
/// `since`/`until`, with `days` as a rolling fallback for `since` (default:
/// the last 7 days, clamped to 1..=365 — the GUI's 7 天 preset). `until`
/// defaults to now. Both usage endpoints resolve their window through this
/// one function. (The bounds stay literal fields on each query struct:
/// salvo's query deserializer cannot drive `#[serde(flatten)]` — a flattened
/// struct buffers every value as a string, breaking the typed i32/DateTime
/// fields. Only the resolution logic is shared.)
fn resolve_window(
    since: Option<chrono::DateTime<chrono::Utc>>,
    until: Option<chrono::DateTime<chrono::Utc>>,
    days: Option<i32>,
) -> (chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>) {
    let until = until.unwrap_or_else(chrono::Utc::now);
    let since = match since {
        Some(since) => since,
        None => until - chrono::Duration::days(i64::from(days.unwrap_or(7).clamp(1, 365))),
    };
    (since, until)
}

/// Query form of `GET /api/usage/trend`. `split` is the category dimension
/// (route|model|provider, default route); `offset_seconds` shifts bucket
/// labels to the caller's wall clock (the GUI passes its local offset);
/// `caller` restricts to one caller identity (`null` = unidentified 本机
/// rows, anything else = a gateway key label / self-named caller).
/// Window bounds resolve via [`resolve_window`].
#[derive(Deserialize)]
struct TrendQuery {
    #[serde(default)]
    since: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default)]
    until: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default)]
    days: Option<i32>,
    #[serde(default)]
    split: Option<store::TrendSplit>,
    #[serde(default)]
    offset_seconds: Option<i64>,
    #[serde(default)]
    caller: Option<String>,
}

/// Usage aggregated by bucket × category for the trend chart; mirrors
/// [`crate::admin_ops::Admin::usage_trend`] (span capped at ~a year; hourly
/// buckets up to a ~25-hour span, else daily).
#[handler]
async fn usage_trend(request: &mut Request, depot: &mut Depot, response: &mut Response) {
    let admin = admin(depot);
    let query = match request.parse_queries::<TrendQuery>() {
        Ok(query) => query,
        Err(_) => {
            response.status_code(StatusCode::BAD_REQUEST);
            let _ = response.body("invalid trend query (since/until as RFC3339, split = route|model|provider|client, offset_seconds)");
            return;
        }
    };
    let (since, until) = resolve_window(query.since, query.until, query.days);
    let split = query.split.unwrap_or(store::TrendSplit::Route);
    // Clamp the wall-clock shift: ±14h covers every real time zone, and
    // Duration::seconds panics on extreme values (i64::MAX overflows the
    // TimeDelta) — reject out-of-range shifts instead of dying. unsigned_abs
    // because abs() itself overflows at i64::MIN (release: wraps negative and
    // bypasses the clamp; debug: negate-overflow panic).
    const MAX_OFFSET_SECONDS: i64 = 14 * 3600;
    let offset_seconds = query.offset_seconds.unwrap_or(0);
    if offset_seconds.unsigned_abs() > MAX_OFFSET_SECONDS as u64 {
        response.status_code(StatusCode::BAD_REQUEST);
        let _ = response.body("offset_seconds must be within ±14 hours");
        return;
    }
    let offset = chrono::Duration::seconds(offset_seconds);
    let caller = caller_filter(query.caller);
    match admin
        .usage_trend(since, until, split, offset, caller_ref(&caller))
        .await
    {
        Ok(rows) => json_response(response, &json!({ "items": rows })),
        Err(error) => internal(response, error),
    }
}

/// The `caller` query parameter's store form: the reserved value `null`
/// selects unidentified callers, any other value is a caller identity label.
fn caller_filter(caller: Option<String>) -> Option<(store::CallerFilter, String)> {
    caller.map(|value| {
        if value == "null" {
            (store::CallerFilter::Null, String::new())
        } else {
            (store::CallerFilter::Label, value)
        }
    })
}

/// Borrowed form of a [`caller_filter`] result, for store calls taking `&str`.
fn caller_ref(
    filter: &Option<(store::CallerFilter, String)>,
) -> Option<(store::CallerFilter, &str)> {
    filter.as_ref().map(|(kind, label)| (*kind, label.as_str()))
}

/// Query form of `GET /api/usage/window` — window bounds plus the optional
/// `caller` restriction (same spelling as [`TrendQuery`]), resolved via
/// [`resolve_window`].
#[derive(Deserialize)]
struct WindowQuery {
    #[serde(default)]
    since: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default)]
    until: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default)]
    days: Option<i32>,
    #[serde(default)]
    caller: Option<String>,
}

/// Whole-window usage aggregates behind the KPI cards; mirrors
/// [`crate::admin_ops::Admin::usage_window`].
#[handler]
async fn usage_window(request: &mut Request, depot: &mut Depot, response: &mut Response) {
    let admin = admin(depot);
    let query = match request.parse_queries::<WindowQuery>() {
        Ok(query) => query,
        Err(_) => {
            response.status_code(StatusCode::BAD_REQUEST);
            let _ = response.body("invalid window query (since/until as RFC3339)");
            return;
        }
    };
    let (since, until) = resolve_window(query.since, query.until, query.days);
    let caller = caller_filter(query.caller);
    match admin.usage_window(since, until, caller_ref(&caller)).await {
        Ok(window) => json_response(response, &window),
        Err(error) => internal(response, error),
    }
}

#[derive(Deserialize)]
struct RequestsQuery {
    #[serde(default = "default_limit")]
    limit: i64,
    /// Cursor: only rows with a smaller id (older than this row) are returned.
    #[serde(default)]
    before_id: Option<i64>,
}

fn default_limit() -> i64 {
    50
}

#[handler]
async fn recent_requests(request: &mut Request, depot: &mut Depot, response: &mut Response) {
    let pool = state_pool(depot);
    let query = request
        .parse_queries::<RequestsQuery>()
        .unwrap_or(RequestsQuery {
            limit: default_limit(),
            before_id: None,
        });
    let limit = query.limit.clamp(1, 500);
    match store::list_recent_requests(pool, limit, query.before_id).await {
        // The Row serializes with exactly these fields (key_label included — the
        // LEFT JOIN selects it into the row); keep the wire the Row itself.
        Ok(rows) => json_response(response, &json!({ "items": rows })),
        Err(error) => internal(response, error),
    }
}

/// `GET /api/requests/model-success`: latest successful request time per
/// (key, served model) — the routes stage's "上次成功" markers.
#[handler]
async fn model_success(depot: &mut Depot, response: &mut Response) {
    let pool = state_pool(depot);
    match store::last_model_success(pool).await {
        Ok(rows) => json_response(response, &json!({ "items": rows })),
        Err(error) => internal(response, error),
    }
}

// ---------- gateway key management ----------

#[derive(Deserialize)]
struct GatewayKeyCreateBody {
    label: String,
}

/// `POST /api/gateway-keys`: create a new gateway key. Returns the plaintext
/// key exactly once — it is stored as its SHA-256 hash and cannot be retrieved.
#[handler]
async fn create_gateway_key(request: &mut Request, depot: &mut Depot, response: &mut Response) {
    let pool = state_pool(depot);
    let body: GatewayKeyCreateBody = match request.parse_json().await {
        Ok(body) => body,
        Err(_) => {
            response.status_code(StatusCode::BAD_REQUEST);
            json_response(response, &json!({ "error": "invalid JSON body" }));
            return;
        }
    };
    if body.label.trim().is_empty() {
        response.status_code(StatusCode::BAD_REQUEST);
        json_response(response, &json!({ "error": "label is required" }));
        return;
    }
    // created_by: the admin caller's identity if available (from CALLER_KEY depot).
    let created_by = depot.get_typed::<String>().ok().map(|s| s.as_str());
    match store::create_gateway_key(pool, body.label.trim(), created_by).await {
        Ok(key) => json_response(response, &json!({ "key": key })),
        Err(error) => internal(response, error),
    }
}

/// `GET /api/gateway-keys`: list all gateway keys (hash truncated for display).
#[handler]
async fn list_gateway_keys(depot: &mut Depot, response: &mut Response) {
    let pool = state_pool(depot);
    match store::list_gateway_keys(pool).await {
        Ok(rows) => json_response(response, &json!({ "items": rows })),
        Err(error) => internal(response, error),
    }
}

#[derive(Deserialize)]
struct GatewayKeyPatchBody {
    enabled: bool,
}

/// `PATCH /api/gateway-keys/{id}`: enable or disable a gateway key.
#[handler]
async fn patch_gateway_key(request: &mut Request, depot: &mut Depot, response: &mut Response) {
    let pool = state_pool(depot);
    let Some(id) = request.param::<i64>("id") else {
        response.status_code(StatusCode::BAD_REQUEST);
        json_response(response, &json!({ "error": "missing id" }));
        return;
    };
    let body: GatewayKeyPatchBody = match request.parse_json().await {
        Ok(body) => body,
        Err(_) => {
            response.status_code(StatusCode::BAD_REQUEST);
            json_response(response, &json!({ "error": "invalid JSON body" }));
            return;
        }
    };
    match store::set_gateway_key_enabled(pool, id, body.enabled).await {
        Ok(true) => json_response(response, &json!({ "ok": true })),
        Ok(false) => {
            response.status_code(StatusCode::NOT_FOUND);
            json_response(response, &json!({ "error": "key not found" }));
        }
        Err(error) => internal(response, error),
    }
}

/// `GET /api/requests/{id}/bodies`: the captured request/response bodies of
/// one row from the hourly payload files, or 404 when the row was never
/// captured (payloads off) or predates the files still on disk. Captures are
/// keyed by the dispatch request id (`req_{n}` — the ledger writer batches
/// inserts, so the row id is unknown at capture time); rows persisted before
/// the batch writer shipped (or by older builds) have no request id and can
/// no longer be matched — the 404 then covers them.
#[handler]
async fn request_bodies(request: &mut Request, depot: &mut Depot, response: &mut Response) {
    let Some(id) = request.param::<i64>("id") else {
        response.status_code(StatusCode::BAD_REQUEST);
        json_response(response, &json!({ "error": "invalid request id" }));
        return;
    };
    // TODO: same as state_pool; change the hot-path expect to returning 500 later.
    let state = depot
        .get_typed::<Arc<crate::api::AppState>>()
        .expect("app state injected");
    // The capture lands in the hour file of when it started; the row's ledger
    // time anchors the scan (±1h covers a capture straddling a boundary).
    let bodies = match store::request_row_anchor(&state.pool, id).await {
        Ok(Some((created_at, Some(request_id)))) => {
            state.body_log.get_near(&request_id, created_at)
        }
        _ => None,
    };
    match bodies {
        Some(bodies) => json_response(response, &bodies),
        None => {
            response.status_code(StatusCode::NOT_FOUND);
            json_response(
                response,
                &json!({ "error": format!("no captured bodies for request {id}") }),
            );
        }
    }
}

// ---------- keys: validate & model snapshots ----------

/// `POST /api/keys/validate` body: the provider's catalog spec plus the
/// credential to probe — the same pair the GUI's add-account form hands to
/// [`crate::admin_ops::Admin::validate_key`].
#[derive(Deserialize)]
struct ValidateKeyBody {
    #[serde(flatten)]
    spec: ProviderSpecBody,
    api_key: String,
}

/// Validate a not-yet-saved key against its provider's model list (the fetch
/// proves the key authenticates; the returned ids are what the route editor
/// offers for picking). No provider row needs to exist yet. 400 = malformed
/// body / endpoint validation; 502 = the upstream probe itself failed (the
/// vendor rejected the credential, DNS, timeout).
#[handler]
async fn validate_key(request: &mut Request, depot: &mut Depot, response: &mut Response) {
    let Ok(body) = request.parse_json::<ValidateKeyBody>().await else {
        response.status_code(StatusCode::BAD_REQUEST);
        let _ = response.body("invalid validate body (expected {name, protocol, base_url, auth_scheme?, enabled?, api_key})");
        return;
    };
    match admin(depot)
        .validate_key(&body.spec.input(), &body.api_key)
        .await
    {
        Ok(models) => json_response(response, &models),
        // A probe failure is the upstream's answer, not a client error;
        // endpoint-validation failures stay 400.
        Err(error) if try_bad_gateway(response, &error) => {}
        Err(error) => bad_request(response, error),
    }
}

/// `GET /api/keys/{id}/models`: re-probe a saved key's model list; a
/// successful probe also refreshes the persisted snapshot (the /v1/models
/// route-object derivation reads it). NOT a pure read — an outbound probe to
/// the provider's model endpoint. 404 = no such key; 502 = the upstream
/// probe failed.
#[handler]
async fn list_key_models(request: &mut Request, depot: &mut Depot, response: &mut Response) {
    let Some(id) = request.param::<i64>("id") else {
        response.status_code(StatusCode::BAD_REQUEST);
        let _ = response.body("bad id");
        return;
    };
    match admin(depot).list_key_models(id).await {
        Ok(models) => json_response(response, &models),
        Err(error)
            if error
                .downcast_ref::<crate::admin_ops::NoSuchKey>()
                .is_some() =>
        {
            not_found(response, "key")
        }
        Err(error) if try_bad_gateway(response, &error) => {}
        // Store failure, orphaned provider row, credential-less key: server-side.
        Err(error) => internal(response, error),
    }
}

/// `PUT /api/keys/{id}/models` body: a freshly validated model list (the
/// add-account flow stores it right after the key row exists, without a
/// second upstream probe).
#[derive(Deserialize)]
struct KeyModelsBody {
    models: Vec<crate::probe::ProbeModel>,
}

/// Persist a key's model-list snapshot (from a prior validation probe). 404
/// when no such key row exists (the update's rows-affected is checked, same
/// as delete_route).
#[handler]
async fn save_key_models(request: &mut Request, depot: &mut Depot, response: &mut Response) {
    let Some(id) = request.param::<i64>("id") else {
        response.status_code(StatusCode::BAD_REQUEST);
        let _ = response.body("bad id");
        return;
    };
    let Ok(body) = request.parse_json::<KeyModelsBody>().await else {
        response.status_code(StatusCode::BAD_REQUEST);
        let _ = response.body("invalid key models body (expected {models: [ProbeModel..]})");
        return;
    };
    match admin(depot).save_key_models(id, &body.models).await {
        Ok(true) => json_response(response, &json!({"ok": true})),
        Ok(false) => not_found(response, "key"),
        Err(error) => internal(response, error),
    }
}

// ---------- chat models / concurrency / quotas ----------

/// The chat picker's model list: route aliases first, then one
/// `provider/model` direct entry per probed model of every enabled account
/// (whitelist-filtered, deduped).
#[handler]
async fn chat_models(depot: &mut Depot, response: &mut Response) {
    match admin(depot).chat_models().await {
        Ok(models) => json_response(response, &json!({ "models": models })),
        Err(error) => internal(response, error),
    }
}

/// Every concurrency-capped key with its live semaphore occupancy.
#[handler]
async fn concurrency_usage(depot: &mut Depot, response: &mut Response) {
    match admin(depot).concurrency_usage().await {
        Ok(rows) => json_response(response, &json!({ "items": rows })),
        Err(error) => internal(response, error),
    }
}

/// LIVE vendor quota probing: one outbound request per enabled key of every
/// enabled provider, run in parallel — expect second-scale latency (each
/// probe carries an 8s timeout budget). Fresh readings are persisted as
/// snapshots before the response. NOT a pure read; the pure counterpart is
/// [`quota_snapshots`].
#[handler]
async fn quotas(depot: &mut Depot, response: &mut Response) {
    json_response(response, &json!({ "items": admin(depot).quotas().await }));
}

/// The stored quota snapshots (pure read, no vendor probing).
#[handler]
async fn quota_snapshots(depot: &mut Depot, response: &mut Response) {
    json_response(
        response,
        &json!({ "items": admin(depot).quota_snapshots().await }),
    );
}

/// `GET /api/privacy`: the masking policy currently in effect. Read-only — the
/// config file is the source of truth; this only reports it.
#[handler]
async fn privacy_status(depot: &mut Depot, response: &mut Response) {
    let privacy = &state(depot).privacy;
    json_response(
        response,
        &json!({
            "enabled": privacy.enabled,
            "secrets": privacy.secrets,
            "personal": privacy.personal,
            "words": privacy.words,
        }),
    );
}

// ---------- live activity (SSE) ----------

/// The SSE rendering of an activity receiver: one JSON frame per event plus
/// a `:alive` comment heartbeat after 15s of silence (the returned stream
/// carries no timer override affordance — tests build their own with
/// [`sse_events`]). Serialization failure is unreachable in practice
/// (ActivityEvent is all primitives and Strings); keep the stream's error
/// type at serde_json for the SSE TryStream contract and trace it when it
/// happens.
///
/// Why not salvo_extra's `SseKeepAlive`: its timer resets with
/// `tokio::time::Sleep::reset`, which leaves a fired sleep in the
/// elapsed-but-pending state — the keep-alive fires exactly once and never
/// again. The interval below is re-created per lap instead.
fn activity_sse_stream(
    receiver: crate::activity::ActivityReceiver,
) -> impl futures::TryStream<Ok = SseEvent, Error = serde_json::Error> + Send {
    sse_events(receiver, std::time::Duration::from_secs(15))
}

/// `receiver` mapped to SSE frames, with a `:alive` comment injected after
/// `keep_alive` of silence. The sleep is re-created each lap (see
/// [`activity_sse_stream`] for why a resettable `Sleep` cannot serve here).
fn sse_events(
    mut receiver: crate::activity::ActivityReceiver,
    keep_alive: std::time::Duration,
) -> impl futures::Stream<Item = Result<SseEvent, serde_json::Error>> + Send {
    async_stream::stream! {
      loop {
        tokio::select! {
          // Silence for the whole interval: a comment frame keeps the
          // connection warm through intermediaries.
          () = tokio::time::sleep(keep_alive) => yield Ok(SseEvent::default().comment("alive")),
          event = receiver.recv() => match event {
            Some(event) => match SseEvent::default().json(&event) {
              Ok(frame) => yield Ok(frame),
              Err(error) => {
                tracing::warn!("activity sse: serialization failed ({error}); event dropped");
              }
            },
            // The listener task is gone (it never returns) — end the stream.
            None => break,
          }
        }
      }
    }
}

/// `GET /api/activity`: the live attempt feed as SSE — every frame is one
/// serialized [`crate::activity::ActivityEvent`]. The FIRST frame is always a
/// [`crate::activity::ActivityEvent::Bootstrap`] (or a bare `Resync` when its
/// reads fail): the pages render from it, so opening a client costs one
/// connection instead of a request per page. Events after that are transient
/// and lossy by design (see the activity module): a client joining late sees
/// nothing retroactive; the ledger remains the source of truth and clients
/// self-heal drift with a slow poll. A comment heartbeat fires every 15s so
/// intermediaries keep the connection alive.
#[handler]
async fn activity_stream(depot: &mut Depot, response: &mut Response) {
    let initial = match admin(depot).bootstrap().await {
        Ok(document) => crate::activity::ActivityEvent::Bootstrap(Box::new(document)),
        Err(error) => {
            tracing::warn!("activity sse: bootstrap failed ({error:#}); subscriber re-reads");
            crate::activity::ActivityEvent::Resync
        }
    };
    // Dropping the JoinHandle detaches the drain; it self-terminates when the
    // SSE response drops the receiver (the drain watches the closed state).
    let (receiver, _drain) = crate::activity::listen(&state(depot).activity, initial);
    salvo::sse::stream(response, activity_sse_stream(receiver));
}

/// `GET /api/bootstrap`: the pushed bootstrap document on demand — the same
/// payload the activity stream carries as its connect frame, for a manual
/// refresh and as the subscriber's reconnect fallback.
#[handler]
async fn bootstrap(depot: &mut Depot, response: &mut Response) {
    match admin(depot).bootstrap().await {
        Ok(document) => json_response(response, &document),
        Err(error) => internal(response, error),
    }
}

// ---------- traces ----------

/// The shared trace ring (the live relay's own; same TODO-invariant as
/// [`state_pool`]).
fn trace_ring(depot: &Depot) -> Arc<crate::relay::trace::TraceRing> {
    Arc::clone(
        &depot
            .get_typed::<Arc<crate::api::AppState>>()
            .expect("app state injected")
            .trace_ring,
    )
}

/// `GET /api/traces`: the trace ring's contents, newest first (capped at
/// the ring's capacity of 128). In the `{items: [...]}` envelope, matching
/// the other list endpoints.
#[handler]
async fn list_traces(depot: &mut Depot, response: &mut Response) {
    let items = trace_ring(depot).list();
    json_response(response, &json!({ "items": items }));
}

/// `GET /api/traces/{request_id}`: one trace by its dispatch request id
/// (`req_{n}`), 404 when the ring never held it or evicted it.
#[handler]
async fn get_trace(request: &mut Request, depot: &mut Depot, response: &mut Response) {
    let request_id = request.param::<String>("request_id").unwrap_or_default();
    match trace_ring(depot).get(&request_id) {
        Some(trace) => json_response(response, &trace),
        None => not_found(response, "trace"),
    }
}

// ---------- helpers ----------

fn not_found(response: &mut Response, what: &str) {
    response.status_code(StatusCode::NOT_FOUND);
    let _ = response.body(format!("no such {what}"));
}

fn bad_request(response: &mut Response, error: anyhow::Error) {
    response.status_code(StatusCode::BAD_REQUEST);
    let _ = response.body(format!("{error:#}"));
}

/// 502 for an upstream probe failure (the vendor rejected the credential,
/// DNS, timeout, undecodable payload): the request was well-formed — the
/// gateway reached its dependency and the dependency failed. Returns false
/// for non-probe errors so the caller can map them itself.
fn try_bad_gateway(response: &mut Response, error: &anyhow::Error) -> bool {
    let Some(probe) = error.downcast_ref::<crate::admin_ops::ProbeError>() else {
        return false;
    };
    response.status_code(StatusCode::BAD_GATEWAY);
    let _ = response.body(format!("upstream probe failed: {probe}"));
    true
}

fn internal(response: &mut Response, error: anyhow::Error) {
    tracing::error!("admin api: {error:#}");
    response.status_code(StatusCode::INTERNAL_SERVER_ERROR);
    let _ = response.body(format!("internal error: {error:#}"));
}

/// `/api/*` sub-router (loopback-only + admin auth). Mounted on the main router.
pub fn router(admin_key: Arc<AdminKey>, admin_remote: Arc<AdminRemote>) -> Router {
    Router::with_path("api")
        .hoop(affix_state::inject(admin_key))
        .hoop(affix_state::inject(admin_remote))
        .hoop(admin_local_only)
        .hoop(admin_auth)
        .push(
            Router::with_path("providers")
                .get(list_providers)
                .post(create_provider),
        )
        .push(
            Router::with_path("providers/{id}")
                .get(get_provider)
                .patch(update_provider)
                .delete(delete_provider),
        )
        .push(
            Router::with_path("providers/{id}/keys")
                .get(list_keys)
                .post(create_key),
        )
        .push(
            Router::with_path("providers/{id}/keys/{key_id}")
                .patch(patch_key)
                .delete(delete_key),
        )
        .push(Router::with_path("providers/{id}/keys/{key_id}/reveal").get(reveal_key))
        .push(Router::with_path("keys/order").put(reorder_keys))
        .push(Router::with_path("rests").get(list_rests))
        .push(Router::with_path("rests/keys/{key_id}").delete(clear_rest_by_key))
        .push(Router::with_path("rests/providers/{provider_id}").delete(clear_rests_by_provider))
        .push(Router::with_path("routes").get(list_routes))
        .push(
            Router::with_path("routes/{alias}")
                .get(get_route)
                .put(put_route)
                .delete(delete_route),
        )
        .push(Router::with_path("usage").get(usage))
        .push(Router::with_path("usage/trend").get(usage_trend))
        .push(Router::with_path("usage/window").get(usage_window))
        .push(Router::with_path("requests").get(recent_requests))
        .push(Router::with_path("requests/model-success").get(model_success))
        .push(Router::with_path("requests/{id}/bodies").get(request_bodies))
        .push(
            Router::with_path("gateway-keys")
                .get(list_gateway_keys)
                .post(create_gateway_key),
        )
        .push(Router::with_path("gateway-keys/{id}").patch(patch_gateway_key))
        .push(Router::with_path("keys/validate").post(validate_key))
        .push(
            Router::with_path("keys/{id}/models")
                .get(list_key_models)
                .put(save_key_models),
        )
        .push(Router::with_path("chat-models").get(chat_models))
        .push(Router::with_path("concurrency").get(concurrency_usage))
        .push(Router::with_path("privacy").get(privacy_status))
        .push(Router::with_path("quotas").get(quotas))
        .push(Router::with_path("quota-snapshots").get(quota_snapshots))
        .push(Router::with_path("activity").get(activity_stream))
        .push(Router::with_path("bootstrap").get(bootstrap))
        .push(Router::with_path("traces").get(list_traces))
        .push(Router::with_path("traces/{request_id}").get(get_trace))
        .push(
            Router::with_path("agents/{agent}")
                .get(agent_status)
                .push(Router::with_path("connect").post(agent_connect))
                .push(Router::with_path("disconnect").post(agent_disconnect)),
        )
}

// ---------- provider keys and failure cooldowns ----------

#[derive(Deserialize)]
struct KeyBody {
    label: String,
    api_key: String,
    /// Per-key in-flight cap; absent or null = unlimited.
    #[serde(default)]
    max_concurrency: Option<i32>,
    /// Model whitelist; absent or null = unrestricted.
    #[serde(default)]
    allowed_models: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct PatchKeyBody {
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    enabled: Option<bool>,
    /// Three-state: absent = untouched, null = clear to unlimited, number = set.
    /// (A plain Option<Option<i32>> cannot tell null from absent — serde maps
    /// both to the outer None — so presence must be captured explicitly.)
    #[serde(default, deserialize_with = "tri_state")]
    max_concurrency: Option<Option<i32>>,
    /// Three-state: absent = untouched, null/[] = clear to unrestricted,
    /// array = set the whitelist.
    #[serde(default, deserialize_with = "tri_state")]
    allowed_models: Option<Option<Vec<String>>>,
}

/// Presence-capturing deserializer for a tri-state field: serde only calls
/// this when the field is present, so wrapping in Some marks "explicitly
/// supplied" (null → Some(None)); absence falls back to the field default.
fn tri_state<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Ok(Some(Option::<T>::deserialize(deserializer)?))
}

/// `PUT /api/keys/order` body: positions are assigned sequentially in array order (0, 1, 2, …).
#[derive(Deserialize)]
struct KeyOrderBody {
    ids: Vec<i64>,
}

#[handler]
async fn list_keys(request: &mut Request, depot: &mut Depot, response: &mut Response) {
    let Some(provider_id) = request.param::<i64>("id") else {
        response.status_code(StatusCode::BAD_REQUEST);
        let _ = response.body("invalid provider id");
        return;
    };
    let pool = state_pool(depot);
    match store::list_provider_keys(pool, provider_id).await {
        Ok(rows) => {
            let live = admin(depot).live_inflight().await;
            let views: Vec<store::ProviderKeyView> = rows
                .iter()
                .map(|row| {
                    let inflight = row
                        .max_concurrency
                        .map(|_| live.get(&(row.id as u64)).copied().unwrap_or(0) as i32);
                    store::ProviderKeyView::new(row, inflight)
                })
                .collect();
            json_response(response, &views)
        }
        Err(error) => internal(response, error),
    }
}

#[handler]
async fn create_key(request: &mut Request, depot: &mut Depot, response: &mut Response) {
    let Some(provider_id) = request.param::<i64>("id") else {
        response.status_code(StatusCode::BAD_REQUEST);
        let _ = response.body("invalid provider id");
        return;
    };
    let pool = state_pool(depot);
    let Ok(body) = request.parse_json::<KeyBody>().await else {
        response.status_code(StatusCode::BAD_REQUEST);
        let _ = response.body("invalid key body");
        return;
    };
    // Keychain-first: the secret is stored under a freshly minted reference
    // BEFORE the row exists; a failed insert rolls the secret back (see
    // admin_ops::create_key).
    match crate::admin_ops::create_key(
        pool,
        provider_id,
        &body.label,
        &body.api_key,
        body.max_concurrency,
        body.allowed_models,
    )
    .await
    {
        Ok(id) => {
            let _ = state(depot).route_cache.refresh(pool).await;
            response.status_code(StatusCode::CREATED);
            json_response(response, &json!({"id": id}));
        }
        Err(error) => bad_request(response, error),
    }
}

#[handler]
async fn patch_key(request: &mut Request, depot: &mut Depot, response: &mut Response) {
    let (Some(provider_id), Some(key_id)) =
        (request.param::<i64>("id"), request.param::<i64>("key_id"))
    else {
        response.status_code(StatusCode::BAD_REQUEST);
        let _ = response.body("invalid id");
        return;
    };
    let pool = state_pool(depot);
    let Ok(body) = request.parse_json::<PatchKeyBody>().await else {
        response.status_code(StatusCode::BAD_REQUEST);
        let _ = response.body("invalid key patch body");
        return;
    };
    match store::update_provider_key(
        pool,
        provider_id,
        key_id,
        body.label.as_deref(),
        body.enabled,
        body.max_concurrency,
        body.allowed_models,
    )
    .await
    {
        Ok(true) => {
            let _ = state(depot).route_cache.refresh(pool).await;
            json_response(response, &json!({"ok": true}))
        }
        Ok(false) => not_found(response, "key"),
        Err(error) => bad_request(response, error),
    }
}

/// Global key reorder: `PUT /api/keys/order` `{ids: [..]}` must list every key exactly once →
/// position = array index, validated and written in one transaction.
#[handler]
async fn reorder_keys(request: &mut Request, depot: &mut Depot, response: &mut Response) {
    let pool = state_pool(depot);
    let Ok(body) = request.parse_json::<KeyOrderBody>().await else {
        response.status_code(StatusCode::BAD_REQUEST);
        let _ = response.body("invalid key order body");
        return;
    };
    match store::reorder_keys(pool, &body.ids).await {
        Ok(()) => {
            let _ = state(depot).route_cache.refresh(pool).await;
            json_response(response, &json!({"ok": true}))
        }
        Err(error) => bad_request(response, error),
    }
}

#[handler]
async fn delete_key(request: &mut Request, depot: &mut Depot, response: &mut Response) {
    let (Some(provider_id), Some(key_id)) =
        (request.param::<i64>("id"), request.param::<i64>("key_id"))
    else {
        response.status_code(StatusCode::BAD_REQUEST);
        let _ = response.body("invalid id");
        return;
    };
    let pool = state_pool(depot);
    match crate::admin_ops::delete_key(pool, provider_id, key_id).await {
        Ok(deleted) => {
            if deleted {
                let _ = state(depot).route_cache.refresh(pool).await;
                json_response(response, &json!({"ok": true}))
            } else {
                response.status_code(StatusCode::NOT_FOUND);
                let _ = response.body("key not found");
            }
        }
        Err(error) => internal(response, error),
    }
}

/// `GET /api/providers/{id}/keys/{key_id}/reveal` → 200 [`crate::admin_ops::KeyView`].
///
/// Deliberately the ONLY admin endpoint that serves the plaintext credential:
/// the masked [`list_keys`] shape cannot drive the GUI's 查看完整 key / editor
/// prefill flow (spec: docs/specs/gateway-gui-split-plan.md §8, deviation 12).
/// Safe because the whole `/api` surface is already loopback-only +
/// admin-key guarded; nothing masking-aware must ever read from here. The
/// response is the full KeyView (live inflight included) so the client can
/// assemble its provider-key listing from reveals alone.
#[handler]
async fn reveal_key(request: &mut Request, depot: &mut Depot, response: &mut Response) {
    let (Some(provider_id), Some(key_id)) =
        (request.param::<i64>("id"), request.param::<i64>("key_id"))
    else {
        response.status_code(StatusCode::BAD_REQUEST);
        let _ = response.body("invalid id");
        return;
    };
    let pool = state_pool(depot);
    match store::list_provider_keys(pool, provider_id).await {
        Ok(rows) => match rows.into_iter().find(|row| row.id == key_id) {
            Some(row) => {
                let api_key = row.api_key.clone().unwrap_or_default();
                let view = crate::admin_ops::key_view(&row, api_key);
                json_response(response, &view);
            }
            None => not_found(response, "key"),
        },
        Err(error) => internal(response, error),
    }
}

#[handler]
async fn list_rests(depot: &mut Depot, response: &mut Response) {
    let pool = state_pool(depot);
    match store::list_rests(pool).await {
        Ok(rows) => json_response(response, &json!({ "items": rows })),
        Err(error) => internal(response, error),
    }
}

/// Clear the cooldowns of all keys of a provider (idempotent). Goes through
/// the facade: the RestCache is the only read path, so a store-direct call
/// would leave the cache stale (the facade writes through); it also forgives
/// every key's consecutive-failure streak alongside the DB rows.
#[handler]
async fn clear_rests_by_provider(
    request: &mut Request,
    depot: &mut Depot,
    response: &mut Response,
) {
    let Some(provider_id) = request.param::<i64>("provider_id") else {
        bad_request(response, anyhow::anyhow!("invalid provider id"));
        return;
    };
    match admin(depot).clear_provider_rests(provider_id).await {
        Ok(()) => json_response(response, &json!({"ok": true})),
        Err(error) => internal(response, error),
    }
}

/// Clear the cooldown of a single key (idempotent). Goes through the facade:
/// clearing forgives the key's consecutive-failure streak (the relay's
/// in-memory backoff input) alongside the DB rest row — a store-direct call
/// would leave the live relay backing off a key the user just un-rested.
#[handler]
async fn clear_rest_by_key(request: &mut Request, depot: &mut Depot, response: &mut Response) {
    let Some(key_id) = request.param::<i64>("key_id") else {
        bad_request(response, anyhow::anyhow!("invalid key id"));
        return;
    };
    match admin(depot).clear_rest(key_id).await {
        Ok(()) => json_response(response, &json!({"ok": true})),
        Err(error) => internal(response, error),
    }
}

// ---------- agent wiring ----------
#[derive(Deserialize)]
struct ConnectBody {
    listen_addr: String,
    gateway_key: String,
    #[serde(default)]
    models: Vec<String>,
}

fn parse_agent(response: &mut Response, raw: &str) -> Option<agent::Agent> {
    match agent::Agent::parse(raw) {
        Some(agent) => Some(agent),
        None => {
            bad_request(
                response,
                anyhow::anyhow!("unknown agent: {raw} (supported: opencode / omp)"),
            );
            None
        }
    }
}

#[handler]
async fn agent_status(request: &mut Request, response: &mut Response) {
    let Some(agent) = parse_agent(response, request.param::<&str>("agent").unwrap_or_default())
    else {
        return;
    };
    match agent::status(agent) {
        Ok(value) => json_response(response, &value),
        Err(error) => internal(response, error),
    }
}

#[handler]
async fn agent_connect(request: &mut Request, response: &mut Response) {
    let Some(agent) = parse_agent(response, request.param::<&str>("agent").unwrap_or_default())
    else {
        return;
    };
    let Ok(body) = request.parse_json::<ConnectBody>().await else {
        response.status_code(StatusCode::BAD_REQUEST);
        let _ = response.body("invalid connect body");
        return;
    };
    let input = agent::ConnectInput {
        listen_addr: &body.listen_addr,
        gateway_key: &body.gateway_key,
        models: body.models,
    };
    let result = match agent.default_path() {
        Some(path) => agent::connect_at(agent, &path, &input),
        None => Err(anyhow::anyhow!("cannot locate the home directory")),
    };
    match result {
        Ok(()) => json_response(response, &json!({"ok": true})),
        Err(error) => bad_request(response, error),
    }
}

#[handler]
async fn agent_disconnect(request: &mut Request, response: &mut Response) {
    let Some(agent) = parse_agent(response, request.param::<&str>("agent").unwrap_or_default())
    else {
        return;
    };
    let result = match agent.default_path() {
        Some(path) => agent::disconnect_at(agent, &path),
        None => Err(anyhow::anyhow!("cannot locate the home directory")),
    };
    match result {
        Ok(restored) => json_response(response, &json!({"ok": true, "restored": restored})),
        Err(error) => internal(response, error),
    }
}
