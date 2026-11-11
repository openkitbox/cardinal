//! Admin API: `/api/*`, authenticated with the admin key (SHA-256 of config.gateway_key).
//!
//! Endpoints:
//! - `GET/POST /api/providers`, `GET/PATCH/DELETE /api/providers/:id` — provider = protocol + endpoint (+ auth scheme), no credential
//! - `POST /api/providers/kiro` `{name, base_url}` — atomic Kiro provider find-or-create by runtime endpoint
//! - `DELETE /api/providers/:id/if-empty` — atomically delete a provider only when it has no keys
//! - `GET/POST /api/providers/:id/keys`, `PATCH/DELETE /api/providers/:id/keys/:key_id` — every credential is a named key
//!   (a Kiro key carries `auth_kind: "kiro_oidc"` + `oauth` instead of `api_key`; PATCH replaces that bundle only on an existing Kiro key)
//!   the key PATCH's `archived` (absent = untouched, true = archive keeping the first archive time, false = unarchive)
//!   is independent of `enabled` and of group membership
//! - `POST /api/providers/:id/kiro-key` `{label, oauth, group_ids?}` — probe then find-or-create a Kiro OIDC key by label
//! - `POST /api/providers/:id/kiro-import` `{label, account?, credentials, group_ids?}` — allow-listed import of a raw `kiro.rs` object or account array
//!   (`group_ids` on both = groups to ADD the key to in the same transaction; existing memberships are kept, an unknown id → 400)
//! - `POST /api/providers/:id/opencode-login` `{label, key_id?, group_ids?, max_concurrency?}` → 201 `{session, user_code,
//!   verification_url, expires_in, interval}` — start an OpenCode Console device login (`key_id` re-authenticates that account;
//!   a taken label → 409, a non-OpenCode provider or unknown group → 400)
//! - `GET /api/opencode-logins/:session` → `{state, key_id, message}` (`waiting|succeeded|failed|expired|cancelled`, 404 once
//!   the session is unknown or its verdict aged out) / `DELETE` cancels a waiting login (204; 404 when unknown or finished)
//! - `POST /api/providers/:id/cursor-login` `{label, key_id?, group_ids?, max_concurrency?}` → 201 `{session, login_url,
//!   expires_in}` — start a Cursor browser login (the operator opens `login_url`; `key_id` re-authenticates that account;
//!   a taken label → 409, a non-Cursor provider or unknown group → 400)
//! - `GET /api/cursor-logins/:session` → `{state, key_id, email, team_id, message}` (same states as OpenCode; never a
//!   token) / `DELETE` cancels a waiting login (204; 404 when unknown or finished)
//! - `POST /api/openai-logins` `{provider_id, label, key_id?, group_ids?, max_concurrency?}` → 201 `{session, user_code,
//!   verification_url, expires_in, interval}` — start an OpenAI Codex device login (`key_id` alone re-authenticates that
//!   account; a taken label → 409, a non-Codex provider or unknown group → 400)
//! - `GET /api/openai-logins/:session` → `{state, key_id, email, plan_type, user_code, verification_url, message}`
//!   (same states as OpenCode; never a token or the device grant id) / `DELETE` cancels a waiting login (204; 404 when
//!   unknown or finished)
//! - `GET /api/providers/:id/keys/:key_id/reveal` — the full KeyView, plaintext credential included (the ONLY
//!   plaintext-serving endpoint; the list shape stays masked)
//! - `POST /api/key-groups` `{name}` → `{id}`, `PATCH/DELETE /api/key-groups/:id` — account groups (409 on a taken name, 400 on an invalid one,
//!   404 on an unknown id); membership is set per key through the key PATCH's `group_ids` (absent = untouched, array = full replace)
//! - `PUT /api/keys/order` `{ids: [..]}` — assign global positions sequentially in array order (one transaction)
//! - `POST /api/keys/validate` `{name, protocol, base_url, auth_scheme?, enabled?, api_key}` — probe a not-yet-saved credential
//! - `GET/PUT /api/keys/:id/models` — a key's model list: GET re-probes the provider, PUT persists a list as the snapshot
//! - `GET /api/routes`, `GET/PUT/DELETE /api/routes/:alias` — route = named list of (account, model) entries exposed to clients
//!   as a model id; each entry names one account (`gateway_provider_keys` row) and the model it serves;
//!   PUT body `{entries: [{key_id, model}], context_window?, strategy?}` (`strategy` = `ordered`|`smart`|`rotate`, absent = `ordered`;
//!   400 when the body is malformed, a referenced key does not exist, or a (key, model) pair repeats). PUT is a full
//!   replace: a strategy-preserving client MUST send it back, or the save resets to `ordered`
//! - `GET /api/rests`, `DELETE /api/rests/keys/:key_id`, `DELETE /api/rests/providers/:provider_id` — cooldowns, identity = key
//! - `GET /api/usage?days=N` (aggregated by day × alias; `key_id` restricts to one gateway key, `caller=null` = unidentified,
//!   `user_id` = every key one user owns; more than one of them is 400, any other `caller` value is 400)
//! - `GET /api/usage/trend?since&until&split&offset_seconds` (bucket × category aggregates for the trend chart; `split` =
//!   `route`|`model`|`provider`|`client`|`user` (`user` = the owning user's login); `caller`/`key_id`/`user_id` as above)
//! - `GET /api/usage/window?since&until` (whole-window aggregate behind the KPI cards; `caller`/`key_id`/`user_id` as above)
//! - `GET /api/requests?limit=N` (recent requests, with `user_id`, `login`, `gateway_key_id`, `charged_microus`, `rate_bp`)
//! - `GET /api/requests/:id/bodies` (captured request/response bodies from the hourly payload files)
//! - `GET /api/chat-models` (the chat picker's model list: route aliases + probed direct entries)
//! - `GET /api/concurrency` (per-key live occupancy for concurrency-capped keys)
//! - `GET /api/quotas` (LIVE per-key vendor quota probing — outbound side effect) / `GET /api/quota-snapshots` (the stored readings)
//! - `GET /api/bootstrap` — every parameterless read the status pages render from, as one document (also the activity stream's connect frame)
//! - `GET /api/activity` (SSE live attempt feed: ActivityEvent frames + keep-alive)
//! - `GET/POST /api/users`, `GET/PATCH /api/users/:id` — billed users (POST requires `group_id`; PATCH `rate_bp`
//!   absent = untouched, null = use the group rate; the balance is never patchable)
//! - `GET/POST /api/user-groups`, `PATCH /api/user-groups/:id` — pricing groups (`route_aliases` null = every route)
//! - `POST /api/users/:id/topup` `{amount_usd, note?, operator?}` (> 0), `POST /api/users/:id/adjust` `{amount_usd, note,
//!   operator?}` (≠ 0) — one ledger entry plus the balance change in one transaction; `operator` defaults to `admin`
//! - `GET /api/users/:id/entries?before_id&limit` (ledger, newest first), `GET /api/users/:id/reconcile`
//!   (balance vs ledger sum, plus `keys: [{key_id, spent_microus, entries_sum_microus}]`; `consistent` covers both)
//! - `GET/POST /api/gateway-keys` (`?user_id=` filters the list; POST `{label, user_id?, expires_at?, quota_usd?}`,
//!   `user_id` defaults to `owner`), `PATCH /api/gateway-keys/:id` `{label?, enabled?, expires_at?, quota_usd?}`
//!   (`expires_at` RFC 3339 in the future, `quota_usd` a non-negative decimal USD string = cumulative cap that never
//!   resets; on PATCH both are three-state: absent = untouched, null = clear). Labels are unique per user (409);
//!   a key whose spend reached its quota is refused with 402
//! - `GET /api/traces`, `GET /api/traces/:request_id` — recent routing traces from the dispatch trace ring
//!   (newest first, capped at the ring's capacity; transient — nothing is persisted)

use std::sync::Arc;

use salvo::affix_state;
use salvo::http::{StatusCode, header};
use salvo::prelude::*;
use salvo::sse::SseEvent;
use serde::Deserialize;
use serde_json::json;

use crate::admin_ops::CursorLoginError;
use crate::admin_ops::OpenaiLoginError;
use crate::admin_ops::OpenaiLoginRequest;
use crate::admin_ops::OpencodeLoginError;
use crate::agent;
use crate::credentials::{AuthKind, KeyCredential, resolve_key_credential};
use crate::key_terms;
use crate::kiro::KiroOAuth;
use crate::store::{self, ProviderInput, RouteEntry, RouteStrategy};
use crate::upstream::Dns;

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

pub(crate) fn constant_time_eq(a: &str, b: &str) -> bool {
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
    admin_from_state(state)
}

/// Build the facade over an already shared state (used by gateway startup to
/// prime the bootstrap snapshot without a synthetic depot).
pub(crate) fn admin_from_state(state: &crate::api::AppState) -> crate::admin_ops::Admin {
    crate::admin_ops::Admin::new(
        state.pool.clone(),
        (
            state.transport.clone(),
            state.transport.limits().allow_private_destinations,
        ),
        Arc::clone(&state.failover),
        state.smart_cache.clone(),
        state.route_cache.clone(),
        state.rest_cache.clone(),
        state.activity.clone(),
    )
    .with_snapshot(state.admin_snapshot.clone())
    .with_kiro_tokens(Arc::clone(&state.kiro_tokens))
    .with_opencode_tokens(Arc::clone(&state.opencode_tokens))
    .with_cursor_tokens(Arc::clone(&state.cursor_tokens))
    .with_openai_tokens(Arc::clone(&state.openai_tokens))
    .with_openai_login(
        Arc::clone(&state.openai_client),
        state.openai_logins.clone(),
    )
    .with_opencode_login(
        Arc::clone(&state.opencode_client),
        state.opencode_logins.clone(),
    )
    .with_cursor_login(
        Arc::clone(&state.cursor_client),
        state.cursor_logins.clone(),
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
    #[serde(default)]
    dns: Dns,
}

impl ProviderSpecBody {
    fn input(&self) -> ProviderInput<'_> {
        ProviderInput {
            name: &self.name,
            protocol: &self.protocol,
            base_url: &self.base_url,
            auth_scheme: self.auth_scheme.as_deref(),
            enabled: self.enabled,
            dns: self.dns,
        }
    }
}

#[derive(Deserialize)]
struct ProviderBody {
    #[serde(flatten)]
    spec: ProviderSpecBody,
}

#[derive(Deserialize)]
struct KiroProviderBody {
    name: String,
    base_url: String,
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
            let _ = admin(depot).refresh_route_cache().await;
            state(depot).admin_snapshot.invalidate().await;
            response.status_code(StatusCode::CREATED);
            json_response(response, &json!({"id": id}));
        }
        Err(error) => bad_request(response, error),
    }
}

#[handler]
async fn find_or_create_kiro_provider(
    request: &mut Request,
    depot: &mut Depot,
    response: &mut Response,
) {
    let Ok(body) = request.parse_json::<KiroProviderBody>().await else {
        response.status_code(StatusCode::BAD_REQUEST);
        let _ = response.body("invalid Kiro provider body");
        return;
    };
    if !validate_base_url(depot, &body.name, &body.base_url, response) {
        return;
    }
    let pool = state_pool(depot);
    match store::find_or_create_kiro_provider(pool, &body.name, &body.base_url).await {
        Ok((id, created)) => {
            if let Err(error) = admin(depot).refresh_route_cache().await {
                tracing::warn!(%error, "route cache refresh after Kiro provider find-or-create failed");
            }
            state(depot).admin_snapshot.invalidate().await;
            response.status_code(if created {
                StatusCode::CREATED
            } else {
                StatusCode::OK
            });
            json_response(response, &json!({"id": id, "created": created}));
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
            let _ = admin(depot).refresh_route_cache().await;
            state(depot).admin_snapshot.invalidate().await;
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
        Ok(store::ProviderDeleteOutcome::Deleted { kiro_key_ids }) => {
            state(depot).kiro_tokens.remove_provider(&kiro_key_ids);
            let _ = admin(depot).refresh_route_cache().await;
            state(depot).admin_snapshot.invalidate().await;
            json_response(response, &json!({"ok": true}))
        }
        Ok(store::ProviderDeleteOutcome::Missing) => not_found(response, "provider"),
        Err(error) => internal(response, error),
    }
}

#[handler]
async fn delete_provider_if_empty(
    request: &mut Request,
    depot: &mut Depot,
    response: &mut Response,
) {
    let Some(id) = request.param::<i64>("id") else {
        response.status_code(StatusCode::BAD_REQUEST);
        let _ = response.body("bad id");
        return;
    };
    let pool = state_pool(depot);
    match store::delete_provider_if_empty(pool, id).await {
        Ok(store::EmptyProviderDeleteOutcome::Deleted) => {
            let _ = admin(depot).refresh_route_cache().await;
            state(depot).admin_snapshot.invalidate().await;
            json_response(response, &json!({"ok": true}))
        }
        Ok(store::EmptyProviderDeleteOutcome::HasKeys) => {
            response.status_code(StatusCode::CONFLICT);
            let _ = response.body("provider has keys");
        }
        Ok(store::EmptyProviderDeleteOutcome::Missing) => not_found(response, "provider"),
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
    /// Three-state: absent = keep the stored list, null = clear back to legacy
    /// derivation, array = set the list.
    #[serde(default, deserialize_with = "crate::tri_state::deserialize")]
    efforts: Option<Option<Vec<String>>>,
}

/// The 400 body for a malformed `PUT /api/routes/{alias}`. An unknown
/// `strategy` string fails [`RouteBody`]'s typed deserialization (serde
/// rejects any variant but `ordered`/`smart`), so the message names the
/// accepted values — same posture as `usage_trend`'s split hint. Kept as a
/// const so the test that pins this exact body
/// (`route_api_tests::unknown_strategy_is_rejected_with_400`) shares one
/// source of truth — the only extracted 400 message in this file.
const INVALID_ROUTE_BODY: &str = "invalid route body (expected {entries: [...], context_window?, strategy? = ordered, smart, rotate, or weighted})";

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
    let efforts = match body.efforts {
        None => store::EffortsUpdate::Preserve,
        Some(None) => store::EffortsUpdate::Set(None),
        Some(Some(names)) => store::EffortsUpdate::Set(Some(names)),
    };
    match store::put_route(
        pool,
        &alias,
        &body.entries,
        body.context_window,
        body.strategy,
        body.note,
        efforts,
    )
    .await
    {
        Ok(()) => {
            let _ = admin(depot).refresh_route_cache().await;
            state(depot).admin_snapshot.invalidate().await;
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
            let _ = admin(depot).refresh_route_cache().await;
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
    #[serde(default)]
    key_id: Option<i64>,
    #[serde(default)]
    user_id: Option<i64>,
}

fn default_days() -> i32 {
    7
}

/// Usage aggregated by day × alias.
#[handler]
async fn usage(request: &mut Request, depot: &mut Depot, response: &mut Response) {
    let pool = state_pool(depot);
    // A malformed query is refused rather than defaulted: falling back would
    // silently drop a `user_id`/`key_id`/`caller` filter and widen the result.
    let query = match request.parse_queries::<UsageQuery>() {
        Ok(query) => query,
        Err(_) => {
            response.status_code(StatusCode::BAD_REQUEST);
            let _ = response.body("invalid usage query (days, caller, key_id, user_id)");
            return;
        }
    };
    let days = query.days.clamp(1, 365);
    let caller = match usage_scope(query.caller.as_deref(), query.key_id, query.user_id) {
        Ok(caller) => caller,
        Err(message) => {
            response.status_code(StatusCode::BAD_REQUEST);
            let _ = response.body(message);
            return;
        }
    };
    match store::usage_by_day(pool, days, caller).await {
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
/// (route|model|provider|client|user, default route); `offset_seconds` shifts
/// bucket labels to the caller's wall clock (the GUI passes its local offset);
/// `caller=null` restricts to unidentified 本机 rows, `key_id` to one gateway
/// key, `user_id` to one user's keys (mutually exclusive, see [`usage_scope`]).
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
    #[serde(default)]
    key_id: Option<i64>,
    #[serde(default)]
    user_id: Option<i64>,
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
            let _ = response.body("invalid trend query (since/until as RFC3339, split = route|model|provider|client|user, offset_seconds)");
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
    let caller = match usage_scope(query.caller.as_deref(), query.key_id, query.user_id) {
        Ok(caller) => caller,
        Err(message) => {
            response.status_code(StatusCode::BAD_REQUEST);
            let _ = response.body(message);
            return;
        }
    };
    match admin.usage_trend(since, until, split, offset, caller).await {
        Ok(rows) => json_response(response, &json!({ "items": rows })),
        Err(error) => internal(response, error),
    }
}

/// The store filter of the usage endpoints' scope query parameters:
/// `caller=null` selects unidentified callers (no other `caller` value is
/// accepted: labels are only unique per user, so a label cannot name a key);
/// `key_id` one gateway key; `user_id` every key that user owns. They name
/// different scopes, so more than one is refused rather than one silently
/// winning.
fn usage_scope(
    caller: Option<&str>,
    key_id: Option<i64>,
    user_id: Option<i64>,
) -> Result<Option<store::CallerFilter>, &'static str> {
    match (caller, key_id, user_id) {
        (None, None, None) => Ok(None),
        (Some("null"), None, None) => Ok(Some(store::CallerFilter::Null)),
        (Some(_), None, None) => Err("caller only accepts null; select a key with key_id"),
        (None, Some(key_id), None) => Ok(Some(store::CallerFilter::Key(key_id))),
        (None, None, Some(user_id)) => Ok(Some(store::CallerFilter::User(user_id))),
        _ => Err("caller, key_id and user_id are mutually exclusive"),
    }
}

/// Query form of `GET /api/usage/window` — window bounds plus the optional
/// `caller`/`key_id`/`user_id` restriction (same spelling as [`TrendQuery`]), resolved
/// via [`resolve_window`].
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
    #[serde(default)]
    key_id: Option<i64>,
    #[serde(default)]
    user_id: Option<i64>,
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
    let caller = match usage_scope(query.caller.as_deref(), query.key_id, query.user_id) {
        Ok(caller) => caller,
        Err(message) => {
            response.status_code(StatusCode::BAD_REQUEST);
            let _ = response.body(message);
            return;
        }
    };
    match admin.usage_window(since, until, caller).await {
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
    /// Owning user; defaults to the built-in `owner` user when absent.
    user_id: Option<i64>,
    /// RFC 3339; absent/null = never expires.
    #[serde(default)]
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Cumulative cap as a decimal USD string; absent/null = unlimited.
    #[serde(default)]
    quota_usd: Option<String>,
}

/// `POST /api/gateway-keys`: create a new gateway key and return its
/// plaintext. Keys are stored in plaintext, so `GET /api/gateway-keys` can
/// show and copy them again later.
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
    let terms = key_terms::create(
        &body.label,
        body.expires_at,
        body.quota_usd.as_deref(),
        chrono::Utc::now(),
    );
    let (label, terms) = match terms {
        Ok(valid) => valid,
        Err(message) => {
            json_error(response, StatusCode::BAD_REQUEST, message);
            return;
        }
    };
    // created_by: the admin caller's identity if available (from CALLER_KEY depot).
    let created_by = depot.get_typed::<String>().ok().map(|s| s.as_str());
    let user_id = match body.user_id {
        Some(user_id) => user_id,
        None => match store::owner_user_id(pool).await {
            Ok(user_id) => user_id,
            Err(error) => {
                internal(response, error);
                return;
            }
        },
    };
    match store::create_gateway_key(pool, user_id, label, terms, created_by).await {
        Ok(key) => {
            state(depot).admin_snapshot.invalidate().await;
            json_response(response, &json!({ "key": key }))
        }
        Err(error) if store::is_label_taken(&error) => {
            response.status_code(StatusCode::CONFLICT);
            json_response(response, &json!({ "error": "label already in use" }));
        }
        Err(error) if store::is_unknown_user(&error) => {
            response.status_code(StatusCode::NOT_FOUND);
            json_response(response, &json!({ "error": "user not found" }));
        }
        Err(error) => internal(response, error),
    }
}

/// `GET /api/gateway-keys[?user_id=N]`: gateway keys with their plaintext
/// and owner; every key, or only those of one user.
#[handler]
async fn list_gateway_keys(request: &mut Request, depot: &mut Depot, response: &mut Response) {
    let pool = state_pool(depot);
    let Ok(query) = request.parse_queries::<GatewayKeysQuery>() else {
        json_error(response, StatusCode::BAD_REQUEST, "invalid query (user_id)");
        return;
    };
    match store::list_gateway_keys(pool, query.user_id).await {
        Ok(rows) => json_response(response, &json!({ "items": rows })),
        Err(error) => internal(response, error),
    }
}

/// `PATCH /api/gateway-keys/{id}`: partial update of label, enabled,
/// expiry and quota.
#[handler]
async fn patch_gateway_key(request: &mut Request, depot: &mut Depot, response: &mut Response) {
    let pool = state_pool(depot);
    let Some(id) = request.param::<i64>("id") else {
        response.status_code(StatusCode::BAD_REQUEST);
        json_response(response, &json!({ "error": "missing id" }));
        return;
    };
    let body: key_terms::PatchBody = match request.parse_json().await {
        Ok(body) => body,
        Err(_) => {
            response.status_code(StatusCode::BAD_REQUEST);
            json_response(response, &json!({ "error": "invalid JSON body" }));
            return;
        }
    };
    let patch = match key_terms::patch(&body, chrono::Utc::now()) {
        Ok(patch) => patch,
        Err(message) => {
            json_error(response, StatusCode::BAD_REQUEST, message);
            return;
        }
    };
    match store::update_gateway_key(pool, id, None, patch).await {
        Ok(true) => {
            state(depot).admin_snapshot.invalidate().await;
            json_response(response, &json!({ "ok": true }))
        }
        Ok(false) => {
            response.status_code(StatusCode::NOT_FOUND);
            json_response(response, &json!({ "error": "key not found" }));
        }
        Err(error) if store::is_label_taken(&error) => {
            json_error(response, StatusCode::CONFLICT, "label already in use");
        }
        Err(error) => internal(response, error),
    }
}

/// `GET /api/requests/{id}/bodies`: the captured request/response bodies of
/// one row from the hourly payload files, or 404 when the row was never
/// captured (payloads off) or predates the files still on disk. Captures are
/// keyed by the dispatch request id (`req_<uuid>` — the ledger writer batches
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
          // Prefer an already queued business event when both branches are
          // ready at the heartbeat boundary; the heartbeat is a keep-alive,
          // never a reason to starve the activity feed.
          biased;
          event = receiver.recv() => match event {
            Some(event) => match SseEvent::default().json(&event) {
              Ok(frame) => yield Ok(frame),
              Err(error) => {
                tracing::warn!("activity sse: serialization failed ({error}); event dropped");
              }
            },
            // The listener task is gone (it never returns) — end the stream.
            None => break,
          },
          // Silence for the whole interval: a comment frame keeps the
          // connection warm through intermediaries.
          () = tokio::time::sleep(keep_alive) => yield Ok(SseEvent::default().comment("alive")),
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
        Ok(document) => crate::activity::ActivityEvent::Bootstrap(document),
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
    match admin(depot).bootstrap_for_refresh().await {
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
/// (`req_<uuid>`), 404 when the ring never held it or evicted it.
#[handler]
async fn get_trace(request: &mut Request, depot: &mut Depot, response: &mut Response) {
    let request_id = request.param::<String>("request_id").unwrap_or_default();
    match trace_ring(depot).get(&request_id) {
        Some(trace) => json_response(response, &trace),
        None => not_found(response, "trace"),
    }
}

// ---------- users, user groups and balances ----------

/// Write `{"error": message}` with `status`.
fn json_error(response: &mut Response, status: StatusCode, message: &str) {
    response.status_code(status);
    json_response(response, &json!({ "error": message }));
}

/// A rate multiplier or concurrency cap the schema CHECKs would refuse, or
/// a rate above [`crate::billing::MAX_RATE_BP`]; answered as 400 instead of
/// a 500 from the constraint.
fn invalid_limits(rate_bp: Option<i64>, max_concurrent: Option<i32>) -> Option<&'static str> {
    if rate_bp.is_some_and(|rate| rate < 0) {
        return Some("rate_bp must not be negative");
    }
    if rate_bp.is_some_and(|rate| rate > crate::billing::MAX_RATE_BP) {
        return Some("rate_bp must not exceed 1000000 (100x)");
    }
    if max_concurrent.is_some_and(|cap| cap <= 0) {
        return Some("max_concurrent must be positive");
    }
    None
}

#[derive(Deserialize)]
struct UserCreateBody {
    login: String,
    #[serde(default)]
    display_name: Option<String>,
    /// Required: a user is always placed in a group explicitly.
    #[serde(default)]
    group_id: Option<i64>,
    /// User rate override; absent/null = the group rate applies.
    #[serde(default)]
    rate_bp: Option<i64>,
    #[serde(default)]
    max_concurrent: Option<i32>,
}

#[derive(Deserialize)]
struct UserPatchBody {
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    group_id: Option<i64>,
    /// Three-state: absent = untouched, null = clear the override (use the
    /// group rate), number = set the override.
    #[serde(default, deserialize_with = "crate::tri_state::deserialize")]
    rate_bp: Option<Option<i64>>,
    #[serde(default)]
    max_concurrent: Option<i32>,
}

#[derive(Deserialize)]
struct GroupCreateBody {
    name: String,
    /// Absent = 10_000 (1.0×).
    #[serde(default)]
    rate_bp: Option<i64>,
    /// Absent/null = every route visible; array = whitelist.
    #[serde(default)]
    route_aliases: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct GroupPatchBody {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    rate_bp: Option<i64>,
    /// Three-state: absent = untouched, null = every route visible, array =
    /// whitelist.
    #[serde(default, deserialize_with = "crate::tri_state::deserialize")]
    route_aliases: Option<Option<Vec<String>>>,
}

#[derive(Deserialize)]
struct CreditBody {
    /// Decimal USD string, e.g. `"10"` or `"-0.5"` (see `billing::parse_usd`).
    amount_usd: String,
    #[serde(default)]
    note: Option<String>,
    /// Who made the change; the admin key carries no identity, so it
    /// defaults to `"admin"`.
    #[serde(default)]
    operator: Option<String>,
}

#[derive(Deserialize)]
struct EntriesQuery {
    #[serde(default)]
    before_id: Option<i64>,
    #[serde(default)]
    limit: Option<i64>,
}

#[derive(Deserialize)]
struct GatewayKeysQuery {
    #[serde(default)]
    user_id: Option<i64>,
}

/// Group rate when a create body names none: 1.0×.
const DEFAULT_GROUP_RATE_BP: i64 = 10_000;

/// Respond with the user row of `id` (200), 404 when it is gone.
async fn respond_user(pool: &sqlx::PgPool, id: i64, response: &mut Response) {
    match store::get_user(pool, id).await {
        Ok(Some(user)) => json_response(response, &user),
        Ok(None) => json_error(response, StatusCode::NOT_FOUND, "user not found"),
        Err(error) => internal(response, error),
    }
}

/// Respond with the group row of `id` (200), 404 when it is gone.
async fn respond_group(pool: &sqlx::PgPool, id: i64, response: &mut Response) {
    match store::get_group(pool, id).await {
        Ok(Some(group)) => json_response(response, &group),
        Ok(None) => json_error(response, StatusCode::NOT_FOUND, "group not found"),
        Err(error) => internal(response, error),
    }
}

/// `GET /api/users`: every user with group name, rates and balance.
#[handler]
async fn list_users(depot: &mut Depot, response: &mut Response) {
    let pool = state_pool(depot);
    match store::list_users(pool).await {
        Ok(rows) => json_response(response, &json!({ "items": rows })),
        Err(error) => internal(response, error),
    }
}

/// `POST /api/users`: create a user (balance 0) and return its row.
#[handler]
async fn create_user(request: &mut Request, depot: &mut Depot, response: &mut Response) {
    let pool = state_pool(depot);
    let Ok(body) = request.parse_json::<UserCreateBody>().await else {
        json_error(response, StatusCode::BAD_REQUEST, "invalid JSON body");
        return;
    };
    let login = body.login.trim();
    if login.is_empty() {
        json_error(response, StatusCode::BAD_REQUEST, "login is required");
        return;
    }
    let Some(group_id) = body.group_id else {
        json_error(response, StatusCode::BAD_REQUEST, "group_id is required");
        return;
    };
    if let Some(message) = invalid_limits(body.rate_bp, body.max_concurrent) {
        json_error(response, StatusCode::BAD_REQUEST, message);
        return;
    }
    let user = store::NewUser {
        login,
        display_name: body.display_name.as_deref().map_or("", str::trim),
        group_id,
        rate_bp: body.rate_bp,
        max_concurrent: body.max_concurrent,
    };
    match store::create_user(pool, user).await {
        Ok(id) => {
            state(depot).admin_snapshot.invalidate().await;
            respond_user(pool, id, response).await
        }
        Err(error) if store::is_conflict(&error) => {
            json_error(response, StatusCode::CONFLICT, "login already in use");
        }
        Err(error) if store::is_unknown_group(&error) => {
            json_error(response, StatusCode::NOT_FOUND, "group not found");
        }
        Err(error) => internal(response, error),
    }
}

/// `GET /api/users/{id}`.
#[handler]
async fn get_user(request: &mut Request, depot: &mut Depot, response: &mut Response) {
    let pool = state_pool(depot);
    let Some(id) = request.param::<i64>("id") else {
        json_error(response, StatusCode::BAD_REQUEST, "invalid user id");
        return;
    };
    respond_user(pool, id, response).await;
}

/// `PATCH /api/users/{id}`: profile, group, rate override and cap. The
/// balance is not patchable; it moves only through topup/adjust.
#[handler]
async fn patch_user(request: &mut Request, depot: &mut Depot, response: &mut Response) {
    let pool = state_pool(depot);
    let Some(id) = request.param::<i64>("id") else {
        json_error(response, StatusCode::BAD_REQUEST, "invalid user id");
        return;
    };
    let Ok(body) = request.parse_json::<UserPatchBody>().await else {
        json_error(response, StatusCode::BAD_REQUEST, "invalid JSON body");
        return;
    };
    if let Some(message) = invalid_limits(body.rate_bp.flatten(), body.max_concurrent) {
        json_error(response, StatusCode::BAD_REQUEST, message);
        return;
    }
    let patch = store::UserPatch {
        display_name: body.display_name.as_deref().map(str::trim),
        enabled: body.enabled,
        group_id: body.group_id,
        rate_bp: body.rate_bp,
        max_concurrent: body.max_concurrent,
    };
    match store::patch_user(pool, id, patch).await {
        Ok(true) => {
            state(depot).admin_snapshot.invalidate().await;
            respond_user(pool, id, response).await
        }
        Ok(false) => json_error(response, StatusCode::NOT_FOUND, "user not found"),
        Err(error) if store::is_unknown_group(&error) => {
            json_error(response, StatusCode::NOT_FOUND, "group not found");
        }
        Err(error) => internal(response, error),
    }
}

/// `GET /api/user-groups`: every group with its member count.
#[handler]
async fn list_user_groups(depot: &mut Depot, response: &mut Response) {
    let pool = state_pool(depot);
    match store::list_groups(pool).await {
        Ok(rows) => json_response(response, &json!({ "items": rows })),
        Err(error) => internal(response, error),
    }
}

/// `POST /api/user-groups`: create a group and return its row.
#[handler]
async fn create_user_group(request: &mut Request, depot: &mut Depot, response: &mut Response) {
    let pool = state_pool(depot);
    let Ok(body) = request.parse_json::<GroupCreateBody>().await else {
        json_error(response, StatusCode::BAD_REQUEST, "invalid JSON body");
        return;
    };
    let name = body.name.trim();
    if name.is_empty() {
        json_error(response, StatusCode::BAD_REQUEST, "name is required");
        return;
    }
    let rate_bp = body.rate_bp.unwrap_or(DEFAULT_GROUP_RATE_BP);
    if let Some(message) = invalid_limits(Some(rate_bp), None) {
        json_error(response, StatusCode::BAD_REQUEST, message);
        return;
    }
    match store::create_group(pool, name, rate_bp, body.route_aliases.as_deref()).await {
        Ok(id) => {
            state(depot).admin_snapshot.invalidate().await;
            respond_group(pool, id, response).await
        }
        Err(error) if store::is_conflict(&error) => {
            json_error(response, StatusCode::CONFLICT, "group name already in use");
        }
        Err(error) => internal(response, error),
    }
}

/// `PATCH /api/user-groups/{id}`: name, rate and route whitelist.
#[handler]
async fn patch_user_group(request: &mut Request, depot: &mut Depot, response: &mut Response) {
    let pool = state_pool(depot);
    let Some(id) = request.param::<i64>("id") else {
        json_error(response, StatusCode::BAD_REQUEST, "invalid group id");
        return;
    };
    let Ok(body) = request.parse_json::<GroupPatchBody>().await else {
        json_error(response, StatusCode::BAD_REQUEST, "invalid JSON body");
        return;
    };
    let name = body.name.as_deref().map(str::trim);
    if name.is_some_and(str::is_empty) {
        json_error(response, StatusCode::BAD_REQUEST, "name must not be empty");
        return;
    }
    if let Some(message) = invalid_limits(body.rate_bp, None) {
        json_error(response, StatusCode::BAD_REQUEST, message);
        return;
    }
    let patch = store::GroupPatch {
        name,
        rate_bp: body.rate_bp,
        route_aliases: body.route_aliases.as_ref().map(Option::as_deref),
    };
    match store::patch_group(pool, id, patch).await {
        Ok(true) => {
            state(depot).admin_snapshot.invalidate().await;
            respond_group(pool, id, response).await
        }
        Ok(false) => json_error(response, StatusCode::NOT_FOUND, "group not found"),
        Err(error) if store::is_conflict(&error) => {
            json_error(response, StatusCode::CONFLICT, "group name already in use");
        }
        Err(error) => internal(response, error),
    }
}

/// Shared body of topup/adjust: validate, write the entry with the balance
/// change, and answer with the entry and the new balance.
async fn credit_user(
    request: &mut Request,
    depot: &Depot,
    response: &mut Response,
    kind: store::CreditKind,
) {
    let pool = state_pool(depot);
    let Some(id) = request.param::<i64>("id") else {
        json_error(response, StatusCode::BAD_REQUEST, "invalid user id");
        return;
    };
    let Ok(body) = request.parse_json::<CreditBody>().await else {
        json_error(response, StatusCode::BAD_REQUEST, "invalid JSON body");
        return;
    };
    let note = body.note.as_deref().map_or("", str::trim);
    let amount = match crate::billing::credit_amount(kind, &body.amount_usd, note) {
        Ok(amount) => amount,
        Err(message) => {
            json_error(response, StatusCode::BAD_REQUEST, message);
            return;
        }
    };
    let operator = body
        .operator
        .as_deref()
        .map(str::trim)
        .filter(|operator| !operator.is_empty())
        .unwrap_or("admin");
    match store::credit(pool, id, kind, amount, note, operator).await {
        Ok(Some(entry)) => {
            state(depot).admin_snapshot.invalidate().await;
            let balance = entry.balance_after_microus;
            json_response(
                response,
                &json!({
                    "entry": entry,
                    "balance_microus": balance,
                    "balance_usd": crate::billing::format_usd(balance),
                }),
            );
        }
        Ok(None) => json_error(response, StatusCode::NOT_FOUND, "user not found"),
        Err(store::CreditError::Overflow) => {
            json_error(
                response,
                StatusCode::BAD_REQUEST,
                "the new balance would overflow",
            );
        }
        Err(store::CreditError::Database(error)) => internal(response, error.into()),
    }
}

/// `POST /api/users/{id}/topup` `{amount_usd, note?, operator?}`.
#[handler]
async fn topup_user(request: &mut Request, depot: &mut Depot, response: &mut Response) {
    credit_user(request, depot, response, store::CreditKind::Topup).await;
}

/// `POST /api/users/{id}/adjust` `{amount_usd, note, operator?}`.
#[handler]
async fn adjust_user(request: &mut Request, depot: &mut Depot, response: &mut Response) {
    credit_user(request, depot, response, store::CreditKind::Adjust).await;
}

/// `GET /api/users/{id}/entries?before_id&limit`: the user's ledger,
/// newest first.
#[handler]
async fn list_user_entries(request: &mut Request, depot: &mut Depot, response: &mut Response) {
    let pool = state_pool(depot);
    let Some(id) = request.param::<i64>("id") else {
        json_error(response, StatusCode::BAD_REQUEST, "invalid user id");
        return;
    };
    let Ok(query) = request.parse_queries::<EntriesQuery>() else {
        json_error(
            response,
            StatusCode::BAD_REQUEST,
            "invalid query (before_id, limit)",
        );
        return;
    };
    match store::get_user(pool, id).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            json_error(response, StatusCode::NOT_FOUND, "user not found");
            return;
        }
        Err(error) => {
            internal(response, error);
            return;
        }
    }
    let limit = crate::billing::entry_page_limit(query.limit);
    match store::list_entries(pool, id, None, query.before_id, limit).await {
        Ok(rows) => json_response(response, &json!({ "items": rows })),
        Err(error) => internal(response, error.into()),
    }
}

/// `GET /api/users/{id}/reconcile`: stored balance against the ledger sum,
/// each owned key's stored spend against the sum of its charges, and the
/// request log's charge total against the ledger's (requests younger than the
/// settlement grace are excluded: they may still be buffered).
#[handler]
async fn reconcile_user(request: &mut Request, depot: &mut Depot, response: &mut Response) {
    let pool = state_pool(depot);
    let Some(id) = request.param::<i64>("id") else {
        json_error(response, StatusCode::BAD_REQUEST, "invalid user id");
        return;
    };
    let settled_before = chrono::Utc::now() - crate::relay::ledger_writer::SETTLEMENT_GRACE;
    match store::reconcile_user(pool, id, settled_before).await {
        // Serialized as the type the GUI deserializes (it flattens the
        // reconciliation), so a new field there needs no edit here.
        Ok(Some(report)) => json_response(
            response,
            &store::ReconcileReport {
                consistent: report.is_consistent(),
                report,
            },
        ),
        Ok(None) => json_error(response, StatusCode::NOT_FOUND, "user not found"),
        Err(error) => internal(response, error.into()),
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
    let message = match probe {
        crate::admin_ops::ProbeError::Kiro(_) => "upstream probe failed".to_owned(),
        crate::admin_ops::ProbeError::Regular(_) => format!("upstream probe failed: {probe}"),
    };
    let _ = response.body(message);
    true
}

fn internal(response: &mut Response, error: anyhow::Error) {
    tracing::error!("admin api: {error:#}");
    response.status_code(StatusCode::INTERNAL_SERVER_ERROR);
    let _ = response.body("internal error");
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
        .push(Router::with_path("providers/kiro").post(find_or_create_kiro_provider))
        .push(
            Router::with_path("providers/{id}")
                .get(get_provider)
                .patch(update_provider)
                .delete(delete_provider),
        )
        .push(Router::with_path("providers/{id}/if-empty").delete(delete_provider_if_empty))
        .push(
            Router::with_path("providers/{id}/keys")
                .get(list_keys)
                .post(create_key),
        )
        .push(Router::with_path("providers/{id}/kiro-key").post(upsert_kiro_key))
        .push(Router::with_path("providers/{id}/kiro-import").post(import_kiro_key))
        .push(Router::with_path("providers/{id}/opencode-login").post(start_opencode_login))
        .push(
            Router::with_path("opencode-logins/{session}")
                .get(opencode_login_status)
                .delete(cancel_opencode_login),
        )
        .push(Router::with_path("openai-logins").post(start_openai_login))
        .push(
            Router::with_path("openai-logins/{session}")
                .get(openai_login_status)
                .delete(cancel_openai_login),
        )
        .push(Router::with_path("providers/{id}/cursor-login").post(start_cursor_login))
        .push(
            Router::with_path("cursor-logins/{session}")
                .get(cursor_login_status)
                .delete(cancel_cursor_login),
        )
        .push(
            Router::with_path("providers/{id}/keys/{key_id}")
                .patch(patch_key)
                .delete(delete_key),
        )
        .push(Router::with_path("providers/{id}/keys/{key_id}/reveal").get(reveal_key))
        .push(Router::with_path("keys/order").put(reorder_keys))
        .push(Router::with_path("key-groups").post(create_key_group))
        .push(
            Router::with_path("key-groups/{id}")
                .patch(rename_key_group)
                .delete(delete_key_group),
        )
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
        .push(Router::with_path("users").get(list_users).post(create_user))
        .push(
            Router::with_path("users/{id}")
                .get(get_user)
                .patch(patch_user),
        )
        .push(Router::with_path("users/{id}/topup").post(topup_user))
        .push(Router::with_path("users/{id}/adjust").post(adjust_user))
        .push(Router::with_path("users/{id}/entries").get(list_user_entries))
        .push(Router::with_path("users/{id}/reconcile").get(reconcile_user))
        .push(
            Router::with_path("user-groups")
                .get(list_user_groups)
                .post(create_user_group),
        )
        .push(Router::with_path("user-groups/{id}").patch(patch_user_group))
        .push(Router::with_path("keys/validate").post(validate_key))
        .push(
            Router::with_path("keys/{id}/models")
                .get(list_key_models)
                .put(save_key_models),
        )
        .push(Router::with_path("chat-models").get(chat_models))
        .push(Router::with_path("concurrency").get(concurrency_usage))
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
    /// The static credential. Absent/empty is only valid for a Kiro OIDC key.
    #[serde(default)]
    api_key: Option<String>,
    /// `static` (default), `kiro_oidc` or `opencode_oauth`; decides which
    /// credential field the new row carries. Unknown values are rejected by the
    /// resolver.
    #[serde(default)]
    auth_kind: Option<String>,
    /// The OAuth bundle, raw: its shape follows `auth_kind`, so the resolver
    /// decodes it as that kind's bundle instead of this body guessing a type.
    #[serde(default)]
    oauth: Option<serde_json::Value>,
    /// Per-key in-flight cap; absent or null = unlimited.
    #[serde(default)]
    max_concurrency: Option<i32>,
    /// Model whitelist; absent or null = unrestricted.
    #[serde(default)]
    allowed_models: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct KiroKeyBody {
    label: String,
    oauth: KiroOAuth,
    /// Absent preserves an existing cap; null clears it; a positive number sets it.
    #[serde(default, deserialize_with = "crate::tri_state::deserialize")]
    max_concurrency: Option<Option<i32>>,
    /// Groups to add the key to (append only); absent/null = untouched.
    #[serde(default)]
    group_ids: Option<Vec<i64>>,
}

/// Raw Kiro import body. `credentials` stays a JSON value until the pure
/// allow-list parser extracts the runtime OAuth fields. It accepts a `kiro.rs`
/// credential object/array or the IDE account export with nested credentials.
#[derive(Deserialize)]
struct KiroImportBody {
    label: String,
    #[serde(default)]
    account: usize,
    credentials: serde_json::Value,
    /// Absent preserves an existing cap; null clears it; a positive number sets it.
    #[serde(default, deserialize_with = "crate::tri_state::deserialize")]
    max_concurrency: Option<Option<i32>>,
    /// Groups to add the key to (append only); absent/null = untouched.
    #[serde(default)]
    group_ids: Option<Vec<i64>>,
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
    #[serde(default, deserialize_with = "crate::tri_state::deserialize")]
    max_concurrency: Option<Option<i32>>,
    /// Three-state: absent = untouched, null/[] = clear to unrestricted,
    /// array = set the whitelist.
    #[serde(default, deserialize_with = "crate::tri_state::deserialize")]
    allowed_models: Option<Option<Vec<String>>>,
    /// Replacement OAuth bundle for an EXISTING Kiro OIDC key. Not accepted on
    /// a static key: a credential-kind conversion is not a patch.
    #[serde(default)]
    oauth: Option<KiroOAuth>,
    /// Group memberships: absent/null = untouched, array = the complete new
    /// set (`[]` leaves every group).
    #[serde(default)]
    group_ids: Option<Vec<i64>>,
    /// Archive state: absent/null = untouched, true = archive (keeps the
    /// first archive time), false = unarchive.
    #[serde(default)]
    archived: Option<bool>,
    /// 429 cooldown switch: absent/null = untouched, false = never cool this
    /// account down on a rate limit. Only a Kiro provider accepts it.
    #[serde(default)]
    rest_on_429: Option<bool>,
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
    // The credential shape depends on the provider's protocol, so read the
    // row first: a Kiro OIDC key is only valid under a `kiro` provider.
    let provider = match store::get_provider(pool, provider_id).await {
        Ok(Some(provider)) => provider,
        Ok(None) => {
            not_found(response, "provider");
            return;
        }
        Err(error) => {
            internal(response, error);
            return;
        }
    };
    let credential = match resolve_key_credential(
        &provider.protocol,
        body.auth_kind.as_deref(),
        body.api_key.as_deref(),
        body.oauth.as_ref(),
    ) {
        Ok(credential) => credential,
        Err(error) => {
            bad_request(response, error);
            return;
        }
    };
    // The token managers verify the committed row and reconcile it with any
    // in-memory refresh under the key lock before the first dispatch.
    let created_kiro = match &credential {
        KeyCredential::KiroOidc(oauth) => Some(oauth.clone()),
        KeyCredential::Static(_)
        | KeyCredential::OpencodeOauth(_)
        | KeyCredential::CursorOauth(_)
        | KeyCredential::OpenaiOauth(_) => None,
    };
    // The OpenCode bundle is adopted as imported: it came from this very
    // request, so there is no newer row to reconcile with and the first
    // dispatch needs no row read.
    let created_opencode = match &credential {
        KeyCredential::OpencodeOauth(oauth) => Some(oauth.clone()),
        KeyCredential::Static(_)
        | KeyCredential::KiroOidc(_)
        | KeyCredential::CursorOauth(_)
        | KeyCredential::OpenaiOauth(_) => None,
    };
    // The OpenAI bundle is adopted as imported, for the same reason.
    let created_openai = match &credential {
        KeyCredential::OpenaiOauth(oauth) => Some(oauth.clone()),
        KeyCredential::Static(_)
        | KeyCredential::KiroOidc(_)
        | KeyCredential::OpencodeOauth(_)
        | KeyCredential::CursorOauth(_) => None,
    };
    match crate::admin_ops::create_key(
        pool,
        provider_id,
        &body.label,
        credential,
        body.max_concurrency,
        body.allowed_models,
    )
    .await
    {
        Ok(id) => {
            if let Some(oauth) = created_kiro {
                // Verify the committed row and reconcile it with any newer
                // in-memory refresh under the token manager's key lock.
                state(depot)
                    .kiro_tokens
                    .adopt_persisted(pool, provider_id, id, oauth)
                    .await;
            }
            if let Some(oauth) = created_opencode {
                state(depot).opencode_tokens.adopt(id, oauth);
            }
            if let Some(oauth) = created_openai {
                state(depot).openai_tokens.adopt(id, oauth);
            }
            let _ = admin(depot).refresh_route_cache().await;
            response.status_code(StatusCode::CREATED);
            json_response(response, &json!({"id": id}));
        }
        Err(error) => bad_request(response, error),
    }
}

/// Import a raw `kiro.rs` credential object or account array. Parsing is
/// allow-listed and happens before the existing probe/upsert path, so raw
/// provider metadata is never persisted and a failed probe leaves the row
/// unchanged.
#[handler]
async fn import_kiro_key(request: &mut Request, depot: &mut Depot, response: &mut Response) {
    let Some(provider_id) = request.param::<i64>("id") else {
        response.status_code(StatusCode::BAD_REQUEST);
        let _ = response.body("invalid provider id");
        return;
    };
    let Ok(body) = request.parse_json::<KiroImportBody>().await else {
        response.status_code(StatusCode::BAD_REQUEST);
        let _ = response.body("invalid Kiro import body");
        return;
    };
    let oauth = match crate::kiro::parse_import_credentials(&body.credentials, body.account) {
        Ok(oauth) => oauth,
        Err(error) => {
            bad_request(response, error);
            return;
        }
    };
    match admin(depot)
        .upsert_kiro_key(
            provider_id,
            &body.label,
            oauth,
            body.group_ids.as_deref(),
            body.max_concurrency,
        )
        .await
    {
        Ok((id, created)) => {
            response.status_code(if created {
                StatusCode::CREATED
            } else {
                StatusCode::OK
            });
            json_response(response, &json!({"id": id, "created": created}));
        }
        Err(error) if try_bad_gateway(response, &error) => {}
        Err(error) => match error.downcast::<store::KiroUpsertError>() {
            Ok(store::KiroUpsertError::InvalidInput(message)) => {
                bad_request(response, anyhow::anyhow!(message))
            }
            Ok(store::KiroUpsertError::ProviderNotFound(_)) => not_found(response, "provider"),
            Ok(
                store::KiroUpsertError::ProviderProtocolMismatch(_)
                | store::KiroUpsertError::Conflict,
            ) => {
                response.status_code(StatusCode::CONFLICT);
                let _ = response.body("Kiro key conflicts with the existing provider or key");
            }
            Ok(store::KiroUpsertError::Internal(error)) => internal(response, error),
            Err(error) => internal(response, error),
        },
    }
}

/// `POST /api/providers/{id}/opencode-login` body: the OpenCode account to
/// create — or, with `key_id`, the existing OpenCode account to re-authenticate
/// (whose label and groups the row already owns).
#[derive(serde::Deserialize)]
struct OpencodeLoginBody {
    /// The label of the key a fresh login creates; ignored for a re-login, so
    /// an absent value is just the empty label (rejected by a fresh login).
    #[serde(default)]
    label: String,
    /// The existing `opencode_oauth` key to replace instead of creating one.
    #[serde(default)]
    key_id: Option<i64>,
    /// Groups to attach to the new key (ignored for a re-login).
    #[serde(default)]
    group_ids: Option<Vec<i64>>,
    #[serde(default)]
    max_concurrency: Option<i32>,
}

/// `POST /api/providers/{id}/opencode-login`: start a device login and answer
/// with the code the operator confirms in the browser. The login continues in
/// the background; this response does not wait for it.
#[handler]
async fn start_opencode_login(request: &mut Request, depot: &mut Depot, response: &mut Response) {
    let Some(provider_id) = request.param::<i64>("id") else {
        response.status_code(StatusCode::BAD_REQUEST);
        let _ = response.body("invalid provider id");
        return;
    };
    let Ok(body) = request.parse_json::<OpencodeLoginBody>().await else {
        response.status_code(StatusCode::BAD_REQUEST);
        let _ = response.body("invalid OpenCode login body");
        return;
    };
    let group_ids = body.group_ids.unwrap_or_default();
    match admin(depot)
        .start_opencode_login(
            provider_id,
            &body.label,
            body.key_id,
            &group_ids,
            body.max_concurrency,
        )
        .await
    {
        Ok(started) => {
            response.status_code(StatusCode::CREATED);
            json_response(response, &started);
        }
        Err(
            error @ (OpencodeLoginError::NotOpencodeProvider { .. }
            | OpencodeLoginError::Invalid(_)),
        ) => bad_request(response, anyhow::Error::new(error)),
        Err(OpencodeLoginError::ProviderNotFound(_)) => not_found(response, "provider"),
        Err(OpencodeLoginError::KeyNotFound(_)) => not_found(response, "OpenCode account key"),
        Err(OpencodeLoginError::LabelConflict(label)) => {
            response.status_code(StatusCode::CONFLICT);
            let _ = response.body(format!(
                "a key with label {label:?} already exists on this provider"
            ));
        }
        Err(OpencodeLoginError::Internal(error)) => internal(response, error),
    }
}

/// `GET /api/opencode-logins/{session}`: the login's state. Unknown ids (and
/// ids whose verdict aged out of the registry) are a 404 — the GUI treats that
/// as "start over", the same as every other unknown resource.
#[handler]
async fn opencode_login_status(request: &mut Request, depot: &mut Depot, response: &mut Response) {
    let Some(session) = request.param::<String>("session") else {
        response.status_code(StatusCode::BAD_REQUEST);
        let _ = response.body("invalid login session");
        return;
    };
    match admin(depot).opencode_login_status(&session) {
        Ok(Some(state)) => json_response(response, &state.status()),
        Ok(None) => not_found(response, "OpenCode login session"),
        Err(error) => internal(response, error),
    }
}

/// `DELETE /api/opencode-logins/{session}`: cancel a waiting login. A finished
/// login is not cancellable and reads as unknown (404).
#[handler]
async fn cancel_opencode_login(request: &mut Request, depot: &mut Depot, response: &mut Response) {
    let Some(session) = request.param::<String>("session") else {
        response.status_code(StatusCode::BAD_REQUEST);
        let _ = response.body("invalid login session");
        return;
    };
    match admin(depot).cancel_opencode_login(&session) {
        Ok(true) => {
            response.status_code(StatusCode::NO_CONTENT);
        }
        Ok(false) => not_found(response, "OpenCode login session"),
        Err(error) => internal(response, error),
    }
}

/// `POST /api/openai-logins`: start a device login and answer with the code the
/// operator types at OpenAI. The login continues in the background; this
/// response does not wait for it.
#[handler]
async fn start_openai_login(request: &mut Request, depot: &mut Depot, response: &mut Response) {
    let Ok(body) = request.parse_json::<OpenaiLoginRequest>().await else {
        response.status_code(StatusCode::BAD_REQUEST);
        let _ = response.body("invalid OpenAI login body");
        return;
    };
    let target = match body.into_target() {
        Ok(target) => target,
        Err(error) => {
            bad_request(response, anyhow::Error::new(error));
            return;
        }
    };
    match admin(depot).start_openai_login(target).await {
        Ok(started) => {
            response.status_code(StatusCode::CREATED);
            json_response(response, &started);
        }
        Err(
            error @ (OpenaiLoginError::NotOpenaiProvider { .. } | OpenaiLoginError::Invalid(_)),
        ) => bad_request(response, anyhow::Error::new(error)),
        Err(OpenaiLoginError::ProviderNotFound(_)) => not_found(response, "provider"),
        Err(OpenaiLoginError::KeyNotFound(_)) => not_found(response, "OpenAI account key"),
        Err(OpenaiLoginError::LabelConflict(label)) => {
            response.status_code(StatusCode::CONFLICT);
            let _ = response.body(format!(
                "a key with label {label:?} already exists on this provider"
            ));
        }
        Err(OpenaiLoginError::Internal(error)) => internal(response, error),
    }
}

/// `GET /api/openai-logins/{session}`: the login's state. Unknown ids (and ids
/// whose verdict aged out of the registry) are a 404, the GUI's "start over".
#[handler]
async fn openai_login_status(request: &mut Request, depot: &mut Depot, response: &mut Response) {
    let Some(session) = request.param::<String>("session") else {
        response.status_code(StatusCode::BAD_REQUEST);
        let _ = response.body("invalid login session");
        return;
    };
    match admin(depot).openai_login_status(&session) {
        Ok(Some(status)) => json_response(response, &status),
        Ok(None) => not_found(response, "OpenAI login session"),
        Err(error) => internal(response, error),
    }
}

/// `DELETE /api/openai-logins/{session}`: cancel a waiting login. A finished
/// login is not cancellable and reads as unknown (404).
#[handler]
async fn cancel_openai_login(request: &mut Request, depot: &mut Depot, response: &mut Response) {
    let Some(session) = request.param::<String>("session") else {
        response.status_code(StatusCode::BAD_REQUEST);
        let _ = response.body("invalid login session");
        return;
    };
    match admin(depot).cancel_openai_login(&session) {
        Ok(true) => {
            response.status_code(StatusCode::NO_CONTENT);
        }
        Ok(false) => not_found(response, "OpenAI login session"),
        Err(error) => internal(response, error),
    }
}

/// `POST /api/providers/{id}/cursor-login` body: same shape as the OpenCode
/// login body (`label`, optional `key_id` for a re-login, `group_ids`,
/// `max_concurrency`).
#[derive(serde::Deserialize)]
struct CursorLoginBody {
    #[serde(default)]
    label: String,
    #[serde(default)]
    key_id: Option<i64>,
    #[serde(default)]
    group_ids: Option<Vec<i64>>,
    #[serde(default)]
    max_concurrency: Option<i32>,
}

/// `POST /api/providers/{id}/cursor-login`: start a browser login and answer
/// with the URL the operator opens. The login continues in the background.
#[handler]
async fn start_cursor_login(request: &mut Request, depot: &mut Depot, response: &mut Response) {
    let Some(provider_id) = request.param::<i64>("id") else {
        response.status_code(StatusCode::BAD_REQUEST);
        let _ = response.body("invalid provider id");
        return;
    };
    let Ok(body) = request.parse_json::<CursorLoginBody>().await else {
        response.status_code(StatusCode::BAD_REQUEST);
        let _ = response.body("invalid Cursor login body");
        return;
    };
    let group_ids = body.group_ids.unwrap_or_default();
    match admin(depot)
        .start_cursor_login(
            provider_id,
            &body.label,
            body.key_id,
            &group_ids,
            body.max_concurrency,
        )
        .await
    {
        Ok(started) => {
            response.status_code(StatusCode::CREATED);
            json_response(response, &started);
        }
        Err(
            error @ (CursorLoginError::NotCursorProvider { .. } | CursorLoginError::Invalid(_)),
        ) => {
            bad_request(response, anyhow::Error::new(error));
        }
        Err(CursorLoginError::ProviderNotFound(_)) => not_found(response, "provider"),
        Err(CursorLoginError::KeyNotFound(_)) => not_found(response, "Cursor account key"),
        Err(CursorLoginError::LabelConflict(label)) => {
            response.status_code(StatusCode::CONFLICT);
            let _ = response.body(format!(
                "a key with label {label:?} already exists on this provider"
            ));
        }
        Err(CursorLoginError::Internal(error)) => internal(response, error),
    }
}

/// `GET /api/cursor-logins/{session}`: the login's state (never a token).
#[handler]
async fn cursor_login_status(request: &mut Request, depot: &mut Depot, response: &mut Response) {
    let Some(session) = request.param::<String>("session") else {
        response.status_code(StatusCode::BAD_REQUEST);
        let _ = response.body("invalid login session");
        return;
    };
    match admin(depot).cursor_login_status(&session) {
        Ok(Some(state)) => json_response(response, &state.status()),
        Ok(None) => not_found(response, "Cursor login session"),
        Err(error) => internal(response, error),
    }
}

/// `DELETE /api/cursor-logins/{session}`: cancel a waiting login. A finished
/// login is not cancellable and reads as unknown (404).
#[handler]
async fn cancel_cursor_login(request: &mut Request, depot: &mut Depot, response: &mut Response) {
    let Some(session) = request.param::<String>("session") else {
        response.status_code(StatusCode::BAD_REQUEST);
        let _ = response.body("invalid login session");
        return;
    };
    match admin(depot).cancel_cursor_login(&session) {
        Ok(true) => {
            response.status_code(StatusCode::NO_CONTENT);
        }
        Ok(false) => not_found(response, "Cursor login session"),
        Err(error) => internal(response, error),
    }
}

#[handler]
async fn upsert_kiro_key(request: &mut Request, depot: &mut Depot, response: &mut Response) {
    let Some(provider_id) = request.param::<i64>("id") else {
        response.status_code(StatusCode::BAD_REQUEST);
        let _ = response.body("invalid provider id");
        return;
    };
    let Ok(body) = request.parse_json::<KiroKeyBody>().await else {
        response.status_code(StatusCode::BAD_REQUEST);
        let _ = response.body("invalid Kiro key body");
        return;
    };
    match admin(depot)
        .upsert_kiro_key(
            provider_id,
            &body.label,
            body.oauth,
            body.group_ids.as_deref(),
            body.max_concurrency,
        )
        .await
    {
        Ok((id, created)) => {
            response.status_code(if created {
                StatusCode::CREATED
            } else {
                StatusCode::OK
            });
            json_response(response, &json!({"id": id, "created": created}));
        }
        Err(error) if try_bad_gateway(response, &error) => {}
        Err(error) => match error.downcast::<store::KiroUpsertError>() {
            Ok(store::KiroUpsertError::InvalidInput(message)) => {
                bad_request(response, anyhow::anyhow!(message))
            }
            Ok(store::KiroUpsertError::ProviderNotFound(_)) => not_found(response, "provider"),
            Ok(
                store::KiroUpsertError::ProviderProtocolMismatch(_)
                | store::KiroUpsertError::Conflict,
            ) => {
                response.status_code(StatusCode::CONFLICT);
                let _ = response.body("Kiro key conflicts with the existing provider or key");
            }
            Ok(store::KiroUpsertError::Internal(error)) => internal(response, error),
            Err(error) => internal(response, error),
        },
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
    // One store transaction applies the OAuth rotation (when supplied) and
    // every other field: all inputs are validated before the first write, so
    // a rejected field never leaves a rotated credential behind. The OAuth
    // branch only accepts an existing Kiro OIDC key — a static target is a
    // 400, a missing key a 404. After a successful patch the in-memory token
    // manager verifies and reconciles the committed row under the key lock; an
    // older refresh cannot overwrite it.
    // Cloned before the transaction: the match scrutinee's temporaries (the
    // `KeyPatch` borrowing the body) live through the arms.
    let rotated_oauth = body.oauth.clone();
    match store::patch_provider_key(
        pool,
        provider_id,
        key_id,
        store::KeyPatch {
            label: body.label.as_deref(),
            enabled: body.enabled,
            max_concurrency: body.max_concurrency,
            allowed_models: body.allowed_models,
            oauth: body.oauth.as_ref(),
            group_ids: body.group_ids.as_deref(),
            archived: body.archived,
            rest_on_429: body.rest_on_429,
        },
    )
    .await
    {
        Ok(true) => {
            if let Some(oauth) = rotated_oauth {
                // Verify the committed row and reconcile it with any newer
                // in-memory refresh under the token manager's key lock.
                state(depot)
                    .kiro_tokens
                    .adopt_persisted(pool, provider_id, key_id, oauth)
                    .await;
            }
            // Any patch may carry a credential replacement (Kiro's bundle
            // today), so the OpenCode cache drops its copy rather than risk
            // serving a bearer the row no longer authorizes. One cache miss
            // afterwards costs a single row read, never a refresh.
            state(depot).opencode_tokens.forget(key_id);
            // Same for a Cursor row: its cached bearer came from the credential
            // the patch may just have replaced (a static key's exchanged
            // token included).
            state(depot).cursor_tokens.forget(key_id);
            // And an OpenAI row's cached bundle: the next resolve rereads the
            // row instead of serving tokens the patch may have replaced.
            state(depot).openai_tokens.forget(key_id);
            let _ = admin(depot).refresh_route_cache().await;
            json_response(response, &json!({"ok": true}))
        }
        Ok(false) => not_found(response, "key"),
        Err(error) => bad_request(response, error),
    }
}

#[derive(Deserialize)]
struct KeyGroupBody {
    name: String,
}

/// Map a group write failure: a bad name is the caller's, a taken name a
/// conflict; storage detail stays in the log.
fn key_group_error(response: &mut Response, error: store::KeyGroupError) {
    match error {
        store::KeyGroupError::InvalidName(_) => {
            response.status_code(StatusCode::BAD_REQUEST);
            let _ = response.body(error.to_string());
        }
        store::KeyGroupError::NameTaken(_) => {
            response.status_code(StatusCode::CONFLICT);
            let _ = response.body(error.to_string());
        }
        store::KeyGroupError::Other(error) => internal(response, error.into()),
    }
}

/// `POST /api/key-groups` `{name}` → `{id}`. Groups are display-side only and
/// never enter the route cache, so no cache refresh follows a group write.
#[handler]
async fn create_key_group(request: &mut Request, depot: &mut Depot, response: &mut Response) {
    let Ok(body) = request.parse_json::<KeyGroupBody>().await else {
        response.status_code(StatusCode::BAD_REQUEST);
        let _ = response.body("invalid key group body");
        return;
    };
    match store::create_key_group(state_pool(depot), &body.name).await {
        Ok(id) => {
            state(depot).admin_snapshot.invalidate().await;
            json_response(response, &json!({"id": id}))
        }
        Err(error) => key_group_error(response, error),
    }
}

/// `PATCH /api/key-groups/{id}` `{name}`: rename.
#[handler]
async fn rename_key_group(request: &mut Request, depot: &mut Depot, response: &mut Response) {
    let Some(id) = request.param::<i64>("id") else {
        response.status_code(StatusCode::BAD_REQUEST);
        let _ = response.body("invalid id");
        return;
    };
    let Ok(body) = request.parse_json::<KeyGroupBody>().await else {
        response.status_code(StatusCode::BAD_REQUEST);
        let _ = response.body("invalid key group body");
        return;
    };
    match store::rename_key_group(state_pool(depot), id, &body.name).await {
        Ok(true) => {
            state(depot).admin_snapshot.invalidate().await;
            json_response(response, &json!({"ok": true}))
        }
        Ok(false) => not_found(response, "key group"),
        Err(error) => key_group_error(response, error),
    }
}

/// `DELETE /api/key-groups/{id}`: drops the group and its memberships; the
/// keys stay.
#[handler]
async fn delete_key_group(request: &mut Request, depot: &mut Depot, response: &mut Response) {
    let Some(id) = request.param::<i64>("id") else {
        response.status_code(StatusCode::BAD_REQUEST);
        let _ = response.body("invalid id");
        return;
    };
    match store::delete_key_group(state_pool(depot), id).await {
        Ok(true) => {
            state(depot).admin_snapshot.invalidate().await;
            json_response(response, &json!({"ok": true}))
        }
        Ok(false) => not_found(response, "key group"),
        Err(error) => internal(response, error),
    }
}

/// Global key reorder: `PUT /api/keys/order` `{ids: [..]}` must list every key exactly once →
/// position = array index, validated and written in one transaction. Kept for API clients; the
/// GUI no longer reorders keys, since `position` only breaks ties in a provider's expansion order.
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
            let _ = admin(depot).refresh_route_cache().await;
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
        Ok(Some(auth_kind)) => {
            if auth_kind == AuthKind::KiroOidc.as_str() {
                state(depot).kiro_tokens.remove(key_id);
            }
            if auth_kind == AuthKind::OpencodeOauth.as_str() {
                // Drop the cached bundle: nothing else holds an OpenCode bearer,
                // and a deleted row must never authenticate again.
                state(depot).opencode_tokens.forget(key_id);
            }
            // A Cursor bearer may be cached for a `cursor_oauth` row or for a
            // `static` key on a Cursor provider; the cache is keyed by row, so
            // forgetting an id that was never cached is a no-op.
            state(depot).cursor_tokens.forget(key_id);
            if auth_kind == AuthKind::OpenaiOauth.as_str() {
                // A deleted account must never authenticate again, and a
                // cached bundle would keep serving it.
                state(depot).openai_tokens.forget(key_id);
            }
            let _ = admin(depot).refresh_route_cache().await;
            json_response(response, &json!({"ok": true}))
        }
        Ok(None) => {
            response.status_code(StatusCode::NOT_FOUND);
            let _ = response.body("key not found");
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

#[cfg(test)]
mod tests {
    use super::sse_events;
    use crate::activity::ActivityEvent;
    use futures::StreamExt;

    #[tokio::test]
    async fn activity_sse_emits_repeated_heartbeats_and_later_activity() {
        let (sender, receiver) = tokio::sync::mpsc::channel(4);
        let mut stream = Box::pin(sse_events(receiver, std::time::Duration::ZERO));

        let first_heartbeat = stream
            .next()
            .await
            .expect("stream should stay open")
            .expect("heartbeat should render");
        assert_eq!(
            first_heartbeat.to_string(),
            ":alive\n\n",
            "first frame should be a heartbeat"
        );

        let second_heartbeat = stream
            .next()
            .await
            .expect("stream should stay open")
            .expect("heartbeat should render");
        assert_eq!(
            second_heartbeat.to_string(),
            ":alive\n\n",
            "second frame should be a heartbeat"
        );

        sender
            .send(ActivityEvent::Persisted)
            .await
            .expect("receiver is open");
        let activity = stream
            .next()
            .await
            .expect("activity stream should stay open")
            .expect("activity should render");
        assert_eq!(
            activity.to_string(),
            "data: {\"t\":\"persisted\"}\n\n",
            "activity should arrive after repeated heartbeats"
        );
    }
}
