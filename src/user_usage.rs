//! Self-service API for ordinary gateway-key users (`/user/*`).
//!
//! This surface is separate from the admin router. It accepts an enabled,
//! unexpired gateway key, or a currently valid portal session. Raw gateway
//! keys and key sessions are scoped to that one key; account sessions are
//! scoped to every key owned by that account. Callers cannot select another
//! scope through query parameters, and the admin key is never accepted here.
//!
//! Endpoints:
//! - `GET /user/me` — profile, group, effective rate, balance, the user's
//!   keys (full plaintext, so the client can copy them again) and 30-day usage
//! - `GET /user/me/entries?before_id&limit` — the user's ledger, newest first
//! - `GET /user/usage/window`, `GET /user/usage/trend` — usage aggregates;
//!   the trend `split` is `route` (default), `model` or `client` — `provider`
//!   and `user` are refused with 400 (users never see upstream providers)
//! - `/user/keys` — self-service key management, see [`crate::user_keys`]

use std::sync::Arc;

use salvo::http::{StatusCode, header};
use salvo::prelude::*;
use serde::Deserialize;
use serde_json::json;

use crate::admin::AdminKey;
use crate::api::AppState;
use crate::store::{self, CallerFilter, Principal};

/// What the authenticated credential may see, injected by [`user_auth`] for
/// the handlers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UserScope {
    /// Every key of one real user, as granted by an account session.
    User(i64),
    /// One gateway key, as granted by a raw key or key session.
    Key { user_id: i64, key_id: i64 },
}

impl UserScope {
    /// The scope granted to a raw gateway key.
    fn key(principal: &Principal) -> Self {
        UserScope::Key {
            user_id: principal.user_id,
            key_id: principal.key_id,
        }
    }

    /// The owning user's id.
    pub(crate) fn user_id(self) -> i64 {
        match self {
            UserScope::User(user_id) | UserScope::Key { user_id, .. } => user_id,
        }
    }

    /// The single key this scope is limited to, if any.
    pub(crate) fn key_id(self) -> Option<i64> {
        match self {
            UserScope::User(_) => None,
            UserScope::Key { key_id, .. } => Some(key_id),
        }
    }

    fn auth(self) -> AuthView {
        match self {
            Self::User(_) => AuthView {
                kind: "account",
                key_id: None,
            },
            Self::Key { key_id, .. } => AuthView {
                kind: "key",
                key_id: Some(key_id),
            },
        }
    }

    /// Whether key `key_id` (already known to belong to [`Self::user_id`])
    /// is visible in this scope.
    pub(crate) fn covers_key(self, key_id: i64) -> bool {
        self.key_id().is_none_or(|own| own == key_id)
    }

    /// The usage-row filter of this scope.
    fn caller_filter(self) -> CallerFilter {
        match self {
            UserScope::User(user_id) => CallerFilter::User(user_id),
            UserScope::Key { key_id, .. } => CallerFilter::Key(key_id),
        }
    }
}

/// Extract a non-empty Bearer token from an Authorization header.
fn bearer_token(value: &str) -> Option<&str> {
    let value = value.trim();
    let prefix = value.get(..7)?;
    if !prefix.eq_ignore_ascii_case("Bearer ") {
        return None;
    }
    let token = value[7..].trim();
    (!token.is_empty()).then_some(token)
}

/// Resolve the usage scope of a raw authenticated key without accepting client
/// input. The admin key is refused, as is a key the relay hoop would refuse
/// (disabled key or user, expired key — [`crate::api::refusal`]).
fn user_scope(
    token: &str,
    principal: &Principal,
    admin_key: &AdminKey,
    now: jiff::Timestamp,
) -> Result<UserScope, String> {
    if is_admin_key(token, admin_key) {
        return Err("admin key is not valid for user usage".to_owned());
    }
    match crate::api::refusal(principal, now) {
        Some(reason) => Err(reason),
        None => Ok(UserScope::key(principal)),
    }
}

fn is_admin_key(token: &str, admin_key: &AdminKey) -> bool {
    crate::admin::constant_time_eq(
        &crate::db::sha256_hex(token),
        &crate::db::sha256_hex(&admin_key.0),
    )
}

/// Query parameters that pick a scope on the admin usage endpoints. The user
/// endpoints are always scoped to the authenticated user, so any of them is
/// refused rather than silently ignored.
const SCOPE_PARAMS: [&str; 4] = ["caller", "label", "key_id", "user_id"];

fn scope_override_requested(present: impl Fn(&str) -> bool) -> bool {
    SCOPE_PARAMS.iter().any(|name| present(name))
}

pub(crate) fn state(depot: &Depot) -> Result<&Arc<AppState>, ()> {
    depot.get_typed::<Arc<AppState>>().map_err(|_| ())
}

pub(crate) fn json_response<T: serde::Serialize>(response: &mut Response, value: &T) {
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/json"),
    );
    let _ = response.body(serde_json::to_vec(value).unwrap_or_default());
}

pub(crate) fn internal(response: &mut Response, error: anyhow::Error) {
    tracing::error!("user usage api: {error:#}");
    response.status_code(StatusCode::INTERNAL_SERVER_ERROR);
    let _ = response.body("internal error");
}

/// Authenticate exactly one ordinary-user Bearer credential. Unlike the relay
/// auth hoop, this surface has no loopback or self-naming fallback.
#[handler]
async fn user_auth(
    request: &mut Request,
    response: &mut Response,
    depot: &mut Depot,
    ctrl: &mut FlowCtrl,
) {
    let pool = match state(depot) {
        Ok(state) => state.pool.clone(),
        Err(()) => {
            response.status_code(StatusCode::INTERNAL_SERVER_ERROR);
            let _ = response.body("user usage state unavailable");
            ctrl.skip_rest();
            return;
        }
    };
    let admin_key = match depot.get_typed::<Arc<AdminKey>>() {
        Ok(admin_key) => admin_key,
        Err(_) => {
            response.status_code(StatusCode::INTERNAL_SERVER_ERROR);
            let _ = response.body("user usage admin key unavailable");
            ctrl.skip_rest();
            return;
        }
    };
    let token = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(bearer_token);
    let Some(token) = token else {
        response.status_code(StatusCode::UNAUTHORIZED);
        let _ = response.body("missing or invalid Bearer key");
        ctrl.skip_rest();
        return;
    };
    let scope = if crate::account_auth::is_portal_session_token(token) {
        let session = match crate::account_auth::lookup_portal_session(&pool, token).await {
            Ok(Some(session)) => session,
            Ok(None) => {
                response.status_code(StatusCode::UNAUTHORIZED);
                let _ = response.body("invalid portal session");
                ctrl.skip_rest();
                return;
            }
            Err(error) => {
                tracing::warn!("portal session lookup failed: {error:#}");
                response.status_code(StatusCode::SERVICE_UNAVAILABLE);
                let _ = response.body("portal session lookup failed");
                ctrl.skip_rest();
                return;
            }
        };
        match session.key_id {
            Some(key_id) => UserScope::Key {
                user_id: session.user_id,
                key_id,
            },
            None => UserScope::User(session.user_id),
        }
    } else {
        let principal = match store::authenticate_principal(&pool, token).await {
            Ok(Some(principal)) => principal,
            Ok(None) => {
                response.status_code(StatusCode::UNAUTHORIZED);
                let _ = response.body("invalid gateway key");
                ctrl.skip_rest();
                return;
            }
            Err(error) => {
                tracing::warn!("user usage gateway key lookup failed: {error:#}");
                response.status_code(StatusCode::SERVICE_UNAVAILABLE);
                let _ = response.body("gateway key lookup failed");
                ctrl.skip_rest();
                return;
            }
        };
        match user_scope(token, &principal, admin_key, jiff::Timestamp::now()) {
            Ok(scope) => scope,
            Err(reason) => {
                response.status_code(StatusCode::UNAUTHORIZED);
                let _ = response.body(reason);
                ctrl.skip_rest();
                return;
            }
        }
    };
    {
        depot.insert_typed(scope);
    }
}

#[derive(Deserialize)]
struct EntriesQuery {
    #[serde(default)]
    before_id: Option<i64>,
    #[serde(default)]
    limit: Option<i64>,
}

/// Window of the usage summary in `GET /user/me`.
const ME_USAGE_DAYS: i64 = 30;

/// The `GET /user/me` body: the caller's own account.
#[derive(serde::Serialize)]
struct MeView {
    auth: AuthView,
    user: MeUser,
    group: MeGroup,
    /// The effective rate: the user override, else the group rate.
    rate_bp: i64,
    balance_microus: i64,
    /// `balance_microus` as a decimal USD string.
    balance_usd: String,
    /// Every key the user owns, full plaintext included.
    keys: Vec<store::GatewayKeyRow>,
    /// Usage over the last [`ME_USAGE_DAYS`] days in the authenticated scope.
    usage_30d: UserUsageWindow,
}

/// User-facing usage omits the internal catalog price while retaining charged
/// usage and the fields needed by the portal charts.
#[derive(serde::Serialize)]
struct UserUsageWindow {
    input_tokens: i64,
    output_tokens: i64,
    cached_input_tokens: i64,
    requests: i64,
    failed: i64,
    charged_microus: i64,
    unpriced: i64,
    timed_output: i64,
    timed_ms: i64,
    decode_ms: i64,
}

impl From<store::UsageWindow> for UserUsageWindow {
    fn from(window: store::UsageWindow) -> Self {
        Self {
            input_tokens: window.input_tokens,
            output_tokens: window.output_tokens,
            cached_input_tokens: window.cached_input_tokens,
            requests: window.requests,
            failed: window.failed,
            charged_microus: window.charged_microus,
            unpriced: window.unpriced,
            timed_output: window.timed_output,
            timed_ms: window.timed_ms,
            decode_ms: window.decode_ms,
        }
    }
}

#[derive(serde::Serialize)]
struct UserTrendRow {
    bucket: String,
    category: Option<String>,
    input_tokens: i64,
    output_tokens: i64,
    cached_input_tokens: i64,
    requests: i64,
    failed: i64,
    charged_microus: i64,
    timed_output: i64,
    timed_ms: i64,
    decode_ms: i64,
}

impl From<store::TrendRow> for UserTrendRow {
    fn from(row: store::TrendRow) -> Self {
        Self {
            bucket: row.bucket,
            category: row.category,
            input_tokens: row.input_tokens,
            output_tokens: row.output_tokens,
            cached_input_tokens: row.cached_input_tokens,
            requests: row.requests,
            failed: row.failed,
            charged_microus: row.charged_microus,
            timed_output: row.timed_output,
            timed_ms: row.timed_ms,
            decode_ms: row.decode_ms,
        }
    }
}

#[derive(serde::Serialize)]
struct UserEntryRow {
    id: i64,
    user_id: i64,
    kind: String,
    amount_microus: i64,
    balance_after_microus: i64,
    request_id: Option<String>,
    rate_bp: Option<i64>,
    gateway_key_id: Option<i64>,
    note: String,
    operator: Option<String>,
    created_at: jiff::Timestamp,
}

impl From<store::EntryRow> for UserEntryRow {
    fn from(row: store::EntryRow) -> Self {
        Self {
            id: row.id,
            user_id: row.user_id,
            kind: row.kind,
            amount_microus: row.amount_microus,
            balance_after_microus: row.balance_after_microus,
            request_id: row.request_id,
            rate_bp: row.rate_bp,
            gateway_key_id: row.gateway_key_id,
            note: row.note,
            operator: row.operator,
            created_at: row.created_at,
        }
    }
}

#[derive(serde::Serialize)]
struct AuthView {
    kind: &'static str,
    key_id: Option<i64>,
}

/// The profile part of [`MeView`].
#[derive(serde::Serialize)]
struct MeUser {
    id: i64,
    login: String,
    display_name: String,
    enabled: bool,
    max_concurrent: i32,
    created_at: jiff::Timestamp,
}

/// The group part of [`MeView`]; `rate_bp` is the group's own rate.
#[derive(serde::Serialize)]
struct MeGroup {
    id: i64,
    name: String,
    rate_bp: i64,
}

#[derive(Deserialize)]
struct WindowQuery {
    #[serde(default)]
    since: Option<jiff::Timestamp>,
    #[serde(default)]
    until: Option<jiff::Timestamp>,
    #[serde(default)]
    days: Option<i32>,
}

#[derive(Deserialize)]
struct TrendQuery {
    #[serde(default)]
    since: Option<jiff::Timestamp>,
    #[serde(default)]
    until: Option<jiff::Timestamp>,
    #[serde(default)]
    days: Option<i32>,
    #[serde(default)]
    split: Option<store::TrendSplit>,
    #[serde(default)]
    offset_seconds: Option<i64>,
}

/// The trend split a user may ask for: route (the default), model or
/// client. Provider would expose upstream accounts and user is meaningless
/// within one user's scope, so both are refused.
fn user_split(split: Option<store::TrendSplit>) -> Result<store::TrendSplit, &'static str> {
    use store::TrendSplit;
    match split {
        None => Ok(TrendSplit::Route),
        Some(split @ (TrendSplit::Route | TrendSplit::Model | TrendSplit::Client)) => Ok(split),
        Some(TrendSplit::Provider | TrendSplit::User) => {
            Err("split must be route, model or client")
        }
    }
}

fn resolve_window(
    since: Option<jiff::Timestamp>,
    until: Option<jiff::Timestamp>,
    days: Option<i32>,
) -> (jiff::Timestamp, jiff::Timestamp) {
    let until = until.unwrap_or_else(jiff::Timestamp::now);
    let since = since.unwrap_or_else(|| {
        until - jiff::SignedDuration::from_hours(24 * i64::from(days.unwrap_or(7).clamp(1, 365)))
    });
    (
        since.clamp(until - jiff::SignedDuration::from_hours(24 * 370), until),
        until,
    )
}

fn client_scope(request: &Request, depot: &Depot) -> Result<CallerFilter, StatusCode> {
    if scope_override_requested(|name| request.queries().get(name).is_some()) {
        return Err(StatusCode::BAD_REQUEST);
    }
    depot
        .get_typed::<UserScope>()
        .map(|scope| scope.caller_filter())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

#[handler]
async fn usage_window(request: &mut Request, depot: &mut Depot, response: &mut Response) {
    let query = match request.parse_queries::<WindowQuery>() {
        Ok(query) => query,
        Err(_) => {
            response.status_code(StatusCode::BAD_REQUEST);
            let _ = response.body("invalid window query (since/until as RFC3339)");
            return;
        }
    };
    let (since, until) = resolve_window(query.since, query.until, query.days);
    let caller = match client_scope(request, depot) {
        Ok(caller) => caller,
        Err(status) => {
            response.status_code(status);
            let _ =
                response.body("scope parameters (caller, label, key_id, user_id) are not accepted");
            return;
        }
    };
    let pool = match state(depot) {
        Ok(state) => &state.pool,
        Err(()) => {
            response.status_code(StatusCode::INTERNAL_SERVER_ERROR);
            let _ = response.body("user usage state unavailable");
            return;
        }
    };
    match store::usage_window(pool, since, until, Some(caller)).await {
        Ok(window) => json_response(response, &UserUsageWindow::from(window)),
        Err(error) => internal(response, error),
    }
}

#[handler]
async fn usage_trend(request: &mut Request, depot: &mut Depot, response: &mut Response) {
    let query = match request.parse_queries::<TrendQuery>() {
        Ok(query) => query,
        Err(_) => {
            response.status_code(StatusCode::BAD_REQUEST);
            let _ = response
                .body("invalid trend query (since/until as RFC3339, split, offset_seconds)");
            return;
        }
    };
    const MAX_OFFSET_SECONDS: i64 = 14 * 3600;
    let offset_seconds = query.offset_seconds.unwrap_or(0);
    if offset_seconds.unsigned_abs() > MAX_OFFSET_SECONDS as u64 {
        response.status_code(StatusCode::BAD_REQUEST);
        let _ = response.body("offset_seconds must be within ±14 hours");
        return;
    }
    let split = match user_split(query.split) {
        Ok(split) => split,
        Err(message) => {
            response.status_code(StatusCode::BAD_REQUEST);
            let _ = response.body(message);
            return;
        }
    };
    let (since, until) = resolve_window(query.since, query.until, query.days);
    let caller = match client_scope(request, depot) {
        Ok(caller) => caller,
        Err(status) => {
            response.status_code(status);
            let _ =
                response.body("scope parameters (caller, label, key_id, user_id) are not accepted");
            return;
        }
    };
    let pool = match state(depot) {
        Ok(state) => &state.pool,
        Err(()) => {
            response.status_code(StatusCode::INTERNAL_SERVER_ERROR);
            let _ = response.body("user usage state unavailable");
            return;
        }
    };
    match store::usage_trend(
        pool,
        since,
        until,
        split,
        jiff::SignedDuration::from_secs(offset_seconds),
        Some(caller),
    )
    .await
    {
        Ok(rows) => {
            let rows: Vec<UserTrendRow> = rows.into_iter().map(UserTrendRow::from).collect();
            json_response(response, &json!({ "items": rows }));
        }
        Err(error) => internal(response, error),
    }
}

/// The authenticated scope; `None` only if the auth hoop did not run.
pub(crate) fn scope(depot: &Depot) -> Option<UserScope> {
    depot.get_typed::<UserScope>().ok().copied()
}

/// `GET /user/me`: the caller's own account. The response carries the
/// scope's full gateway keys by design (they stay retrievable); nothing here
/// logs the body.
#[handler]
async fn me(depot: &mut Depot, response: &mut Response) {
    let (Ok(state), Some(scope)) = (state(depot), scope(depot)) else {
        response.status_code(StatusCode::INTERNAL_SERVER_ERROR);
        let _ = response.body("user usage state unavailable");
        return;
    };
    let pool = &state.pool;
    let user = match store::get_user(pool, scope.user_id()).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            response.status_code(StatusCode::UNAUTHORIZED);
            let _ = response.body("user no longer exists");
            return;
        }
        Err(error) => {
            internal(response, error);
            return;
        }
    };
    let until = jiff::Timestamp::now();
    let since = until - jiff::SignedDuration::from_hours(24 * ME_USAGE_DAYS);
    let (mut keys, usage) = match futures::try_join!(
        store::list_gateway_keys(pool, Some(scope.user_id())),
        store::usage_window(pool, since, until, Some(scope.caller_filter())),
    ) {
        Ok(results) => results,
        Err(error) => {
            internal(response, error);
            return;
        }
    };
    keys.retain(|key| scope.covers_key(key.id));
    let rate_bp = crate::billing::effective_rate_bp(user.rate_bp, user.group_rate_bp);
    let view = MeView {
        auth: scope.auth(),
        user: MeUser {
            id: user.id,
            login: user.login,
            display_name: user.display_name,
            enabled: user.enabled,
            max_concurrent: user.max_concurrent,
            created_at: user.created_at,
        },
        group: MeGroup {
            id: user.group_id,
            name: user.group_name,
            rate_bp: user.group_rate_bp,
        },
        rate_bp,
        balance_microus: user.balance_microus,
        balance_usd: crate::billing::format_usd(user.balance_microus),
        keys,
        usage_30d: usage.into(),
    };
    json_response(response, &view);
}

/// `GET /user/me/entries?before_id&limit`: the caller's ledger, newest
/// first; a one-key scope sees only the entries made through that key.
#[handler]
async fn me_entries(request: &mut Request, depot: &mut Depot, response: &mut Response) {
    let Ok(query) = request.parse_queries::<EntriesQuery>() else {
        response.status_code(StatusCode::BAD_REQUEST);
        let _ = response.body("invalid query (before_id, limit)");
        return;
    };
    let (Ok(state), Some(scope)) = (state(depot), scope(depot)) else {
        response.status_code(StatusCode::INTERNAL_SERVER_ERROR);
        let _ = response.body("user usage state unavailable");
        return;
    };
    let limit = crate::billing::entry_page_limit(query.limit);
    match store::list_entries(
        &state.pool,
        scope.user_id(),
        scope.key_id(),
        query.before_id,
        limit,
    )
    .await
    {
        Ok(rows) => {
            let rows: Vec<UserEntryRow> = rows.into_iter().map(UserEntryRow::from).collect();
            json_response(response, &json!({ "items": rows }));
        }
        Err(error) => internal(response, error.into()),
    }
}

/// `/user/*` sub-router: the caller's account and ledger, the two usage
/// endpoints and the caller's own keys ([`crate::user_keys`]). Admin
/// management, request-log, and streaming routes are intentionally absent.
pub fn router(admin_key: Arc<AdminKey>) -> Router {
    Router::with_path("user")
        .hoop(salvo::affix_state::inject(admin_key))
        .hoop(user_auth)
        .push(
            Router::with_path("me")
                .get(me)
                .push(Router::with_path("entries").get(me_entries)),
        )
        .push(
            Router::with_path("usage")
                .push(Router::with_path("window").get(usage_window))
                .push(Router::with_path("trend").get(usage_trend)),
        )
        .push(crate::user_keys::router())
        .push(crate::user_topup::router())
}
