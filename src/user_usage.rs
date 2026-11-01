//! Read-only self-service API for ordinary gateway-key users (`/user/*`).
//!
//! This surface is separate from the admin router. It authenticates one
//! gateway key that is enabled, unexpired and owned by an enabled user, and
//! scopes every read to that user — every key the user owns, by `user_id`.
//! Callers cannot select another scope through query parameters, and the
//! admin key is never accepted here.
//!
//! Endpoints:
//! - `GET /user/me` — profile, group, effective rate, balance, the user's
//!   keys (full plaintext, so the client can copy them again) and 30-day usage
//! - `GET /user/me/entries?before_id&limit` — the user's ledger, newest first
//! - `GET /user/usage/window`, `GET /user/usage/trend` — usage aggregates

use std::sync::Arc;

use salvo::http::{StatusCode, header};
use salvo::prelude::*;
use serde::Deserialize;
use serde_json::json;

use crate::admin::AdminKey;
use crate::api::AppState;
use crate::store::{self, CallerFilter, Principal};

/// The authenticated user's id, injected by [`user_auth`] for the handlers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct UserScope(i64);

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

/// Resolve the usage scope of an authenticated key without accepting client
/// input: the admin key is refused, as is a key the relay hoop would refuse
/// (disabled key or user, expired key — [`crate::api::refusal`]).
fn user_scope(
    token: &str,
    principal: &Principal,
    admin_key: &AdminKey,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<UserScope, String> {
    if is_admin_key(token, admin_key) {
        return Err("admin key is not valid for user usage".to_owned());
    }
    match crate::api::refusal(principal, now) {
        Some(reason) => Err(reason),
        None => Ok(UserScope(principal.user_id)),
    }
}

fn is_admin_key(token: &str, admin_key: &AdminKey) -> bool {
    crate::admin::constant_time_eq(
        &crate::db::sha256_hex(token),
        &crate::db::sha256_hex(&admin_key.0),
    )
}

fn scope_override_requested(caller: bool, label: bool) -> bool {
    caller || label
}

fn state(depot: &Depot) -> Result<&Arc<AppState>, ()> {
    depot.get_typed::<Arc<AppState>>().map_err(|_| ())
}

fn json_response<T: serde::Serialize>(response: &mut Response, value: &T) {
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/json"),
    );
    let _ = response.body(serde_json::to_vec(value).unwrap_or_default());
}

fn internal(response: &mut Response, error: anyhow::Error) {
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
    match user_scope(token, &principal, admin_key, chrono::Utc::now()) {
        Ok(scope) => {
            depot.insert_typed(scope);
        }
        Err(reason) => {
            response.status_code(StatusCode::UNAUTHORIZED);
            let _ = response.body(reason);
            ctrl.skip_rest();
        }
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

#[derive(Deserialize)]
struct WindowQuery {
    #[serde(default)]
    since: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default)]
    until: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default)]
    days: Option<i32>,
}

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
}

fn resolve_window(
    since: Option<chrono::DateTime<chrono::Utc>>,
    until: Option<chrono::DateTime<chrono::Utc>>,
    days: Option<i32>,
) -> (chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>) {
    let until = until.unwrap_or_else(chrono::Utc::now);
    let since = since.unwrap_or_else(|| {
        until - chrono::Duration::days(i64::from(days.unwrap_or(7).clamp(1, 365)))
    });
    (
        since.clamp(until - chrono::Duration::days(370), until),
        until,
    )
}

fn client_scope(request: &Request, depot: &Depot) -> Result<CallerFilter<'static>, StatusCode> {
    if scope_override_requested(
        request.queries().get("caller").is_some(),
        request.queries().get("label").is_some(),
    ) {
        return Err(StatusCode::BAD_REQUEST);
    }
    depot
        .get_typed::<UserScope>()
        .map(|scope| CallerFilter::User(scope.0))
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
            let _ = response.body("caller and label filters are not accepted");
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
        Ok(window) => json_response(response, &window),
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
    let (since, until) = resolve_window(query.since, query.until, query.days);
    let caller = match client_scope(request, depot) {
        Ok(caller) => caller,
        Err(status) => {
            response.status_code(status);
            let _ = response.body("caller and label filters are not accepted");
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
        query.split.unwrap_or(store::TrendSplit::Route),
        chrono::Duration::seconds(offset_seconds),
        Some(caller),
    )
    .await
    {
        Ok(rows) => json_response(response, &json!({ "items": rows })),
        Err(error) => internal(response, error),
    }
}

/// The authenticated user's id; `None` only if the auth hoop did not run.
fn scoped_user(depot: &Depot) -> Option<i64> {
    depot.get_typed::<UserScope>().ok().map(|scope| scope.0)
}

/// `GET /user/me`: the caller's own account. The response carries the
/// user's full gateway keys by design (they stay retrievable); nothing here
/// logs the body.
#[handler]
async fn me(depot: &mut Depot, response: &mut Response) {
    let (Ok(state), Some(user_id)) = (state(depot), scoped_user(depot)) else {
        response.status_code(StatusCode::INTERNAL_SERVER_ERROR);
        let _ = response.body("user usage state unavailable");
        return;
    };
    let pool = &state.pool;
    let user = match store::get_user(pool, user_id).await {
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
    let until = chrono::Utc::now();
    let since = until - chrono::Duration::days(ME_USAGE_DAYS);
    let (keys, usage) = match futures::try_join!(
        store::list_gateway_keys(pool, Some(user_id)),
        store::usage_window(pool, since, until, Some(CallerFilter::User(user_id))),
    ) {
        Ok(results) => results,
        Err(error) => {
            internal(response, error);
            return;
        }
    };
    let rate_bp = crate::billing::effective_rate_bp(user.rate_bp, user.group_rate_bp);
    json_response(
        response,
        &json!({
            "user": {
                "id": user.id,
                "login": user.login,
                "display_name": user.display_name,
                "enabled": user.enabled,
                "max_concurrent": user.max_concurrent,
                "created_at": user.created_at,
            },
            "group": {
                "id": user.group_id,
                "name": user.group_name,
                "rate_bp": user.group_rate_bp,
            },
            "rate_bp": rate_bp,
            "balance_microus": user.balance_microus,
            "balance_usd": crate::billing::format_usd(user.balance_microus),
            "keys": keys,
            "usage_30d": usage,
        }),
    );
}

/// `GET /user/me/entries?before_id&limit`: the caller's ledger, newest first.
#[handler]
async fn me_entries(request: &mut Request, depot: &mut Depot, response: &mut Response) {
    let Ok(query) = request.parse_queries::<EntriesQuery>() else {
        response.status_code(StatusCode::BAD_REQUEST);
        let _ = response.body("invalid query (before_id, limit)");
        return;
    };
    let (Ok(state), Some(user_id)) = (state(depot), scoped_user(depot)) else {
        response.status_code(StatusCode::INTERNAL_SERVER_ERROR);
        let _ = response.body("user usage state unavailable");
        return;
    };
    let limit = crate::billing::entry_page_limit(query.limit);
    match store::list_entries(&state.pool, user_id, query.before_id, limit).await {
        Ok(rows) => json_response(response, &json!({ "items": rows })),
        Err(error) => internal(response, error.into()),
    }
}

/// `/user/*` sub-router: the caller's account and ledger plus the two
/// usage endpoints, all read-only. Management, request-log, and streaming
/// routes are intentionally absent.
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin::AdminKey;

    fn principal(user_id: i64, key_enabled: bool, user_enabled: bool) -> Principal {
        Principal {
            key_id: 1,
            key_label: "alice".to_owned(),
            key_enabled,
            key_expires_at: None,
            user_id,
            login: "alice".to_owned(),
            user_enabled,
            group_id: 1,
            group_rate_bp: 0,
            user_rate_bp: None,
            balance_microus: 0,
            max_concurrent: 4,
            route_aliases: None,
        }
    }

    #[test]
    fn ordinary_user_key_is_allowed_but_admin_key_is_not() {
        let admin_key = AdminKey("admin-secret".to_owned());
        let now = chrono::Utc::now();
        assert_eq!(
            user_scope("user-secret", &principal(7, true, true), &admin_key, now),
            Ok(UserScope(7))
        );
        assert!(user_scope("admin-secret", &principal(7, true, true), &admin_key, now).is_err());
    }

    #[test]
    fn disabled_or_expired_keys_and_disabled_users_are_rejected() {
        let admin_key = AdminKey("admin-secret".to_owned());
        let now = chrono::Utc::now();
        assert!(user_scope("k", &principal(7, false, true), &admin_key, now).is_err());
        assert!(user_scope("k", &principal(7, true, false), &admin_key, now).is_err());
        let mut expired = principal(7, true, true);
        expired.key_expires_at = Some(now - chrono::Duration::seconds(1));
        assert!(user_scope("k", &expired, &admin_key, now).is_err());
    }

    #[test]
    fn caller_and_label_query_parameters_cannot_override_scope() {
        assert!(!scope_override_requested(false, false));
        assert!(scope_override_requested(true, false));
        assert!(scope_override_requested(false, true));
        assert!(scope_override_requested(true, true));
    }

    #[test]
    fn bearer_token_requires_bearer_scheme() {
        assert_eq!(bearer_token("Bearer alice-key"), Some("alice-key"));
        assert_eq!(bearer_token("bearer alice-key"), Some("alice-key"));
        assert_eq!(bearer_token("alice-key"), None);
        assert_eq!(bearer_token("Bearer "), None);
    }
}
