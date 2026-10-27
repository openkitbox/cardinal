//! Read-only usage API for ordinary gateway-key users.
//!
//! This surface is separate from the admin router. It authenticates only an
//! enabled gateway key and derives the usage scope from that key's stored label;
//! callers cannot select another label through query parameters.

use std::sync::Arc;

use salvo::http::{StatusCode, header};
use salvo::prelude::*;
use serde::Deserialize;
use serde_json::json;

use crate::admin::AdminKey;
use crate::api::AppState;
use crate::store::{self, CallerFilter, GatewayKeyInfo};

const CALLER_KEY: &str = "user_usage_caller_key";

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

/// Resolve the authenticated request identity without accepting client input.
fn authenticated_scope(info: &GatewayKeyInfo) -> Option<(CallerFilter, String)> {
    if !info.enabled || info.label.is_empty() {
        return None;
    }
    Some((CallerFilter::Label, info.label.clone()))
}

fn user_scope(
    token: &str,
    info: Option<&GatewayKeyInfo>,
    admin_key: &AdminKey,
) -> Option<(CallerFilter, String)> {
    if is_admin_key(token, admin_key) {
        return None;
    }
    info.and_then(authenticated_scope)
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
    let info = match store::gateway_key_info(&pool, token).await {
        Ok(Some(info)) => info,
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
    let admin_token = is_admin_key(token, admin_key);
    let Some((_, label)) = user_scope(token, Some(&info), admin_key) else {
        response.status_code(if admin_token || !info.enabled {
            StatusCode::UNAUTHORIZED
        } else {
            StatusCode::INTERNAL_SERVER_ERROR
        });
        let _ = response.body(if admin_token {
            "admin key is not valid for user usage"
        } else if !info.enabled {
            "gateway key is disabled"
        } else {
            "gateway key has no identity label"
        });
        ctrl.skip_rest();
        return;
    };
    depot.insert(CALLER_KEY, label);
    tokio::spawn(async move { store::touch_gateway_key(&pool, info.id).await });
}

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

fn client_scope(request: &Request, depot: &Depot) -> Result<(CallerFilter, String), StatusCode> {
    if scope_override_requested(
        request.queries().get("caller").is_some(),
        request.queries().get("label").is_some(),
    ) {
        return Err(StatusCode::BAD_REQUEST);
    }
    depot
        .get::<String>(CALLER_KEY)
        .map(|label| (CallerFilter::Label, label.clone()))
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
        Ok((kind, label)) => (kind, label),
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
    match store::usage_window(pool, since, until, Some((caller.0, caller.1.as_str()))).await {
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
        Ok((kind, label)) => (kind, label),
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
        Some((caller.0, caller.1.as_str())),
    )
    .await
    {
        Ok(rows) => json_response(response, &json!({ "items": rows })),
        Err(error) => internal(response, error),
    }
}

/// `/user/usage/*` sub-router. Only the two read-only usage endpoints are
/// mounted; management, request-log, and streaming routes are intentionally
/// absent.
pub fn router(admin_key: Arc<AdminKey>) -> Router {
    Router::with_path("user")
        .hoop(salvo::affix_state::inject(admin_key))
        .hoop(user_auth)
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

    fn key_info(label: &str, enabled: bool) -> GatewayKeyInfo {
        GatewayKeyInfo {
            id: 1,
            label: label.to_owned(),
            enabled,
        }
    }

    #[test]
    fn ordinary_user_key_is_allowed_but_admin_key_is_not() {
        let admin_key = AdminKey("admin-secret".to_owned());
        assert_eq!(
            user_scope("user-secret", Some(&key_info("alice", true)), &admin_key),
            Some((CallerFilter::Label, "alice".to_owned()))
        );
        assert_eq!(
            user_scope("admin-secret", Some(&key_info("default", true)), &admin_key),
            None
        );
    }

    #[test]
    fn missing_or_disabled_user_keys_are_rejected() {
        let admin_key = AdminKey("admin-secret".to_owned());
        assert_eq!(user_scope("missing", None, &admin_key), None);
        assert_eq!(
            user_scope("disabled", Some(&key_info("alice", false)), &admin_key),
            None
        );
    }

    #[test]
    fn caller_and_label_query_parameters_cannot_override_scope() {
        assert!(!scope_override_requested(false, false));
        assert!(scope_override_requested(true, false));
        assert!(scope_override_requested(false, true));
        assert!(scope_override_requested(true, true));
    }

    #[test]
    fn user_scope_ignores_client_caller_and_uses_authenticated_label() {
        let info = key_info("alice", true);
        assert_eq!(
            authenticated_scope(&info),
            Some((CallerFilter::Label, "alice".to_owned()))
        );
    }

    #[test]
    fn disabled_or_unlabelled_keys_have_no_user_scope() {
        assert_eq!(authenticated_scope(&key_info("alice", false)), None);
        assert_eq!(authenticated_scope(&key_info("", true)), None);
    }

    #[test]
    fn bearer_token_requires_bearer_scheme() {
        assert_eq!(bearer_token("Bearer alice-key"), Some("alice-key"));
        assert_eq!(bearer_token("bearer alice-key"), Some("alice-key"));
        assert_eq!(bearer_token("alice-key"), None);
        assert_eq!(bearer_token("Bearer "), None);
    }
}
