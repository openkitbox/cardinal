//! Self-service gateway keys for ordinary users (`/user/keys`).
//!
//! Mounted by [`crate::user_usage::router`] inside its auth hoop, so every
//! handler acts for the one authenticated user and only on keys that user
//! owns; a key id the caller does not own answers 404, the same as an
//! unknown id. A one-key scope (a built-in owner key) sees and edits only
//! that key and cannot create keys (403). Terms are validated by
//! [`crate::key_terms`], the same rules as the admin API.
//!
//! Endpoints:
//! - `GET /user/keys` — the caller's keys, newest first, full plaintext
//!   included (keys stay retrievable for copying)
//! - `POST /user/keys` `{label, expires_at?, quota_usd?}` — create a key;
//!   returns the full row. 409 when the label is taken or the caller already
//!   holds [`MAX_KEYS_PER_USER`] keys (disabled ones count)
//! - `PATCH /user/keys/{id}` `{label?, enabled?, expires_at?, quota_usd?}` —
//!   partial update; `expires_at` and `quota_usd` are three-state (absent =
//!   untouched, null = clear). A user may re-enable a key an admin disabled;
//!   to lock a user out an admin disables the user.
//!
//! There is no delete: disabling a key is the way to retire it.

use salvo::http::StatusCode;
use salvo::prelude::*;
use serde::Deserialize;
use serde_json::json;

use crate::key_terms;
use crate::store;
use crate::user_usage;

/// Most keys one user may hold, disabled keys included.
pub const MAX_KEYS_PER_USER: i64 = 20;

/// Write `{"error": message}` with `status`.
fn json_error(response: &mut Response, status: StatusCode, message: &str) {
    response.status_code(status);
    user_usage::json_response(response, &json!({ "error": message }));
}

fn state_unavailable(response: &mut Response) {
    json_error(
        response,
        StatusCode::INTERNAL_SERVER_ERROR,
        "user state unavailable",
    );
}

/// `GET /user/keys`: the caller's keys. The body carries full keys by
/// design; nothing here logs it.
#[handler]
async fn list_keys(depot: &mut Depot, response: &mut Response) {
    let (Ok(state), Some(scope)) = (user_usage::state(depot), user_usage::scope(depot)) else {
        state_unavailable(response);
        return;
    };
    match store::list_gateway_keys(&state.pool, Some(scope.user_id())).await {
        Ok(mut rows) => {
            rows.retain(|row| scope.covers_key(row.id));
            user_usage::json_response(response, &json!({ "items": rows }));
        }
        Err(error) => user_usage::internal(response, error),
    }
}

#[derive(Deserialize)]
struct CreateBody {
    label: String,
    /// RFC 3339; absent/null = never expires.
    #[serde(default)]
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Cumulative cap as a decimal USD string; absent/null = unlimited.
    #[serde(default)]
    quota_usd: Option<String>,
}

/// `POST /user/keys`: create a key owned by the caller.
#[handler]
async fn create_key(request: &mut Request, depot: &mut Depot, response: &mut Response) {
    let (Ok(state), Some(scope)) = (user_usage::state(depot), user_usage::scope(depot)) else {
        state_unavailable(response);
        return;
    };
    if scope.key_id().is_some() {
        json_error(
            response,
            StatusCode::FORBIDDEN,
            "keys cannot be created when signed in with a single key",
        );
        return;
    }
    let Ok(body) = request.parse_json::<CreateBody>().await else {
        json_error(response, StatusCode::BAD_REQUEST, "invalid JSON body");
        return;
    };
    let (label, terms) = match key_terms::create(
        &body.label,
        body.expires_at,
        body.quota_usd.as_deref(),
        chrono::Utc::now(),
    ) {
        Ok(valid) => valid,
        Err(message) => {
            json_error(response, StatusCode::BAD_REQUEST, message);
            return;
        }
    };
    match store::create_user_gateway_key(
        &state.pool,
        scope.user_id(),
        label,
        terms,
        MAX_KEYS_PER_USER,
    )
    .await
    {
        Ok(Some(row)) => user_usage::json_response(response, &row),
        Ok(None) => json_error(
            response,
            StatusCode::CONFLICT,
            "key limit reached (20 keys per user, disabled keys included)",
        ),
        Err(error) if store::is_label_taken(&error) => {
            json_error(response, StatusCode::CONFLICT, "label already in use");
        }
        Err(error) => user_usage::internal(response, error),
    }
}

/// `PATCH /user/keys/{id}`: partial update of one of the caller's keys.
#[handler]
async fn patch_key(request: &mut Request, depot: &mut Depot, response: &mut Response) {
    let Some(id) = request.param::<i64>("id") else {
        json_error(response, StatusCode::BAD_REQUEST, "invalid key id");
        return;
    };
    let Ok(body) = request.parse_json::<key_terms::PatchBody>().await else {
        json_error(response, StatusCode::BAD_REQUEST, "invalid JSON body");
        return;
    };
    let patch = match key_terms::patch(&body, chrono::Utc::now()) {
        Ok(patch) => patch,
        Err(message) => {
            json_error(response, StatusCode::BAD_REQUEST, message);
            return;
        }
    };
    let (Ok(state), Some(scope)) = (user_usage::state(depot), user_usage::scope(depot)) else {
        state_unavailable(response);
        return;
    };
    if !scope.covers_key(id) {
        json_error(response, StatusCode::NOT_FOUND, "key not found");
        return;
    }
    match store::update_gateway_key(&state.pool, id, Some(scope.user_id()), patch).await {
        Ok(true) => user_usage::json_response(response, &json!({ "ok": true })),
        Ok(false) => json_error(response, StatusCode::NOT_FOUND, "key not found"),
        Err(error) if store::is_label_taken(&error) => {
            json_error(response, StatusCode::CONFLICT, "label already in use");
        }
        Err(error) => user_usage::internal(response, error),
    }
}

/// `keys` sub-router; mount it only behind the `/user` auth hoop.
pub fn router() -> Router {
    Router::with_path("keys")
        .get(list_keys)
        .post(create_key)
        .push(Router::with_path("{id}").patch(patch_key))
}
