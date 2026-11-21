//! Account-only top-up HTTP edge. Auth, body parsing and status mapping only:
//! every money/state decision lives in [`crate::payments`].

use salvo::http::{StatusCode, header};
use salvo::prelude::*;
use serde::Deserialize;
use serde_json::json;

use crate::payments::{self, PaymentError, WebhookRequest};
use crate::user_usage;

#[derive(Debug, Deserialize)]
struct CreateBody {
    amount_fen: i64,
}

fn account_scope(depot: &Depot, response: &mut Response) -> Option<i64> {
    let Some(scope) = user_usage::scope(depot) else {
        response.status_code(StatusCode::INTERNAL_SERVER_ERROR);
        let _ = response.body("user usage state unavailable");
        return None;
    };
    if scope.key_id().is_some() {
        response.status_code(StatusCode::FORBIDDEN);
        user_usage::json_response(
            response,
            &json!({ "error": "topup orders require an account session" }),
        );
        return None;
    }
    Some(scope.user_id())
}

fn reply_error(response: &mut Response, error: PaymentError) {
    let status = match error {
        PaymentError::InvalidAmount | PaymentError::MissingPayerIp => StatusCode::BAD_REQUEST,
        PaymentError::NotFound => StatusCode::NOT_FOUND,
        PaymentError::Terminal | PaymentError::Conflict => StatusCode::CONFLICT,
        PaymentError::AmountMismatch => StatusCode::UNPROCESSABLE_ENTITY,
        PaymentError::Disabled => StatusCode::SERVICE_UNAVAILABLE,
        _ => StatusCode::BAD_GATEWAY,
    };
    response.status_code(status);
    user_usage::json_response(response, &json!({ "error": error.to_string() }));
}

#[handler]
async fn capabilities(depot: &mut Depot, response: &mut Response) {
    let Some(_) = account_scope(depot, response) else {
        return;
    };
    let enabled = payments::is_enabled();
    if enabled {
        let mut body =
            json!({ "enabled": true, "online_payment_available": true, "channel": "ALIPAY_H5" });
        if let Some(rate) = payments::usd_micros_per_cny_fen() {
            body["usd_micros_per_cny_fen"] = json!(rate);
        }
        user_usage::json_response(response, &body);
    } else {
        user_usage::json_response(response, &json!({ "online_payment_available": false }));
    }
}

#[handler]
async fn create_order(request: &mut Request, depot: &mut Depot, response: &mut Response) {
    let Some(user_id) = account_scope(depot, response) else {
        return;
    };
    let Ok(state) = user_usage::state(depot) else {
        response.status_code(StatusCode::INTERNAL_SERVER_ERROR);
        let _ = response.body("user usage state unavailable");
        return;
    };
    let Some(payer_ip) = request.remote_addr().ip() else {
        response.status_code(StatusCode::BAD_REQUEST);
        let _ = response.body("payer address unavailable");
        return;
    };
    let Ok(body) = request.parse_json::<CreateBody>().await else {
        response.status_code(StatusCode::BAD_REQUEST);
        let _ = response.body("invalid amount_fen");
        return;
    };
    match payments::place_order(&state.pool, user_id, body.amount_fen, &payer_ip).await {
        Ok(view) => {
            response.status_code(StatusCode::CREATED);
            user_usage::json_response(response, &view);
        }
        Err(error) => reply_error(response, error),
    }
}

#[handler]
async fn list_orders(depot: &mut Depot, response: &mut Response) {
    let Some(user_id) = account_scope(depot, response) else {
        return;
    };
    let Ok(state) = user_usage::state(depot) else {
        response.status_code(StatusCode::INTERNAL_SERVER_ERROR);
        let _ = response.body("user usage state unavailable");
        return;
    };
    match payments::list_orders(&state.pool, user_id).await {
        Ok(orders) => user_usage::json_response(response, &json!({ "orders": orders })),
        Err(error) => reply_error(response, error),
    }
}

#[handler]
async fn order_detail(request: &mut Request, depot: &mut Depot, response: &mut Response) {
    let Some(user_id) = account_scope(depot, response) else {
        return;
    };
    let Ok(state) = user_usage::state(depot) else {
        response.status_code(StatusCode::INTERNAL_SERVER_ERROR);
        let _ = response.body("user usage state unavailable");
        return;
    };
    let Some(id) = request.param::<i64>("id") else {
        response.status_code(StatusCode::BAD_REQUEST);
        let _ = response.body("invalid order id");
        return;
    };
    match payments::get_order(&state.pool, user_id, id).await {
        Ok(Some(view)) => user_usage::json_response(response, &view),
        Ok(None) => reply_error(response, PaymentError::NotFound),
        Err(error) => reply_error(response, error),
    }
}

#[handler]
async fn retry_attempt(request: &mut Request, depot: &mut Depot, response: &mut Response) {
    let Some(user_id) = account_scope(depot, response) else {
        return;
    };
    let Ok(state) = user_usage::state(depot) else {
        response.status_code(StatusCode::INTERNAL_SERVER_ERROR);
        let _ = response.body("user usage state unavailable");
        return;
    };
    let Some(id) = request.param::<i64>("id") else {
        response.status_code(StatusCode::BAD_REQUEST);
        let _ = response.body("invalid order id");
        return;
    };
    match payments::retry_attempt(&state.pool, user_id, id).await {
        Ok(view) => {
            response.status_code(StatusCode::CREATED);
            user_usage::json_response(response, &view);
        }
        Err(error) => reply_error(response, error),
    }
}

/// Public webhook: no gateway auth, signature verified over the raw bytes in
/// the payments module. The acknowledgement is the exact bytes `success`.
#[handler]
pub async fn webhook(request: &mut Request, depot: &mut Depot, response: &mut Response) {
    let Ok(state) = user_usage::state(depot) else {
        response.status_code(StatusCode::SERVICE_UNAVAILABLE);
        let _ = response.body("payments unavailable");
        return;
    };
    let raw = match request.payload().await {
        Ok(bytes) => bytes.to_vec(),
        Err(_) => {
            response.status_code(StatusCode::BAD_REQUEST);
            let _ = response.body("invalid webhook body");
            return;
        }
    };
    let header_value = |name: &str| {
        request
            .headers()
            .get(name)
            .and_then(|value| value.to_str().ok())
    };
    let verdict = payments::handle_webhook(
        &state.pool,
        &raw,
        WebhookRequest {
            signature: header_value("x-xd-webhook-signature"),
            key_id: header_value("x-xd-webhook-key-id"),
            timestamp: header_value("x-xd-webhook-timestamp"),
            nonce: header_value("x-xd-webhook-nonce"),
            event_id: header_value("x-xd-webhook-event-id"),
            event_type: header_value("x-xd-webhook-event-type"),
        },
    )
    .await;
    response.status_code(StatusCode::from_u16(verdict.status).unwrap_or(StatusCode::BAD_REQUEST));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    let _ = response.body(verdict.body);
}

/// The account-only top-up router, mounted under `/user` by the API layer.
pub fn router() -> Router {
    let router =
        Router::with_path("topup").push(Router::with_path("capabilities").get(capabilities));
    if !payments::is_enabled() {
        return router;
    }
    router
        .push(
            Router::with_path("orders")
                .get(list_orders)
                .post(create_order),
        )
        .push(Router::with_path("orders/{id}").get(order_detail))
        .push(Router::with_path("orders/{id}/attempts").post(retry_attempt))
}
