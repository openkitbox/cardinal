//! Account-only payment capability discovery for the customer portal.
//!
//! This module deliberately exposes no order, payment, webhook, or ledger
//! mutation route. The capability is always unavailable until a payment
//! channel is selected and integrated.

use salvo::http::StatusCode;
use salvo::prelude::*;
use serde_json::json;

use crate::user_usage;

#[handler]
async fn capabilities(depot: &mut Depot, response: &mut Response) {
    let Some(scope) = user_usage::scope(depot) else {
        response.status_code(StatusCode::INTERNAL_SERVER_ERROR);
        let _ = response.body("user usage state unavailable");
        return;
    };
    if scope.key_id().is_some() {
        response.status_code(StatusCode::FORBIDDEN);
        user_usage::json_response(
            response,
            &json!({ "error": "topup capabilities require an account session" }),
        );
        return;
    }
    user_usage::json_response(response, &json!({ "online_payment_available": false }));
}

/// The account-only capability endpoint. No payment routes are mounted here.
pub fn router() -> Router {
    Router::with_path("topup").push(Router::with_path("capabilities").get(capabilities))
}
