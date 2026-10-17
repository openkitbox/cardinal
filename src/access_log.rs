//! Access logging middleware: salvo_extra's `Logger` re-implemented with the
//! `Response` line at INFO for relay traffic (`/v1*`) and DEBUG for the admin
//! surface (GUI polls, /health, /api/*) — so a production `level = "info"`
//! shows the audited relay traffic without the poll noise, and the same lines
//! reappear at `debug`. The `Request` span stays INFO so cardinal's own
//! events inside a request keep their context at production level.

use std::time::Instant;

use salvo::http::{Request, ResBody, Response, StatusCode};
use salvo::{Depot, FlowCtrl, Handler, async_trait};
use tracing::{Instrument, Level};

/// Per-request access log: `INFO` span for context + one `Response` line at
/// INFO for `/v1*` relay traffic, DEBUG for the rest.
pub struct AccessLog;

#[async_trait]
impl Handler for AccessLog {
    async fn handle(
        &self,
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        ctrl: &mut FlowCtrl,
    ) {
        let path = req.uri().path();
        // `/v1` and `/v1beta` are the relay surface; `v1beta` starts with
        // `v1` too, so one prefix covers both.
        let relay = path.starts_with("/v1");
        let span = tracing::span!(
            Level::INFO,
            "Request",
            remote_addr = %req.remote_addr(),
            version = ?req.version(),
            method = %req.method(),
            // Log only the path, not the full URI: the query string can carry
            // secrets (`?token=`, `?api_key=`, signed URLs) that should not land
            // in logs by default.
            path = %path,
            kind = if relay { "relay" } else { "admin" },
        );

        async move {
            let now = Instant::now();
            ctrl.call_next(req, depot, res).await;
            let duration = now.elapsed();

            let status = res.status_code.unwrap_or(match &res.body {
                ResBody::None => StatusCode::NOT_FOUND,
                ResBody::Error(e) => e.code,
                _ => StatusCode::OK,
            });
            // The Response event: INFO for relay, DEBUG for admin. The
            // trailing unit field keeps relay/admin structurally identical so
            // a single field-keyed span filter (see span_level!) can re-key
            // the level without missing-field noise.
            if let ResBody::Error(error) = &res.body {
                if relay {
                    tracing::info!(%status, ?duration, ?error, "Response");
                } else {
                    tracing::debug!(%status, ?duration, ?error, "Response");
                }
            } else if relay {
                tracing::info!(%status, ?duration, "Response");
            } else {
                tracing::debug!(%status, ?duration, "Response");
            }
        }
        .instrument(span)
        .await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use salvo::prelude::*;
    use salvo::test::{ResponseExt, TestClient};
    use tracing_subscriber::layer::SubscriberExt;

    use crate::access_log::AccessLog;

    /// One captured event: its level, its `path` field, and its message.
    type Captured = Arc<Mutex<Vec<(tracing::Level, String, String)>>>;

    struct Capture {
        events: Captured,
    }

    impl Capture {
        /// Extract one named field of an event as its `Debug` text.
        fn field(event: &tracing::Event<'_>, name: &str) -> String {
            struct Visitor<'a> {
                name: &'a str,
                value: String,
            }
            impl tracing::field::Visit for Visitor<'_> {
                fn record_debug(
                    &mut self,
                    field: &tracing::field::Field,
                    value: &dyn std::fmt::Debug,
                ) {
                    if field.name() == self.name {
                        self.value = format!("{value:?}");
                    }
                }
            }
            let mut visitor = Visitor {
                name,
                value: String::new(),
            };
            event.record(&mut visitor);
            visitor.value
        }
    }

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Capture {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            self.events.lock().unwrap().push((
                *event.metadata().level(),
                Self::field(event, "path"),
                Self::field(event, "message"),
            ));
        }
    }

    /// The span context fmt writes for events: the gateway's router attaches
    /// `path` to the span, so an event inside it carries it. The capture
    /// layer above records only the event's own fields, so instead of reading
    /// `path` we assert on the event level + message for each route — the
    /// router under test has exactly one route per request.
    async fn recorded(
        events: Captured,
        url: &str,
        relay: bool,
    ) -> Vec<(tracing::Level, String, String)> {
        let _guard =
            tracing::subscriber::set_default(tracing_subscriber::registry().with(Capture {
                events: events.clone(),
            }));
        let router = Router::new()
            .hoop(AccessLog)
            .push(Router::with_path("v1/chat/completions").post(ok))
            .push(Router::with_path("api/requests").get(ok));
        let request = if relay {
            TestClient::post(url)
        } else {
            TestClient::get(url)
        };
        request.send(router).await.take_string().await.unwrap();
        events.lock().unwrap().clone()
    }

    #[handler]
    async fn ok() -> &'static str {
        "ok"
    }
}
