//! `GatewayHttpClient`: the GUI's pure-HTTP client of the standalone
//! gateway's admin API (`/api/*`), plus the reconnecting SSE subscription to
//! the live activity feed.
//!
//! Step 2 of the gateway/GUI split (docs/specs/gateway-gui-split-plan.md):
//! the GUI no longer reaches the gateway database directly — every admin
//! operation is an HTTP call against the loopback admin surface, authorized
//! with `Authorization: Bearer <gateway_key>` (the same credential the
//! `admin_auth` hoop expects). Method names follow the pre-split in-process
//! facade (what remains of it lives in [`crate::admin_ops`]) so the GUI's
//! call sites read unchanged.
//!
//! Error contract: transport failures and non-2xx answers both surface as
//! [`ClientError`], carrying the HTTP status plus the handler's body text
//! (the handlers write the anyhow chain into the body, so the GUI's error
//! cards show the same messages the in-process facade produced).
//!
//! Wire-shape notes (deviations 12–13 of the spec):
//! - [`Self::bootstrap`] returns the whole page-bootstrap document (providers,
//!   every key, routes, rests, quota snapshots, gateway keys, model-success) in
//!   ONE request — the same payload the activity stream pushes as its connect
//!   frame. It carries no upstream credential: [`Self::reveal_key`] is the only
//!   credential-serving call, and the key's model snapshot rides along in the
//!   bootstrap's credential-free key shape.
//! - [`Self::find_or_create_provider`] emulates the general provider facade's
//!   find-or-create client-side (create, then on failure fall back to a
//!   name lookup with the base_url-mismatch guard). Kiro imports use the
//!   dedicated [`Self::find_or_create_kiro_provider`] endpoint instead.

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use futures::StreamExt as _;

use crate::activity::{ActivityEvent, ActivityReceiver};
use crate::admin_ops::{ConcurrencyView, KeyQuotaRow, KeyQuotaSnapshotRow, KeyView};
use crate::body_log::CapturedBodies;
use crate::kiro::KiroOAuth;
use crate::probe::ProbeModel;
use crate::relay::DispatchTrace;
use crate::store::{
    GatewayKeyRow, ModelSuccessRow, ProviderInput, ProviderRow, RequestRow, RestRow, RouteEntry,
    RouteRow, RouteStrategy, TrendRow, TrendSplit, UsageWindow,
};

/// What the GUI shows when the gateway is not running (spec §8 decision 1).
/// Single definition shared by the runtime's status plumbing and the admin
/// call error path.
pub const UNREACHABLE_MESSAGE: &str =
    "gateway 未运行，请先运行 `cardinal-gateway`（或 `task gateway`）";

/// The whole admin surface is loopback-bound: no request may take longer
/// than this. Generous because `/api/quotas` probes every vendor in
/// parallel (each probe carries an 8s budget).
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// SSE reconnect backoff: first retry after [`BACKOFF_BASE`], doubling per
/// consecutive failure, capped at [`BACKOFF_MAX`].
const BACKOFF_BASE: Duration = Duration::from_millis(500);
const BACKOFF_MAX: Duration = Duration::from_secs(30);

/// One client-side failure: transport-level, a non-2xx answer, or an
/// undecodable success body (wire drift — surfaces loudly instead of
/// silently defaulting).
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// The request never got a usable response (connection refused, timeout).
    #[error("request failed: {0}")]
    Transport(#[from] reqwest::Error),
    /// The gateway answered with a non-success status; the body carries the
    /// handler's error text (the anyhow chain, verbatim).
    #[error("HTTP {status}: {body}")]
    Http {
        status: reqwest::StatusCode,
        body: String,
    },
    /// A 2xx body did not decode into the expected shape — wire drift between
    /// this binary and the running gateway. Carries the serde cause's message.
    #[error("undecodable response body: {0}")]
    Decode(String),
}

impl ClientError {
    /// True when the connection itself failed (refused — the gateway is
    /// down): what the GUI maps onto its 「gateway 未运行」 state. Request
    /// timeouts are deliberately NOT included — a slow upstream probe
    /// (`list_key_models`, `quotas`) must not flip the status bar red while
    /// the gateway is answering.
    pub fn is_unreachable(&self) -> bool {
        matches!(self, ClientError::Transport(error) if error.is_connect())
    }
}

/// Build one reqwest client, with `timeout` as the total per-request budget
/// (`None` for the SSE stream — see [`GatewayHttpClient`]). The builder's
/// only realistic failure mode is TLS-backend init; on that we retry the
/// SAME configuration once (so the timeout can never be silently dropped by
/// a fallback) and only then accept reqwest's infallible default — at that
/// point TLS is broken process-wide and requests fail with legible
/// transport errors anyway.
fn build_client(timeout: Option<Duration>) -> reqwest::Client {
    let build = || {
        let mut builder = reqwest::Client::builder();
        if let Some(timeout) = timeout {
            builder = builder.timeout(timeout);
        }
        builder.build()
    };
    build().unwrap_or_else(|error| {
    tracing::warn!(%error, "admin HTTP client build failed; retrying once before the infallible default");
    build().unwrap_or_default()
  })
}

/// HTTP client of the gateway's loopback admin API. Cheap to clone (the
/// reqwest clients are shared).
#[derive(Clone)]
pub struct GatewayHttpClient {
    /// Timed client for every request/response endpoint.
    http: reqwest::Client,
    /// Timeout-free client for `GET /api/activity` ONLY: a total timeout
    /// would kill the never-ending event stream every ~30s (a reconnect +
    /// reseed storm that defeats the server's keep-alive). Read timeouts are
    /// unnecessary here — the loop is loopback-bound and the server sends a
    /// 15s `:alive` heartbeat, so a wedged peer surfaces via TCP.
    stream: reqwest::Client,
    /// e.g. `http://127.0.0.1:10202` — every request path is appended to it.
    base: String,
    /// The `[gateway].gateway_key` admin credential (sent as a bearer token).
    admin_key: Arc<str>,
}

impl GatewayHttpClient {
    /// Build a client for the gateway at `listen`. Two shapes accepted:
    /// `host:port` (same as `[gateway].listen`, `http://` is prepended) or a
    /// full URL (`https://gateway.example.com:8787`), used as-is.
    pub fn new(listen: &str, admin_key: &str) -> Self {
        let trimmed = listen.trim_end_matches('/');
        let base = if trimmed.contains("://") {
            trimmed.to_string()
        } else {
            format!("http://{trimmed}")
        };
        Self {
            http: build_client(Some(REQUEST_TIMEOUT)),
            stream: build_client(None),
            base,
            admin_key: Arc::from(admin_key),
        }
    }

    /// The base URL the client talks to (for display: settings page, status
    /// bar).
    pub fn base_url(&self) -> &str {
        &self.base
    }

    /// `GET /health` — no auth (the route sits outside the `/api` hoops).
    /// `Ok(())` when any 2xx answers.
    pub async fn health(&self) -> Result<(), ClientError> {
        let response = self
            .http
            .get(format!("{}/health", self.base))
            .send()
            .await?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(http_error(response).await)
        }
    }

    fn request(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        self.http
            .request(method, format!("{}{}", self.base, path))
            .bearer_auth(&*self.admin_key)
    }

    fn get(&self, path: &str) -> reqwest::RequestBuilder {
        self.request(reqwest::Method::GET, path)
    }

    fn post(&self, path: &str) -> reqwest::RequestBuilder {
        self.request(reqwest::Method::POST, path)
    }

    fn put(&self, path: &str) -> reqwest::RequestBuilder {
        self.request(reqwest::Method::PUT, path)
    }

    fn patch(&self, path: &str) -> reqwest::RequestBuilder {
        self.request(reqwest::Method::PATCH, path)
    }

    fn delete(&self, path: &str) -> reqwest::RequestBuilder {
        self.request(reqwest::Method::DELETE, path)
    }

    // ---------- reads ----------

    /// Every provider, in id order. The wire shape is [`ProviderRow`] itself.
    pub async fn providers(&self) -> Result<Vec<ProviderRow>, ClientError> {
        json(self.get("/api/providers")).await
    }

    /// Every provider's key at once, credential-free (the shared
    /// [`crate::store::ProviderKeyView`] shape). One query server-side — the
    /// per-provider fan-out this replaces cost 1 + N requests. The plaintext
    /// credential is NOT here: it stays behind [`Self::reveal_key`].
    pub async fn bootstrap(&self) -> Result<crate::admin_ops::Bootstrap, ClientError> {
        json(self.get("/api/bootstrap")).await
    }

    /// One provider's credential-free keys, used by idempotent import flows.
    pub async fn provider_keys(
        &self,
        provider_id: i64,
    ) -> Result<Vec<crate::store::ProviderKeyView>, ClientError> {
        json(self.get(&format!("/api/providers/{provider_id}/keys"))).await
    }

    /// One key's full view, plaintext credential included. The ONLY
    /// credential-serving call on the client.
    pub async fn reveal_key(&self, provider_id: i64, key_id: i64) -> Result<KeyView, ClientError> {
        json(self.get(&format!(
            "/api/providers/{provider_id}/keys/{key_id}/reveal"
        )))
        .await
    }

    /// Every concurrency-limited key with its live occupancy (health page).
    pub async fn concurrency_usage(&self) -> Result<Vec<ConcurrencyView>, ClientError> {
        items(self.get("/api/concurrency")).await
    }

    /// Every route (alias → key/model entries), ordered by alias.
    pub async fn routes(&self) -> Result<Vec<RouteRow>, ClientError> {
        json(self.get("/api/routes")).await
    }

    /// Whole-window usage aggregates for the KPI cards over `[since, until)`;
    /// `caller` restricts to one caller identity (None = all, Some("null") =
    /// unidentified 本机 rows, anything else = a caller label).
    pub async fn usage_window(
        &self,
        since: DateTime<Utc>,
        until: DateTime<Utc>,
        caller: Option<&str>,
    ) -> Result<UsageWindow, ClientError> {
        #[derive(serde::Serialize)]
        struct WindowParams {
            since: String,
            until: String,
            #[serde(skip_serializing_if = "Option::is_none")]
            caller: Option<String>,
        }
        let params = WindowParams {
            since: rfc3339(since),
            until: rfc3339(until),
            caller: caller.map(str::to_string),
        };
        json(self.get("/api/usage/window").query(&params)).await
    }

    /// Usage aggregated by bucket × category for the trend chart. `split` is
    /// one of `route`, `model`, `provider`, `client`, or `user`;
    /// `local_offset` shifts bucket labels to the caller's wall clock;
    /// `caller` restricts to one caller identity (same spelling as
    /// [`Self::usage_window`]).
    pub async fn usage_trend(
        &self,
        since: DateTime<Utc>,
        until: DateTime<Utc>,
        split: TrendSplit,
        local_offset: chrono::Duration,
        caller: Option<&str>,
    ) -> Result<Vec<TrendRow>, ClientError> {
        #[derive(serde::Serialize)]
        struct TrendParams {
            since: String,
            until: String,
            split: TrendSplit,
            offset_seconds: i64,
            #[serde(skip_serializing_if = "Option::is_none")]
            caller: Option<String>,
        }
        let params = TrendParams {
            since: rfc3339(since),
            until: rfc3339(until),
            split,
            offset_seconds: local_offset.num_seconds(),
            caller: caller.map(str::to_string),
        };
        items(self.get("/api/usage/trend").query(&params)).await
    }

    /// Models the chat picker offers (route aliases first, then probed direct
    /// entries).
    pub async fn chat_models(&self) -> Result<Vec<String>, ClientError> {
        #[derive(serde::Deserialize)]
        struct ChatModels {
            models: Vec<String>,
        }
        Ok(json::<ChatModels>(self.get("/api/chat-models"))
            .await?
            .models)
    }

    /// The most recent requests (clamped to 1..=500 server-side), newest
    /// first. `before_id` paginates.
    pub async fn recent_requests(
        &self,
        limit: i64,
        before_id: Option<i64>,
    ) -> Result<Vec<RequestRow>, ClientError> {
        #[derive(serde::Serialize)]
        struct RequestsParams {
            limit: i64,
            #[serde(skip_serializing_if = "Option::is_none")]
            before_id: Option<i64>,
        }
        items(
            self.get("/api/requests")
                .query(&RequestsParams { limit, before_id }),
        )
        .await
    }

    /// Latest successful request time per (key, served model) — the routes
    /// stage's "上次成功" markers.
    pub async fn model_success(&self) -> Result<Vec<ModelSuccessRow>, ClientError> {
        items(self.get("/api/requests/model-success")).await
    }

    /// The captured request/response bodies of one row, `None` when the ring
    /// never captured it or evicted it (404).
    pub async fn request_bodies(
        &self,
        request_id: i64,
    ) -> Result<Option<CapturedBodies>, ClientError> {
        let response = self
            .get(&format!("/api/requests/{request_id}/bodies"))
            .send()
            .await?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if response.status().is_success() {
            return response
                .json::<CapturedBodies>()
                .await
                .map(Some)
                .map_err(decode_error);
        }
        Err(http_error(response).await)
    }

    /// The currently active cooldowns, with provider/key labels.
    pub async fn rests(&self) -> Result<Vec<RestRow>, ClientError> {
        items(self.get("/api/rests")).await
    }

    /// Live vendor quota/balance readings for every enabled key (probes the
    /// vendors; second-scale latency).
    pub async fn quotas(&self) -> Result<Vec<KeyQuotaRow>, ClientError> {
        items(self.get("/api/quotas")).await
    }

    /// Stored quota snapshots (pure read, no vendor probing).
    pub async fn quota_snapshots(&self) -> Result<Vec<KeyQuotaSnapshotRow>, ClientError> {
        items(self.get("/api/quota-snapshots")).await
    }

    /// The recent routing traces, newest first (the ring's transient contents,
    /// capped server-side at its capacity of 128).
    pub async fn traces(&self) -> Result<Vec<DispatchTrace>, ClientError> {
        items(self.get("/api/traces")).await
    }

    /// One routing trace by its dispatch request id (`req_{n}`), `None` when
    /// the ring never held it or evicted it (404).
    pub async fn trace(&self, request_id: &str) -> Result<Option<DispatchTrace>, ClientError> {
        let response = self
            .get(&format!("/api/traces/{request_id}"))
            .send()
            .await?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if response.status().is_success() {
            return response
                .json::<DispatchTrace>()
                .await
                .map(Some)
                .map_err(decode_error);
        }
        Err(http_error(response).await)
    }

    /// Validate a not-yet-saved key against its provider's model list (an
    /// upstream probe; nothing persisted).
    pub async fn validate_key(
        &self,
        input: &ProviderInput<'_>,
        api_key: &str,
    ) -> Result<Vec<ProbeModel>, ClientError> {
        let body = serde_json::json!({
          "name": input.name,
          "protocol": input.protocol,
          "base_url": input.base_url,
          "auth_scheme": input.auth_scheme,
          "enabled": input.enabled,
          "api_key": api_key,
        });
        json(self.post("/api/keys/validate").json(&body)).await
    }

    /// The models a saved key can list (route editor's picker; a successful
    /// probe refreshes the persisted snapshot server-side).
    pub async fn list_key_models(&self, key_id: i64) -> Result<Vec<ProbeModel>, ClientError> {
        json(self.get(&format!("/api/keys/{key_id}/models"))).await
    }

    /// Persist a key's model-list snapshot. Returns false when no such key
    /// row exists (404).
    pub async fn save_key_models(
        &self,
        key_id: i64,
        models: &[ProbeModel],
    ) -> Result<bool, ClientError> {
        let response = self
            .put(&format!("/api/keys/{key_id}/models"))
            .json(&serde_json::json!({ "models": models }))
            .send()
            .await?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(false);
        }
        if response.status().is_success() {
            return Ok(true);
        }
        Err(http_error(response).await)
    }

    // ---------- writes ----------

    /// Create a provider; returns the new id.
    pub async fn create_provider(&self, input: &ProviderInput<'_>) -> Result<i64, ClientError> {
        let body = provider_body(input);
        created_id(self.post("/api/providers").json(&body)).await
    }

    /// Find or create a Kiro provider by its endpoint identity. The gateway
    /// owns matching and returns whether this call created the provider.
    pub async fn find_or_create_kiro_provider(
        &self,
        name: &str,
        base_url: &str,
    ) -> Result<(i64, bool), ClientError> {
        #[derive(serde::Deserialize)]
        struct KiroProviderResponse {
            id: i64,
            created: bool,
        }
        let body = serde_json::json!({ "name": name, "base_url": base_url });
        let response: KiroProviderResponse =
            json(self.post("/api/providers/kiro").json(&body)).await?;
        Ok((response.id, response.created))
    }

    /// Find a provider by name, creating it when absent — client-side
    /// emulation of the facade's `find_or_create_provider`: create first, and
    /// when the insert fails (unique-name race with the survivor row), look
    /// the name up and reuse it when the base_url matches, mirroring the
    /// store's mismatch guard. No dedicated HTTP endpoint exists (the wire
    /// contract stays untouched).
    pub async fn find_or_create_provider(
        &self,
        input: &ProviderInput<'_>,
    ) -> Result<i64, ClientError> {
        self.create_or_reuse_provider(input).await.map(|(id, _)| id)
    }

    /// Create a provider after an initial name lookup. If another writer wins
    /// the insert race, re-read the name and reuse only an equivalent provider.
    pub async fn create_or_reuse_provider(
        &self,
        input: &ProviderInput<'_>,
    ) -> Result<(i64, bool), ClientError> {
        match self.create_provider(input).await {
            Ok(id) => Ok((id, true)),
            Err(create_error) => {
                let providers = self.providers().await.map_err(|lookup_error| {
                    ClientError::Decode(format!(
                        "provider creation failed: {create_error}; provider lookup failed: {lookup_error}"
                    ))
                })?;
                let Some(provider) = providers
                    .into_iter()
                    .find(|provider| provider.name.trim() == input.name.trim())
                else {
                    return Err(create_error);
                };
                if provider.protocol != input.protocol {
                    return Err(ClientError::Decode(format!(
                        "provider {} has incompatible protocol {}",
                        input.name, provider.protocol
                    )));
                }
                if provider.base_url.trim().trim_end_matches('/')
                    != input.base_url.trim().trim_end_matches('/')
                {
                    return Err(ClientError::Decode(format!(
                        "provider {} has incompatible endpoint {}",
                        input.name, provider.base_url
                    )));
                }
                Ok((provider.id, false))
            }
        }
    }

    /// Replace a provider's endpoint config. Errors (404) when the id does
    /// not exist.
    pub async fn update_provider(
        &self,
        id: i64,
        input: &ProviderInput<'_>,
    ) -> Result<(), ClientError> {
        ok(self
            .patch(&format!("/api/providers/{id}"))
            .json(&provider_body(input)))
        .await
    }

    /// Enable/disable a provider — a full-body PATCH assembled from a fresh
    /// read (the wire has no enabled-only verb; errors when the id is gone).
    pub async fn set_provider_enabled(&self, id: i64, enabled: bool) -> Result<(), ClientError> {
        let provider: ProviderRow = json(self.get(&format!("/api/providers/{id}"))).await?;
        let input = ProviderInput {
            name: &provider.name,
            protocol: &provider.protocol,
            base_url: &provider.base_url,
            auth_scheme: Some(provider.auth_scheme.as_str()),
            enabled,
        };
        self.update_provider(id, &input).await
    }

    /// Delete a provider. Errors (404) when the id does not exist.
    pub async fn delete_provider(&self, id: i64) -> Result<(), ClientError> {
        ok(self.delete(&format!("/api/providers/{id}"))).await
    }

    /// Delete a provider only if it has no keys. A 409 response means the
    /// provider still has keys; 404 means the provider does not exist.
    pub async fn delete_provider_if_empty(&self, id: i64) -> Result<(), ClientError> {
        ok(self.delete(&format!("/api/providers/{id}/if-empty"))).await
    }

    // ---------- gateway key management ----------

    /// List all gateway keys.
    pub async fn gateway_keys(&self) -> Result<Vec<GatewayKeyRow>, ClientError> {
        let response: GatewayKeysResponse = json(self.get("/api/gateway-keys")).await?;
        Ok(response.items)
    }

    /// Create a new gateway key; returns the plaintext key (shown once).
    pub async fn create_gateway_key(&self, label: &str) -> Result<String, ClientError> {
        let response: GatewayKeyCreateResponse = json(
            self.post("/api/gateway-keys")
                .json(&serde_json::json!({ "label": label })),
        )
        .await?;
        Ok(response.key)
    }

    /// Enable or disable a gateway key by its id. Errors (404) when not found.
    pub async fn set_gateway_key_enabled(&self, id: i64, enabled: bool) -> Result<(), ClientError> {
        ok(self
            .patch(&format!("/api/gateway-keys/{id}"))
            .json(&serde_json::json!({ "enabled": enabled })))
        .await
    }

    /// Add a named key to a provider; returns the new key id.
    pub async fn create_key(
        &self,
        provider_id: i64,
        label: &str,
        api_key: &str,
        max_concurrency: Option<i32>,
        allowed_models: Option<Vec<String>>,
    ) -> Result<i64, ClientError> {
        let body = serde_json::json!({
          "label": label,
          "api_key": api_key,
          "max_concurrency": max_concurrency,
          "allowed_models": allowed_models,
        });
        created_id(
            self.post(&format!("/api/providers/{provider_id}/keys"))
                .json(&body),
        )
        .await
    }

    /// Probe then atomically create or replace a Kiro OIDC key selected by its
    /// label; returns `(key_id, created)`. The gateway validates the supplied
    /// credential against the Kiro model catalogue before persisting anything,
    /// so a failure here leaves an existing key's credential untouched.
    pub async fn upsert_kiro_key(
        &self,
        provider_id: i64,
        label: &str,
        oauth: &KiroOAuth,
    ) -> Result<(i64, bool), ClientError> {
        #[derive(serde::Deserialize)]
        struct Upserted {
            id: i64,
            created: bool,
        }
        let body = serde_json::json!({ "label": label, "oauth": oauth });
        let result: Upserted = json(
            self.post(&format!("/api/providers/{provider_id}/kiro-key"))
                .json(&body),
        )
        .await?;
        Ok((result.id, result.created))
    }

    /// Patch a key's label/enabled/concurrency cap/whitelist. `max_concurrency`
    /// is three-state (outer None = untouched, inner None = clear); so is
    /// `allowed_models`.
    pub async fn update_key(
        &self,
        provider_id: i64,
        key_id: i64,
        label: Option<&str>,
        enabled: Option<bool>,
        max_concurrency: Option<Option<i32>>,
        allowed_models: Option<Option<Vec<String>>>,
    ) -> Result<(), ClientError> {
        // skip_serializing_if preserves the server's absent/null/value tri-state.
        #[derive(serde::Serialize)]
        struct PatchKey<'a> {
            #[serde(skip_serializing_if = "Option::is_none")]
            label: Option<&'a str>,
            #[serde(skip_serializing_if = "Option::is_none")]
            enabled: Option<bool>,
            #[serde(skip_serializing_if = "Option::is_none")]
            max_concurrency: Option<Option<i32>>,
            #[serde(skip_serializing_if = "Option::is_none")]
            allowed_models: Option<Option<Vec<String>>>,
        }
        let body = PatchKey {
            label,
            enabled,
            max_concurrency,
            allowed_models,
        };
        ok(self
            .patch(&format!("/api/providers/{provider_id}/keys/{key_id}"))
            .json(&body))
        .await
    }

    /// Delete a key. Errors (404) when the key does not exist.
    pub async fn delete_key(&self, provider_id: i64, key_id: i64) -> Result<(), ClientError> {
        ok(self.delete(&format!("/api/providers/{provider_id}/keys/{key_id}"))).await
    }

    /// Reorder keys globally; `ids` must list every key exactly once.
    pub async fn reorder_keys(&self, ids: &[i64]) -> Result<(), ClientError> {
        ok(self
            .put("/api/keys/order")
            .json(&serde_json::json!({ "ids": ids })))
        .await
    }

    /// Create or replace a route (alias → key/model entries) with its dispatch
    /// `strategy` and optional display `note`. Strategy and note are always
    /// sent; the server defaults an absent strategy to `ordered` and treats an
    /// absent note as unset, for old clients. `efforts` 缺席时字段不发送,
    /// 服务端保留库值(三态);传 `Some(&[])` 显式清空变体。
    pub async fn put_route(
        &self,
        alias: &str,
        entries: &[RouteEntry],
        context_window: Option<i64>,
        strategy: RouteStrategy,
        note: Option<&str>,
        efforts: Option<&[String]>,
    ) -> Result<(), ClientError> {
        let mut body = serde_json::json!({ "entries": entries, "context_window": context_window, "strategy": strategy, "note": note });
        if let Some(efforts) = efforts {
            body["efforts"] = serde_json::json!(efforts);
        }
        ok(self.put(&format!("/api/routes/{alias}")).json(&body)).await
    }

    /// Delete a route. Errors (404) when the alias does not exist.
    pub async fn delete_route(&self, alias: &str) -> Result<(), ClientError> {
        ok(self.delete(&format!("/api/routes/{alias}"))).await
    }

    /// Clear one key's cooldown (idempotent).
    pub async fn clear_rest(&self, key_id: i64) -> Result<(), ClientError> {
        ok(self.delete(&format!("/api/rests/keys/{key_id}"))).await
    }

    /// Clear the cooldowns of every key of one provider (idempotent).
    pub async fn clear_provider_rests(&self, provider_id: i64) -> Result<(), ClientError> {
        ok(self.delete(&format!("/api/rests/providers/{provider_id}"))).await
    }

    // ---------- agent wiring ----------

    /// The wiring status of one agent (opencode / omp), as the agent module
    /// reports it.
    pub async fn agent_status(&self, agent: &str) -> Result<serde_json::Value, ClientError> {
        json(self.get(&format!("/api/agents/{agent}"))).await
    }

    /// Write the agent's config so it routes through this gateway.
    pub async fn agent_connect(
        &self,
        agent: &str,
        listen_addr: &str,
        gateway_key: &str,
        models: Vec<String>,
    ) -> Result<(), ClientError> {
        let body = serde_json::json!({ "listen_addr": listen_addr, "gateway_key": gateway_key, "models": models });
        ok(self
            .post(&format!("/api/agents/{agent}/connect"))
            .json(&body))
        .await
    }

    /// Remove the gateway wiring from the agent's config. Returns whether a
    /// backup was restored.
    pub async fn agent_disconnect(&self, agent: &str) -> Result<bool, ClientError> {
        #[derive(serde::Deserialize)]
        struct Disconnected {
            restored: bool,
        }
        Ok(
            json::<Disconnected>(self.post(&format!("/api/agents/{agent}/disconnect")))
                .await?
                .restored,
        )
    }

    // ---------- live activity (SSE) ----------

    /// Subscribe to `GET /api/activity`: a pump task owns the connection —
    /// exponential-backoff reconnect, and after every reconnect a reseed: the
    /// newest ledger row id is fetched through [`Self::recent_requests`] and,
    /// when it advanced past the high-water mark, one synthetic
    /// [`ActivityEvent::Persisted`] is emitted so the GUI's pages re-read the
    /// ledger and heal whatever the disconnect dropped (the same
    /// seed+dedupe semantic the PG LISTEN path had: events are lossy, the
    /// ledger is truth — the live map's (origin, seq) keying dedupes the
    /// in-flight side downstream).
    ///
    /// The tokio runtime handle the pump task is spawned on. Explicit
    /// parameter, NOT thread-local context: the GUI calls this from the GPUI
    /// main thread, which has no runtime — a bare `tokio::spawn` here panicked
    /// at startup (regression test:
    /// `tests::subscribe_activity_runs_without_caller_runtime_context`).
    pub fn subscribe_activity(&self, handle: &tokio::runtime::Handle) -> ActivityReceiver {
        let (tx, rx) = tokio::sync::mpsc::channel(256);
        let client = self.clone();
        drop(handle.spawn(async move {
            let mut reseed = Reseed::default();
            let mut failures = 0u32;
            loop {
                if tx.is_closed() {
                    return; // the GUI's feed is gone
                }
                match client.activity_events().await {
                    Ok(stream) => {
                        // Connected: reseed BEFORE draining so the pages converge on the
                        // ledger state at stream start (events missed during the outage
                        // surface as one Persisted).
                        let newest = client
                            .recent_requests(1, None)
                            .await
                            .ok()
                            .and_then(|rows| rows.first().map(|row| row.id));
                        if reseed.on_connect(newest)
                            && tx.send(ActivityEvent::Persisted).await.is_err()
                        {
                            return;
                        }
                        failures = 0;
                        futures::pin_mut!(stream);
                        while let Some(event) = stream.next().await {
                            match event {
                                Ok(event) => {
                                    if tx.send(event).await.is_err() {
                                        return;
                                    }
                                }
                                Err(error) => {
                                    tracing::warn!("activity sse: frame skipped ({error})")
                                }
                            }
                        }
                        tracing::warn!("activity sse: stream ended; reconnecting");
                    }
                    Err(error) => {
                        tracing::warn!("activity sse: connect failed ({error}); retrying");
                    }
                }
                let wait = backoff_delay(failures);
                failures = failures.saturating_add(1);
                tokio::select! {
                  () = tokio::time::sleep(wait) => {}
                  () = tx.closed() => return,
                }
            }
        }));
        rx
    }

    /// One connection attempt to the activity SSE endpoint: the decoded event
    /// stream. The stream ends (a transport error surfaces as one terminal
    /// `Err` item first) when the connection drops — reconnection and reseed
    /// are [`Self::subscribe_activity`]'s job.
    async fn activity_events(
        &self,
    ) -> Result<
        impl futures::Stream<Item = Result<ActivityEvent, ClientError>> + Send + 'static,
        ClientError,
    > {
        // `stream`, not `http`: no total timeout on the never-ending response.
        let response = self
            .stream
            .get(format!("{}/api/activity", self.base))
            .bearer_auth(&*self.admin_key)
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(http_error(response).await);
        }
        // unfold over (byte stream, decoder, decoded backlog): one chunk may
        // complete several events; the backlog feeds them out one per poll.
        type State = (
            std::pin::Pin<
                Box<dyn futures::Stream<Item = Result<bytes::Bytes, reqwest::Error>> + Send>,
            >,
            SseDecoder,
            std::collections::VecDeque<Result<ActivityEvent, ClientError>>,
        );
        let state: State = (
            Box::pin(response.bytes_stream()),
            SseDecoder::new(),
            std::collections::VecDeque::new(),
        );
        Ok(futures::stream::unfold(
            state,
            |(mut bytes, mut decoder, mut ready)| async move {
                loop {
                    if let Some(item) = ready.pop_front() {
                        return Some((item, (bytes, decoder, ready)));
                    }
                    match bytes.next().await {
                        Some(Ok(chunk)) => {
                            for data in decoder.push(&chunk) {
                                ready.push_back(
                                    match serde_json::from_str::<ActivityEvent>(&data) {
                                        Ok(event) => Ok(event),
                                        Err(error) => Err(ClientError::Decode(error.to_string())),
                                    },
                                );
                            }
                        }
                        // Terminal: after a transport error the byte stream yields None,
                        // so the next poll ends the event stream — the pump reconnects.
                        Some(Err(error)) => {
                            return Some((
                                Err(ClientError::Transport(error)),
                                (bytes, decoder, ready),
                            ));
                        }
                        None => return None,
                    }
                }
            },
        ))
    }
}

/// Incremental SSE frame decoder (RFC 4329/`text/event-stream` core): feed
/// arbitrary byte chunks, get back the `data:` payloads of completed events.
/// Comment lines (`:…`) and field lines other than `data:` are ignored
/// (`event:`/`id:`/`retry:` carry nothing this client needs); a blank line
/// dispatches the event. Cutting at `\n` bytes is UTF-8 safe (a newline byte
/// never appears inside a multi-byte character).
#[derive(Default)]
pub struct SseDecoder {
    /// Undelivered bytes (a partial line at the chunk tail).
    pending: Vec<u8>,
    /// `data:` lines of the event currently being accumulated.
    data: Vec<String>,
}

impl SseDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Consume one byte chunk; return the data payloads of every event it
    /// completed (multi-line `data:` joins with `\n`, per the spec).
    pub fn push(&mut self, chunk: &[u8]) -> Vec<String> {
        self.pending.extend_from_slice(chunk);
        let mut events = Vec::new();
        while let Some(newline) = self.pending.iter().position(|byte| *byte == b'\n') {
            let mut line: Vec<u8> = self.pending.drain(..=newline).collect();
            line.pop(); // the \n
            if line.last() == Some(&b'\r') {
                line.pop(); // CRLF
            }
            let Ok(line) = String::from_utf8(line) else {
                continue;
            };
            if line.is_empty() {
                // Blank line: dispatch.
                if !self.data.is_empty() {
                    events.push(self.data.join("\n"));
                    self.data.clear();
                }
            } else if line.starts_with(':') {
                // Comment / keep-alive — ignored.
            } else if let Some(data) = line.strip_prefix("data:") {
                self.data
                    .push(data.strip_prefix(' ').unwrap_or(data).to_string());
            }
            // event:/id:/retry: fields are intentionally dropped.
        }
        events
    }
}

/// Exponential backoff for the SSE reconnect: 500ms, 1s, 2s, … capped at
/// 30s. `failures` is the consecutive-failure count (0 on the first retry).
pub fn backoff_delay(failures: u32) -> Duration {
    let shift = failures.min(10); // 2^10×base already far exceeds the cap
    (BACKOFF_BASE * 2u32.saturating_pow(shift)).min(BACKOFF_MAX)
}

/// Reseed bookkeeping for the SSE reconnect (spec §8 decision 7): the
/// high-water mark of ledger row ids the client has observed. The FIRST
/// connect only baselines (the pages load their own initial data — an
/// immediate Persisted would fire a redundant reload); every RECONNECT with
/// an advanced newest row emits one Persisted so the pages re-read the
/// ledger and converge. A same-or-lower id dedupes the bump (already seen).
#[derive(Default)]
pub struct Reseed {
    high_water: Option<i64>,
    connected_once: bool,
}

impl Reseed {
    /// Record one successful connect and the ledger's newest row id at that
    /// moment (None = empty ledger). Returns whether a synthetic
    /// `Persisted` should be emitted.
    pub fn on_connect(&mut self, newest: Option<i64>) -> bool {
        let reconnect = std::mem::replace(&mut self.connected_once, true);
        if !reconnect {
            self.high_water = newest;
            return false;
        }
        match (self.high_water, newest) {
            (Some(high), Some(newest)) if newest > high => {
                self.high_water = Some(newest);
                true
            }
            (None, Some(newest)) => {
                self.high_water = Some(newest);
                true
            }
            _ => false,
        }
    }
}

// ---------- response plumbing ----------

/// RFC3339 with the `Z` spelling — human-diffable in logs; reqwest's query
/// serializer percent-encodes whatever it gets, so the `+00:00` pitfall the
/// handler tests document cannot bite here.
fn rfc3339(ts: DateTime<Utc>) -> String {
    ts.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// The `{ "items": [...] }` envelope most list endpoints answer with.
#[derive(serde::Deserialize)]
struct Items<T> {
    items: Vec<T>,
}

/// `GET /api/gateway-keys` response (same envelope as Items, but typed for
/// the client method's return).
#[derive(serde::Deserialize)]
struct GatewayKeysResponse {
    items: Vec<GatewayKeyRow>,
}

/// `POST /api/gateway-keys` response: the plaintext key, shown once.
#[derive(serde::Deserialize)]
struct GatewayKeyCreateResponse {
    key: String,
}

/// Decode the items envelope out of a list-endpoint request.
async fn items<T: serde::de::DeserializeOwned>(
    request: reqwest::RequestBuilder,
) -> Result<Vec<T>, ClientError> {
    Ok(json::<Items<T>>(request).await?.items)
}

/// Send a request expecting a 2xx JSON body decoded as `T`.
async fn json<T: serde::de::DeserializeOwned>(
    request: reqwest::RequestBuilder,
) -> Result<T, ClientError> {
    let response = request.send().await?;
    if !response.status().is_success() {
        return Err(http_error(response).await);
    }
    response.json::<T>().await.map_err(decode_error)
}

/// Send a request expecting any 2xx (body ignored — the `{"ok": true}`
/// acknowledgements).
async fn ok(request: reqwest::RequestBuilder) -> Result<(), ClientError> {
    let response = request.send().await?;
    if response.status().is_success() {
        Ok(())
    } else {
        Err(http_error(response).await)
    }
}

/// The `{"id": …}` answer of the create endpoints.
async fn created_id(request: reqwest::RequestBuilder) -> Result<i64, ClientError> {
    #[derive(serde::Deserialize)]
    struct Created {
        id: i64,
    }
    Ok(json::<Created>(request).await?.id)
}

/// A non-success response into the typed error (status + body text).
async fn http_error(response: reqwest::Response) -> ClientError {
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    ClientError::Http { status, body }
}

/// reqwest's decode failure into the wire-drift variant: surface the serde
/// cause's message (it names the missing/mismatched field) instead of the
/// bare "error decoding response body".
fn decode_error(error: reqwest::Error) -> ClientError {
    use std::error::Error as _;
    let mut message = error.to_string();
    let mut cause = error.source();
    while let Some(inner) = cause {
        message = inner.to_string();
        cause = inner.source();
    }
    ClientError::Decode(message)
}

/// The provider create/update body (the shared catalog spec).
fn provider_body(input: &ProviderInput<'_>) -> serde_json::Value {
    serde_json::json!({
      "name": input.name,
      "protocol": input.protocol,
      "base_url": input.base_url,
      "auth_scheme": input.auth_scheme,
      "enabled": input.enabled,
    })
}
