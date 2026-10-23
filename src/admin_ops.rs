//! Business-logic admin facade shared by the HTTP admin API handlers.
//!
//! [`Admin`] is the assembly point for the admin operations that are more
//! than a bare store call: quota probing and snapshot reads, key validation
//! against upstream providers, usage aggregation, chat-model listing, live
//! concurrency views, and cooldown clearing (which forgives the relay's
//! in-memory failure streak alongside the DB row). The HTTP handlers in
//! [`crate::admin`] build it per request from the shared
//! [`crate::api::AppState`], so the facade sees the LIVE relay's registries.
//! Endpoint URLs go through the shared save-time SSRF check
//! ([`crate::upstream::transport::validate_saved_endpoint`]). Error messages
//! are preserved verbatim (`anyhow` chains) so the HTTP 400/404/502 bodies
//! stay informative.

use std::sync::Arc;

use sqlx::PgPool;

use crate::probe::{self, ProbeModel};
use crate::quota::{self, KeyQuota};
use crate::store::{self, ProviderInput};

/// In-process key view: the full row plus the row-stored plaintext credential
/// (display layers mask it; empty when the key has none) plus the live
/// semaphore occupancy (`Some` only for limited keys).
///
/// ⚠ `api_key` is the PLAINTEXT credential. On the wire (this type is
/// `Serialize` for exactly that) it is intended for one path only: the
/// loopback + admin-key guarded `GET /api/providers/{id}/keys/{key_id}/reveal`
/// endpoint backing the GUI's view-key flow. Never return a KeyView from any
/// endpoint that masks (e.g. the `list_keys` shape must stay masked).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct KeyView {
    pub id: i64,
    pub provider_id: i64,
    pub label: String,
    pub api_key: String,
    pub enabled: bool,
    pub position: i32,
    pub max_concurrency: Option<i32>,
    pub inflight: Option<i32>,
    /// The key's cached model-list snapshot (None until the first successful probe).
    pub models: Option<Vec<ProbeModel>>,
    /// The key's model whitelist (None = unrestricted).
    pub allowed_models: Option<Vec<String>>,
}

/// One concurrency-limited key with its live occupancy, for the health page.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ConcurrencyView {
    pub key_id: i64,
    pub provider_id: i64,
    pub provider_name: String,
    pub key_label: String,
    pub max_concurrency: i32,
    pub inflight: i32,
}

/// One key's probed vendor quota reading ([`Admin::quotas`]). A named struct
/// rather than a tuple: tuples have no self-describing JSON shape, and this
/// row doubles as the `/api/quotas` wire shape.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct KeyQuotaRow {
    pub key_id: i64,
    pub quota: KeyQuota,
}

/// One key's stored quota snapshot ([`Admin::quota_snapshots`]): the last
/// successful reading and when it was probed. The `/api/quota-snapshots`
/// wire shape.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct KeyQuotaSnapshotRow {
    pub key_id: i64,
    pub quota: KeyQuota,
    /// When the reading was probed (the snapshot row's `probed_at`).
    pub fetched_at: chrono::DateTime<chrono::Utc>,
}

/// The admin UI's bootstrap document: every parameterless admin read the
/// status pages render from, assembled in one pass.
///
/// It rides as the first frame of `GET /api/activity`, so opening the client
/// costs one connection instead of one HTTP request per page (plus a
/// per-provider fan-out for the key lists). `GET /api/bootstrap` serves the
/// same document for a manual refresh and as the reconnect fallback.
///
/// Credentials are excluded by construction: `keys` is the credential-free
/// [`store::ProviderKeyView`] shape, and the plaintext upstream credential
/// stays behind the single reveal endpoint.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Bootstrap {
    pub providers: Vec<store::ProviderRow>,
    /// Every provider key across all providers, credential-free.
    pub keys: Vec<store::ProviderKeyView>,
    pub routes: Vec<store::RouteRow>,
    pub rests: Vec<store::RestRow>,
    /// The stored vendor quota readings (instant; the live probe is `/api/quotas`).
    pub quota_snapshots: Vec<KeyQuotaSnapshotRow>,
    /// Daily probe samples behind the quota readings, for the account cards'
    /// cumulative trend charts. Older gateways omit the field; the GUI then
    /// renders the current point alone.
    #[serde(default)]
    pub quota_history: Vec<store::QuotaHistoryPoint>,
    pub gateway_keys: Vec<store::GatewayKeyRow>,
    /// Latest successful request time per (key, model).
    pub model_success: Vec<store::ModelSuccessRow>,
}

/// The probed key row does not exist. The admin HTTP surface maps this to
/// 404; in-process callers see the same message as before.
#[derive(Debug, thiserror::Error)]
#[error("no such key {0}")]
pub struct NoSuchKey(pub i64);
/// An outbound probe failed: the vendor rejected the credential, DNS,
/// timeout, or an undecodable payload. The admin HTTP surface maps this to
/// 502 Bad Gateway — the request was well-formed; the dependency failed.
#[derive(Debug, thiserror::Error)]
#[error("{0:#}")]
pub struct ProbeError(pub anyhow::Error);

/// A key row plus its live slot occupancy (`inflight` = Some only for
/// limited keys) as a view — used by the loopback-only reveal endpoint
/// (`GET /api/providers/{id}/keys/{key_id}/reveal`, the GUI's view-key flow).
/// `api_key` is the row-stored plaintext credential (display layers mask
/// it); pass an empty string when the key has none yet.
///
/// Live occupancy currently reads 0: slot state moved into the centralized
/// dispatcher (an opaque task), so the admin surface has no read path yet.
pub fn key_view(row: &store::ProviderKeyRow, api_key: String) -> KeyView {
    let inflight = row.max_concurrency.map(|_| 0);
    KeyView {
        id: row.id,
        provider_id: row.provider_id,
        label: row.label.clone(),
        api_key,
        enabled: row.enabled,
        position: row.position,
        max_concurrency: row.max_concurrency,
        inflight,
        models: row.models.clone(),
        allowed_models: row.allowed_models.clone(),
    }
}

pub async fn create_key(
    pool: &PgPool,
    provider_id: i64,
    label: &str,
    api_key: &str,
    max_concurrency: Option<i32>,
    allowed_models: Option<Vec<String>>,
) -> anyhow::Result<i64> {
    anyhow::ensure!(!api_key.is_empty(), "api_key must not be empty");
    store::insert_provider_key(
        pool,
        provider_id,
        label,
        api_key,
        max_concurrency,
        allowed_models,
    )
    .await
}

/// Delete a key row (route entries are stripped in the same transaction).
/// Returns whether the row existed and was deleted.
pub async fn delete_key(pool: &PgPool, provider_id: i64, key_id: i64) -> anyhow::Result<bool> {
    store::delete_provider_key(pool, provider_id, key_id).await
}

/// Probe every enabled key of every enabled provider that has a quota source,
/// persist each successful reading as that key's snapshot
/// (`gateway_key_quota_snapshots`), and return the live readings for the HTTP
/// admin surface. One task per probe; each reading is persisted as it joins.
///
/// Quota is decorative: a key whose probe fails (or whose provider has no quota
/// source) simply has no entry, and a store failure degrades to a warning —
/// both logged, never an error. This is the single fan-out shared by the
/// request-driven admin refresh ([`Admin::quotas`]) and the background prober
/// that keeps Smart-routing snapshots fresh (spawned in `gateway::Gateway::start`).
/// The relay reads snapshots from the database, never from this call, so the
/// prober holds no request-path state; the prober's rounds are sequential —
/// the join set drains before the next tick.
pub async fn probe_all_quotas(
    pool: &PgPool,
    smart_cache: Option<&crate::relay::SmartCache>,
) -> Vec<KeyQuotaRow> {
    let providers = match store::list_providers(pool).await {
        Ok(providers) => providers,
        Err(error) => {
            tracing::warn!(error = %format!("{error:#}"), "quota probe: provider list failed");
            return Vec::new();
        }
    };
    let mut tasks = tokio::task::JoinSet::new();
    // Per-key quota anchors (quota_overrides) fill vendor-hidden monthly
    // resets; a store failure leaves every reading as the vendor reported it.
    let anchors = store::list_quota_reset_anchors(pool)
        .await
        .unwrap_or_else(|error| {
            tracing::warn!(error = %format!("{error:#}"), "quota probe: reset anchors unavailable");
            std::collections::HashMap::new()
        });
    for provider in providers.iter().filter(|provider| provider.enabled) {
        let keys = match store::list_provider_keys(pool, provider.id).await {
            Ok(keys) => keys,
            Err(error) => {
                tracing::warn!(provider = %provider.name, error = %format!("{error:#}"), "quota probe: key list failed");
                continue;
            }
        };
        // Only enabled keys get probed — filter BEFORE the probe: a disabled
        // key never costs a vendor call.
        let keys: Vec<_> = keys.into_iter().filter(|key| key.enabled).collect();
        for key in keys {
            let Some(api_key) = key.api_key else { continue }; // no credential — nothing to probe
            let key_id = key.id;
            let provider_name = provider.name.clone();
            let base_url = provider.base_url.clone();
            let anchor = anchors.get(&key_id).copied();
            tasks.spawn(async move {
                let mut quota = quota::fetch_quota(&provider_name, &base_url, &api_key).await;
                if let (Some(day), Some(quota)) = (anchor, quota.as_mut()) {
                    quota::apply_monthly_anchor(quota, day, chrono::Utc::now());
                }
                (key_id, quota)
            });
        }
    }
    let mut quotas = Vec::new();
    while let Some(joined) = tasks.join_next().await {
        match joined {
            Ok((key_id, Some(quota))) => {
                // Persist the snapshot for the GUI's instant first paint; a store
                // failure must not lose the reading itself (quota is decorative).
                if let Err(error) = store::quota_snapshot_upsert(pool, key_id, &quota).await {
                    tracing::warn!(key_id, error = %format!("{error:#}"), "quota snapshot upsert failed");
                }
                // The trend chart's series: one row per window per probe. A
                // failure never loses the reading itself (the snapshot above
                // and the in-memory cache below still carry it).
                if let Err(error) = store::quota_history_insert(pool, key_id, &quota).await {
                    tracing::warn!(key_id, error = %format!("{error:#}"), "quota history insert failed");
                }
                quotas.push(KeyQuotaRow { key_id, quota });
            }
            Ok((key_id, None)) => tracing::debug!(key_id, "quota probe: no reading"),
            Err(error) => tracing::warn!(%error, "quota probe task panicked"),
        }
    }
    // Feed the in-memory cache so Smart routes see the fresh readings on the
    // very next dispatch — no PG round-trip on the request path.
    if let Some(cache) = smart_cache {
        let snapshots: std::collections::HashMap<i64, crate::quota::KeyQuota> = quotas
            .iter()
            .map(|row| (row.key_id, row.quota.clone()))
            .collect();
        cache.refresh(snapshots);
    }
    quotas
}

/// In-process admin facade over the gateway store, assembled by the HTTP
/// handlers from the shared [`crate::api::AppState`]. Cheap to clone (the
/// pool and registries are shared).
#[derive(Clone)]
pub struct Admin {
    pool: PgPool,
    /// Mirrors `Transport::limits().allow_private_destinations`: whether the
    /// save-time endpoint check accepts private/loopback upstreams.
    allow_private: bool,
    /// Consecutive-failure streaks (shared with relay dispatch): clearing a key's
    /// rest also forgives its streak.
    failover: Arc<crate::relay::Failover>,
    /// In-memory quota cache: probing refreshes it so Smart routes see the
    /// fresh readings immediately.
    smart_cache: crate::relay::SmartCache,
    /// In-memory route/provider/key cache.
    route_cache: crate::relay::RouteCache,
    /// In-memory cooldown cache.
    rest_cache: crate::relay::RestCache,
    /// Live-activity publisher: quota probes push a refresh notification so
    /// subscribed GUIs update their cards without polling.
    activity: crate::activity::ActivitySink,
    /// Centralized dispatcher: queried for live slot occupancy (None until
    /// [`Self::with_dispatcher`] wires it).
    dispatcher: Option<tokio::sync::mpsc::UnboundedSender<crate::relay::dispatcher::DispatchEvent>>,
}

impl Admin {
    /// Construct the admin facade directly over a pool. The failover registry
    /// must be the live relay's own (the AppState one): with a fresh registry,
    /// clearing a rest cannot forgive the consecutive-failure streak held by
    /// the live relay process.
    pub fn new(
        pool: PgPool,
        allow_private: bool,
        failover: Arc<crate::relay::Failover>,
        smart_cache: crate::relay::SmartCache,
        route_cache: crate::relay::RouteCache,
        rest_cache: crate::relay::RestCache,
        activity: crate::activity::ActivitySink,
    ) -> Self {
        Self {
            pool,
            allow_private,
            failover,
            smart_cache,
            route_cache,
            rest_cache,
            activity,
            dispatcher: None,
        }
    }

    /// Wire the dispatcher for live inflight queries. Called once by the
    /// admin surface which owns the sender.
    pub fn with_dispatcher(
        mut self,
        dispatcher: tokio::sync::mpsc::UnboundedSender<crate::relay::dispatcher::DispatchEvent>,
    ) -> Self {
        self.dispatcher = Some(dispatcher);
        self
    }

    /// Assemble the admin UI's bootstrap document (see [`Bootstrap`]): every
    /// parameterless read the status pages render from, in one pass.
    ///
    /// The key list comes from a single global query rather than a
    /// per-provider fan-out, and live occupancy is filled from one dispatcher
    /// query — so this replaces the client's whole startup burst.
    pub async fn bootstrap(&self) -> anyhow::Result<Bootstrap> {
        let providers = store::list_providers(&self.pool).await?;
        let rows = store::list_all_keys(&self.pool).await?;
        let live = self.live_inflight().await;
        let keys = rows
            .iter()
            .map(|row| {
                let inflight = row
                    .max_concurrency
                    .map(|_| live.get(&(row.id as u64)).copied().unwrap_or(0) as i32);
                store::ProviderKeyView::new(row, inflight)
            })
            .collect();
        Ok(Bootstrap {
            providers,
            keys,
            routes: store::list_routes(&self.pool).await?,
            rests: store::list_rests(&self.pool).await?,
            quota_snapshots: self.quota_snapshots().await,
            quota_history: store::list_quota_history(&self.pool).await?,
            gateway_keys: store::list_gateway_keys(&self.pool).await?,
            model_success: store::last_model_success(&self.pool).await?,
        })
    }

    /// Every concurrency-limited key with its live occupancy (for the health page).
    pub async fn concurrency_usage(&self) -> anyhow::Result<Vec<ConcurrencyView>> {
        let rows = self.route_cache.all_limited_keys();
        let live = self.live_inflight().await;
        Ok(rows
            .iter()
            .map(|row| ConcurrencyView {
                key_id: row.key_id,
                provider_id: row.provider_id,
                provider_name: row.provider_name.clone(),
                key_label: row.key_label.clone(),
                max_concurrency: row.max_concurrency,
                inflight: live.get(&(row.key_id as u64)).copied().unwrap_or(0) as i32,
            })
            .collect())
    }

    /// Query the dispatcher for live key-level inflight counts.
    pub(crate) async fn live_inflight(&self) -> std::collections::HashMap<u64, usize> {
        let Some(dispatcher) = &self.dispatcher else {
            return std::collections::HashMap::new();
        };
        let (tx, rx) = tokio::sync::oneshot::channel();
        if dispatcher
            .send(crate::relay::dispatcher::DispatchEvent::QueryInflight { reply: tx })
            .is_err()
        {
            return std::collections::HashMap::new();
        }
        rx.await.unwrap_or_default()
    }

    /// Whole-window usage aggregates for the KPI cards over `[since, until)`
    /// (span capped at roughly a year, same as [`Self::usage_trend`]).
    /// `caller` restricts the window to one caller identity (None = all).
    pub async fn usage_window(
        &self,
        since: chrono::DateTime<chrono::Utc>,
        until: chrono::DateTime<chrono::Utc>,
        caller: Option<(store::CallerFilter, &str)>,
    ) -> anyhow::Result<store::UsageWindow> {
        store::usage_window(
            &self.pool,
            since.clamp(until - chrono::Duration::days(370), until),
            until,
            caller,
        )
        .await
    }

    /// Usage aggregated by bucket × category for the trend chart over
    /// `[since, until)`; `local_offset` shifts bucket labels to the caller's
    /// wall clock. The span is capped at roughly a year. `caller` restricts
    /// the aggregates to one caller identity (None = all).
    pub async fn usage_trend(
        &self,
        since: chrono::DateTime<chrono::Utc>,
        until: chrono::DateTime<chrono::Utc>,
        split: store::TrendSplit,
        local_offset: chrono::Duration,
        caller: Option<(store::CallerFilter, &str)>,
    ) -> anyhow::Result<Vec<store::TrendRow>> {
        let since = since.clamp(until - chrono::Duration::days(370), until);
        store::usage_trend(&self.pool, since, until, split, local_offset, caller).await
    }

    /// Models the chat picker offers: route aliases first (routes are the
    /// user-facing models), then one `provider/model` direct entry per probed
    /// model of every enabled account (whitelist-filtered, deduped). An
    /// unprobed account contributes no direct entries until it is probed.
    /// Aliases are listed even when every entry's key is disabled — the relay
    /// is the source of truth for dispatch-time failure (404).
    ///
    /// Retrieval rows and retrieval-only routes are excluded: an embeddings id
    /// in a chat picker is a model no agent can hold a conversation with.
    pub async fn chat_models(&self) -> anyhow::Result<Vec<String>> {
        let mut models: Vec<String> = self
            .route_cache
            .chat_routes()
            .into_iter()
            .map(|route| route.alias)
            .collect();
        let mut direct = Vec::new();
        for key in self.route_cache.all_enabled_key_models() {
            for model in key.models.unwrap_or_default() {
                let allowed = key
                    .allowed_models
                    .as_ref()
                    .is_none_or(|whitelist| whitelist.is_empty() || whitelist.contains(&model.id));
                if allowed {
                    direct.push(format!("{}/{}", key.provider, model.id));
                }
            }
        }
        direct.sort();
        direct.dedup();
        models.extend(direct);
        Ok(models)
    }

    /// Live vendor quota/balance readings for every enabled key of an enabled
    /// provider. Thin wrapper over [`probe_all_quotas`], which owns the
    /// probe/persist fan-out; the HTTP response shape (`{"items": [...]}`) is
    /// unchanged.
    pub async fn quotas(&self) -> Vec<KeyQuotaRow> {
        let rows = probe_all_quotas(&self.pool, Some(&self.smart_cache)).await;
        if !rows.is_empty() {
            self.activity.quota_refreshed();
        }
        rows
    }

    /// Stored quota snapshots (key id, last reading, probe time) for the GUI's
    /// instant first paint — no vendor probing involved. Decorative like
    /// [`Self::quotas`]: a store failure degrades to an empty list, logged.
    pub async fn quota_snapshots(&self) -> Vec<KeyQuotaSnapshotRow> {
        match store::list_quota_snapshots(&self.pool).await {
            Ok(snapshots) => snapshots
                .into_iter()
                .map(|(key_id, quota, fetched_at)| KeyQuotaSnapshotRow {
                    key_id,
                    quota,
                    fetched_at,
                })
                .collect(),
            Err(error) => {
                tracing::warn!(error = %format!("{error:#}"), "quota snapshots: list failed");
                Vec::new()
            }
        }
    }

    // ---------- writes (same validation semantics as the HTTP admin handlers) ----------

    /// Save-time endpoint check, identical to the HTTP admin handlers':
    /// SSRF policy plus the hardcoded-vendor base_url contract (version root,
    /// never a protocol leaf — see relay::capabilities).
    fn validate_endpoint(&self, name: &str, base_url: &str) -> anyhow::Result<()> {
        crate::upstream::transport::validate_saved_endpoint(base_url, self.allow_private)?;
        crate::relay::capabilities::validate_base_url(name, base_url)
    }

    /// Validate a not-yet-saved key against its provider's model list: the
    /// fetch proves the key authenticates and the endpoint answers, and the
    /// returned ids are what the route editor offers for picking. The input is
    /// the catalog spec — no provider row needs to exist yet.
    pub async fn validate_key(
        &self,
        input: &ProviderInput<'_>,
        api_key: &str,
    ) -> anyhow::Result<Vec<probe::ProbeModel>> {
        self.validate_endpoint(input.name, input.base_url)?;
        Ok(probe::fetch_models(
            input.base_url,
            input.protocol,
            input.resolved_auth_scheme(),
            api_key,
        )
        .await
        .map_err(ProbeError)?)
    }

    /// The models a saved key can list (route editor's picker). A successful
    /// probe also refreshes the key's persisted model-list snapshot (the
    /// /v1/models route-object derivation reads it); a snapshot-store failure
    /// degrades to a warning — the fresh list is still returned.
    pub async fn list_key_models(&self, key_id: i64) -> anyhow::Result<Vec<probe::ProbeModel>> {
        let keys = store::list_keys_by_ids(&self.pool, &[key_id]).await?;
        let Some(key) = keys.into_iter().next() else {
            return Err(NoSuchKey(key_id).into());
        };
        let Some(provider) = store::get_provider(&self.pool, key.provider_id).await? else {
            anyhow::bail!("key {key_id} 的 provider {} 不存在", key.provider_id)
        };
        let models = probe::fetch_models(
            &provider.base_url,
            &provider.protocol,
            &provider.auth_scheme,
            key.api_key
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("key {key_id} has no api_key to probe with"))?,
        )
        .await
        .map_err(ProbeError)?;
        if let Err(error) = store::update_key_models(&self.pool, key_id, &models).await {
            tracing::warn!(key_id, error = %format!("{error:#}"), "model snapshot persist failed");
        }
        // The route cache is the only read path for /v1/models; refresh it so a
        // successful persist is visible immediately. A refresh failure degrades
        // to a warn — the next admin write retries it.
        if let Err(error) = self.route_cache.refresh(&self.pool).await {
            tracing::warn!(key_id, error = %format!("{error:#}"), "route cache refresh after model snapshot failed");
        }
        Ok(models)
    }

    /// Persist a key's model-list snapshot. The add-account flow already holds
    /// the freshly validated list (from [`Self::validate_key`]) and stores it
    /// right after the key row exists, without a second upstream probe. Returns
    /// false when no such key row exists.
    pub async fn save_key_models(
        &self,
        key_id: i64,
        models: &[ProbeModel],
    ) -> anyhow::Result<bool> {
        let updated = store::update_key_models(&self.pool, key_id, models).await?;
        // The route cache is the only read path for /v1/models; refresh it so a
        // successful persist is visible immediately. A refresh failure degrades
        // to a warn — the next admin write retries it.
        if updated && let Err(error) = self.route_cache.refresh(&self.pool).await {
            tracing::warn!(key_id, error = %format!("{error:#}"), "route cache refresh after model snapshot failed");
        }
        Ok(updated)
    }

    /// Add a named key to a provider; returns the new key id.
    /// `max_concurrency`: per-key in-flight cap (None = unlimited).
    /// `allowed_models`: the key's model whitelist (None/empty = unrestricted).
    /// The secret goes to the secret store first (Keychain-first ordering, see
    /// [`create_key`]); the row stores only its reference.
    pub async fn create_key(
        &self,
        provider_id: i64,
        label: &str,
        api_key: &str,
        max_concurrency: Option<i32>,
        allowed_models: Option<Vec<String>>,
    ) -> anyhow::Result<i64> {
        create_key(
            &self.pool,
            provider_id,
            label,
            api_key,
            max_concurrency,
            allowed_models,
        )
        .await
    }

    /// Delete a key (row + its secret-store item, see [`delete_key`]).
    /// Errors when the key does not exist.
    pub async fn delete_key(&self, provider_id: i64, key_id: i64) -> anyhow::Result<()> {
        let deleted = delete_key(&self.pool, provider_id, key_id).await?;
        anyhow::ensure!(deleted, "no such key {key_id}");
        Ok(())
    }

    /// Clear one key's cooldown (idempotent).
    pub async fn clear_rest(&self, key_id: i64) -> anyhow::Result<()> {
        self.failover.failures().clear(key_id);
        self.rest_cache.clear_key(key_id).await
    }

    /// Clear all cooldown rows for every key of a provider (idempotent).
    pub async fn clear_provider_rests(&self, provider_id: i64) -> anyhow::Result<()> {
        // Forgive every key's failure streak first (the in-memory counter must not
        // re-rest them on the next attempt).
        for key in store::list_provider_keys(&self.pool, provider_id).await? {
            self.failover.failures().clear(key.id);
        }
        self.rest_cache.clear_provider(provider_id).await
    }

    /// All active cooldown rows (admin display).
    pub async fn list_rests(&self) -> anyhow::Result<Vec<crate::store::RestRow>> {
        self.rest_cache.list_all().await
    }
}
