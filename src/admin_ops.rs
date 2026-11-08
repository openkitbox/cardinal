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

use anyhow::Context;
use chrono::Duration;
use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

use crate::credentials::AuthKind;
use crate::credentials::CursorOAuth;
use crate::credentials::KeyCredential;
use crate::cursor;
use crate::kiro::KiroOAuth;
use crate::openai::OpenaiOAuth;
use crate::openai::auth as openai_auth;
use crate::openai::login as openai_login;
use crate::opencode::OpencodeOAuth;
use crate::opencode::auth;
use crate::opencode::auth::TokenGrant;
use crate::opencode::login;
use crate::opencode::login::SessionState;
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
    /// How the row authenticates upstream (`static`, `kiro_oidc`,
    /// `opencode_oauth`): the reveal view names the credential kind so the GUI
    /// can label the account instead of guessing from the api_key shape.
    pub auth_kind: String,
    /// When the account was archived (None = not archived).
    pub archived_at: Option<chrono::DateTime<chrono::Utc>>,
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
    /// The current balance segment of every prepaid key (segment-opening row
    /// plus downsampled change rows), for the cards' balance charts. Older
    /// gateways omit the field; the GUI then renders the current reading alone.
    #[serde(default)]
    pub balance_history: Vec<store::BalanceHistoryPoint>,
    pub gateway_keys: Vec<store::GatewayKeyRow>,
    /// Latest successful request time per (key, model).
    pub model_success: Vec<store::ModelSuccessRow>,
    /// Account groups with their member key ids (the only place membership
    /// lives; `keys` carries none), in id order.
    pub key_groups: Vec<store::KeyGroupView>,
}

/// The probed key row does not exist. The admin HTTP surface maps this to
/// 404; in-process callers see the same message as before.
#[derive(Debug, thiserror::Error)]
#[error("no such key {0}")]
pub struct NoSuchKey(pub i64);
/// An outbound probe failed: the vendor rejected the credential, DNS,
/// timeout, or an undecodable payload. The admin HTTP surface maps this to
/// 502 Bad Gateway — the request was well-formed; the dependency failed.
#[derive(Debug)]
pub enum ProbeError {
    /// A regular provider probe keeps its detailed diagnostic for the GUI.
    Regular(anyhow::Error),
    /// Kiro probe details may include upstream-controlled content and must not
    /// cross the admin API boundary.
    Kiro(anyhow::Error),
}

impl std::fmt::Display for ProbeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Regular(error) => write!(formatter, "{error:#}"),
            Self::Kiro(_) => formatter.write_str("upstream probe failed"),
        }
    }
}

impl std::error::Error for ProbeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Regular(error) | Self::Kiro(error) => Some(error.as_ref()),
        }
    }
}

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
        auth_kind: row.auth_kind.clone(),
        archived_at: row.archived_at,
    }
}

/// Create a key with the credential its create request resolved to: a static
/// api_key row, or an OAuth row whose bundle replaces the api_key (a Kiro OIDC
/// bundle or an OpenCode Console bundle). The caller
/// ([`crate::admin::router`]'s create endpoint) resolves the provider's protocol
/// and validates the bundle via [`crate::credentials::resolve_key_credential`];
/// the empty-static-key guard stays here as well so this public facade cannot
/// store a blank credential.
pub async fn create_key(
    pool: &PgPool,
    provider_id: i64,
    label: &str,
    credential: KeyCredential<'_>,
    max_concurrency: Option<i32>,
    allowed_models: Option<Vec<String>>,
) -> anyhow::Result<i64> {
    match credential {
        KeyCredential::Static(api_key) => {
            anyhow::ensure!(!api_key.trim().is_empty(), "api_key must not be empty");
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
        KeyCredential::KiroOidc(oauth) => {
            store::insert_kiro_provider_key(
                pool,
                provider_id,
                label,
                oauth,
                max_concurrency,
                allowed_models,
            )
            .await
        }
        KeyCredential::OpencodeOauth(oauth) => {
            store::insert_opencode_provider_key(
                pool,
                provider_id,
                label,
                oauth,
                max_concurrency,
                allowed_models,
            )
            .await
        }
        KeyCredential::CursorOauth(oauth) => {
            store::insert_cursor_provider_key(
                pool,
                provider_id,
                label,
                oauth,
                max_concurrency,
                allowed_models,
            )
            .await
        }
        KeyCredential::OpenaiOauth(oauth) => {
            store::insert_openai_provider_key(
                pool,
                provider_id,
                label,
                oauth,
                max_concurrency,
                allowed_models,
            )
            .await
        }
    }
}

/// Delete a key row (this account's route entries are stripped in the same
/// transaction).
/// Returns the deleted row's `auth_kind` (None = no such row), which the caller
/// uses to evict the per-key token cache that credential owned.
pub async fn delete_key(
    pool: &PgPool,
    provider_id: i64,
    key_id: i64,
) -> anyhow::Result<Option<String>> {
    store::delete_provider_key(pool, provider_id, key_id).await
}

/// Probe every enabled, unarchived key of every enabled provider that has a
/// quota source,
/// persist each successful reading as that key's snapshot
/// (`gateway_key_quota_snapshots`), and return the live readings for the HTTP
/// admin surface. One task per probe; each reading is persisted as it joins.
///
/// Two probe kinds: a static key asks its provider's vendor endpoint
/// ([`quota::fetch_quota`]) with its own credential, while a Kiro key and an
/// OpenCode account key have no api_key — their OAuth bundles come from the
/// shared token managers ([`crate::upstream::KiroTokens`],
/// [`crate::upstream::OpencodeTokens`]). Those are the same instances dispatch
/// uses, so a probe's token refresh is a chat's refresh too, never a second
/// cache.
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
    kiro_tokens: Option<&Arc<crate::upstream::KiroTokens>>,
    opencode_tokens: Option<&Arc<crate::upstream::OpencodeTokens>>,
    cursor_tokens: Option<&Arc<crate::upstream::CursorTokens>>,
    openai_tokens: Option<&Arc<crate::upstream::OpenaiTokens>>,
) -> Vec<KeyQuotaRow> {
    /// Which credential a key's probe uses.
    enum QuotaSource {
        /// The row's own api_key, at its provider's vendor endpoint.
        Static(String),
        /// The shared Kiro token manager, at the credential's region host.
        Kiro(Arc<crate::upstream::KiroTokens>),
        /// The shared OpenCode token manager: the account's bearer, with the
        /// workspace header an organization-scoped login requires.
        Opencode(Arc<crate::upstream::OpencodeTokens>),
        /// The shared Cursor bearer cache, at the Cursor dashboard.
        Cursor(Arc<crate::upstream::CursorTokens>),
        /// The shared OpenAI token manager: the account's bearer, at the
        /// ChatGPT usage endpoint.
        Openai(Arc<crate::upstream::OpenaiTokens>),
    }
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
        // Only enabled, unarchived keys get probed — filter BEFORE the probe:
        // a disabled or archived key never costs a vendor call.
        let keys: Vec<_> = keys.into_iter().filter(|key| key.active()).collect();
        for mut key in keys {
            let key_id = key.id;
            // Kiro's and Cursor's quota sources are decided by the provider's
            // protocol, not by the presence of an api_key (an account row
            // never carries one). Every other provider keeps the
            // credential-or-nothing rule.
            let source = if provider.protocol == "cursor" {
                // Same rule as Kiro: the bearer must come from the one live
                // manager, or a second cache would race dispatch's refreshes.
                let Some(tokens) = cursor_tokens else {
                    tracing::warn!(provider = %provider.name, "quota probe: no Cursor token manager wired; skipping its keys");
                    break;
                };
                QuotaSource::Cursor(Arc::clone(tokens))
            } else if provider.protocol == "kiro" {
                let Some(tokens) = kiro_tokens else {
                    // Without the live manager there is no bearer to reuse, and
                    // minting a second cache would race dispatch's refreshes.
                    // Kiro quotas stay unprobed (decorative, and the GUI's last
                    // snapshot remains) instead of spending vendor traffic.
                    tracing::warn!(provider = %provider.name, "quota probe: no Kiro token manager wired; skipping its keys");
                    break;
                };
                QuotaSource::Kiro(Arc::clone(tokens))
            } else if key.auth_kind == AuthKind::OpencodeOauth.as_str() {
                // Same rule for an OpenCode account row: no api_key by
                // construction, and minting a second token cache would race
                // dispatch's refreshes (which would lock the account out, since
                // the console rotates the refresh token).
                let Some(tokens) = opencode_tokens else {
                    tracing::warn!(provider = %provider.name, "quota probe: no OpenCode token manager wired; skipping its keys");
                    break;
                };
                QuotaSource::Opencode(Arc::clone(tokens))
            } else if key.auth_kind == AuthKind::OpenaiOauth.as_str() {
                // Same rule for an OpenAI account row: no api_key, and the
                // refresh token rotates, so only the shared manager may refresh.
                let Some(tokens) = openai_tokens else {
                    tracing::warn!(provider = %provider.name, "quota probe: no OpenAI token manager wired; skipping its keys");
                    break;
                };
                QuotaSource::Openai(Arc::clone(tokens))
            } else {
                match key.api_key.take() {
                    Some(api_key) => QuotaSource::Static(api_key),
                    None => continue, // no credential — nothing to probe
                }
            };
            let provider_name = provider.name.clone();
            let base_url = provider.base_url.clone();
            let anchor = anchors.get(&key_id).copied();
            let pool = pool.clone();
            tasks.spawn(async move {
                let mut quota = match &source {
                    QuotaSource::Kiro(tokens) => quota::fetch_kiro_quota(&pool, tokens, &key).await,
                    QuotaSource::Cursor(tokens) => {
                        quota::fetch_cursor_quota(&pool, tokens, &key).await
                    }
                    QuotaSource::Opencode(tokens) => match tokens.resolve(&pool, key_id).await {
                        Ok(bundle) => {
                            quota::fetch_quota(
                                &provider_name,
                                &base_url,
                                &bundle.access_token,
                                bundle.org_id.as_deref(),
                            )
                            .await
                        }
                        Err(error) => {
                            // Quota is decorative: a credential-plane failure
                            // only costs this round's reading.
                            tracing::warn!(key_id, error = %error, "quota probe: OpenCode bearer unavailable");
                            None
                        }
                    },
                    QuotaSource::Openai(tokens) => match tokens.resolve(&pool, key_id).await {
                        Ok(bearer) => quota::fetch_openai_codex_quota(&bearer, key_id).await,
                        Err(error) => {
                            // Quota is decorative: a credential-plane failure
                            // only costs this round's reading.
                            tracing::warn!(key_id, error = %error, "quota probe: OpenAI bearer unavailable");
                            None
                        }
                    },
                    QuotaSource::Static(api_key) => {
                        quota::fetch_quota(&provider_name, &base_url, api_key, None).await
                    }
                };
                // The vendor read's own instant, taken before any DB work: the
                // balance history orders readings by it, so a probe that
                // finishes late cannot overwrite a newer one.
                let probed_at = chrono::Utc::now();
                if let (Some(day), Some(quota)) = (anchor, quota.as_mut()) {
                    quota::apply_monthly_anchor(quota, day, probed_at);
                }
                (key_id, probed_at, quota)
            });
        }
    }
    let mut quotas = Vec::new();
    while let Some(joined) = tasks.join_next().await {
        match joined {
            Ok((key_id, probed_at, Some(quota))) => {
                // Persist the snapshot for the GUI's instant first paint; a store
                // failure must not lose the reading itself (quota is decorative).
                if let Err(error) =
                    store::quota_snapshot_upsert(pool, key_id, &quota, probed_at).await
                {
                    tracing::warn!(key_id, error = %format!("{error:#}"), "quota snapshot upsert failed");
                }
                // The trend chart's series: one row per window per probe. A
                // failure never loses the reading itself (the snapshot above
                // and the in-memory cache below still carry it).
                if let Err(error) = store::quota_history_insert(pool, key_id, &quota).await {
                    tracing::warn!(key_id, error = %format!("{error:#}"), "quota history insert failed");
                }
                // The balance chart's series: written only when the amount
                // changed. A failure never loses the reading itself.
                if let Some(balance) = &quota.balance
                    && let Err(error) =
                        store::balance_history_record(pool, key_id, balance, probed_at).await
                {
                    tracing::warn!(key_id, error = %format!("{error:#}"), "balance history record failed");
                }
                quotas.push(KeyQuotaRow { key_id, quota });
            }
            Ok((key_id, _, None)) => tracing::debug!(key_id, "quota probe: no reading"),
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
    /// The process's single Kiro token manager (None until
    /// [`Self::with_kiro_tokens`] wires it). Kiro quota probes resolve their
    /// bearer through it — the same single-flight cache dispatch uses — so a
    /// refresh is shared instead of duplicated.
    kiro_tokens: Option<Arc<crate::upstream::KiroTokens>>,
    /// The same arrangement for OpenCode account rows (None until
    /// [`Self::with_opencode_tokens`] wires it): model probing and quota probing
    /// resolve their bearer through dispatch's cache.
    opencode_tokens: Option<Arc<crate::upstream::OpencodeTokens>>,
    /// The same arrangement for Cursor rows (None until
    /// [`Self::with_cursor_tokens`] wires it): model probing and save-time key
    /// validation resolve their bearer through dispatch's cache.
    cursor_tokens: Option<Arc<crate::upstream::CursorTokens>>,
    /// The OpenCode device-login flow's dependencies (None until
    /// [`Self::with_opencode_login`] wires them): the same stateless console
    /// client dispatch uses, plus the process's session registry.
    opencode_login: Option<OpencodeLogin>,
    /// The Cursor browser-login flow's dependencies (None until
    /// [`Self::with_cursor_login`] wires them): the login client and the
    /// process's session registry.
    cursor_login: Option<CursorLogin>,
    /// The same arrangement for OpenAI Codex rows (None until
    /// [`Self::with_openai_tokens`] wires it): model probing and quota probing
    /// resolve their bearer through dispatch's cache.
    openai_tokens: Option<Arc<crate::upstream::OpenaiTokens>>,
    /// The OpenAI Codex device-login flow's dependencies (None until
    /// [`Self::with_openai_login`] wires them).
    openai_login: Option<OpenaiLogin>,
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
            kiro_tokens: None,
            opencode_tokens: None,
            cursor_tokens: None,
            opencode_login: None,
            cursor_login: None,
            openai_tokens: None,
            openai_login: None,
            dispatcher: None,
        }
    }

    /// Wire the live Cursor token manager so its model probes and key
    /// validation share dispatch's bearer cache. Called once by the admin
    /// surface which owns the same instance.
    pub fn with_cursor_tokens(mut self, cursor_tokens: Arc<crate::upstream::CursorTokens>) -> Self {
        self.cursor_tokens = Some(cursor_tokens);
        self
    }

    /// Wire the live Kiro token manager so Kiro quota probes share dispatch's
    /// single-flight credential cache. Called once by the admin surface which
    /// owns the same instance.
    pub fn with_kiro_tokens(mut self, kiro_tokens: Arc<crate::upstream::KiroTokens>) -> Self {
        self.kiro_tokens = Some(kiro_tokens);
        self
    }

    /// Wire the live OpenCode token manager so its model and quota probes share
    /// dispatch's bearer cache. Called once by the admin surface which owns the
    /// same instance.
    pub fn with_opencode_tokens(
        mut self,
        opencode_tokens: Arc<crate::upstream::OpencodeTokens>,
    ) -> Self {
        self.opencode_tokens = Some(opencode_tokens);
        self
    }

    /// Wire the live OpenAI token manager so its model and quota probes share
    /// dispatch's bearer cache and a finished login installs its bundle there.
    pub fn with_openai_tokens(mut self, openai_tokens: Arc<crate::upstream::OpenaiTokens>) -> Self {
        self.openai_tokens = Some(openai_tokens);
        self
    }

    /// Wire the OpenAI Codex login flow: the issuer client and the process's
    /// session registry.
    pub fn with_openai_login(
        mut self,
        client: Arc<openai_auth::Client>,
        logins: openai_login::OpenaiLogins,
    ) -> Self {
        self.openai_login = Some(OpenaiLogin { client, logins });
        self
    }

    /// Wire the OpenCode login flow: the console client and the process's
    /// session registry. Called once by the admin surface, which owns the same
    /// client instance dispatch and probing use.
    pub fn with_opencode_login(
        mut self,
        client: Arc<auth::Client>,
        logins: login::OpencodeLogins,
    ) -> Self {
        self.opencode_login = Some(OpencodeLogin { client, logins });
        self
    }

    /// Wire the Cursor login flow: the login client and the process's session
    /// registry. Called once by the admin surface.
    pub fn with_cursor_login(
        mut self,
        client: Arc<cursor::Client>,
        logins: cursor::CursorLogins,
    ) -> Self {
        self.cursor_login = Some(CursorLogin { client, logins });
        self
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

    /// Refresh the route cache and publish its complete concurrency-cap view. Existing
    /// inflight work is never cancelled; the dispatcher applies the new cap
    /// only to future assignments.
    pub(crate) async fn refresh_route_cache(&self) -> anyhow::Result<()> {
        let Some(dispatcher) = &self.dispatcher else {
            self.route_cache.refresh(&self.pool).await?;
            return Ok(());
        };
        self.route_cache
            .refresh_and_sync(&self.pool, dispatcher)
            .await
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
            balance_history: store::list_balance_history(&self.pool).await?,
            gateway_keys: store::list_gateway_keys(&self.pool, None).await?,
            model_success: store::last_model_success(&self.pool).await?,
            key_groups: store::list_key_groups(&self.pool).await?,
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
        caller: Option<store::CallerFilter>,
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
        caller: Option<store::CallerFilter>,
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

    /// Live vendor quota/balance readings for every enabled, unarchived key of
    /// an enabled provider. Thin wrapper over [`probe_all_quotas`], which owns the
    /// probe/persist fan-out; the HTTP response shape (`{"items": [...]}`) is
    /// unchanged.
    pub async fn quotas(&self) -> Vec<KeyQuotaRow> {
        let rows = probe_all_quotas(
            &self.pool,
            Some(&self.smart_cache),
            self.kiro_tokens.as_ref(),
            self.opencode_tokens.as_ref(),
            self.cursor_tokens.as_ref(),
            self.openai_tokens.as_ref(),
        )
        .await;
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
        if input.protocol == "cursor" {
            // A Cursor API key never authenticates a request itself: it is
            // exchanged for a bearer, and the usable-models list proves both
            // the exchange and the account.
            let Some(tokens) = &self.cursor_tokens else {
                anyhow::bail!("Cursor 模型列表需要已接线的 token 管理器")
            };
            let bearer = tokens
                .probe_static(api_key)
                .await
                .map_err(|error| ProbeError::Regular(error.into()))?;
            return probe::fetch_cursor_models(tokens.transport(), &bearer)
                .await
                .map_err(|error| ProbeError::Regular(error).into());
        }
        Ok(probe::fetch_models(
            input.base_url,
            input.protocol,
            input.resolved_auth_scheme(),
            api_key,
            None,
        )
        .await
        .map_err(ProbeError::Regular)?)
    }

    /// The models a saved key can list (route editor's picker). A successful
    /// probe also refreshes the key's persisted model-list snapshot (the
    /// /v1/models route-object derivation reads it); a snapshot-store failure
    /// degrades to a warning — the fresh list is still returned.
    ///
    /// Two credential shapes reach two catalogues: a static key asks its
    /// provider's `/models` with `api_key`; a Kiro key has no api_key and its
    /// catalogue lives on the credential's control plane
    /// ([`Self::probe_kiro_models`]); an OpenCode account key also has no
    /// api_key and asks the provider's `/models` with its resolved bearer
    /// ([`Self::probe_opencode_models`]).
    pub async fn list_key_models(&self, key_id: i64) -> anyhow::Result<Vec<probe::ProbeModel>> {
        let keys = store::list_keys_by_ids(&self.pool, &[key_id]).await?;
        let Some(key) = keys.into_iter().next() else {
            return Err(NoSuchKey(key_id).into());
        };
        let Some(provider) = store::get_provider(&self.pool, key.provider_id).await? else {
            anyhow::bail!("key {key_id} 的 provider {} 不存在", key.provider_id)
        };
        let models = if provider.protocol == "kiro" {
            self.probe_kiro_models(&key).await?
        } else if provider.protocol == "cursor" {
            self.probe_cursor_models(&key).await?
        } else if key.auth_kind == AuthKind::OpencodeOauth.as_str() {
            self.probe_opencode_models(&provider, &key).await?
        } else if key.auth_kind == AuthKind::OpenaiOauth.as_str() {
            self.probe_openai_models(&key).await?
        } else {
            let api_key = key
                .api_key
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("key {key_id} has no api_key to probe with"))?;
            probe::fetch_models(
                &provider.base_url,
                &provider.protocol,
                &provider.auth_scheme,
                api_key,
                None,
            )
            .await
            .map_err(ProbeError::Regular)?
        };
        if let Err(error) = store::update_key_models(&self.pool, key_id, &models).await {
            tracing::warn!(
                key_id,
                error = %format!("{error:#}"),
                "model snapshot persistence failed after a successful probe"
            );
        }
        // The route cache is the only read path for /v1/models; refresh it so a
        // successful persist is visible immediately. A refresh failure degrades
        // to a warn — the next admin write retries it.
        if let Err(error) = self.refresh_route_cache().await {
            tracing::warn!(key_id, error = %format!("{error:#}"), "route cache refresh after model snapshot failed");
        }
        Ok(models)
    }

    /// One Kiro key's model catalogue via the control plane's
    /// `ListAvailableModels`. The bearer comes from the shared
    /// [`crate::upstream::KiroTokens`] instance — the same single-flight cache
    /// dispatch uses — and the host is derived from the credential's
    /// `api_region`, never from the provider row's runtime `base_url`.
    async fn probe_kiro_models(
        &self,
        key: &store::ProviderKeyRow,
    ) -> anyhow::Result<Vec<ProbeModel>> {
        let Some(tokens) = &self.kiro_tokens else {
            // Without the live manager there is no bearer to reuse, and a
            // second cache would race dispatch's refresh-token rotation.
            anyhow::bail!("Kiro 模型列表需要已接线的 token 管理器")
        };
        let context = tokens
            .access_token(&self.pool, key)
            .await
            .map_err(|error| ProbeError::Kiro(error.into()))?;
        probe::fetch_kiro_models(tokens.transport(), &context)
            .await
            .map_err(|error| ProbeError::Kiro(error).into())
    }

    /// One OpenCode account key's model catalogue via the provider's `/models`,
    /// authenticated with the account's resolved bearer. The bearer comes from
    /// the shared [`crate::upstream::OpencodeTokens`] instance — the same
    /// single-flight cache dispatch uses — so a probe's refresh is a chat's
    /// refresh, never a second rotation of the account's refresh token.
    async fn probe_opencode_models(
        &self,
        provider: &store::ProviderRow,
        key: &store::ProviderKeyRow,
    ) -> anyhow::Result<Vec<ProbeModel>> {
        let Some(tokens) = &self.opencode_tokens else {
            anyhow::bail!("OpenCode 模型列表需要已接线的 token 管理器")
        };
        let bundle = tokens
            .resolve(&self.pool, key.id)
            .await
            .map_err(|error| ProbeError::Regular(error.into()))?;
        probe::fetch_models(
            &provider.base_url,
            &provider.protocol,
            &provider.auth_scheme,
            &bundle.access_token,
            bundle.org_id.as_deref(),
        )
        .await
        .map_err(|error| ProbeError::Regular(error).into())
    }

    /// One OpenAI Codex account's model catalogue, authenticated with its
    /// resolved bearer from the shared [`crate::upstream::OpenaiTokens`]
    /// instance (a probe's refresh is a chat's refresh, never a second rotation
    /// of the account's refresh token).
    async fn probe_openai_models(
        &self,
        key: &store::ProviderKeyRow,
    ) -> anyhow::Result<Vec<ProbeModel>> {
        let Some(tokens) = &self.openai_tokens else {
            anyhow::bail!("OpenAI 模型列表需要已接线的 token 管理器")
        };
        let bearer = tokens
            .resolve(&self.pool, key.id)
            .await
            .map_err(|error| ProbeError::Regular(error.into()))?;
        probe::fetch_openai_codex_models(&bearer)
            .await
            .map_err(|error| ProbeError::Regular(error).into())
    }

    /// One Cursor key's usable-models list, authenticated with the account's
    /// resolved bearer: the row's login bundle refreshed, or its API key
    /// exchanged, by the shared [`crate::upstream::CursorTokens`] instance.
    /// The protocol decides (every Cursor row goes through the manager), not
    /// the credential kind.
    async fn probe_cursor_models(
        &self,
        key: &store::ProviderKeyRow,
    ) -> anyhow::Result<Vec<ProbeModel>> {
        let Some(tokens) = &self.cursor_tokens else {
            anyhow::bail!("Cursor 模型列表需要已接线的 token 管理器")
        };
        let credential = match key.cursor_oauth() {
            Some(bundle) => KeyCredential::CursorOauth(bundle),
            None => KeyCredential::Static(key.api_key.as_deref().ok_or_else(|| {
                anyhow::anyhow!("key {} has no credential to probe with", key.id)
            })?),
        };
        let bearer = tokens
            .resolve(&self.pool, key.id, &credential)
            .await
            .map_err(|error| ProbeError::Regular(error.into()))?;
        probe::fetch_cursor_models(tokens.transport(), &bearer)
            .await
            .map_err(|error| ProbeError::Regular(error).into())
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
        if updated && let Err(error) = self.refresh_route_cache().await {
            tracing::warn!(key_id, error = %format!("{error:#}"), "route cache refresh after model snapshot failed");
        }
        Ok(updated)
    }

    /// Find-or-create a Kiro key from an operator-supplied OAuth bundle, but
    /// only after that candidate proves usable against the Kiro model
    /// catalogue.
    ///
    /// The probe is deliberately pre-persistence: a failed probe leaves any
    /// existing key's credential and model snapshot untouched and creates no
    /// row. A stale candidate access token is refreshed in memory through the
    /// shared [`crate::upstream::KiroTokens`] lifecycle (no DB write), and the
    /// refreshed bundle — not the submitted one — is stored once the catalogue
    /// answers. That catalogue response is also the key's model snapshot (stored
    /// best-effort: a snapshot-write failure never undoes a proven credential),
    /// so the already-probed credential is not sent upstream a second time.
    ///
    /// Returns `(key_id, created)` like [`store::upsert_kiro_key_by_label`].
    /// `group_ids`, when given, are added to the key's memberships in the
    /// same transaction (never removed); an unknown id fails the whole write.
    pub async fn upsert_kiro_key(
        &self,
        provider_id: i64,
        label: &str,
        oauth: KiroOAuth,
        group_ids: Option<&[i64]>,
        max_concurrency: Option<Option<i32>>,
    ) -> anyhow::Result<(i64, bool)> {
        if label.is_empty() {
            return Err(
                store::KiroUpsertError::InvalidInput("label must not be empty".to_owned()).into(),
            );
        }
        oauth
            .validate()
            .map_err(|error| store::KiroUpsertError::InvalidInput(format!("{error:#}")))?;
        if let Some(limit) = max_concurrency.flatten()
            && limit <= 0
        {
            return Err(store::KiroUpsertError::InvalidInput(
                "max_concurrency must be positive".to_owned(),
            )
            .into());
        }
        // Both regions become URL hosts (the OIDC token endpoint and the
        // control plane), so the grammar guard dispatch shares applies before
        // any request is built — an unusable region is caller error, not a
        // vendor failure.
        for region in [&oauth.api_region, &oauth.auth_region] {
            if !crate::kiro::valid_region(region) {
                return Err(store::KiroUpsertError::InvalidInput(
                    "Kiro OAuth regions must be AWS region names".to_owned(),
                )
                .into());
            }
        }
        // Reject a missing/mismatched provider before spending a vendor probe.
        // The store repeats both checks under its transaction lock.
        let Some(provider) = store::get_provider(&self.pool, provider_id).await? else {
            return Err(store::KiroUpsertError::ProviderNotFound(provider_id).into());
        };
        if provider.protocol != "kiro" {
            return Err(store::KiroUpsertError::ProviderProtocolMismatch(provider_id).into());
        }
        if !crate::kiro::kas_endpoint_matches(&provider.base_url, &oauth.api_region) {
            return Err(store::KiroUpsertError::InvalidInput(
                "Kiro provider endpoint does not match the OAuth API region".to_owned(),
            )
            .into());
        }
        if let Some(group_ids) = group_ids
            && !store::key_groups_exist(&self.pool, group_ids).await?
        {
            return Err(store::KiroUpsertError::InvalidInput("unknown group id".to_owned()).into());
        }
        let expectation = store::kiro_upsert_expectation(&self.pool, provider_id, label).await?;
        let Some(tokens) = &self.kiro_tokens else {
            // Without the live manager there is no bearer to reuse, and minting
            // a second cache would race dispatch's refresh-token rotation.
            anyhow::bail!("Kiro 模型列表需要已接线的 token 管理器")
        };
        let candidate = tokens
            .candidate_for_probe(oauth)
            .await
            .map_err(|error| ProbeError::Kiro(error.into()))?;
        let models = probe::fetch_kiro_models(tokens.transport(), &candidate.call)
            .await
            .map_err(ProbeError::Kiro)?;
        let candidate_oauth = candidate.oauth;
        let (key_id, created) = store::upsert_kiro_key_by_label(
            &self.pool,
            provider_id,
            label,
            &candidate_oauth,
            &expectation,
            max_concurrency,
            group_ids,
        )
        .await?;
        // The catalogue answer also becomes the key's model snapshot. That is a
        // second write, so its failure must not fail an import whose credential
        // is already proven and adopted: losing the snapshot only defers the
        // derived /v1/models attributes until the next successful probe — the
        // same degradation `list_key_models` accepts.
        let models_saved =
            store::update_key_models_for_oauth(&self.pool, key_id, &candidate_oauth, &models).await;
        tokens
            .adopt_persisted(&self.pool, provider_id, key_id, candidate_oauth)
            .await;
        if let Err(error) = self.refresh_route_cache().await {
            tracing::warn!(key_id, error = %format!("{error:#}"), "route cache refresh after Kiro key upsert failed");
        }
        match models_saved {
            Ok(true) => {}
            Ok(false) => tracing::warn!(
                key_id,
                "Kiro key row vanished before its model snapshot could be stored"
            ),
            Err(error) => tracing::warn!(
                key_id,
                error = %format!("{error:#}"),
                "Kiro model snapshot was not stored after a successful credential probe"
            ),
        }
        Ok((key_id, created))
    }

    /// Start one OpenCode Console device login; the browser half comes back
    /// here and the rest of the handshake continues in the background.
    ///
    /// Every check runs before the console is dialed, so a rejected request
    /// leaves no session behind: the provider must be an OpenCode gateway on an
    /// inference protocol, `group_ids` must name existing groups, and `label`
    /// must be free (a taken label is a conflict, not an overwrite). For a
    /// re-login (`key_id`) the row must exist and already be an
    /// `opencode_oauth` account, whose label and memberships stay untouched.
    ///
    /// The poller is spawned here and owns everything after this call — the
    /// session, the account it creates or replaces, and its verdict — because a
    /// login outlives the HTTP request that started it. Its state therefore
    /// lives in the shared registry ([`login::OpencodeLogins`]), not in this
    /// call.
    pub async fn start_opencode_login(
        &self,
        provider_id: i64,
        label: &str,
        key_id: Option<i64>,
        group_ids: &[i64],
        max_concurrency: Option<i32>,
    ) -> Result<OpencodeLoginStarted, OpencodeLoginError> {
        let wiring = self.opencode_login()?;
        let Some(provider) = store::get_provider(&self.pool, provider_id).await? else {
            return Err(OpencodeLoginError::ProviderNotFound(provider_id));
        };
        ensure_opencode_provider(&provider)?;
        if max_concurrency.is_some_and(|limit| limit <= 0) {
            return Err(OpencodeLoginError::Invalid(
                "max_concurrency must be positive".to_owned(),
            ));
        }
        let keys = store::list_provider_keys(&self.pool, provider_id).await?;
        let (label, key_id, group_ids) = match key_id {
            Some(key_id) => {
                let Some(existing) = keys.iter().find(|row| row.id == key_id) else {
                    return Err(OpencodeLoginError::KeyNotFound(key_id));
                };
                if existing.auth_kind != AuthKind::OpencodeOauth.as_str() {
                    return Err(OpencodeLoginError::KeyNotFound(key_id));
                }
                // A re-login replaces the credential of an account that already
                // exists and is configured: the key editor's PATCH owns its
                // label and memberships, so the login neither reads nor rewrites
                // them.
                (existing.label.clone(), Some(key_id), Vec::new())
            }
            None => {
                let label = label.trim();
                if label.is_empty() {
                    return Err(OpencodeLoginError::Invalid(
                        "label must not be empty".to_owned(),
                    ));
                }
                if keys.iter().any(|row| row.label == label) {
                    return Err(OpencodeLoginError::LabelConflict(label.to_owned()));
                }
                if !store::key_groups_exist(&self.pool, group_ids).await? {
                    return Err(OpencodeLoginError::Invalid("unknown group id".to_owned()));
                }
                (label.to_owned(), None, group_ids.to_vec())
            }
        };
        let code = wiring
            .client
            .device_code(auth::DEFAULT_SERVER)
            .await
            .context("starting an OpenCode device login")?;
        let auth::DeviceCode {
            device_code,
            user_code,
            verification_url,
            expires_in,
            interval,
        } = code;
        // The console's lifetime is trusted for the answer but bounded for the
        // session: a bogus `expires_in` must not park a session in the registry
        // (and a poller) for the life of the process.
        let lifetime = i64::try_from(expires_in)
            .unwrap_or(i64::MAX)
            .min(LOGIN_MAX_LIFETIME_SECS);
        let now = Utc::now();
        let session = login::Session::new(device_code, now + Duration::seconds(lifetime), key_id);
        let (id, session) = wiring.logins.insert(session, now);
        let poll = LoginPoll {
            session,
            client: Arc::clone(&wiring.client),
            provider,
            label,
            group_ids,
            max_concurrency,
            interval,
        };
        tokio::spawn(self.clone().drive_opencode_login(poll));
        Ok(OpencodeLoginStarted {
            session: id.to_string(),
            user_code,
            verification_url,
            expires_in,
            interval,
        })
    }

    /// Drive one started login to its verdict: wait `interval`, trade the
    /// device code, back off on `slow_down`, give up at the deadline, and on
    /// `Ready` commit the account and land the session.
    ///
    /// A transient console failure (unreachable, 5xx, 429) only skips a round:
    /// the grant still lives, and a DNS blip must not kill a login the human is
    /// completing. The deadline ends it either way.
    async fn drive_opencode_login(self, poll: LoginPoll) {
        let LoginPoll {
            session,
            client,
            provider,
            label,
            group_ids,
            max_concurrency,
            interval,
        } = poll;
        let mut wait = std::time::Duration::from_secs(interval.max(LOGIN_MIN_INTERVAL_SECS));
        loop {
            tokio::time::sleep(wait).await;
            // Cancelled between ticks: the cancel already wrote the verdict.
            if session.is_terminal() {
                return;
            }
            let now = Utc::now();
            if now >= session.expires_at() {
                session.finish(SessionState::Expired, now);
                return;
            }
            match client
                .poll_device_token(auth::DEFAULT_SERVER, session.device_code())
                .await
            {
                Ok(TokenGrant::Pending) => {}
                Ok(TokenGrant::SlowDown) => {
                    wait = std::time::Duration::from_secs(
                        wait.as_secs().saturating_add(LOGIN_SLOW_DOWN_STEP_SECS),
                    );
                }
                Ok(TokenGrant::Expired) => {
                    session.finish(SessionState::Expired, Utc::now());
                    return;
                }
                Ok(TokenGrant::Ready(token)) => {
                    // The poll's own round trip may have outlived the grant: a
                    // session the registry (or this loop's next round) will
                    // report `expired` must not leave a key behind. Re-check
                    // before committing and drop the grant when it lost the
                    // race; the token itself never reaches a log line.
                    let approved_at = Utc::now();
                    if approved_at >= session.expires_at() {
                        tracing::warn!(
                            provider = %provider.name,
                            key_id = ?session.key_id(),
                            "OpenCode login was approved after its grant deadline; discarding the issued grant"
                        );
                        session.finish(SessionState::Expired, approved_at);
                        return;
                    }
                    let verdict = match self
                        .finish_opencode_login(
                            &provider,
                            &label,
                            session.key_id(),
                            &group_ids,
                            max_concurrency,
                            token,
                        )
                        .await
                    {
                        Ok(key_id) => SessionState::Succeeded { key_id },
                        Err(error) => {
                            tracing::warn!(
                                provider = %provider.name,
                                error = %format!("{error:#}"),
                                "OpenCode account login could not be committed"
                            );
                            // The session state is GUI text, so it carries a
                            // fixed message: a store error's DETAIL can quote
                            // the row (tokens included).
                            SessionState::Failed {
                                message: login_failure_message(&error),
                            }
                        }
                    };
                    session.finish(verdict, Utc::now());
                    return;
                }
                Err(error) if is_transient_poll_failure(&error) => {
                    tracing::warn!(
                        %error,
                        "OpenCode device poll failed transiently; retrying until the grant expires"
                    );
                }
                Err(error) => {
                    session.finish(
                        SessionState::Failed {
                            message: error.to_string(),
                        },
                        Utc::now(),
                    );
                    return;
                }
            }
        }
    }

    /// Commit one approved login: read the account's display identity from the
    /// console (best effort — decoration only), build and validate the bundle,
    /// persist it, probe the model catalogue, adopt the bundle into the bearer
    /// cache and refresh the route cache. Returns the account key id.
    ///
    /// Only persistence can fail the login. A missing display email, an
    /// unreachable catalogue or a failed cache refresh degrade to warnings: the
    /// credential is already committed, and the first dispatch refreshes what
    /// this step missed.
    async fn finish_opencode_login(
        &self,
        provider: &store::ProviderRow,
        label: &str,
        key_id: Option<i64>,
        group_ids: &[i64],
        max_concurrency: Option<i32>,
        token: auth::ReadyToken,
    ) -> anyhow::Result<i64> {
        let wiring = self.opencode_login()?;
        let expires_at = token.expires_at(Utc::now());
        let auth::ReadyToken {
            access_token,
            refresh_token,
            org_id,
            ..
        } = token;
        let email = match wiring
            .client
            .fetch_account(auth::DEFAULT_SERVER, &access_token)
            .await
        {
            Ok(account) => Some(account.email),
            Err(error) => {
                tracing::warn!(
                    %error,
                    "OpenCode account lookup failed after login; storing the account without an email"
                );
                None
            }
        };
        let org_name = match wiring
            .client
            .fetch_organizations(auth::DEFAULT_SERVER, &access_token)
            .await
        {
            Ok(organizations) => org_id.as_deref().and_then(|org_id| {
                organizations
                    .iter()
                    .find(|org| org.id == org_id)
                    .map(|org| org.name.clone())
            }),
            Err(error) => {
                tracing::warn!(
                    %error,
                    "OpenCode organization lookup failed after login; storing the account without an organization name"
                );
                None
            }
        };
        let bundle = OpencodeOAuth {
            access_token,
            refresh_token,
            expires_at,
            server: auth::DEFAULT_SERVER.to_owned(),
            org_id,
            org_name,
            email,
        };
        bundle.validate()?;
        let key_id = match key_id {
            Some(key_id) => {
                self.replace_opencode_bundle(key_id, &bundle).await?;
                key_id
            }
            None => {
                self.insert_opencode_bundle(provider, label, group_ids, max_concurrency, &bundle)
                    .await?
            }
        };
        // The credential is committed: everything below is best effort, and the
        // new bearer is the one just minted, so the catalogue probe runs before
        // the cache adoption (which consumes the bundle).
        match probe::fetch_models(
            &provider.base_url,
            &provider.protocol,
            &provider.auth_scheme,
            &bundle.access_token,
            bundle.org_id.as_deref(),
        )
        .await
        {
            Ok(models) => {
                if let Err(error) = store::update_key_models(&self.pool, key_id, &models).await {
                    tracing::warn!(
                        key_id,
                        error = %format!("{error:#}"),
                        "model snapshot persistence failed after a successful OpenCode login"
                    );
                }
            }
            Err(error) => tracing::warn!(
                key_id,
                error = %format!("{error:#}"),
                "model probe failed after a successful OpenCode login; the key keeps its old snapshot"
            ),
        }
        match &self.opencode_tokens {
            Some(tokens) => {
                tokens.adopt(key_id, bundle);
            }
            None => tracing::warn!(
                key_id,
                "OpenCode token manager is not wired; the first dispatch will read the row instead of this cache"
            ),
        }
        if let Err(error) = self.refresh_route_cache().await {
            tracing::warn!(
                key_id,
                error = %format!("{error:#}"),
                "route cache refresh after an OpenCode login failed"
            );
        }
        // The account list changed: the same signal a quota round sends, so an
        // open GUI re-reads its account cards instead of waiting for the poll.
        self.activity.quota_refreshed();
        Ok(key_id)
    }

    /// Create the account key a fresh login lands on, attaching the form's
    /// group memberships the way the Kiro import attaches them.
    async fn insert_opencode_bundle(
        &self,
        provider: &store::ProviderRow,
        label: &str,
        group_ids: &[i64],
        max_concurrency: Option<i32>,
        bundle: &OpencodeOAuth,
    ) -> anyhow::Result<i64> {
        // One clone for the row: the caller still needs the bundle for the
        // catalogue probe and the cache adoption, and this path runs once per
        // manual login rather than per request.
        let key_id = store::insert_opencode_provider_key(
            &self.pool,
            provider.id,
            label,
            bundle.clone(),
            max_concurrency,
            None,
        )
        .await?;
        if !group_ids.is_empty() {
            // The insert and the memberships are two statements (the public
            // store surface attaches groups through the key PATCH), so a race
            // with a group delete can leave the row without them. The key row is
            // already committed, though: failing the login here would report a
            // dead account that exists, so the memberships degrade to a warning
            // and the key editor owns attaching them.
            if let Err(error) = store::patch_provider_key(
                &self.pool,
                provider.id,
                key_id,
                store::KeyPatch {
                    group_ids: Some(group_ids),
                    ..Default::default()
                },
            )
            .await
            {
                tracing::warn!(
                    key_id,
                    provider = provider.id,
                    groups = group_ids.len(),
                    error = %format!("{error:#}"),
                    "OpenCode account key was created, but attaching its groups failed; attach them from the key editor"
                );
            }
        }
        Ok(key_id)
    }

    /// Write a re-login's bundle over the pinned row with one retry when a
    /// concurrent writer (a dispatch-time refresh of the same account) wins the
    /// compare-and-swap: the retry rereads the row it lost to, so the second
    /// attempt is still compared against the current bundle.
    async fn replace_opencode_bundle(
        &self,
        key_id: i64,
        bundle: &OpencodeOAuth,
    ) -> anyhow::Result<()> {
        for _ in 0..LOGIN_CAS_ATTEMPTS {
            let Some(stored) = store::opencode_oauth(&self.pool, key_id).await? else {
                anyhow::bail!(
                    "account key {key_id} no longer exists or is no longer an OpenCode account"
                );
            };
            if store::replace_opencode_oauth(&self.pool, key_id, &stored, bundle).await? {
                return Ok(());
            }
            tracing::warn!(
                key_id,
                "OpenCode login write lost the compare-and-swap; rereading the row"
            );
        }
        anyhow::bail!(
            "account key {key_id} was rewritten concurrently, so the login's bundle was not stored"
        )
    }

    /// One login's current state; `Ok(None)` when the id is unknown (never
    /// issued, or pruned after its verdict aged out). A login past its deadline
    /// is marked `Expired` here, so a status read never reports `waiting` for a
    /// grant that can no longer be approved.
    pub fn opencode_login_status(&self, session: &str) -> anyhow::Result<Option<SessionState>> {
        let wiring = self.opencode_login()?;
        let id: Uuid = match session.parse() {
            Ok(id) => id,
            Err(_) => return Ok(None),
        };
        let now = Utc::now();
        let Some(session) = wiring.logins.get(&id, now) else {
            return Ok(None);
        };
        let state = session.state();
        if state == SessionState::Waiting && now >= session.expires_at() {
            session.finish(SessionState::Expired, now);
            return Ok(Some(SessionState::Expired));
        }
        Ok(Some(state))
    }

    /// Cancel a waiting login; `Ok(false)` when the id is unknown or the login
    /// already has a verdict (a finished login is not cancellable, and the
    /// admin API answers 404 for both).
    pub fn cancel_opencode_login(&self, session: &str) -> anyhow::Result<bool> {
        let wiring = self.opencode_login()?;
        let id: Uuid = match session.parse() {
            Ok(id) => id,
            Err(_) => return Ok(false),
        };
        Ok(wiring.logins.cancel(&id, Utc::now()))
    }

    /// The wired login dependencies, or a configuration error: every login
    /// endpoint fails closed when the surface was built without them.
    fn opencode_login(&self) -> anyhow::Result<&OpencodeLogin> {
        self.opencode_login
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("OpenCode 登录需要已接线的 console 客户端与会话注册表"))
    }

    /// Start an OpenAI Codex device login. A fresh login creates an account on
    /// `provider_id`; a re-login replaces the credential of an existing
    /// `openai_oauth` key and leaves its label, groups and cap alone.
    ///
    /// Every check runs before the issuer is dialed, so a rejected request leaves
    /// no session behind. The poller is spawned here and owns everything after
    /// this call, because a login outlives the HTTP request that started it.
    pub async fn start_openai_login(
        &self,
        target: OpenaiLoginTarget,
    ) -> Result<OpenaiLoginStarted, OpenaiLoginError> {
        let wiring = self.openai_login()?;
        let (provider, label, key_id, group_ids, max_concurrency) = match target {
            OpenaiLoginTarget::Relogin { key_id } => {
                let existing = store::list_keys_by_ids(&self.pool, &[key_id]).await?;
                let Some(existing) = existing
                    .into_iter()
                    .find(|row| row.auth_kind == AuthKind::OpenaiOauth.as_str())
                else {
                    return Err(OpenaiLoginError::KeyNotFound(key_id));
                };
                let Some(provider) = store::get_provider(&self.pool, existing.provider_id).await?
                else {
                    return Err(OpenaiLoginError::ProviderNotFound(existing.provider_id));
                };
                (provider, existing.label, Some(key_id), Vec::new(), None)
            }
            OpenaiLoginTarget::New {
                provider_id,
                label,
                group_ids,
                max_concurrency,
            } => {
                let Some(provider) = store::get_provider(&self.pool, provider_id).await? else {
                    return Err(OpenaiLoginError::ProviderNotFound(provider_id));
                };
                let keys = store::list_provider_keys(&self.pool, provider_id).await?;
                if keys.iter().any(|row| row.label == label) {
                    return Err(OpenaiLoginError::LabelConflict(label));
                }
                if !store::key_groups_exist(&self.pool, &group_ids).await? {
                    return Err(OpenaiLoginError::Invalid("unknown group id".to_owned()));
                }
                (provider, label, None, group_ids, max_concurrency)
            }
        };
        ensure_openai_provider(&provider)?;
        let grant = wiring
            .client
            .start_device()
            .await
            .context("starting an OpenAI device login")?;
        let openai_auth::DeviceGrant {
            device_auth_id,
            user_code,
            interval,
        } = grant;
        let now = Utc::now();
        let session = openai_login::Session::new(
            device_auth_id,
            user_code.clone(),
            interval,
            now + Duration::seconds(OPENAI_LOGIN_LIFETIME_SECS),
            key_id,
        );
        let (id, session) = wiring.logins.insert(session, now);
        let poll = OpenaiLoginPoll {
            session,
            client: Arc::clone(&wiring.client),
            provider,
            label,
            group_ids,
            max_concurrency,
        };
        tokio::spawn(self.clone().drive_openai_login(poll));
        Ok(OpenaiLoginStarted {
            session: id.to_string(),
            user_code,
            verification_url: openai_login::VERIFICATION_URL,
            expires_in: OPENAI_LOGIN_LIFETIME_SECS.unsigned_abs(),
            interval: interval.as_secs(),
        })
    }

    /// Drive one started login to its verdict: wait, ask the issuer whether the
    /// operator approved, and on approval trade the code and commit the account.
    /// What each poll result means is [`decide_poll`]'s call; a transient issuer
    /// failure only skips a round, since the grant still lives.
    async fn drive_openai_login(self, poll: OpenaiLoginPoll) {
        let session = Arc::clone(&poll.session);
        let wait = openai_poll_wait(session.interval());
        let mut polls: u32 = 0;
        loop {
            tokio::time::sleep(wait).await;
            // Cancelled between ticks: the cancel already wrote the verdict.
            if session.is_terminal() {
                return;
            }
            polls += 1;
            let observation = match poll
                .client
                .poll_device(session.device_auth_id(), session.user_code())
                .await
            {
                Ok(openai_auth::PollVerdict::Pending) => PollObservation::Pending,
                Ok(openai_auth::PollVerdict::Approved(approval)) => {
                    // The poll's own round trip may have outlived the grant: a
                    // session the registry will report `expired` must not leave
                    // a key behind.
                    let approved_at = Utc::now();
                    if approved_at >= session.expires_at() {
                        tracing::warn!(
                            provider = %poll.provider.name,
                            key_id = ?session.key_id(),
                            "OpenAI login was approved after its grant deadline; discarding the approval"
                        );
                        session.finish(openai_login::SessionState::Expired, approved_at);
                        return;
                    }
                    let verdict = self.finish_openai_login(&poll, approval).await;
                    session.finish(verdict, Utc::now());
                    return;
                }
                Err(error) => {
                    tracing::warn!(%error, "OpenAI device poll failed");
                    observe_openai_failure(&error)
                }
            };
            match decide_poll(observation, Utc::now(), session.expires_at(), polls) {
                PollDecision::Continue => {}
                PollDecision::Expire => {
                    session.finish(openai_login::SessionState::Expired, Utc::now());
                    return;
                }
                PollDecision::Fail(message) => {
                    session.finish(
                        openai_login::SessionState::Failed {
                            message: message.to_owned(),
                        },
                        Utc::now(),
                    );
                    return;
                }
            }
        }
    }

    /// Commit one approved login and return its verdict: trade the approval
    /// for tokens, build the bundle, persist it, install it in the bearer
    /// cache, probe the model catalogue and refresh the route cache.
    ///
    /// Only the exchange and persistence can fail the login. A failed catalogue
    /// probe or cache refresh degrades to a warning: the credential is already
    /// committed and the first dispatch refreshes what this step missed. Every
    /// failure text is fixed; details go to the log (no token among them).
    async fn finish_openai_login(
        &self,
        poll: &OpenaiLoginPoll,
        approval: openai_auth::DeviceApproval,
    ) -> openai_login::SessionState {
        let provider = &poll.provider;
        let failed = |message: &str| openai_login::SessionState::Failed {
            message: message.to_owned(),
        };
        let tokens = match poll.client.exchange_code(&approval, Utc::now()).await {
            Ok(tokens) => tokens,
            Err(error) => {
                tracing::warn!(provider = %provider.name, %error, "OpenAI code exchange failed");
                return failed(openai_exchange_failure_message(&error));
            }
        };
        let bundle = match tokens.into_bundle() {
            Ok(bundle) => bundle,
            Err(error) => {
                tracing::warn!(provider = %provider.name, %error, "OpenAI login produced no usable bundle");
                return failed(OPENAI_LOGIN_NO_WORKSPACE_MESSAGE);
            }
        };
        // Cancelled while the code exchange was in flight: no key may appear.
        if poll.session.is_terminal() {
            return poll.session.state();
        }
        let (email, plan_type) = (bundle.email.clone(), bundle.plan_type.clone());
        let key_id = match self.commit_openai_bundle(poll, &bundle).await {
            Ok(key_id) => key_id,
            Err(error) => {
                tracing::warn!(
                    provider = %provider.name,
                    error = %format!("{error:#}"),
                    "OpenAI account login could not be committed"
                );
                return failed(&openai_commit_failure_message(&error));
            }
        };
        // The credential is committed: everything below is best effort.
        if let Some(tokens) = &self.openai_tokens {
            let bearer = tokens.adopt(key_id, bundle);
            match probe::fetch_openai_codex_models(&bearer).await {
                Ok(models) => {
                    if let Err(error) = store::update_key_models(&self.pool, key_id, &models).await
                    {
                        tracing::warn!(
                            key_id,
                            error = %format!("{error:#}"),
                            "model snapshot persistence failed after a successful OpenAI login"
                        );
                    }
                }
                Err(error) => tracing::warn!(
                    key_id,
                    error = %format!("{error:#}"),
                    "model probe failed after a successful OpenAI login; the key keeps its old snapshot"
                ),
            }
        } else {
            tracing::warn!(
                key_id,
                "OpenAI token manager is not wired; the first dispatch will read the row instead of this cache"
            );
        }
        if let Err(error) = self.refresh_route_cache().await {
            tracing::warn!(
                key_id,
                error = %format!("{error:#}"),
                "route cache refresh after an OpenAI login failed"
            );
        }
        // The account list changed: an open GUI re-reads its account cards.
        self.activity.quota_refreshed();
        openai_login::SessionState::Succeeded {
            key_id,
            email,
            plan_type,
        }
    }

    /// Write the bundle: a new key row (with the form's group memberships) or
    /// the pinned row of a re-login. Returns the account key id.
    async fn commit_openai_bundle(
        &self,
        poll: &OpenaiLoginPoll,
        bundle: &OpenaiOAuth,
    ) -> anyhow::Result<i64> {
        let provider = &poll.provider;
        let group_ids = poll.group_ids.as_slice();
        if let Some(key_id) = poll.session.key_id() {
            self.replace_openai_bundle(key_id, bundle).await?;
            return Ok(key_id);
        }
        // One clone for the row: the caller still needs the bundle for the
        // cache adoption, and this runs once per manual login.
        let key_id = store::insert_openai_provider_key(
            &self.pool,
            provider.id,
            &poll.label,
            bundle.clone(),
            poll.max_concurrency,
            None,
        )
        .await?;
        if !group_ids.is_empty()
            && let Err(error) = store::patch_provider_key(
                &self.pool,
                provider.id,
                key_id,
                store::KeyPatch {
                    group_ids: Some(group_ids),
                    ..Default::default()
                },
            )
            .await
        {
            // The key row is committed: failing the login would report a dead
            // account that exists, so the memberships degrade to a warning.
            tracing::warn!(
                key_id,
                provider = provider.id,
                groups = group_ids.len(),
                error = %format!("{error:#}"),
                "OpenAI account key was created, but attaching its groups failed; attach them from the key editor"
            );
        }
        Ok(key_id)
    }

    /// Write a re-login's bundle over the pinned row, retrying once when a
    /// dispatch-time refresh of the same account wins the compare-and-swap.
    async fn replace_openai_bundle(&self, key_id: i64, bundle: &OpenaiOAuth) -> anyhow::Result<()> {
        for _ in 0..OPENAI_LOGIN_CAS_ATTEMPTS {
            let Some(stored) = store::openai_oauth(&self.pool, key_id).await? else {
                anyhow::bail!(
                    "account key {key_id} no longer exists or is no longer an OpenAI account"
                );
            };
            if store::replace_openai_oauth(&self.pool, key_id, &stored, bundle).await? {
                return Ok(());
            }
            tracing::warn!(
                key_id,
                "OpenAI login write lost the compare-and-swap; rereading the row"
            );
        }
        anyhow::bail!(
            "account key {key_id} was rewritten concurrently, so the login's bundle was not stored"
        )
    }

    /// One login's current state; `Ok(None)` when the id is unknown (never
    /// issued, or pruned after its verdict aged out). The registry expires a
    /// waiting login past its deadline on read.
    pub fn openai_login_status(
        &self,
        session: &str,
    ) -> anyhow::Result<Option<openai_login::LoginStatus>> {
        let wiring = self.openai_login()?;
        let Ok(id) = session.parse::<Uuid>() else {
            return Ok(None);
        };
        Ok(wiring
            .logins
            .get(&id, Utc::now())
            .map(|session| session.status()))
    }

    /// Cancel a waiting login; `Ok(false)` when the id is unknown or the login
    /// already has a verdict (the admin API answers 404 for both).
    pub fn cancel_openai_login(&self, session: &str) -> anyhow::Result<bool> {
        let wiring = self.openai_login()?;
        let Ok(id) = session.parse::<Uuid>() else {
            return Ok(false);
        };
        Ok(wiring.logins.cancel(&id, Utc::now()))
    }

    /// The wired login dependencies, or a configuration error: every login
    /// endpoint fails closed when the surface was built without them.
    fn openai_login(&self) -> anyhow::Result<&OpenaiLogin> {
        self.openai_login
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("OpenAI 登录需要已接线的 issuer 客户端与会话注册表"))
    }

    /// Start a Cursor browser login for `provider_id` (plan §2.1.2).
    ///
    /// Mints the challenge pair, registers the session, spawns the poller and
    /// returns the URL the operator opens. Same contract as
    /// [`Self::start_opencode_login`] for labels, re-logins (`key_id` must name
    /// an existing `cursor_oauth` row) and groups. Nothing here touches the
    /// local Cursor app's stores (D5): the operator's browser signs in.
    pub async fn start_cursor_login(
        &self,
        provider_id: i64,
        label: &str,
        key_id: Option<i64>,
        group_ids: &[i64],
        max_concurrency: Option<i32>,
    ) -> Result<CursorLoginStarted, CursorLoginError> {
        let wiring = self.cursor_login()?;
        let Some(provider) = store::get_provider(&self.pool, provider_id).await? else {
            return Err(CursorLoginError::ProviderNotFound(provider_id));
        };
        ensure_cursor_provider(&provider)?;
        if max_concurrency.is_some_and(|limit| limit <= 0) {
            return Err(CursorLoginError::Invalid(
                "max_concurrency must be positive".to_owned(),
            ));
        }
        let keys = store::list_provider_keys(&self.pool, provider_id).await?;
        let (label, key_id, group_ids) = match key_id {
            Some(key_id) => {
                let Some(existing) = keys.iter().find(|row| row.id == key_id) else {
                    return Err(CursorLoginError::KeyNotFound(key_id));
                };
                if existing.auth_kind != AuthKind::CursorOauth.as_str() {
                    return Err(CursorLoginError::KeyNotFound(key_id));
                }
                (existing.label.clone(), Some(key_id), Vec::new())
            }
            None => {
                let label = label.trim();
                if label.is_empty() {
                    return Err(CursorLoginError::Invalid(
                        "label must not be empty".to_owned(),
                    ));
                }
                if keys.iter().any(|row| row.label == label) {
                    return Err(CursorLoginError::LabelConflict(label.to_owned()));
                }
                if !store::key_groups_exist(&self.pool, group_ids).await? {
                    return Err(CursorLoginError::Invalid("unknown group id".to_owned()));
                }
                (label.to_owned(), None, group_ids.to_vec())
            }
        };
        let challenge = cursor::auth::Challenge::new();
        let login_url = challenge.login_url();
        let now = Utc::now();
        let session = cursor::login::Session::new(
            challenge,
            now + Duration::seconds(CURSOR_LOGIN_LIFETIME_SECS),
            key_id,
        );
        let (id, session) = wiring.logins.insert(session, now);
        let poll = CursorLoginPoll {
            session,
            client: Arc::clone(&wiring.client),
            provider,
            label,
            group_ids,
            max_concurrency,
        };
        tokio::spawn(self.clone().drive_cursor_login(poll));
        Ok(CursorLoginStarted {
            session: id.to_string(),
            login_url,
            expires_in: CURSOR_LOGIN_LIFETIME_SECS.unsigned_abs(),
        })
    }

    /// Drive one started Cursor login to its verdict: poll every 500ms, keep
    /// going on 404 and on transient failures, stop at the deadline, end on a
    /// policy refusal, and on `Ready` commit the account.
    async fn drive_cursor_login(self, poll: CursorLoginPoll) {
        let CursorLoginPoll {
            session,
            client,
            provider,
            label,
            group_ids,
            max_concurrency,
        } = poll;
        let wait = std::time::Duration::from_millis(CURSOR_LOGIN_POLL_MS);
        loop {
            tokio::time::sleep(wait).await;
            if session.is_terminal() {
                return;
            }
            let now = Utc::now();
            if now >= session.expires_at() {
                session.finish(cursor::login::SessionState::Expired, now);
                return;
            }
            match client.poll(session.challenge()).await {
                Ok(cursor::auth::PollVerdict::Waiting) => {}
                Ok(cursor::auth::PollVerdict::PolicyRefused) => {
                    tracing::warn!(
                        provider = %provider.name,
                        key_id = ?session.key_id(),
                        "Cursor login was refused by the account's sign-in policy"
                    );
                    session.finish(
                        cursor::login::SessionState::Failed {
                            message: CURSOR_LOGIN_POLICY_MESSAGE.to_owned(),
                        },
                        Utc::now(),
                    );
                    return;
                }
                Ok(cursor::auth::PollVerdict::Ready(token)) => {
                    let landed_at = Utc::now();
                    if landed_at >= session.expires_at() {
                        tracing::warn!(
                            provider = %provider.name,
                            key_id = ?session.key_id(),
                            "Cursor login landed after its deadline; discarding the issued tokens"
                        );
                        session.finish(cursor::login::SessionState::Expired, landed_at);
                        return;
                    }
                    let verdict = match self
                        .finish_cursor_login(
                            &provider,
                            &label,
                            session.key_id(),
                            &group_ids,
                            max_concurrency,
                            token,
                        )
                        .await
                    {
                        Ok(landed) => landed,
                        Err(error) => {
                            // Fixed GUI text; the detail (which may quote the
                            // row) goes to the log only.
                            tracing::warn!(
                                provider = %provider.name,
                                error = %format!("{error:#}"),
                                "Cursor account login could not be committed"
                            );
                            cursor::login::SessionState::Failed {
                                message: login_failure_message(&error),
                            }
                        }
                    };
                    session.finish(verdict, Utc::now());
                    return;
                }
                Err(error) if error.is_transient() => {
                    tracing::warn!(
                        %error,
                        "Cursor login poll failed transiently; retrying until the deadline"
                    );
                }
                Err(error) => {
                    tracing::warn!(%error, "Cursor login poll failed");
                    session.finish(
                        cursor::login::SessionState::Failed {
                            message: CURSOR_LOGIN_BACKEND_MESSAGE.to_owned(),
                        },
                        Utc::now(),
                    );
                    return;
                }
            }
        }
    }

    /// Commit one landed login: expiry from the access token's JWT `exp`
    /// (fail closed when unreadable), the account email (best effort), the
    /// bundle validated and persisted (insert, or CAS replace for a re-login),
    /// then the usable-models snapshot, the bearer-cache adoption, the route
    /// cache and the GUI signal — all best effort once the row is committed.
    async fn finish_cursor_login(
        &self,
        provider: &store::ProviderRow,
        label: &str,
        key_id: Option<i64>,
        group_ids: &[i64],
        max_concurrency: Option<i32>,
        token: cursor::auth::ReadyToken,
    ) -> anyhow::Result<cursor::login::SessionState> {
        let wiring = self.cursor_login()?;
        let cursor::auth::ReadyToken {
            access_token,
            refresh_token,
            team_id,
        } = token;
        let Some(expires_at) = crate::upstream::cursor_tokens::jwt_expiry(&access_token) else {
            anyhow::bail!("the issued Cursor access token carries no readable expiry");
        };
        let email = wiring.client.email(&access_token, team_id.as_deref()).await;
        let bundle = CursorOAuth {
            access_token,
            refresh_token,
            expires_at,
            email,
            team_id,
        };
        bundle.validate()?;
        let key_id = match key_id {
            Some(key_id) => {
                self.replace_cursor_bundle(key_id, &bundle).await?;
                key_id
            }
            None => {
                self.insert_cursor_bundle(provider, label, group_ids, max_concurrency, &bundle)
                    .await?
            }
        };
        match &self.cursor_tokens {
            Some(tokens) => {
                let bearer = tokens.adopt(key_id, &bundle);
                match probe::fetch_cursor_models(tokens.transport(), &bearer).await {
                    Ok(models) => {
                        if let Err(error) =
                            store::update_key_models(&self.pool, key_id, &models).await
                        {
                            tracing::warn!(
                                key_id,
                                error = %format!("{error:#}"),
                                "model snapshot persistence failed after a successful Cursor login"
                            );
                        }
                    }
                    Err(error) => tracing::warn!(
                        key_id,
                        error = %format!("{error:#}"),
                        "model probe failed after a successful Cursor login; the key keeps its old snapshot"
                    ),
                }
            }
            None => tracing::warn!(
                key_id,
                "Cursor token manager is not wired; the first dispatch will read the row instead of this cache"
            ),
        }
        if let Err(error) = self.refresh_route_cache().await {
            tracing::warn!(
                key_id,
                error = %format!("{error:#}"),
                "route cache refresh after a Cursor login failed"
            );
        }
        self.activity.quota_refreshed();
        Ok(cursor::login::SessionState::Succeeded {
            key_id,
            email: bundle.email,
            team_id: bundle.team_id,
        })
    }

    /// Create the account key a fresh Cursor login lands on (`api_key IS
    /// NULL`, the bundle plus email/team on the row), attaching the form's
    /// groups the way [`Self::insert_opencode_bundle`] does.
    async fn insert_cursor_bundle(
        &self,
        provider: &store::ProviderRow,
        label: &str,
        group_ids: &[i64],
        max_concurrency: Option<i32>,
        bundle: &CursorOAuth,
    ) -> anyhow::Result<i64> {
        let key_id = store::insert_cursor_provider_key(
            &self.pool,
            provider.id,
            label,
            bundle.clone(),
            max_concurrency,
            None,
        )
        .await?;
        if !group_ids.is_empty()
            && let Err(error) = store::patch_provider_key(
                &self.pool,
                provider.id,
                key_id,
                store::KeyPatch {
                    group_ids: Some(group_ids),
                    ..Default::default()
                },
            )
            .await
        {
            tracing::warn!(
                key_id,
                provider = provider.id,
                groups = group_ids.len(),
                error = %format!("{error:#}"),
                "Cursor account key was created, but attaching its groups failed; attach them from the key editor"
            );
        }
        Ok(key_id)
    }

    /// Write a re-login's bundle over the pinned row with one retry when a
    /// concurrent writer (a dispatch-time refresh) wins the compare-and-swap.
    async fn replace_cursor_bundle(&self, key_id: i64, bundle: &CursorOAuth) -> anyhow::Result<()> {
        for _ in 0..LOGIN_CAS_ATTEMPTS {
            let Some(stored) = store::cursor_oauth(&self.pool, key_id).await? else {
                anyhow::bail!(
                    "account key {key_id} no longer exists or is no longer a Cursor account"
                );
            };
            if store::replace_cursor_oauth(&self.pool, key_id, &stored, bundle).await? {
                return Ok(());
            }
            tracing::warn!(
                key_id,
                "Cursor login write lost the compare-and-swap; rereading the row"
            );
        }
        anyhow::bail!(
            "account key {key_id} was rewritten concurrently, so the login's bundle was not stored"
        )
    }

    /// One Cursor login's current state; `Ok(None)` when the id is unknown. A
    /// login past its deadline is marked `Expired` here.
    pub fn cursor_login_status(
        &self,
        session: &str,
    ) -> anyhow::Result<Option<cursor::login::SessionState>> {
        let wiring = self.cursor_login()?;
        let id: Uuid = match session.parse() {
            Ok(id) => id,
            Err(_) => return Ok(None),
        };
        let now = Utc::now();
        let Some(session) = wiring.logins.get(&id, now) else {
            return Ok(None);
        };
        let state = session.state();
        if state == cursor::login::SessionState::Waiting && now >= session.expires_at() {
            session.finish(cursor::login::SessionState::Expired, now);
            return Ok(Some(cursor::login::SessionState::Expired));
        }
        Ok(Some(state))
    }

    /// Cancel a waiting Cursor login; `Ok(false)` when the id is unknown or
    /// the login already has a verdict.
    pub fn cancel_cursor_login(&self, session: &str) -> anyhow::Result<bool> {
        let wiring = self.cursor_login()?;
        let id: Uuid = match session.parse() {
            Ok(id) => id,
            Err(_) => return Ok(false),
        };
        Ok(wiring.logins.cancel(&id, Utc::now()))
    }

    fn cursor_login(&self) -> anyhow::Result<&CursorLogin> {
        self.cursor_login
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Cursor 登录需要已接线的登录客户端与会话注册表"))
    }

    /// Add a named key to a provider; returns the new key id.
    /// `credential`: the validated credential shape — a static api_key or an
    /// OAuth bundle (see [`crate::credentials::resolve_key_credential`]).
    /// `max_concurrency`: per-key in-flight cap (None = unlimited).
    /// `allowed_models`: the key's model whitelist (None/empty = unrestricted).
    pub async fn create_key(
        &self,
        provider_id: i64,
        label: &str,
        credential: KeyCredential<'_>,
        max_concurrency: Option<i32>,
        allowed_models: Option<Vec<String>>,
    ) -> anyhow::Result<i64> {
        create_key(
            &self.pool,
            provider_id,
            label,
            credential,
            max_concurrency,
            allowed_models,
        )
        .await
    }

    /// Delete a key (row + its secret-store item, see [`delete_key`]).
    /// Errors when the key does not exist.
    pub async fn delete_key(&self, provider_id: i64, key_id: i64) -> anyhow::Result<()> {
        let deleted = delete_key(&self.pool, provider_id, key_id).await?;
        anyhow::ensure!(deleted.is_some(), "no such key {key_id}");
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

// ---------- OpenCode account login ----------

/// How long a login poller waits between attempts before the console asks for
/// more (the protocol's floor; the console's `interval` only raises it).
const LOGIN_MIN_INTERVAL_SECS: u64 = 5;

/// Added to the poll interval every time the console answers `slow_down`.
const LOGIN_SLOW_DOWN_STEP_SECS: u64 = 5;

/// Ceiling on a login's lifetime. The console's `expires_in` is reported
/// verbatim to the GUI but bounded for the session: a bogus value must not park
/// a session (and a poller) in the registry for the life of the process.
const LOGIN_MAX_LIFETIME_SECS: i64 = 15 * 60;

/// Compare-and-swap attempts for a re-login's write (one retry after losing to
/// a concurrent writer, whose row the retry rereads).
const LOGIN_CAS_ATTEMPTS: usize = 2;

/// The wiring a login needs: the stateless console client and the process's
/// session registry. Grouped so one `None` covers both, and
/// [`Admin::with_opencode_login`] is the single place that supplies them.
#[derive(Clone)]
struct OpencodeLogin {
    client: Arc<auth::Client>,
    logins: login::OpencodeLogins,
}

/// Everything one spawned login needs to reach its verdict.
struct LoginPoll {
    session: Arc<login::Session>,
    client: Arc<auth::Client>,
    /// The provider the account belongs to: its endpoint, protocol and auth
    /// scheme are what the catalogue probe uses once the bundle is committed.
    provider: store::ProviderRow,
    /// The label of the key to create (ignored by a re-login).
    label: String,
    /// Groups to attach to a newly created key (ignored by a re-login).
    group_ids: Vec<i64>,
    max_concurrency: Option<i32>,
    /// The console's poll cadence in seconds, before any `slow_down` backoff.
    interval: u64,
}

/// A started OpenCode device login: what
/// `POST /api/providers/{id}/opencode-login` answers with. The GUI shows the
/// code and the URL, then polls `session`.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct OpencodeLoginStarted {
    /// The registry id to poll and to cancel.
    pub session: String,
    /// The short code the browser asks the user to confirm.
    pub user_code: String,
    /// Absolute console URL that prefills the code.
    pub verification_url: String,
    /// Seconds the console keeps the grant open (reported verbatim).
    pub expires_in: u64,
    /// Seconds between polls, as the console asked for them.
    pub interval: u64,
}

/// Why a login could not be started. The variants mirror the admin API's status
/// codes (404 / 400 / 409 / 500), so the handler maps them without parsing
/// messages.
#[derive(Debug, thiserror::Error)]
pub enum OpencodeLoginError {
    /// No such provider row.
    #[error("provider {0} does not exist")]
    ProviderNotFound(i64),
    /// The provider is not an OpenCode gateway, or speaks a protocol the
    /// console's tokens cannot authenticate.
    #[error(
        "provider {provider_id} is not an OpenCode gateway (protocol {protocol:?}, base_url {base_url:?})"
    )]
    NotOpencodeProvider {
        provider_id: i64,
        protocol: String,
        base_url: String,
    },
    /// A re-login named a row that is absent, or is not an OpenCode account.
    #[error("key {0} does not exist on this provider or is not an OpenCode account")]
    KeyNotFound(i64),
    /// Caller input: an empty label, a non-positive cap, an unknown group id.
    #[error("{0}")]
    Invalid(String),
    /// The label already names another key of this provider.
    #[error("a key with label {0:?} already exists on this provider")]
    LabelConflict(String),
    /// Wiring or storage failed. Never raised for caller input.
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

/// Whether the login may mint a console token for this provider: the endpoint
/// host must be OpenCode's gateway (Zen or Go) and the protocol one of the
/// inference protocols that gateway serves. The provider name is user-chosen,
/// so the wire host is the factual identity — the relay's own
/// [`crate::relay::is_opencode_upstream`] decides it, once for both planes.
fn ensure_opencode_provider(provider: &store::ProviderRow) -> Result<(), OpencodeLoginError> {
    let protocol = provider.protocol.as_str();
    let served = matches!(
        protocol,
        "openai_chat" | "anthropic_messages" | "openai_responses"
    );
    if served && crate::relay::is_opencode_upstream(&provider.base_url) {
        return Ok(());
    }
    Err(OpencodeLoginError::NotOpencodeProvider {
        provider_id: provider.id,
        protocol: provider.protocol.clone(),
        base_url: provider.base_url.clone(),
    })
}

/// The operator-facing reason an approved login could not be committed.
///
/// Never the raw error: the session state is shown in the GUI, and a store
/// failure's `DETAIL` can quote the row (credential bundle included), while a
/// vendor error can quote a request. The detail goes to the log instead.
fn login_failure_message(error: &anyhow::Error) -> String {
    match error.downcast_ref::<store::LabelTaken>() {
        // The label passed the pre-check and was taken before the commit.
        Some(taken) => format!(
            "a key with label {:?} already exists on this provider; log in again with another label",
            taken.label
        ),
        None => {
            "the account could not be stored after the console approved the login; see the server log"
                .to_owned()
        }
    }
}

/// Whether a poll failure is worth retrying: the console unreachable, or
/// answering 5xx/429. Everything else (wire drift, a refusal the protocol does
/// not model as a grant verdict) cannot improve by waiting.
fn is_transient_poll_failure(error: &auth::AuthError) -> bool {
    match error {
        auth::AuthError::Transport { .. } => true,
        auth::AuthError::Status { status, .. } => {
            status.is_server_error() || status.as_u16() == 429
        }
        _ => false,
    }
}

// ---------- Cursor account login ----------

/// The poll cadence (plan §2.1.2: 500ms).
const CURSOR_LOGIN_POLL_MS: u64 = 500;

/// How long a login may wait for the browser (plan §2.1.2: 180s).
const CURSOR_LOGIN_LIFETIME_SECS: i64 = 180;

/// The fixed operator text for a device-policy refusal (403
/// `sign_in_policy_violation`); the vendor's words stay in the log.
const CURSOR_LOGIN_POLICY_MESSAGE: &str =
    "Cursor refused this sign-in under the account's device policy; ask the team admin";

/// The fixed operator text for an unexpected backend answer during the poll.
const CURSOR_LOGIN_BACKEND_MESSAGE: &str =
    "the Cursor backend answered the login poll unexpectedly; see the server log";

/// The wiring a Cursor login needs. Grouped so one `None` covers both, and
/// [`Admin::with_cursor_login`] is the single place that supplies them.
#[derive(Clone)]
struct CursorLogin {
    client: Arc<cursor::Client>,
    logins: cursor::CursorLogins,
}

/// Everything one spawned Cursor login needs to reach its verdict.
struct CursorLoginPoll {
    session: Arc<cursor::login::Session>,
    client: Arc<cursor::Client>,
    provider: store::ProviderRow,
    label: String,
    group_ids: Vec<i64>,
    max_concurrency: Option<i32>,
}

/// A started Cursor login: what `POST /api/providers/{id}/cursor-login`
/// answers with. The GUI opens `login_url`, then polls `session`.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct CursorLoginStarted {
    /// The registry id to poll and to cancel.
    pub session: String,
    /// The `cursor.com` URL the operator signs in on.
    pub login_url: String,
    /// Seconds the gateway keeps polling.
    pub expires_in: u64,
}

/// Why a Cursor login could not be started (404 / 400 / 409 / 500).
#[derive(Debug, thiserror::Error)]
pub enum CursorLoginError {
    #[error("provider {0} does not exist")]
    ProviderNotFound(i64),
    /// The provider does not speak the Cursor protocol.
    #[error("provider {provider_id} is not a Cursor provider (protocol {protocol:?})")]
    NotCursorProvider { provider_id: i64, protocol: String },
    /// A re-login named a row that is absent, or is not a Cursor account.
    #[error("key {0} does not exist on this provider or is not a Cursor account")]
    KeyNotFound(i64),
    #[error("{0}")]
    Invalid(String),
    #[error("a key with label {0:?} already exists on this provider")]
    LabelConflict(String),
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

/// Whether the login may mint Cursor tokens for this provider: its protocol
/// must be `cursor` (the base URL is not consulted — the Cursor backend origin
/// is fixed in code, not per provider).
fn ensure_cursor_provider(provider: &store::ProviderRow) -> Result<(), CursorLoginError> {
    if provider.protocol == "cursor" {
        return Ok(());
    }
    Err(CursorLoginError::NotCursorProvider {
        provider_id: provider.id,
        protocol: provider.protocol.clone(),
    })
}

// ---------- OpenAI Codex account login ----------

/// Ceiling on a login's lifetime. The issuer reports no grant lifetime, so the
/// session is bounded here (the Codex CLI waits the same 15 minutes).
const OPENAI_LOGIN_LIFETIME_SECS: i64 = 15 * 60;

/// Polls after which a login gives up even when the deadline is still ahead.
const OPENAI_LOGIN_MAX_POLLS: u32 = 120;

/// Added to the issuer's poll interval, so a clock that runs a little fast
/// never polls earlier than the issuer allows.
const OPENAI_LOGIN_POLL_MARGIN_SECS: u64 = 3;

/// The operator text for a device grant or code exchange the issuer refused.
const OPENAI_LOGIN_REJECTED_MESSAGE: &str =
    "OpenAI refused the login; start it again and re-enter the code";

/// The operator text for tokens that name no ChatGPT workspace.
const OPENAI_LOGIN_NO_WORKSPACE_MESSAGE: &str =
    "OpenAI's tokens did not identify a ChatGPT workspace, so this account cannot be used";

/// The operator text for a code exchange that failed without a refusal
/// (issuer unreachable or answering unusably); the approval is single-use, so
/// the login cannot retry it.
const OPENAI_LOGIN_EXCHANGE_MESSAGE: &str =
    "OpenAI approved the login but the token exchange failed; start it again";

/// Ceiling on the pause between polls, so a bogus issuer `interval` cannot
/// park the poller far past the grant.
const OPENAI_LOGIN_MAX_INTERVAL_SECS: u64 = 60;

/// Compare-and-swap attempts for a re-login's write.
const OPENAI_LOGIN_CAS_ATTEMPTS: usize = 2;

/// The operator text for an approved login that could not be stored.
const OPENAI_LOGIN_STORE_MESSAGE: &str =
    "the account could not be stored after OpenAI approved the login; see the server log";

/// `POST /api/openai-logins` body: the account to create, or (with `key_id`) the
/// existing account to re-authenticate.
#[derive(Debug, serde::Deserialize)]
pub struct OpenaiLoginRequest {
    /// The provider a new account belongs to. Ignored for a re-login, whose
    /// key row already names its provider.
    #[serde(default)]
    pub provider_id: Option<i64>,
    /// The label of the account a fresh login creates (ignored for a re-login).
    #[serde(default)]
    pub label: String,
    /// The existing `openai_oauth` key to replace the credential of.
    #[serde(default)]
    pub key_id: Option<i64>,
    /// Groups to attach to the new account (ignored for a re-login).
    #[serde(default)]
    pub group_ids: Vec<i64>,
    #[serde(default)]
    pub max_concurrency: Option<i32>,
}

/// What a validated start request asks for.
#[derive(Debug, PartialEq, Eq)]
pub enum OpenaiLoginTarget {
    /// Create an account on `provider_id`.
    New {
        provider_id: i64,
        label: String,
        group_ids: Vec<i64>,
        max_concurrency: Option<i32>,
    },
    /// Replace the credential of an existing account; its label, groups and
    /// cap stay as the key editor left them.
    Relogin { key_id: i64 },
}

impl OpenaiLoginRequest {
    /// Check the request's shape (no I/O): which of the two flows it asks for
    /// and that the inputs of that flow are usable.
    pub fn into_target(self) -> Result<OpenaiLoginTarget, OpenaiLoginError> {
        if let Some(key_id) = self.key_id {
            return Ok(OpenaiLoginTarget::Relogin { key_id });
        }
        let Some(provider_id) = self.provider_id else {
            return Err(OpenaiLoginError::Invalid(
                "provider_id is required for a new login".to_owned(),
            ));
        };
        let label = self.label.trim();
        if label.is_empty() {
            return Err(OpenaiLoginError::Invalid(
                "label must not be empty".to_owned(),
            ));
        }
        if self.max_concurrency.is_some_and(|limit| limit <= 0) {
            return Err(OpenaiLoginError::Invalid(
                "max_concurrency must be positive".to_owned(),
            ));
        }
        Ok(OpenaiLoginTarget::New {
            provider_id,
            label: label.to_owned(),
            group_ids: self.group_ids,
            max_concurrency: self.max_concurrency,
        })
    }
}

/// What one issuer round told the poller, reduced to what the decision needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PollObservation {
    /// Not approved yet.
    Pending,
    /// The issuer could not be reached or answered 5xx/429 (asking again can
    /// still work).
    Transient,
    /// The issuer refused the grant or the code (only a new login helps).
    Rejected,
}

/// The poller's next move.
#[derive(Debug, PartialEq, Eq)]
pub enum PollDecision {
    /// Wait and ask again.
    Continue,
    /// The grant ran out before the human approved it.
    Expire,
    /// End the login with this operator text.
    Fail(&'static str),
}

/// Classify an issuer failure for [`decide_poll`].
fn observe_openai_failure(error: &openai_auth::AuthError) -> PollObservation {
    if error.is_rejection() {
        PollObservation::Rejected
    } else {
        PollObservation::Transient
    }
}

/// The pause before each poll.
fn openai_poll_wait(interval: std::time::Duration) -> std::time::Duration {
    interval.min(std::time::Duration::from_secs(
        OPENAI_LOGIN_MAX_INTERVAL_SECS,
    )) + std::time::Duration::from_secs(OPENAI_LOGIN_POLL_MARGIN_SECS)
}

/// One poll result plus the clock decides what happens next. A refusal ends
/// the login; otherwise the deadline and the poll budget end it as expired.
fn decide_poll(
    observation: PollObservation,
    now: chrono::DateTime<Utc>,
    expires_at: chrono::DateTime<Utc>,
    polls: u32,
) -> PollDecision {
    if observation == PollObservation::Rejected {
        return PollDecision::Fail(OPENAI_LOGIN_REJECTED_MESSAGE);
    }
    if now >= expires_at || polls >= OPENAI_LOGIN_MAX_POLLS {
        return PollDecision::Expire;
    }
    PollDecision::Continue
}

/// The operator text for a failed code exchange.
fn openai_exchange_failure_message(error: &openai_auth::AuthError) -> &'static str {
    if error.is_rejection() {
        OPENAI_LOGIN_REJECTED_MESSAGE
    } else {
        OPENAI_LOGIN_EXCHANGE_MESSAGE
    }
}

/// The operator-facing reason an approved login could not be committed. Never
/// the raw error: a store failure's detail can quote the row, tokens included.
fn openai_commit_failure_message(error: &anyhow::Error) -> String {
    match error.downcast_ref::<store::LabelTaken>() {
        // The label passed the pre-check and was taken before the commit.
        Some(taken) => format!(
            "a key with label {:?} already exists on this provider; log in again with another label",
            taken.label
        ),
        None => OPENAI_LOGIN_STORE_MESSAGE.to_owned(),
    }
}

/// The wiring an OpenAI login needs: the stateless issuer client and the
/// process's session registry. Grouped so one `None` covers both, and
/// [`Admin::with_openai_login`] is the single place that supplies them.
#[derive(Clone)]
struct OpenaiLogin {
    client: Arc<openai_auth::Client>,
    logins: openai_login::OpenaiLogins,
}

/// Everything one spawned OpenAI login needs to reach its verdict.
struct OpenaiLoginPoll {
    session: Arc<openai_login::Session>,
    client: Arc<openai_auth::Client>,
    provider: store::ProviderRow,
    /// The label of the key to create (ignored by a re-login).
    label: String,
    /// Groups to attach to a newly created key (ignored by a re-login).
    group_ids: Vec<i64>,
    max_concurrency: Option<i32>,
}

/// A started OpenAI device login: what `POST /api/openai-logins` answers with.
/// The grant handle the poller redeems stays server-side.
#[derive(Clone, Debug, serde::Serialize)]
pub struct OpenaiLoginStarted {
    /// The registry id to poll and to cancel.
    pub session: String,
    /// The short code the operator types.
    pub user_code: String,
    /// Where the operator types it.
    pub verification_url: &'static str,
    /// Seconds the gateway keeps polling.
    pub expires_in: u64,
    /// Seconds between polls, as the issuer asked for them.
    pub interval: u64,
}

/// Why an OpenAI login could not be started. The variants mirror the admin
/// API's status codes (404 / 400 / 409 / 500).
#[derive(Debug, thiserror::Error)]
pub enum OpenaiLoginError {
    /// No such provider row.
    #[error("provider {0} does not exist")]
    ProviderNotFound(i64),
    /// The provider does not speak the Responses protocol the Codex backend
    /// serves.
    #[error("provider {provider_id} is not an OpenAI Codex provider (protocol {protocol:?})")]
    NotOpenaiProvider { provider_id: i64, protocol: String },
    /// A re-login named a row that is absent, or is not an OpenAI account.
    #[error("key {0} does not exist or is not an OpenAI Codex account")]
    KeyNotFound(i64),
    /// Caller input: an empty label, a non-positive cap, an unknown group id.
    #[error("{0}")]
    Invalid(String),
    /// The label already names another key of this provider.
    #[error("a key with label {0:?} already exists on this provider")]
    LabelConflict(String),
    /// Wiring or storage failed. Never raised for caller input.
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

/// Whether the login may mint ChatGPT tokens for this provider: its protocol
/// is `openai_responses` (the only one an `openai_oauth` key is accepted on,
/// see `credentials`) and its endpoint is the ChatGPT backend, so a credential
/// is never attached to some other host.
fn ensure_openai_provider(provider: &store::ProviderRow) -> Result<(), OpenaiLoginError> {
    let on_chatgpt = reqwest::Url::parse(&provider.base_url)
        .ok()
        .and_then(|url| url.host_str().map(|host| host == "chatgpt.com"))
        .unwrap_or(false);
    if provider.protocol == "openai_responses" && on_chatgpt {
        return Ok(());
    }
    Err(OpenaiLoginError::NotOpenaiProvider {
        provider_id: provider.id,
        protocol: provider.protocol.clone(),
    })
}
