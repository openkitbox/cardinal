//! Kiro credential lifecycle: lazy refresh, per-key single-flight, and
//! persistence back into the key's `oauth` bundle.
//!
//! Kiro authenticates either with Social credentials or AWS SSO OIDC
//! (device-code / Builder ID). A key row carries the whole credential bundle
//! ([`crate::kiro::KiroOAuth`]), and the access token inside it expires (typically
//! hourly). The gateway therefore must refresh it itself — the downstream client
//! never holds the refresh token — and write the rotated bundle back so a restart
//! does not resurrect a token upstream has already invalidated.
//!
//! Semantics follow the reference `kiro2claude`
//! (`packages/core/src/kiro/token-manager.ts`):
//!
//! * **Lazy refresh with a ten-minute margin.** [`KiroOAuth::fresh_for`] is the
//!   one freshness rule (`expires_at > now + 600`).
//! * **One refresh per key.** Each key owns an async mutex; a waiter rechecks
//!   freshness under the lock and skips the refresh another caller performed.
//!   The same lock de-duplicates the 401 path ([`KiroTokens::recover_invalidated`]):
//!   N concurrent requests that all presented the same stale bearer trigger
//!   exactly one `CreateToken`.
//! * **Disk is authoritative only while memory is persisted.** The route cache
//!   seeds the in-memory bundle. When a refresh is due and the in-memory bundle
//!   is known to be persisted, the manager rereads the row under the lock: a
//!   fresher token written by another process/kiro-cli wins. After a successful
//!   refresh memory becomes newer than the row (`persisted = false`) and is
//!   written back; a persistence failure leaves it that way so a later reread
//!   can never restore the stale refresh token.
//! * **Admin adoption serializes with refresh.** [`KiroTokens::adopt_persisted`]
//!   rereads the committed row outside the state lock, then reconciles it under
//!   the key lock. A committed candidate is adopted when it still matches the
//!   row; a different stored bundle replaces a persisted or newly seeded state,
//!   while a newer pending in-memory refresh is retained.
//! * **Refresh-token rotation is total.** A response without `refreshToken`
//!   keeps the old one; otherwise the whole bundle (access token, expiry, refresh
//!   token, `profileArn`) is replaced in memory and persisted as one JSONB
//!   update.
//! * **`invalid_grant` gets the reference's narrow reload-and-retry.** A 400
//!   `invalid_grant` can mean another holder (another process, kiro-cli, the
//!   admin plane) rotated the credential after this process seeded memory. When
//!   memory is known to be persisted, the manager rereads the row once: a fresh
//!   stored bearer wins; otherwise, only when the exchange identity (refresh
//!   token, client id/secret, auth region) actually changed does it retry
//!   `CreateToken` once from the stored bundle. The same bundle is never retried,
//!   and an unchanged row stays permanently invalidated. Memory is only replaced
//!   by a successful exchange or by the fresh stored bearer, so a failed recovery
//!   never rolls back a newer in-memory bundle.
//! * **The 401 path rereads the row.** [`KiroTokens::recover_invalidated`]
//!   rereads the credential under the key's lock before refreshing: a stored
//!   bearer different from the rejected one and still fresh is returned as is
//!   (the external rotation case), and a changed-but-stale bundle becomes the
//!   refresh base instead of the stale in-memory copy. This fixes the
//!   stale-but-unexpired access token a rotation leaves behind.
//! * **Permanent vs temporary.** A `400 invalid_grant` means the refresh token
//!   is dead (`invalid_grant`) — only a fresh login can recover, so it surfaces
//!   as [`KiroTokenError::Invalidated`] and the relay fails over without blaming
//!   the request. 429/5xx/network/timeout are temporary and follow the relay's
//!   existing transient-failure policy.
//!
//! Secrets never leave this module except as a bearer on the wire: errors carry
//! only statuses, and no log line ever includes an OAuth body or token.
//!
//! Deliberate deviations from the reference (its SQLite source is replaced by
//! the gateway database, which the manager rereads under the same lock):
//!
//! * `expiresIn` is required and positive for IdC. Social responses use a
//!   positive `expiresIn`; omitted, zero, and negative values use the bounded
//!   3600-second default from the local reference behavior. An unrepresentable
//!   `now + expiresIn` is rejected as an invalid response, and an empty access
//!   token is never accepted.
//! * The OIDC request omits the reference's explicit `host` and
//!   `Connection: close` headers. `reqwest` derives `Host` from the URL, and the
//!   transport owns connection lifetime (its `idle` deadline bounds a stuck
//!   exchange); forcing `Connection: close` would disable pooling for every
//!   refresh to buy nothing the protocol needs.
//! * `invalid_grant` is recognized as HTTP 400 with `invalid_grant` in the
//!   bounded body, not "400 + `invalid_grant` + the literal `Invalid refresh
//!   token provided`". The OAuth error code is the stable machine-readable
//!   field; the human sentence is vendor wording that has already varied across
//!   AWS endpoints. The body remains sensitive: it is read only to classify,
//!   never logged and never forwarded.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use secrecy::{ExposeSecret as _, SecretString};
use sha2::{Digest as _, Sha256};
use sqlx::PgPool;
use tokio::sync::{Mutex, Notify};

use crate::kiro::{AuthMethod, KiroOAuth, profile};
use crate::protocol::{Prepared, ProtocolId};
use crate::store::{self, ProviderKeyRow};
use crate::upstream::transport::{self, Transport, TransportError};

/// Attempts cardinal declares to the SSO OIDC service. Distinct from KAS'
/// `KIRO_MAX_ATTEMPTS` (= 3): the OIDC `CreateToken` call has no
/// `x-kiro-attempt` header and the reference declares `max=4`.
const OIDC_MAX_ATTEMPTS: u32 = 4;
/// Whole-call budget for one `CreateToken`, matching the reference's 60s client
/// timeout. The transport's own opening/idle deadlines are much longer; an OIDC
/// answer is small and prompt, and holding the per-key lock for an hour would
/// block every request that key serves.
const TOKEN_TIMEOUT: Duration = Duration::from_secs(60);
/// Hard cap on a successful token response body. A `CreateToken` answer is a
/// few hundred bytes; 64 KiB leaves room for unknown fields without buffering
/// an unbounded body.
const MAX_TOKEN_BODY: usize = 64 * 1024;
/// Social token responses may omit or send a nonpositive lifetime. Match the
/// local reference behavior without allowing an unbounded or immediate expiry.
const SOCIAL_DEFAULT_EXPIRES_IN: i64 = 3600;
/// The failure of one token acquisition/refresh.
///
/// Deliberately carries no upstream body and no OAuth material: this value is
/// formatted into the client response, ledger rows and logs. Only statuses,
/// categories and a non-secret `Retry-After` capture travel here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KiroTokenError {
    /// The OIDC endpoint rejected the refresh token permanently
    /// (`400 invalid_grant`). The account must be re-imported.
    Invalidated,
    /// OIDC answered a non-success status that the reference treats as
    /// transient (429/5xx, and — conservatively — any other non-permanent
    /// status). This never carries OAuth material. On the client surface,
    /// 400/401/403 map to 502 (the credential plane failed, not the caller;
    /// an AWS `invalid_client` never becomes the caller's 400), while 429/5xx
    /// keep their own status.
    Status {
        status: u16,
        /// Raw `Retry-After` header, for the relay's rate-limit classification.
        retry_after: Option<String>,
    },
    /// No answer within [`TOKEN_TIMEOUT`].
    Timeout,
    /// The OIDC endpoint could not be reached or its answer could not be read.
    Network,
    /// OIDC answered successfully but with an unusable document (missing
    /// token/expiry, malformed JSON).
    InvalidResponse,
    /// The key row carries no OAuth bundle (a race or a non-Kiro key reaching
    /// the Kiro transport).
    MissingCredential,
    /// The provider's KAS endpoint is not this credential's
    /// `runtime.{api_region}.kiro.dev` origin. Sending the bearer anywhere else
    /// is refused (fail closed).
    EndpointMismatch,
}

impl KiroTokenError {
    /// Whether re-importing the account (or fixing configuration) is the only
    /// remedy. The relay skips such a candidate instead of treating the request
    /// as at fault.
    pub fn is_permanent(&self) -> bool {
        matches!(
            self,
            Self::Invalidated | Self::MissingCredential | Self::EndpointMismatch
        )
    }

    /// The HTTP status the downstream client sees when every candidate failed.
    pub fn client_status(&self) -> u16 {
        match self {
            Self::Invalidated => 401,
            Self::MissingCredential => 500,
            Self::EndpointMismatch => 502,
            // The OIDC token plane rejected *our* credential; the caller's
            // request is not at fault, and an AWS `invalid_client` must never
            // masquerade as the client's own 400. `invalid_grant` never reaches
            // this arm (it classifies as Invalidated/401 above).
            Self::Status {
                status: 400 | 401 | 403,
                ..
            } => 502,
            // Everything else keeps its own meaning: 429 for rate limits, the
            // upstream 5xx for service failures, and any remaining status as-is.
            Self::Status { status, .. } => *status,
            Self::Timeout => 504,
            Self::Network | Self::InvalidResponse => 502,
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            Self::Invalidated => "kiro_credentials_invalid",
            Self::Status { .. } => "kiro_token_refresh_failed",
            Self::Timeout => "kiro_token_refresh_timeout",
            Self::Network => "kiro_token_refresh_unreachable",
            Self::InvalidResponse => "kiro_token_refresh_invalid",
            Self::MissingCredential => "kiro_credential_missing",
            Self::EndpointMismatch => "kiro_endpoint_mismatch",
        }
    }

    /// The upstream's `Retry-After` ask, parsed for the relay's backoff.
    pub fn retry_after(&self) -> Option<chrono::Duration> {
        match self {
            Self::Status {
                retry_after: Some(raw),
                ..
            } => transport::parse_retry_after(raw),
            _ => None,
        }
    }
}

impl std::fmt::Display for KiroTokenError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalidated => {
                formatter.write_str("Kiro credentials invalidated; re-import the account")
            }
            Self::Status { status, .. } => {
                write!(
                    formatter,
                    "Kiro token refresh failed (upstream HTTP {status})"
                )
            }
            Self::Timeout => formatter.write_str("Kiro token refresh timed out"),
            Self::Network => {
                formatter.write_str("Kiro token refresh could not reach the OIDC endpoint")
            }
            Self::InvalidResponse => {
                formatter.write_str("Kiro token refresh returned an unusable answer")
            }
            Self::MissingCredential => formatter.write_str("Kiro key has no OAuth credential"),
            Self::EndpointMismatch => {
                formatter.write_str("Kiro KAS endpoint does not match the credential's API region")
            }
        }
    }
}

impl std::error::Error for KiroTokenError {}

/// What one attempt may know about the credential: the bearer to put on the
/// wire and the account profile the KAS body names. The refresh token and the
/// OIDC client secrets never leave this module.
#[derive(Clone)]
pub struct KiroCallContext {
    bearer: SecretString,
    pub profile_arn: Option<String>,
    /// The credential's AWS region for its runtime host (`runtime.{region}.kiro.dev`).
    /// Non-secret: the relay reasserts the endpoint against it after resolving a
    /// credential, so a route-cache bundle that lags behind a region move cannot
    /// validate the wrong host before the bearer is sent.
    pub api_region: String,
}

impl KiroCallContext {
    /// The bearer value, exposed only at the header-injection point.
    pub fn bearer(&self) -> &str {
        self.bearer.expose_secret()
    }
}

/// A not-yet-persisted candidate bundle resolved for a pre-persistence probe.
///
/// `oauth` is what the caller must persist *iff* the probe succeeds: either the
/// submitted bundle (its access token was fresh) or the in-memory refresh of it.
/// Nothing in [`KiroTokens::candidate_for_probe`] writes this bundle to the
/// database or to the key-state map.
#[derive(Debug)]
pub struct KiroProbeCredential {
    /// The bundle to persist after a successful probe.
    pub oauth: KiroOAuth,
    /// The bearer/profile for the probe itself.
    pub call: KiroCallContext,
}

/// Never prints the bearer (nor anything else secret).
impl std::fmt::Debug for KiroCallContext {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("KiroCallContext")
            .field("profile_arn", &self.profile_arn)
            .field("api_region", &self.api_region)
            .finish_non_exhaustive()
    }
}

/// One key's in-memory token state.
pub struct KiroTokenState {
    pub oauth: KiroOAuth,
    /// `true` = the row holds this exact bundle (or a newer one); `false` =
    /// memory is newer (a refresh whose write-back has not succeeded yet) and
    /// must never be overwritten by a database reread.
    pub persisted: bool,
    /// The exact bundle that was used to produce `oauth` when a refresh is
    /// pending persistence. CAS write-back must never replace a row changed
    /// since that exchange started.
    pending_expected: Option<KiroOAuth>,
    /// Changes whenever the bundle or persistence marker changes. Async work
    /// snapshots this value and may commit only if it is still current.
    generation: u64,
}

/// Per-key Kiro OIDC token manager. Cheap to clone: the state map is shared,
/// the transport is already a process-wide handle.
///
/// The map is behind an `Arc` on purpose: `DashMap`'s own `Clone` forks the
/// map (it copies the entries), so a cloned manager would grow a second,
/// unsynchronized lock per key and defeat the single-flight guarantee. Only an
/// `Arc` makes the derived `Clone` share the locks.
#[derive(Clone)]
pub struct KiroTokens {
    transport: Transport,
    states: Arc<DashMap<i64, Arc<Mutex<KiroTokenState>>>>,
    refresh_gates: Arc<DashMap<[u8; 32], Arc<KiroRefreshGate>>>,
}

/// The last exchange result shared by dispatch and pre-persistence probes.
///
/// Keeping the result only until all waiters have observed it lets a probe that
/// races a dispatch reuse the exchange without retaining OAuth material in the
/// single-flight map permanently. Failures are shared as well, so concurrent
/// callers do not each repeat a failed exchange.
struct KiroRefreshGate {
    result: StdMutex<Option<Result<RefreshExchange, KiroTokenError>>>,
    users: AtomicUsize,
    closed: AtomicBool,
    started: AtomicBool,
    notify: Notify,
}

fn lock_gate_result(
    gate: &KiroRefreshGate,
) -> std::sync::MutexGuard<'_, Option<Result<RefreshExchange, KiroTokenError>>> {
    match gate.result.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            tracing::warn!("Kiro refresh gate mutex was poisoned; recovering its state");
            poisoned.into_inner()
        }
    }
}

/// The exchange result is deliberately independent of the caller's OAuth
/// context. In particular, api_region and profile_arn belong to the caller,
/// not to whichever waiter happened to become the gate owner.
#[derive(Clone)]
struct RefreshExchange {
    access_token: String,
    expires_at: i64,
    refresh_token: Option<String>,
    profile_arn: Option<String>,
}

struct RefreshOwner {
    user: RefreshGateUser,
}

impl RefreshOwner {
    fn new(user: RefreshGateUser) -> Self {
        Self { user }
    }
}

impl Drop for RefreshOwner {
    fn drop(&mut self) {
        let mut result = lock_gate_result(&self.user.gate);
        if result.is_none() {
            *result = Some(Err(KiroTokenError::Network));
            self.user.gate.notify.notify_waiters();
        }
    }
}

struct RefreshGateUser {
    gate: Arc<KiroRefreshGate>,
    identity: [u8; 32],
    gates: Arc<DashMap<[u8; 32], Arc<KiroRefreshGate>>>,
}

impl RefreshGateUser {
    fn new(
        gate: Arc<KiroRefreshGate>,
        identity: [u8; 32],
        gates: Arc<DashMap<[u8; 32], Arc<KiroRefreshGate>>>,
    ) -> Self {
        Self {
            gate,
            identity,
            gates,
        }
    }
}

impl Drop for RefreshGateUser {
    fn drop(&mut self) {
        release_refresh_gate(&self.gates, self.identity, &self.gate);
    }
}

fn release_refresh_gate(
    gates: &DashMap<[u8; 32], Arc<KiroRefreshGate>>,
    identity: [u8; 32],
    gate: &Arc<KiroRefreshGate>,
) {
    if gate.users.fetch_sub(1, Ordering::AcqRel) == 1 {
        gate.closed.store(true, Ordering::Release);
        gates.remove_if(&identity, |_, existing| Arc::ptr_eq(existing, gate));
    }
}

struct StateSnapshot {
    oauth: KiroOAuth,
    persisted: bool,
    pending_expected: Option<KiroOAuth>,
    generation: u64,
}

impl StateSnapshot {
    fn matches(&self, state: &KiroTokenState) -> bool {
        state.generation == self.generation
            && state.oauth == self.oauth
            && state.persisted == self.persisted
            && state.pending_expected == self.pending_expected
    }
}

fn snapshot(state: &KiroTokenState) -> StateSnapshot {
    StateSnapshot {
        oauth: state.oauth.clone(),
        persisted: state.persisted,
        pending_expected: state.pending_expected.clone(),
        generation: state.generation,
    }
}

fn commit(
    state: &mut KiroTokenState,
    snapshot: &StateSnapshot,
    oauth: KiroOAuth,
    persisted: bool,
    expected: Option<KiroOAuth>,
) -> bool {
    if !snapshot.matches(state) {
        return false;
    }
    state.oauth = oauth;
    state.persisted = persisted;
    state.pending_expected = expected;
    state.generation = state.generation.wrapping_add(1);
    true
}

fn merged_exchange(current: &KiroOAuth, exchange: RefreshExchange) -> KiroOAuth {
    let mut next = current.clone();
    next.access_token = exchange.access_token;
    next.expires_at = exchange.expires_at;
    if let Some(refresh_token) = exchange
        .refresh_token
        .filter(|token| !token.trim().is_empty())
    {
        next.refresh_token = refresh_token;
    }
    if let Some(profile_arn) = exchange.profile_arn.filter(|arn| !arn.trim().is_empty()) {
        next.profile_arn = Some(profile_arn);
    }
    next
}

fn exchange_identity_digest(oauth: &KiroOAuth) -> [u8; 32] {
    let mut hasher = Sha256::new();
    let (auth_method, endpoint) = match oauth.effective_auth_method() {
        AuthMethod::Social => (
            "social",
            profile::social_refresh_endpoint(&oauth.auth_region),
        ),
        AuthMethod::Idc => (
            "idc",
            format!("https://oidc.{}.amazonaws.com/token", oauth.auth_region),
        ),
    };
    for value in [auth_method, endpoint.as_str()] {
        hasher.update(value.len().to_le_bytes());
        hasher.update(value.as_bytes());
    }
    for value in [
        oauth.refresh_token.as_str(),
        match oauth.effective_auth_method() {
            AuthMethod::Social => "",
            AuthMethod::Idc => oauth.client_id.as_str(),
        },
        match oauth.effective_auth_method() {
            AuthMethod::Social => "",
            AuthMethod::Idc => oauth.client_secret.as_str(),
        },
    ] {
        hasher.update(value.len().to_le_bytes());
        hasher.update(value.as_bytes());
    }
    hasher.finalize().into()
}

impl KiroTokens {
    pub fn new(transport: Transport) -> Self {
        Self {
            transport,
            states: Arc::new(DashMap::new()),
            refresh_gates: Arc::new(DashMap::new()),
        }
    }

    /// Derive the process's shared transport to a caller that must speak to
    /// Kiro outside the chat path (the quota probe). Same instance, same
    /// destination policy — never a second client.
    pub fn transport(&self) -> &Transport {
        &self.transport
    }

    /// Resolve an operator-supplied candidate bundle for a probe that must
    /// succeed before anything is persisted (the `kiro-key` import).
    ///
    /// A candidate whose access token is still fresh is used as-is. A stale one
    /// is exchanged through the same [`Self::refresh`] path dispatch uses, but
    /// the result stays in memory: this method touches neither the key-state
    /// map nor the database. The caller persists `oauth` only after the probe
    /// it enables has succeeded.
    pub async fn candidate_for_probe(
        &self,
        candidate: KiroOAuth,
    ) -> Result<KiroProbeCredential, KiroTokenError> {
        let now = chrono::Utc::now().timestamp();
        let oauth = if candidate.fresh_for(now) {
            candidate
        } else {
            merged_exchange(&candidate, self.refresh(None, &candidate).await?)
        };
        let call = call_context(&oauth);
        Ok(KiroProbeCredential { oauth, call })
    }

    /// Read the committed row outside the state lock, then reconcile it under
    /// the key lock. A committed candidate is adopted when it still matches the
    /// row; a different stored bundle replaces persisted or newly seeded state,
    /// while a newer pending in-memory refresh is retained.
    pub async fn adopt_persisted(
        &self,
        pool: &PgPool,
        provider_id: i64,
        key_id: i64,
        candidate: KiroOAuth,
    ) {
        let state = match self.states.get(&key_id) {
            Some(existing) => Arc::clone(existing.value()),
            None => {
                let created = Arc::new(Mutex::new(KiroTokenState {
                    oauth: candidate.clone(),
                    persisted: false,
                    pending_expected: None,
                    generation: 0,
                }));
                match self.states.entry(key_id) {
                    dashmap::mapref::entry::Entry::Occupied(entry) => Arc::clone(entry.get()),
                    dashmap::mapref::entry::Entry::Vacant(entry) => {
                        entry.insert(Arc::clone(&created));
                        created
                    }
                }
            }
        };
        let before = {
            let guard = state.lock().await;
            snapshot(&guard)
        };
        match store::kiro_oauth(pool, key_id).await {
            Ok(Some(stored)) if stored == candidate => {
                let mut guard = state.lock().await;
                commit(&mut guard, &before, candidate, true, None);
            }
            Ok(Some(stored)) => {
                let mut guard = state.lock().await;
                if before.persisted || before.oauth == candidate {
                    commit(&mut guard, &before, stored, true, None);
                }
            }
            Ok(None) => tracing::warn!(
                key_id,
                provider_id,
                "Kiro credential adoption found no persisted row"
            ),
            Err(error) => tracing::warn!(
                key_id,
                provider_id,
                error = %error,
                "Kiro credential adoption could not verify the persisted row"
            ),
        }
    }

    /// Drop a key's cached state (key deletion). The next access re-seeds from
    /// the route cache / row.
    pub fn remove(&self, key_id: i64) {
        self.states.remove(&key_id);
    }

    /// Drop all cached states for a provider after its rows are deleted.
    pub fn remove_provider(&self, key_ids: &[i64]) {
        for key_id in key_ids {
            self.states.remove(key_id);
        }
    }

    /// The credential for one dispatch: a fresh bearer plus the profile ARN the
    /// KAS body should name. Refreshes lazily under the key's lock.
    pub async fn access_token(
        &self,
        pool: &PgPool,
        key: &ProviderKeyRow,
    ) -> Result<KiroCallContext, KiroTokenError> {
        let state = self.state_for(key)?;
        loop {
            let before = {
                let guard = state.lock().await;
                snapshot(&guard)
            };
            let now = chrono::Utc::now().timestamp();
            if before.oauth.fresh_for(now) {
                if !before.persisted {
                    self.persist_snapshot(pool, key.provider_id, key.id, &state, &before)
                        .await;
                }
                let guard = state.lock().await;
                return Ok(call_context(&guard.oauth));
            }
            if before.persisted
                && let Ok(Some(stored)) = store::kiro_oauth(pool, key.id).await
                && persisted_reread_changed(&before.oauth, &stored)
            {
                let mut guard = state.lock().await;
                commit(&mut guard, &before, stored, true, None);
                continue;
            }
            let (refreshed, expected) = self.refresh_from_snapshot(pool, key, &before).await?;
            let mut guard = state.lock().await;
            if !commit(&mut guard, &before, refreshed, false, Some(expected)) {
                continue;
            }
            let after = snapshot(&guard);
            drop(guard);
            self.persist_snapshot(pool, key.provider_id, key.id, &state, &after)
                .await;
            let guard = state.lock().await;
            return Ok(call_context(&guard.oauth));
        }
    }

    /// The bearer was rejected by the runtime service: rotate once. Concurrent
    /// callers that all presented the same stale bearer de-duplicate here — the
    /// first rotates under the lock, the rest observe a different current bearer
    /// and reuse it.
    pub async fn recover_invalidated(
        &self,
        pool: &PgPool,
        key: &ProviderKeyRow,
        old_bearer: &str,
    ) -> Result<KiroCallContext, KiroTokenError> {
        let state = self.state_for(key)?;
        loop {
            let before = {
                let guard = state.lock().await;
                snapshot(&guard)
            };
            if before.oauth.access_token != old_bearer {
                let guard = state.lock().await;
                return Ok(call_context(&guard.oauth));
            }
            let now = chrono::Utc::now().timestamp();
            // Reconcile the row snapshot with a short state-lock commit. The lock
            // is deliberately not held during the database or refresh awaits.
            let mut base = before;
            match store::kiro_oauth(pool, key.id).await {
                Ok(Some(stored)) => {
                    let newer_access = stored.access_token != old_bearer;
                    if newer_access && stored.fresh_for(now) {
                        let mut guard = state.lock().await;
                        if commit(&mut guard, &base, stored, true, None) {
                            return Ok(call_context(&guard.oauth));
                        }
                        continue;
                    }
                    if base.persisted || newer_access {
                        base.oauth = stored;
                        base.persisted = true;
                        base.pending_expected = None;
                    }
                }
                Ok(None) => tracing::warn!(
                    key_id = key.id,
                    "Kiro token row vanished; recovering from memory"
                ),
                Err(error) => tracing::warn!(
                    key_id = key.id,
                    error = %error,
                    "Kiro token reread failed; recovering from memory"
                ),
            }
            let (refreshed, expected) = self.refresh_from_snapshot(pool, key, &base).await?;
            let mut guard = state.lock().await;
            if !commit(&mut guard, &base, refreshed, false, Some(expected)) {
                continue;
            }
            let after = snapshot(&guard);
            drop(guard);
            self.persist_snapshot(pool, key.provider_id, key.id, &state, &after)
                .await;
            let guard = state.lock().await;
            return Ok(call_context(&guard.oauth));
        }
    }

    /// The key's state entry, seeded from the route cache's bundle on first use
    /// (no database access on this path).
    fn state_for(
        &self,
        key: &ProviderKeyRow,
    ) -> Result<Arc<Mutex<KiroTokenState>>, KiroTokenError> {
        if let Some(existing) = self.states.get(&key.id) {
            return Ok(Arc::clone(existing.value()));
        }
        let oauth = key.oauth.clone().ok_or(KiroTokenError::MissingCredential)?;
        let created = Arc::new(Mutex::new(KiroTokenState {
            oauth,
            persisted: true,
            pending_expected: None,
            generation: 0,
        }));
        match self.states.entry(key.id) {
            dashmap::mapref::entry::Entry::Occupied(entry) => Ok(Arc::clone(entry.get())),
            dashmap::mapref::entry::Entry::Vacant(entry) => {
                entry.insert(Arc::clone(&created));
                Ok(created)
            }
        }
    }

    /// Refresh the bundle currently in `state` and persist the result, applying
    /// the reference's narrow reload-and-retry for `invalid_grant`. The caller
    /// holds the key's lock. A pre-persistence candidate
    /// ([`Self::candidate_for_probe`]) has no shared key state yet, so it calls
    /// this directly and simply drops the result if its probe fails.
    ///
    /// A 400 `invalid_grant` may simply mean another holder rotated the
    /// credential after this process seeded memory. When memory is known to match
    /// the row, reread it once: a fresh stored bearer wins; otherwise retry
    /// `CreateToken` once only if the exchange identity (refresh token, client
    /// id/secret, auth region) changed. Retrying the same bundle is pointless
    /// and is never done; an unchanged row stays permanently invalidated. Memory
    /// is replaced only by a successful exchange or the fresh stored bearer, so
    /// a failed recovery cannot roll a newer in-memory bundle backwards.
    async fn refresh_from_snapshot(
        &self,
        pool: &PgPool,
        key: &ProviderKeyRow,
        before: &StateSnapshot,
    ) -> Result<(KiroOAuth, KiroOAuth), KiroTokenError> {
        let refreshed = match self.refresh(Some(key.id), &before.oauth).await {
            Ok(exchange) => merged_exchange(&before.oauth, exchange),
            Err(KiroTokenError::Invalidated) if before.persisted => {
                let Some(stored) = store::kiro_oauth(pool, key.id)
                    .await
                    .map_err(|_| KiroTokenError::Invalidated)?
                else {
                    return Err(KiroTokenError::Invalidated);
                };
                if stored.access_token != before.oauth.access_token
                    && stored.fresh_for(chrono::Utc::now().timestamp())
                {
                    return Ok((stored.clone(), stored));
                }
                if !same_exchange_identity(&stored, &before.oauth) {
                    let refreshed =
                        merged_exchange(&stored, self.refresh(Some(key.id), &stored).await?);
                    return Ok((refreshed, stored));
                } else {
                    return Err(KiroTokenError::Invalidated);
                }
            }
            Err(error) => return Err(error),
        };
        Ok((refreshed, before.oauth.clone()))
    }

    /// Best-effort write-back of a memory-newer bundle. The state lock is
    /// acquired only to commit the CAS outcome; database I/O is never done
    /// while it is held.
    async fn persist_snapshot(
        &self,
        pool: &PgPool,
        provider_id: i64,
        key_id: i64,
        state: &Arc<Mutex<KiroTokenState>>,
        before: &StateSnapshot,
    ) {
        if before.persisted {
            return;
        }
        let Some(expected) = before.pending_expected.as_ref() else {
            tracing::warn!(
                key_id,
                "Kiro token bundle has no CAS baseline; serving from memory"
            );
            return;
        };
        match store::replace_kiro_oauth(pool, provider_id, key_id, expected, &before.oauth).await {
            Ok(true) => {
                let mut guard = state.lock().await;
                if before.matches(&guard) {
                    guard.persisted = true;
                    guard.pending_expected = None;
                    guard.generation = guard.generation.wrapping_add(1);
                }
            }
            Ok(false) => match store::kiro_oauth(pool, key_id).await {
                Ok(Some(stored)) => {
                    let mut guard = state.lock().await;
                    if before.matches(&guard) {
                        guard.oauth = stored;
                        guard.persisted = true;
                        guard.pending_expected = None;
                        guard.generation = guard.generation.wrapping_add(1);
                    }
                }
                Ok(None) => tracing::warn!(
                    key_id,
                    "Kiro token bundle write-back found no OIDC row; serving from memory"
                ),
                Err(error) => tracing::warn!(
                    key_id,
                    error = %error,
                    "Kiro token bundle write-back lost its CAS race and could not reread the row"
                ),
            },
            // The error text never contains the bundle (it is a bind value, not
            // part of the message), and the bundle itself is never logged.
            Err(error) => tracing::warn!(
                key_id,
                error = %error,
                "Kiro token bundle write-back failed; serving from memory"
            ),
        }
    }

    /// One AWS SSO OIDC `CreateToken` exchange against the credential's auth
    /// region. The caller holds the key's lock.
    async fn refresh(
        &self,
        key_id: Option<i64>,
        current: &KiroOAuth,
    ) -> Result<RefreshExchange, KiroTokenError> {
        let identity = exchange_identity_digest(current);
        let gate = match self.refresh_gates.entry(identity) {
            dashmap::mapref::entry::Entry::Occupied(entry) => Arc::clone(entry.get()),
            dashmap::mapref::entry::Entry::Vacant(entry) => {
                let gate = Arc::new(KiroRefreshGate {
                    result: StdMutex::new(None),
                    users: AtomicUsize::new(0),
                    closed: AtomicBool::new(false),
                    started: AtomicBool::new(false),
                    notify: Notify::new(),
                });
                entry.insert(Arc::clone(&gate));
                gate
            }
        };
        if gate.closed.load(Ordering::Acquire) {
            if let Some(result) = self.closed_refresh_result(&gate).await {
                return result;
            }
            self.refresh_gates
                .remove_if(&identity, |_, existing| Arc::ptr_eq(existing, &gate));
            return Box::pin(self.refresh(key_id, current)).await;
        }
        gate.users.fetch_add(1, Ordering::AcqRel);
        let user =
            RefreshGateUser::new(Arc::clone(&gate), identity, Arc::clone(&self.refresh_gates));
        if gate.closed.load(Ordering::Acquire) {
            if let Some(result) = self.closed_refresh_result(&gate).await {
                return result;
            }
            return Box::pin(self.refresh(key_id, current)).await;
        }
        let notified = gate.notify.notified();
        let existing = {
            let guard = lock_gate_result(&gate);
            guard.as_ref().cloned()
        };
        if let Some(result) = existing {
            match result {
                Ok(exchange) => {
                    return Ok(exchange);
                }
                Err(error) => {
                    return Err(error);
                }
            }
        }
        if gate.started.swap(true, Ordering::AcqRel) {
            notified.await;
            let result = lock_gate_result(&gate);
            let answer = result.as_ref().cloned();
            drop(result);
            drop(user);
            match answer {
                Some(Ok(exchange)) => return Ok(exchange),
                Some(Err(error)) => return Err(error),
                None => return Err(KiroTokenError::Network),
            }
        }
        let owner = RefreshOwner::new(user);
        let answer = match self.create_token(key_id, current).await {
            Ok(answer) => answer,
            Err(error) => {
                let mut result = lock_gate_result(&gate);
                *result = Some(Err(error.clone()));
                drop(result);
                gate.notify.notify_waiters();
                drop(owner);
                return Err(error);
            }
        };
        let now = chrono::Utc::now().timestamp();
        let expires_at =
            match refresh_expiry(current.effective_auth_method(), answer.expires_in, now) {
                Ok(expires_at) => expires_at,
                Err(error) => {
                    let mut result = lock_gate_result(&gate);
                    *result = Some(Err(error.clone()));
                    drop(result);
                    gate.notify.notify_waiters();
                    drop(owner);
                    return Err(error);
                }
            };
        let exchange = RefreshExchange {
            access_token: answer.access_token,
            expires_at,
            refresh_token: answer.refresh_token,
            profile_arn: answer.profile_arn,
        };
        if exchange.access_token.trim().is_empty() {
            let error = KiroTokenError::InvalidResponse;
            let mut result = lock_gate_result(&gate);
            *result = Some(Err(error.clone()));
            drop(result);
            gate.notify.notify_waiters();
            drop(owner);
            return Err(error);
        }
        let mut result = lock_gate_result(&gate);
        *result = Some(Ok(exchange.clone()));
        drop(result);
        gate.notify.notify_waiters();
        drop(owner);
        Ok(exchange)
    }

    /// Reuse an exchange that finished just before this caller acquired its
    /// gate reference. A closed gate is removed promptly, but its result must be
    /// observed first or the caller can start a duplicate exchange for the same
    /// refresh-token identity.
    async fn closed_refresh_result(
        &self,
        gate: &KiroRefreshGate,
    ) -> Option<Result<RefreshExchange, KiroTokenError>> {
        let guard = lock_gate_result(gate);
        match guard.as_ref() {
            Some(Ok(exchange)) => Some(Ok(exchange.clone())),
            Some(Err(error)) => Some(Err(error.clone())),
            _ => None,
        }
    }

    /// The raw credential exchange. Request bodies carry secrets; they are never
    /// logged or included in an error.
    async fn create_token(
        &self,
        key_id: Option<i64>,
        oauth: &KiroOAuth,
    ) -> Result<CreateTokenResponse, KiroTokenError> {
        if !crate::kiro::valid_region(&oauth.auth_region)
            || !crate::kiro::valid_region(&oauth.api_region)
        {
            // A region string becomes part of the URL host: anything outside
            // AWS' region grammar could point the credential elsewhere.
            return Err(KiroTokenError::Invalidated);
        }
        let body = serde_json::to_vec(&refresh_request(oauth))
            .map_err(|_| KiroTokenError::InvalidResponse)?;
        let mut headers = profile::retry_headers(
            &uuid::Uuid::new_v4().to_string(),
            1,
            OIDC_MAX_ATTEMPTS,
            false,
            chrono::Utc::now(),
        );
        if oauth.effective_auth_method() == AuthMethod::Social {
            headers.splice(0..0, profile::social_static_headers());
        }
        let prepared = Prepared {
            protocol: ProtocolId::Kiro,
            url: self.refresh_url(oauth),
            content_type: "application/json",
            body: bytes::Bytes::from(body),
            stream: false,
            headers,
        };
        let deadline = Instant::now() + TOKEN_TIMEOUT;
        let response = self
            .transport
            .send(&prepared, deadline)
            .await
            .map_err(send_error)?;
        let status = response.status().as_u16();
        if !(200..300).contains(&status) {
            let retry_after = response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok())
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_owned);
            // Drain a bounded body only to classify `invalid_grant`; it is never
            // logged and never forwarded.
            let body = match self
                .transport
                .read_body(response, transport::MAX_ERROR_BODY, deadline)
                .await
            {
                Ok(body) => body,
                Err(error) => {
                    if let Some(key_id) = key_id {
                        tracing::warn!(
                            key_id,
                            status,
                            category = %error_category(&error),
                            "Kiro OIDC CreateToken error body could not be read"
                        );
                    } else {
                        tracing::warn!(
                            status,
                            category = %error_category(&error),
                            "Kiro OIDC CreateToken error body could not be read"
                        );
                    }
                    return Err(match error {
                        TransportError::Timeout => KiroTokenError::Network,
                        TransportError::Connect
                        | TransportError::BodyTooLarge
                        | TransportError::InvalidBody
                        | TransportError::ClientGone
                        | TransportError::Status { .. } => KiroTokenError::InvalidResponse,
                    });
                }
            };
            // Log the numeric facts only: the OIDC body can echo request fields.
            if let Some(key_id) = key_id {
                tracing::warn!(key_id, status, "Kiro OIDC CreateToken rejected the refresh");
            } else {
                tracing::warn!(status, "Kiro OIDC CreateToken rejected the refresh");
            }
            if status == 400 && String::from_utf8_lossy(&body).contains("invalid_grant") {
                return Err(KiroTokenError::Invalidated);
            }
            return Err(KiroTokenError::Status {
                status,
                retry_after,
            });
        }
        let body = self
            .transport
            .read_body(response, MAX_TOKEN_BODY, deadline)
            .await
            .map_err(|_| KiroTokenError::InvalidResponse)?;
        serde_json::from_slice(&body).map_err(|_| KiroTokenError::InvalidResponse)
    }

    fn refresh_url(&self, oauth: &KiroOAuth) -> String {
        match oauth.effective_auth_method() {
            AuthMethod::Social => profile::social_refresh_endpoint(&oauth.auth_region),
            AuthMethod::Idc => self.token_url(&oauth.auth_region),
        }
    }

    fn token_url(&self, auth_region: &str) -> String {
        format!("https://oidc.{auth_region}.amazonaws.com/token")
    }
}

fn call_context(oauth: &KiroOAuth) -> KiroCallContext {
    KiroCallContext {
        bearer: SecretString::from(oauth.access_token.clone()),
        profile_arn: oauth.effective_profile_arn().map(str::to_owned),
        api_region: oauth.api_region.clone(),
    }
}

fn same_exchange_identity(left: &KiroOAuth, right: &KiroOAuth) -> bool {
    exchange_identity_digest(left) == exchange_identity_digest(right)
}

fn send_error(error: TransportError) -> KiroTokenError {
    match error {
        TransportError::Timeout => KiroTokenError::Timeout,
        TransportError::Connect
        | TransportError::BodyTooLarge
        | TransportError::InvalidBody
        | TransportError::ClientGone
        | TransportError::Status { .. } => KiroTokenError::Network,
    }
}

fn error_category(error: &TransportError) -> &'static str {
    match error {
        TransportError::Timeout => "timeout",
        TransportError::Connect => "connect",
        TransportError::BodyTooLarge => "body_too_large",
        TransportError::InvalidBody => "invalid_body",
        TransportError::ClientGone => "client_gone",
        TransportError::Status { .. } => "status",
    }
}

/// AWS region grammar (lowercase letters, digits, hyphens). The value is
/// interpolated into the OIDC hostname, so it must not be able to introduce
/// another host, a port or a path. Public because every host-building caller
/// shares this guard (the token URL here, the usage host in
/// [`crate::quota::fetch_kiro_quota`]).
/// The runtime's own invalidation signal: a 401/403 whose bounded body says
/// the bearer was invalid. Only this exact combination licenses the one-shot
/// refresh-and-retry (any other 401/403 is a regular authentication failure).
pub fn bearer_token_invalid(status: u16, body: &[u8]) -> bool {
    matches!(status, 401 | 403)
        && String::from_utf8_lossy(body)
            .contains("The bearer token included in the request is invalid")
}

fn refresh_request(oauth: &KiroOAuth) -> serde_json::Value {
    match oauth.effective_auth_method() {
        AuthMethod::Social => serde_json::json!({
            "refreshToken": oauth.refresh_token,
        }),
        AuthMethod::Idc => serde_json::json!({
            "clientId": oauth.client_id,
            "clientSecret": oauth.client_secret,
            "refreshToken": oauth.refresh_token,
            "grantType": "refresh_token",
        }),
    }
}

fn persisted_reread_changed(before: &KiroOAuth, stored: &KiroOAuth) -> bool {
    before != stored
}

fn refresh_expiry(
    auth_method: AuthMethod,
    expires_in: Option<i64>,
    now: i64,
) -> Result<i64, KiroTokenError> {
    let lifetime = match auth_method {
        AuthMethod::Social => expires_in
            .filter(|expires_in| *expires_in > 0)
            .unwrap_or(SOCIAL_DEFAULT_EXPIRES_IN),
        AuthMethod::Idc => expires_in
            .filter(|expires_in| *expires_in > 0)
            .ok_or(KiroTokenError::InvalidResponse)?,
    };
    now.checked_add(lifetime)
        .ok_or(KiroTokenError::InvalidResponse)
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateTokenResponse {
    access_token: String,
    /// Social refresh responses may omit this field; IdC responses must include
    /// a positive value. Missing or nonpositive Social values use the bounded
    /// default lifetime in [`SOCIAL_DEFAULT_EXPIRES_IN`].
    expires_in: Option<i64>,
    refresh_token: Option<String>,
    profile_arn: Option<String>,
}
