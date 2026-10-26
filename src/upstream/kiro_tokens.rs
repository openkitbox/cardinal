//! Kiro OIDC token lifecycle: lazy refresh, per-key single-flight, and
//! persistence back into the key's `oauth` bundle.
//!
//! Kiro authenticates with AWS SSO OIDC (device-code / Builder ID). A key row
//! carries the whole credential bundle ([`crate::kiro::KiroOAuth`]), and the
//! access token inside it expires (typically hourly). The gateway therefore
//! must refresh it itself — the downstream client never holds the refresh
//! token — and write the rotated bundle back so a restart does not resurrect a
//! token upstream has already invalidated.
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
//! * **Admin replacement serializes with refresh.** [`KiroTokens::replace`]
//!   takes the key's lock, makes the operator's bundle authoritative in memory
//!   with `persisted = false`, and writes that exact bundle to the row before
//!   returning. An in-flight refresh therefore either wrote before the operator
//!   bundle (and the operator write corrects the row) or runs after it under the
//!   lock and starts from the operator bundle; on success disk and memory agree.
//!   A failed replacement write keeps the operator bundle in memory with
//!   `persisted = false` and warns — it is never reported as persisted.
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
//! * `expiresIn` is required. The reference treats a missing `expiresIn` as
//!   "keep the old expiry"; cardinal refuses the answer as
//!   [`KiroTokenError::InvalidResponse`] — persisting a bearer with no honest
//!   expiry would make every later freshness decision a guess.
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

use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use secrecy::{ExposeSecret as _, SecretString};
use sqlx::PgPool;
use tokio::sync::Mutex;

use crate::kiro::{KiroOAuth, profile};
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
}

impl KiroTokens {
    pub fn new(transport: Transport) -> Self {
        Self {
            transport,
            states: Arc::new(DashMap::new()),
        }
    }

    /// Derive the process's shared transport to a caller that must speak to
    /// Kiro outside the chat path (the quota probe). Same instance, same
    /// destination policy — never a second client.
    pub fn transport(&self) -> &Transport {
        &self.transport
    }

    /// Drop a key's cached state (key deletion). The next access re-seeds from
    /// the route cache / row.
    pub fn remove(&self, key_id: i64) {
        self.states.remove(&key_id);
    }

    /// Adopt a bundle the admin plane just persisted (create or credential
    /// rotation) and make disk match it before returning.
    ///
    /// Serializes with any in-flight refresh: the operator bundle becomes
    /// authoritative in memory (`persisted = false`), and the exact same bundle
    /// is written to the row while the key's lock is held. An older refresh that
    /// already wrote the row is corrected here; one that runs later takes the
    /// lock and starts from the operator bundle. A failed write keeps the
    /// operator bundle in memory with `persisted = false` and warns — memory is
    /// newer, and no caller is told the row holds it.
    pub async fn replace(&self, pool: &PgPool, provider_id: i64, key_id: i64, oauth: KiroOAuth) {
        let state = match self.states.get(&key_id) {
            Some(existing) => Arc::clone(existing.value()),
            None => {
                // Clone only when this may be a new entry: the entry API needs
                // an owned candidate, and on a race the losing insert is dropped.
                let created = Arc::new(Mutex::new(KiroTokenState {
                    oauth: oauth.clone(),
                    persisted: false,
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
        let mut guard = state.lock().await;
        guard.oauth = oauth;
        guard.persisted = false;
        self.persist_pending(pool, provider_id, key_id, &mut guard)
            .await;
    }

    /// The credential for one dispatch: a fresh bearer plus the profile ARN the
    /// KAS body should name. Refreshes lazily under the key's lock.
    pub async fn access_token(
        &self,
        pool: &PgPool,
        key: &ProviderKeyRow,
    ) -> Result<KiroCallContext, KiroTokenError> {
        let state = self.state_for(key)?;
        let mut guard = state.lock().await;
        let now = chrono::Utc::now().timestamp();
        if guard.oauth.fresh_for(now) {
            self.persist_pending(pool, key.provider_id, key.id, &mut guard)
                .await;
            return Ok(call_context(&guard.oauth));
        }
        // Refresh is due. While memory is known to match the row, another
        // process (or kiro-cli) may have rotated the credential already: reread
        // under the lock and prefer a fresh row over a second refresh.
        if guard.persisted {
            self.reload_if_persisted(pool, key, &mut guard).await;
            if guard.oauth.fresh_for(now) {
                return Ok(call_context(&guard.oauth));
            }
        }
        self.refresh_locked(pool, key, &mut guard).await?;
        Ok(call_context(&guard.oauth))
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
        let mut guard = state.lock().await;
        if guard.oauth.access_token != old_bearer {
            return Ok(call_context(&guard.oauth));
        }
        let now = chrono::Utc::now().timestamp();
        // Reread the row under the lock: an external login may have written a
        // newer bundle. A fresh stored bearer that differs from the rejected one
        // is the recovery, no CreateToken needed. A stored bundle that is not
        // fresh replaces memory only when memory is known to match the row
        // (`persisted`) or when it proved newer by carrying a different bearer;
        // otherwise it could only roll a pending newer refresh token back.
        match store::kiro_oauth(pool, key.id).await {
            Ok(Some(stored)) => {
                let newer_access = stored.access_token != old_bearer;
                if newer_access && stored.fresh_for(now) {
                    guard.oauth = stored;
                    guard.persisted = true;
                    return Ok(call_context(&guard.oauth));
                }
                if guard.persisted || newer_access {
                    guard.oauth = stored;
                    guard.persisted = true;
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
        self.refresh_locked(pool, key, &mut guard).await?;
        Ok(call_context(&guard.oauth))
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
        }));
        match self.states.entry(key.id) {
            dashmap::mapref::entry::Entry::Occupied(entry) => Ok(Arc::clone(entry.get())),
            dashmap::mapref::entry::Entry::Vacant(entry) => {
                entry.insert(Arc::clone(&created));
                Ok(created)
            }
        }
    }

    /// Reread the row while memory is known to match it, adopting whatever the
    /// row holds as the refresh base (or as the answer, if it is fresh). The
    /// caller then rechecks freshness and refreshes from it.
    async fn reload_if_persisted(
        &self,
        pool: &PgPool,
        key: &ProviderKeyRow,
        state: &mut KiroTokenState,
    ) {
        match store::kiro_oauth(pool, key.id).await {
            Ok(Some(stored)) => state.oauth = stored,
            Ok(None) => tracing::warn!(
                key_id = key.id,
                "Kiro token row vanished; refreshing from memory"
            ),
            Err(error) => tracing::warn!(
                key_id = key.id,
                error = %error,
                "Kiro token reread failed; refreshing from memory"
            ),
        }
    }

    /// Refresh the bundle currently in `state` and persist the result, applying
    /// the reference's narrow reload-and-retry for `invalid_grant`. The caller
    /// holds the key's lock.
    ///
    /// A 400 `invalid_grant` may simply mean another holder rotated the
    /// credential after this process seeded memory. When memory is known to match
    /// the row, reread it once: a fresh stored bearer wins; otherwise retry
    /// `CreateToken` once only if the exchange identity (refresh token, client
    /// id/secret, auth region) changed. Retrying the same bundle is pointless
    /// and is never done; an unchanged row stays permanently invalidated. Memory
    /// is replaced only by a successful exchange or the fresh stored bearer, so
    /// a failed recovery cannot roll a newer in-memory bundle backwards.
    async fn refresh_locked(
        &self,
        pool: &PgPool,
        key: &ProviderKeyRow,
        state: &mut KiroTokenState,
    ) -> Result<(), KiroTokenError> {
        match self.refresh(key.id, &state.oauth).await {
            Ok(refreshed) => {
                state.oauth = refreshed;
                state.persisted = false;
                self.persist_pending(pool, key.provider_id, key.id, state)
                    .await;
                Ok(())
            }
            Err(KiroTokenError::Invalidated) if state.persisted => {
                let attempted = state.oauth.clone();
                let stored = match store::kiro_oauth(pool, key.id).await {
                    Ok(Some(stored)) => stored,
                    Ok(None) => {
                        tracing::warn!(
                            key_id = key.id,
                            "Kiro token row vanished while recovering from invalid_grant"
                        );
                        return Err(KiroTokenError::Invalidated);
                    }
                    Err(error) => {
                        tracing::warn!(
                            key_id = key.id,
                            error = %error,
                            "Kiro token reread failed while recovering from invalid_grant"
                        );
                        return Err(KiroTokenError::Invalidated);
                    }
                };
                let now = chrono::Utc::now().timestamp();
                if stored.access_token != attempted.access_token && stored.fresh_for(now) {
                    // Another holder already refreshed: adopt its bearer instead
                    // of exchanging the dead refresh token a second time.
                    state.oauth = stored;
                    state.persisted = true;
                    return Ok(());
                }
                if !exchange_identity_changed(&stored, &attempted) {
                    // The row still holds the bundle OIDC just rejected: this is
                    // a permanent invalidation, not a rotation.
                    return Err(KiroTokenError::Invalidated);
                }
                tracing::warn!(
                    key_id = key.id,
                    "Kiro OIDC rejected the cached refresh token; row holds a rotated bundle, retrying once"
                );
                let refreshed = self.refresh(key.id, &stored).await?;
                state.oauth = refreshed;
                state.persisted = false;
                self.persist_pending(pool, key.provider_id, key.id, state)
                    .await;
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    /// Best-effort write-back of a memory-newer bundle. Failure is a warning,
    /// never an error: the refreshed token is valid in memory and the next
    /// access retries the write.
    async fn persist_pending(
        &self,
        pool: &PgPool,
        provider_id: i64,
        key_id: i64,
        state: &mut KiroTokenState,
    ) {
        if state.persisted {
            return;
        }
        match store::replace_kiro_oauth(pool, provider_id, key_id, &state.oauth).await {
            Ok(true) => state.persisted = true,
            Ok(false) => tracing::warn!(
                key_id,
                "Kiro token bundle write-back matched no OIDC row; serving from memory"
            ),
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
    async fn refresh(&self, key_id: i64, current: &KiroOAuth) -> Result<KiroOAuth, KiroTokenError> {
        let answer = self.create_token(key_id, current).await?;
        let mut next = current.clone();
        next.access_token = answer.access_token;
        next.expires_at = chrono::Utc::now().timestamp() + answer.expires_in;
        // Rotation: an omitted refresh token keeps the old one (the credential
        // stays usable); a returned profileArn replaces the account identity.
        if let Some(refresh_token) = answer
            .refresh_token
            .filter(|token| !token.trim().is_empty())
        {
            next.refresh_token = refresh_token;
        }
        if let Some(profile_arn) = answer.profile_arn.filter(|arn| !arn.trim().is_empty()) {
            next.profile_arn = Some(profile_arn);
        }
        if next.access_token.trim().is_empty() || answer.expires_in <= 0 {
            return Err(KiroTokenError::InvalidResponse);
        }
        Ok(next)
    }

    /// The raw OIDC call. The request body carries the OIDC client secret and
    /// the refresh token; it is never logged, never included in an error.
    async fn create_token(
        &self,
        key_id: i64,
        oauth: &KiroOAuth,
    ) -> Result<CreateTokenResponse, KiroTokenError> {
        if !valid_region(&oauth.auth_region) || !valid_region(&oauth.api_region) {
            // A region string becomes part of the URL host: anything outside
            // AWS' region grammar could point the credential elsewhere.
            return Err(KiroTokenError::Invalidated);
        }
        let request = CreateTokenRequest {
            client_id: &oauth.client_id,
            client_secret: &oauth.client_secret,
            refresh_token: &oauth.refresh_token,
            grant_type: "refresh_token",
        };
        let body = serde_json::to_vec(&request).map_err(|_| KiroTokenError::InvalidResponse)?;
        let prepared = Prepared {
            protocol: ProtocolId::Kiro,
            url: self.token_url(&oauth.auth_region),
            content_type: "application/json",
            body: bytes::Bytes::from(body),
            stream: false,
            headers: profile::retry_headers(
                &uuid::Uuid::new_v4().to_string(),
                1,
                OIDC_MAX_ATTEMPTS,
                false,
                chrono::Utc::now(),
            ),
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
            let body = self
                .transport
                .read_body(response, transport::MAX_ERROR_BODY, deadline)
                .await
                .unwrap_or_default();
            // Log the numeric facts only: the OIDC body can echo request fields.
            tracing::warn!(key_id, status, "Kiro OIDC CreateToken rejected the refresh");
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

    fn token_url(&self, auth_region: &str) -> String {
        format!("https://oidc.{auth_region}.amazonaws.com/token")
    }
}

fn call_context(oauth: &KiroOAuth) -> KiroCallContext {
    KiroCallContext {
        bearer: SecretString::from(oauth.access_token.clone()),
        profile_arn: oauth.profile_arn.clone(),
        api_region: oauth.api_region.clone(),
    }
}

/// Whether a reloaded bundle could make the same `CreateToken` attempt succeed:
/// the refresh token, the OIDC client identity, or the auth region that builds
/// the token URL changed. `region` and `api_region` never reach that exchange, so
/// a difference there must not cause a pointless retry of the same dead token.
fn exchange_identity_changed(stored: &KiroOAuth, attempted: &KiroOAuth) -> bool {
    stored.refresh_token != attempted.refresh_token
        || stored.client_id != attempted.client_id
        || stored.client_secret != attempted.client_secret
        || stored.auth_region != attempted.auth_region
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

/// AWS region grammar (lowercase letters, digits, hyphens). The value is
/// interpolated into the OIDC hostname, so it must not be able to introduce
/// another host, a port or a path. Public because every host-building caller
/// shares this guard (the token URL here, the usage host in
/// [`crate::quota::fetch_kiro_quota`]).
pub fn valid_region(region: &str) -> bool {
    !region.is_empty()
        && region.len() <= 32
        && region
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

/// Whether an endpoint is exactly the KAS origin for `api_region`:
/// `https://runtime.{api_region}.kiro.dev` on port 443, with no userinfo, no
/// query and the bare root path.
///
/// The bearer must only ever travel to the credential's own runtime host. A
/// provider row's `base_url` is operator-editable, so a bad or malicious value
/// could otherwise send a live token to an arbitrary server.
pub fn kas_endpoint_matches(endpoint: &str, api_region: &str) -> bool {
    if !valid_region(api_region) {
        return false;
    }
    let Ok(url) = reqwest::Url::parse(endpoint) else {
        return false;
    };
    url.scheme() == "https"
        && url.port_or_known_default() == Some(443)
        && url.username().is_empty()
        && url.password().is_none()
        && url.path() == "/"
        && url.query().is_none()
        && url.fragment().is_none()
        && url.host_str().is_some_and(|host| {
            host.eq_ignore_ascii_case(&format!("runtime.{api_region}.kiro.dev"))
        })
}

/// The runtime's own invalidation signal: a 401/403 whose bounded body says
/// the bearer was invalid. Only this exact combination licenses the one-shot
/// refresh-and-retry (any other 401/403 is a regular authentication failure).
pub fn bearer_token_invalid(status: u16, body: &[u8]) -> bool {
    matches!(status, 401 | 403)
        && String::from_utf8_lossy(body)
            .contains("The bearer token included in the request is invalid")
}

/// Strict camelCase Smithy wire shape for `CreateToken`.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateTokenRequest<'a> {
    client_id: &'a str,
    client_secret: &'a str,
    refresh_token: &'a str,
    grant_type: &'a str,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateTokenResponse {
    access_token: String,
    /// Required, deliberately: the reference keeps the old expiry when this is
    /// absent, but a bearer with no honest expiry cannot inform a later
    /// freshness decision, so cardinal rejects such an answer
    /// ([`KiroTokenError::InvalidResponse`]) instead of persisting a fiction.
    expires_in: i64,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    profile_arn: Option<String>,
}
