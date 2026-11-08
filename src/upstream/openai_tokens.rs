//! Lazy, single-flight bearer resolution for `openai_oauth` provider keys.
//!
//! The issuer rotates the refresh token on every refresh, so refreshing from a
//! stale copy invalidates the account. Nothing here refreshes on a timer: a
//! dispatch resolves its bearer at attempt time, and the per-key gate plus the
//! compare-and-swap write-back ([`crate::store::replace_openai_oauth`]) make
//! concurrent refreshes converge on one surviving bundle.
//!
//! The cache holds `Arc<OpenaiOAuth>`, so a hit is one map lookup and one
//! pointer clone: no token copy and no I/O on the request path while the bundle
//! keeps more than [`REFRESH_SKEW_SECS`] of validity. Callers read
//! `access_token` and `account_id` straight off the shared bundle.
//!
//! A refused grant is remembered in the manager's dead set: once the issuer
//! answers the refresh token with a 4xx (revoked, already used), no retry can
//! recover it, and the account stays dispatchable until an operator logs it in
//! again. Without that verdict cache every dispatched request would pay one
//! issuer round-trip and one warning for an account that can only be fixed by
//! hand. Only a write to the row from this process (login, credential replace,
//! delete) clears it. The refusal is checked against the row first: a bundle
//! that already moved was replaced by a login (or another process) while the
//! refresh was in flight, so it is adopted instead of buried.
//!
//! A refresh always starts from the row the store returns (never from the
//! cache's copy): another process may have rotated the token since this one
//! last read it, and refreshing from a rotated-away token would lock the
//! account out until a new login.
//!
//! When the write-back of a refreshed bundle fails, the new pair is still the
//! only one the issuer honors, so it is served from memory rather than thrown
//! away; the row keeps the rotated-away refresh token, which a restart loses
//! and a new login repairs.

use std::sync::Arc;

use chrono::Duration;
use chrono::Utc;
use dashmap::DashMap;
use sqlx::PgPool;
use tokio::sync::Mutex;

use crate::openai::OpenaiOAuth;
use crate::openai::auth::AuthError;
use crate::openai::auth::Client;
use crate::store;

/// The margin a bundle must keep before its `expires_at` to count as fresh.
/// A request never races the expiry: inside the skew the bundle is refreshed
/// first, under the key's gate.
pub const REFRESH_SKEW_SECS: i64 = 300;

/// The bundle a request authenticates with: dispatch reads `access_token` and
/// `account_id` off the shared bundle, so a cache hit copies no token.
pub type OpenaiBearer = Arc<OpenaiOAuth>;

/// Why one candidate's OpenAI bearer could not be produced.
///
/// Every variant names a credential-plane verdict and carries no token, no
/// refresh token and no `authorization` value — the value travels to the relay's
/// attempt log and, when every candidate fails, into the client's error body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenaiTokenError {
    /// No usable bundle: the key row is gone, is not an `openai_oauth` row, or
    /// its stored bundle no longer decodes.
    Missing,
    /// The issuer refused the refresh token (revoked or already used): only a
    /// new login recovers the account.
    Expired,
    /// The store could not read or write the row. Distinct from [`Self::Missing`]
    /// because the credential itself may be fine: this is a storage failure, not
    /// an account verdict, and a retry later can succeed.
    Store,
    /// The issuer could not be reached (connect, TLS, timeout).
    Transport,
    /// The issuer (or the store) answered, but not with a usable token.
    Client,
}

impl OpenaiTokenError {
    /// The HTTP status the downstream client sees when every candidate failed.
    #[must_use]
    pub fn client_status(&self) -> u16 {
        match self {
            Self::Expired => 401,
            Self::Missing => 500,
            Self::Store | Self::Transport | Self::Client => 502,
        }
    }

    /// Stable machine code for the client error body and the request row.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Missing => "openai_credentials_missing",
            Self::Expired => "openai_credentials_expired",
            Self::Store => "openai_credential_store_failed",
            Self::Transport | Self::Client => "openai_token_refresh_failed",
        }
    }
}

impl std::fmt::Display for OpenaiTokenError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Missing => {
                "the OpenAI account has no usable stored credential; log the account in again"
            }
            Self::Expired => {
                "the OpenAI auth service no longer accepts this account's grant; log the account in again"
            }
            Self::Store => "the OpenAI account's stored credential could not be read",
            Self::Transport => "the OpenAI auth service could not be reached for a token refresh",
            Self::Client => "the OpenAI auth service issued no token for this account",
        })
    }
}

impl std::error::Error for OpenaiTokenError {}

/// Whether a caller may trust the stored bundle's own expiry claim.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Freshness<'a> {
    /// Ordinary dispatch: a still-fresh row (someone refreshed while this
    /// caller waited on the gate) is adopted instead of refreshed again.
    Check,
    /// After the upstream rejected `rejected`: a row that still carries that
    /// bearer cannot be trusted even when the clock says otherwise, so it is
    /// refreshed; a row that moved past it was rotated by whoever won and is
    /// adopted as is.
    Force { rejected: &'a str },
}

/// The process's OpenAI account bearer cache: one lazily refreshed bundle per
/// `openai_oauth` key, shared by dispatch, model probing and quota probing.
pub struct OpenaiTokens {
    client: Arc<Client>,
    /// Resolved bundles. A hit costs one lookup and one `Arc` clone.
    bundles: DashMap<i64, Arc<OpenaiOAuth>>,
    /// Keys whose grant the issuer refused (revoked or already used). The row
    /// stays dispatchable until an operator acts, so without this set every
    /// request to it would cost an issuer refresh and a warning for a verdict
    /// only a new login can change. `()` — the verdict is the membership.
    dead: DashMap<i64, ()>,
    /// One gate per key: the single-flight boundary of a refresh. The map owns
    /// `Arc`s so a waiter that queued behind a completed refresh still holds a
    /// valid gate while the map entry is reused.
    gates: DashMap<i64, Arc<Mutex<()>>>,
}

impl OpenaiTokens {
    /// Build the manager over the issuer client. The client is stateless, so a
    /// second instance would only duplicate the connection pool — callers share
    /// one manager instead.
    #[must_use]
    pub fn new(client: Arc<Client>) -> Self {
        Self {
            client,
            bundles: DashMap::new(),
            dead: DashMap::new(),
            gates: DashMap::new(),
        }
    }

    /// The bundle to authenticate with right now: the cached one while it keeps
    /// more than [`REFRESH_SKEW_SECS`] of validity (no lock, no I/O), otherwise
    /// a single-flight refresh. A key whose grant the issuer already refused
    /// answers from the verdict cache — no lock, no I/O, no log.
    pub async fn resolve(
        &self,
        pool: &PgPool,
        key_id: i64,
    ) -> Result<OpenaiBearer, OpenaiTokenError> {
        if let Some(verdict) = self.dead_verdict(key_id) {
            return Err(verdict);
        }
        if let Some(bundle) = self.fresh_cached(key_id) {
            return Ok(bundle);
        }
        self.resolve_locked(pool, key_id, Freshness::Check).await
    }

    /// Resolve past the freshness check: the upstream just rejected `rejected`,
    /// the bearer this attempt presented, so that bearer is due for replacement
    /// even if `expires_at` says otherwise. Still single-flight — concurrent
    /// 401s of one key share one refresh, and a winner's bundle is adopted
    /// instead of rotated away.
    pub async fn resolve_forced(
        &self,
        pool: &PgPool,
        key_id: i64,
        rejected: &str,
    ) -> Result<OpenaiBearer, OpenaiTokenError> {
        if let Some(verdict) = self.dead_verdict(key_id) {
            return Err(verdict);
        }
        self.resolve_locked(pool, key_id, Freshness::Force { rejected })
            .await
    }

    /// Install a bundle the caller just wrote to the store (login, import,
    /// credential replace), so the first dispatch after it needs no row read.
    /// Also clears a remembered refusal: the new bundle is a new grant.
    pub fn adopt(&self, key_id: i64, bundle: OpenaiOAuth) -> OpenaiBearer {
        let bundle = Arc::new(bundle);
        self.dead.remove(&key_id);
        self.bundles.insert(key_id, Arc::clone(&bundle));
        bundle
    }

    /// Drop one key's cached bundle and any remembered refusal. The next resolve
    /// rereads the row, which is what a delete or a credential replace wants; the
    /// gate stays (it holds no credential and its waiters are already queued).
    pub fn forget(&self, key_id: i64) {
        self.bundles.remove(&key_id);
        self.dead.remove(&key_id);
    }

    /// The remembered verdict for `key_id`, if the issuer already refused it.
    /// Consulted before the fast path and before every store or issuer call.
    fn dead_verdict(&self, key_id: i64) -> Option<OpenaiTokenError> {
        self.dead
            .contains_key(&key_id)
            .then_some(OpenaiTokenError::Expired)
    }

    /// Remember that the issuer refused this key's grant, and drop the bundle
    /// that cannot work. Returns whether the verdict is new, so the caller logs
    /// its cause exactly once instead of once per dispatched request.
    fn mark_dead(&self, key_id: i64) -> bool {
        self.bundles.remove(&key_id);
        self.dead.insert(key_id, ()).is_none()
    }

    /// The cached bundle for `key_id` while it is still fresh. A clone of the
    /// `Arc`, never of the tokens.
    fn fresh_cached(&self, key_id: i64) -> Option<Arc<OpenaiOAuth>> {
        let bundle = self.bundles.get(&key_id)?;
        let fresh = bundle.fresh_for(Utc::now(), skew());
        fresh.then(|| Arc::clone(bundle.value()))
    }

    /// The gate for `key_id`, created on first use.
    fn gate(&self, key_id: i64) -> Arc<Mutex<()>> {
        if let Some(gate) = self.gates.get(&key_id) {
            return Arc::clone(gate.value());
        }
        let gate = Arc::new(Mutex::new(()));
        Arc::clone(self.gates.entry(key_id).or_insert(gate).value())
    }

    /// The refresh path proper, called with the key's gate held: reread the row,
    /// adopt it when it is fresh (or, forced, when it moved past the rejected
    /// bearer), refresh otherwise, and write the result back through the
    /// compare-and-swap.
    async fn resolve_locked(
        &self,
        pool: &PgPool,
        key_id: i64,
        mode: Freshness<'_>,
    ) -> Result<OpenaiBearer, OpenaiTokenError> {
        let gate = self.gate(key_id);
        let _guard = gate.lock().await;
        // The verdict can land while this caller waits on the gate (a concurrent
        // 401 of the same key): rechecking under the gate is what keeps the
        // issuer to one refresh per refusal instead of one per waiter.
        if let Some(verdict) = self.dead_verdict(key_id) {
            return Err(verdict);
        }
        let stored = match store::openai_oauth(pool, key_id).await {
            Ok(Some(bundle)) => bundle,
            Ok(None) => {
                self.bundles.remove(&key_id);
                return Err(OpenaiTokenError::Missing);
            }
            Err(error) => {
                // Fail closed: without the row the credential cannot be proven.
                // A store failure is not an account verdict, though — the next
                // attempt retries instead of asking for a new login.
                tracing::warn!(
                    key_id,
                    error = %format!("{error:#}"),
                    "OpenAI bundle read failed; the candidate has no credential"
                );
                return Err(OpenaiTokenError::Store);
            }
        };
        let adoptable = adoptable(mode, &stored, Utc::now());
        if adoptable {
            return Ok(self.adopt(key_id, stored));
        }
        let tokens = match self.client.refresh(&stored.refresh_token, Utc::now()).await {
            Ok(tokens) => tokens,
            Err(error) => {
                let verdict = map_auth_error(&error);
                if verdict == OpenaiTokenError::Expired {
                    // A revoked or already-used refresh token: the issuer
                    // refuses this token, not this request.
                    return self
                        .refuse_refresh(pool, key_id, &stored, Some(&error))
                        .await;
                }
                tracing::warn!(key_id, error = %error, "OpenAI token refresh failed");
                return Err(verdict);
            }
        };
        let next = tokens.refresh_bundle(&stored);
        match store::replace_openai_oauth(pool, key_id, &stored, &next).await {
            Ok(true) => {}
            Ok(false) => {
                // A concurrent writer won the swap and already consumed the
                // refresh token this attempt rotated away: adopt its bundle
                // instead of overwriting the only one that still works.
                match store::openai_oauth(pool, key_id).await {
                    Ok(Some(winner)) => return Ok(self.adopt(key_id, winner)),
                    Ok(None) => {
                        self.bundles.remove(&key_id);
                        return Err(OpenaiTokenError::Missing);
                    }
                    Err(error) => {
                        tracing::warn!(
                            key_id,
                            error = %format!("{error:#}"),
                            "OpenAI bundle reread after a lost compare-and-swap failed"
                        );
                        // The refreshed pair in hand is still valid for this
                        // process; keep serving it rather than failing a request
                        // whose bearer works.
                        return Ok(self.adopt(key_id, next));
                    }
                }
            }
            Err(error) => {
                // The new pair is valid even though its write-back failed; the
                // rotated refresh token is lost to a restart, which the next
                // login repairs.
                tracing::warn!(
                    key_id,
                    error = %format!("{error:#}"),
                    "OpenAI bundle write-back failed; serving the in-memory bundle"
                );
            }
        }
        Ok(self.adopt(key_id, next))
    }

    /// Turn one refused refresh into a verdict, unless the row already moved.
    ///
    /// A refusal names the token the refused call presented, not the key: a
    /// login (or another process) can replace the bundle while this refresh is
    /// in flight, and remembering the refusal would then discard the working
    /// grant and answer `Expired` until the next login. So the row is re-read
    /// first and a bundle that no longer carries either presented token is
    /// adopted instead. Only a refusal that still applies to the stored row
    /// marks the key dead; a failed re-read cannot prove the row moved, so it
    /// keeps the verdict and says so.
    async fn refuse_refresh(
        &self,
        pool: &PgPool,
        key_id: i64,
        presented: &OpenaiOAuth,
        cause: Option<&AuthError>,
    ) -> Result<OpenaiBearer, OpenaiTokenError> {
        match store::openai_oauth(pool, key_id).await {
            Ok(Some(stored))
                if stored.refresh_token != presented.refresh_token
                    || stored.access_token != presented.access_token =>
            {
                tracing::warn!(
                    key_id,
                    "OpenAI refused a bundle the row has already replaced; adopting the newer grant"
                );
                return Ok(self.adopt(key_id, stored));
            }
            Ok(Some(_)) | Ok(None) => {}
            Err(error) => tracing::warn!(
                key_id,
                error = %format!("{error:#}"),
                "OpenAI bundle reread after a refused refresh failed; applying the refusal to this key"
            ),
        }
        if self.mark_dead(key_id) {
            match cause {
                Some(error) => tracing::warn!(
                    key_id,
                    error = %error,
                    "OpenAI grant was refused; the account needs a new login"
                ),
                None => tracing::warn!(
                    key_id,
                    "OpenAI refresh token was rejected; the account needs a new login"
                ),
            }
        }
        Err(OpenaiTokenError::Expired)
    }
}

/// Whether the row's bundle already answers this call, decided without I/O.
///
/// An ordinary dispatch adopts a bundle that is still fresh (someone refreshed
/// while this caller waited on the gate). After a 401 it adopts only a bundle
/// that moved past the bearer the upstream rejected: a row still carrying that
/// bearer must be refreshed even if its clock claim says fresh, and a row that
/// moved was rotated by whoever won the gate (or another process), so
/// refreshing it again would rotate the account's only working refresh token
/// away.
fn adoptable(mode: Freshness<'_>, stored: &OpenaiOAuth, now: chrono::DateTime<Utc>) -> bool {
    match mode {
        Freshness::Check => stored.fresh_for(now, skew()),
        Freshness::Force { rejected } => stored.access_token != rejected,
    }
}

/// The shared refresh margin as a duration.
fn skew() -> Duration {
    Duration::seconds(REFRESH_SKEW_SECS)
}

/// Reduce one issuer failure to the relay-facing verdict.
fn map_auth_error(error: &AuthError) -> OpenaiTokenError {
    match error {
        AuthError::Transport { .. } => OpenaiTokenError::Transport,
        AuthError::Status { .. } if error.is_rejection() => OpenaiTokenError::Expired,
        AuthError::Status { .. } | AuthError::Protocol { .. } => OpenaiTokenError::Client,
    }
}
