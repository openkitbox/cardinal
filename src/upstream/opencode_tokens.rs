//! Lazy, single-flight bearer resolution for `opencode_oauth` provider keys.
//!
//! The console rotates the refresh token on every refresh, so refreshing from a
//! stale copy invalidates the account. Nothing here refreshes on a timer: a
//! dispatch resolves its bearer at attempt time, and the per-key gate plus the
//! compare-and-swap write-back ([`crate::store::replace_opencode_oauth`]) make
//! concurrent refreshes converge on one surviving bundle.
//!
//! The cache holds `Arc<OpencodeOAuth>`, so a hit is one map lookup and one
//! pointer clone — no token copy and no I/O on the request path while the bundle
//! keeps more than [`REFRESH_SKEW_SECS`] of validity.
//!
//! A refused grant is remembered in the manager's dead set: once the console
//! says the refresh token is dead or demands SSO, no retry can recover it, and
//! the account stays dispatchable until an operator logs it in again. Without
//! that verdict cache every dispatched request would pay one console round-trip
//! and one warning for an account that can only be fixed by hand. Only a write
//! to the row from this process (login, import, credential replace, delete)
//! clears it. The refusal is checked against the row first: a bundle that
//! already moved was replaced by a login (or another process) while the refresh
//! was in flight, so it is adopted instead of buried.
//!
//! A refresh always starts from the row the store returns (never from the
//! cache's copy): another process may have rotated the token since this one
//! last read it, and refreshing from a rotated-away token would lock the
//! account out until a new login.

use std::sync::Arc;

use chrono::Duration;
use chrono::Utc;
use dashmap::DashMap;
use sqlx::PgPool;
use tokio::sync::Mutex;

use crate::opencode::OpencodeOAuth;
use crate::opencode::auth::AuthError;
use crate::opencode::auth::Client;
use crate::opencode::auth::TokenGrant;
use crate::store;

/// The margin a bundle must keep before its `expires_at` to count as fresh.
/// A request never races the expiry: inside the skew the bundle is refreshed
/// first, under the key's gate.
pub const REFRESH_SKEW_SECS: i64 = 60;

/// Why one candidate's OpenCode bearer could not be produced.
///
/// Every variant names a credential-plane verdict and carries no token, no
/// refresh token and no `authorization` value — the value travels to the relay's
/// attempt log and, when every candidate fails, into the client's error body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpencodeTokenError {
    /// No usable bundle: the key row is gone, is not an `opencode_oauth` row, or
    /// its stored bundle no longer decodes.
    Missing,
    /// The console revoked the grant, or demands the organization's SSO in a
    /// browser: only a new login recovers the account.
    Expired,
    /// The store could not read or write the row. Distinct from [`Self::Missing`]
    /// because the credential itself may be fine: this is a storage failure, not
    /// an account verdict, and a retry later can succeed.
    Store,
    /// The console could not be reached (connect, TLS, timeout).
    Transport,
    /// The console (or the store) answered, but not with a usable token.
    Client,
}

impl OpencodeTokenError {
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
            Self::Missing => "opencode_credentials_missing",
            Self::Expired => "opencode_credentials_expired",
            Self::Store => "opencode_credential_store_failed",
            Self::Transport | Self::Client => "opencode_token_refresh_failed",
        }
    }
}

impl std::fmt::Display for OpencodeTokenError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Missing => {
                "the OpenCode account has no usable stored credential; log the account in again"
            }
            Self::Expired => {
                "the OpenCode console no longer accepts this account's grant; log the account in again"
            }
            Self::Store => "the OpenCode account's stored credential could not be read",
            Self::Transport => "the OpenCode console could not be reached for a token refresh",
            Self::Client => "the OpenCode console issued no token for this account",
        })
    }
}

impl std::error::Error for OpencodeTokenError {}

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

/// The process's OpenCode account bearer cache: one lazily refreshed bundle per
/// `opencode_oauth` key, shared by dispatch, model probing and quota probing.
pub struct OpencodeTokens {
    client: Arc<Client>,
    /// Resolved bundles. A hit costs one lookup and one `Arc` clone.
    bundles: DashMap<i64, Arc<OpencodeOAuth>>,
    /// Keys whose grant the console refused (revoked, or SSO demanded). The row
    /// stays dispatchable until an operator acts, so without this set every
    /// request to it would cost a console refresh and a warning for a verdict
    /// only a new login can change. `()` — the verdict is the membership.
    dead: DashMap<i64, ()>,
    /// One gate per key: the single-flight boundary of a refresh. The map owns
    /// `Arc`s so a waiter that queued behind a completed refresh still holds a
    /// valid gate while the map entry is reused.
    gates: DashMap<i64, Arc<Mutex<()>>>,
}

impl OpencodeTokens {
    /// Build the manager over the console client. The client is stateless, so a
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
    /// a single-flight refresh. A key whose grant the console already refused
    /// answers from the verdict cache — no lock, no I/O, no log.
    pub async fn resolve(
        &self,
        pool: &PgPool,
        key_id: i64,
    ) -> Result<Arc<OpencodeOAuth>, OpencodeTokenError> {
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
    ) -> Result<Arc<OpencodeOAuth>, OpencodeTokenError> {
        if let Some(verdict) = self.dead_verdict(key_id) {
            return Err(verdict);
        }
        self.resolve_locked(pool, key_id, Freshness::Force { rejected })
            .await
    }

    /// Install a bundle the caller just wrote to the store (login, import,
    /// credential replace), so the first dispatch after it needs no row read.
    /// Also clears a remembered refusal: the new bundle is a new grant.
    pub fn adopt(&self, key_id: i64, bundle: OpencodeOAuth) -> Arc<OpencodeOAuth> {
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

    /// The remembered verdict for `key_id`, if the console already refused it.
    /// Consulted before the fast path and before every store or console call.
    fn dead_verdict(&self, key_id: i64) -> Option<OpencodeTokenError> {
        self.dead
            .contains_key(&key_id)
            .then_some(OpencodeTokenError::Expired)
    }

    /// Remember that the console refused this key's grant, and drop the bundle
    /// that cannot work. Returns whether the verdict is new, so the caller logs
    /// its cause exactly once instead of once per dispatched request.
    fn mark_dead(&self, key_id: i64) -> bool {
        self.bundles.remove(&key_id);
        self.dead.insert(key_id, ()).is_none()
    }

    /// The cached bundle for `key_id` while it is still fresh. A clone of the
    /// `Arc`, never of the tokens.
    fn fresh_cached(&self, key_id: i64) -> Option<Arc<OpencodeOAuth>> {
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
    ) -> Result<Arc<OpencodeOAuth>, OpencodeTokenError> {
        let gate = self.gate(key_id);
        let _guard = gate.lock().await;
        // The verdict can land while this caller waits on the gate (a concurrent
        // 401 of the same key): rechecking under the gate is what keeps the
        // console to one refresh per refusal instead of one per waiter.
        if let Some(verdict) = self.dead_verdict(key_id) {
            return Err(verdict);
        }
        let stored = match store::opencode_oauth(pool, key_id).await {
            Ok(Some(bundle)) => bundle,
            Ok(None) => {
                self.bundles.remove(&key_id);
                return Err(OpencodeTokenError::Missing);
            }
            Err(error) => {
                // Fail closed: without the row the credential cannot be proven.
                // A store failure is not an account verdict, though — the next
                // attempt retries instead of asking for a new login.
                tracing::warn!(
                    key_id,
                    error = %format!("{error:#}"),
                    "OpenCode bundle read failed; the candidate has no credential"
                );
                return Err(OpencodeTokenError::Store);
            }
        };
        let adoptable = adoptable(mode, &stored, Utc::now());
        if adoptable {
            return Ok(self.adopt(key_id, stored));
        }
        let grant = self
            .client
            .refresh(&stored.server, &stored.refresh_token)
            .await;
        let ready = match grant {
            Ok(TokenGrant::Ready(ready)) => ready,
            Ok(TokenGrant::Expired) => {
                return self.refuse_refresh(pool, key_id, &stored, None).await;
            }
            // A refresh grant never waits for a user: the console issued no
            // token this round, so this attempt cannot authenticate.
            Ok(TokenGrant::Pending | TokenGrant::SlowDown) => {
                tracing::warn!(
                    key_id,
                    "OpenCode console issued no token for the refresh grant; candidate skipped"
                );
                return Err(OpencodeTokenError::Client);
            }
            Err(error) => {
                let verdict = map_auth_error(&error);
                if verdict == OpencodeTokenError::Expired {
                    // Revoked grant or an SSO demand: the console refuses this
                    // token, not this request.
                    return self
                        .refuse_refresh(pool, key_id, &stored, Some(&error))
                        .await;
                }
                tracing::warn!(key_id, error = %error, "OpenCode token refresh failed");
                return Err(verdict);
            }
        };
        let expires_at = ready.expires_at(Utc::now());
        let next = OpencodeOAuth {
            access_token: ready.access_token,
            refresh_token: ready.refresh_token,
            expires_at,
            server: stored.server.clone(),
            org_id: ready.org_id.or_else(|| stored.org_id.clone()),
            org_name: stored.org_name.clone(),
            email: stored.email.clone(),
        };
        match store::replace_opencode_oauth(pool, key_id, &stored, &next).await {
            Ok(true) => {}
            Ok(false) => {
                // A concurrent writer won the swap and already consumed the
                // refresh token this attempt rotated away: adopt its bundle
                // instead of overwriting the only one that still works.
                match store::opencode_oauth(pool, key_id).await {
                    Ok(Some(winner)) => return Ok(self.adopt(key_id, winner)),
                    Ok(None) => {
                        self.bundles.remove(&key_id);
                        return Err(OpencodeTokenError::Missing);
                    }
                    Err(error) => {
                        tracing::warn!(
                            key_id,
                            error = %format!("{error:#}"),
                            "OpenCode bundle reread after a lost compare-and-swap failed"
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
                    "OpenCode bundle write-back failed; serving the in-memory bundle"
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
        presented: &OpencodeOAuth,
        cause: Option<&AuthError>,
    ) -> Result<Arc<OpencodeOAuth>, OpencodeTokenError> {
        match store::opencode_oauth(pool, key_id).await {
            Ok(Some(stored))
                if stored.refresh_token != presented.refresh_token
                    || stored.access_token != presented.access_token =>
            {
                tracing::warn!(
                    key_id,
                    "OpenCode refused a bundle the row has already replaced; adopting the newer grant"
                );
                return Ok(self.adopt(key_id, stored));
            }
            Ok(Some(_)) | Ok(None) => {}
            Err(error) => tracing::warn!(
                key_id,
                error = %format!("{error:#}"),
                "OpenCode bundle reread after a refused refresh failed; applying the refusal to this key"
            ),
        }
        if self.mark_dead(key_id) {
            match cause {
                Some(error) => tracing::warn!(
                    key_id,
                    error = %error,
                    "OpenCode grant was refused; the account needs a new login"
                ),
                None => tracing::warn!(
                    key_id,
                    "OpenCode refresh token was rejected; the account needs a new login"
                ),
            }
        }
        Err(OpencodeTokenError::Expired)
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
fn adoptable(mode: Freshness<'_>, stored: &OpencodeOAuth, now: chrono::DateTime<Utc>) -> bool {
    match mode {
        Freshness::Check => stored.fresh_for(now, skew()),
        Freshness::Force { rejected } => stored.access_token != rejected,
    }
}

/// The shared refresh margin as a duration.
fn skew() -> Duration {
    Duration::seconds(REFRESH_SKEW_SECS)
}

/// Reduce one console failure to the relay-facing verdict.
fn map_auth_error(error: &AuthError) -> OpencodeTokenError {
    match error {
        AuthError::Transport { .. } => OpencodeTokenError::Transport,
        AuthError::SsoRequired { .. } | AuthError::Unauthorized { .. } => {
            OpencodeTokenError::Expired
        }
        AuthError::Server { .. }
        | AuthError::Status { .. }
        | AuthError::Decode { .. }
        | AuthError::VerificationUrl { .. } => OpencodeTokenError::Client,
    }
}
