//! Lazy, single-flight bearer resolution for Cursor provider keys.
//!
//! Cursor accepts exactly one credential on the wire: `Authorization: Bearer
//! <access token>`. Two stored shapes produce it — an `auth_kind =
//! "cursor_oauth"` bundle (a token pair from the browser login, refreshed with
//! `POST /oauth/token`) and a `static` row holding a Cursor user API key
//! (exchanged for an access token at `POST /auth/exchange_user_api_key`). Both
//! converge here so the dispatch path never learns which one a key carries.
//!
//! The vendor publishes no token lifetime. The access token is a JWT and its
//! `exp` claim is the only expiry that exists, so every resolved bearer carries
//! the instant decoded from it and is refreshed [`REFRESH_SKEW_SECS`] before
//! that instant. The signature is never verified: this process only decodes its
//! own token to decide *when to refresh*, and trusts the upstream — not the
//! claim — for whether a token is accepted.
//!
//! Nothing here refreshes on a timer. A dispatch resolves at attempt time:
//!
//! * the fast path is one map lookup and one `Arc` clone — no lock, no I/O, no
//!   token copy — while the cached bearer keeps more than the skew;
//! * otherwise the key's gate serialises the refresh: waiters recheck the cache
//!   under the gate, so N concurrent attempts on one account cost one upstream
//!   call;
//! * an OAuth refresh writes the new bundle back through a compare-and-swap on
//!   the exact stored JSON. The vendor does **not** rotate the refresh token, so
//!   the old one is kept verbatim and a lost swap can never lock the account
//!   out: the winner's bundle is adopted instead;
//! * a `static` row's derived token is cached in memory only — the API key is
//!   the credential the row owns, and nothing derived from it is persisted.
//!
//! A credential the backend refuses (`shouldLogout`, or a 401/403 on either
//! endpoint) is a verdict, not a per-request failure: it is remembered for
//! [`DEAD_TTL_SECS`] so the account stops costing one round trip and one warning
//! per dispatched request. The memory is a TTL rather than permanent because the
//! fix — a new login, or a corrected API key — happens in another writer, and a
//! re-login must not stay masked by a verdict this process took earlier.
//!
//! Permanent (`Expired`, `Missing`) and transient failures are distinguished for
//! the relay: a revoked account is a credential verdict, while a network error,
//! 429 or 5xx is worth failing over and retrying later. No token, API key or JWT
//! payload ever reaches a log line or an error message — the error type carries
//! categories only.
//!
//! The two row operations this manager performs (the compare-and-swap write-back
//! and the post-swap reread) live here rather than in `store::key`: they exist
//! for this refresh path alone, and keeping the guard and its only caller
//! together is what makes the "exact stored bundle" invariant checkable.

use std::sync::Arc;
use std::time::Duration as StdDuration;
use std::time::Instant;

use chrono::DateTime;
use chrono::Duration;
use chrono::Utc;
use dashmap::DashMap;
use sqlx::PgPool;
use tokio::sync::Mutex;

use crate::credentials::CursorOAuth;
use crate::credentials::KeyCredential;
use crate::protocol::Prepared;
use crate::protocol::ProtocolId;
use crate::upstream::transport::MAX_ERROR_BODY;
use crate::upstream::transport::Transport;
use crate::upstream::transport::TransportError;

/// The Cursor backend every credential call dials. Fixed: the site the vendors'
/// own clients use, never derived from provider input.
const BACKEND_URL: &str = crate::protocol::cursor::API_ORIGIN;

/// Refresh grant endpoint (`grant_type=refresh_token`).
const REFRESH_PATH: &str = "/oauth/token";

/// API-key exchange endpoint (`Authorization: Bearer <user API key>`).
const EXCHANGE_PATH: &str = "/auth/exchange_user_api_key";

/// The OAuth client id the vendor's own clients name in a refresh grant. The
/// refresh endpoint requires it and does not use it to identify us.
const CLIENT_ID: &str = "KbZUR41cY7W6zRSdpSUJ7I7mLYBKOCmB";

/// How much validity a bearer must keep to count as fresh. A bearer inside the
/// margin is refreshed first, so a dispatched request never races the expiry.
pub const REFRESH_SKEW_SECS: i64 = 300;

/// How long a refusal stays remembered. Long enough to keep a revoked account
/// off the hot path, short enough that a login or a corrected API key taking
/// effect elsewhere is picked up without an operator touching this process.
const DEAD_TTL: StdDuration = StdDuration::from_secs(300);

/// Whole-call budget for one credential request. Both answers are a few hundred
/// bytes and prompt; holding a key's gate for longer would block every request
/// that key serves.
const TOKEN_TIMEOUT: StdDuration = StdDuration::from_secs(20);

/// Hard cap on a token answer body. Both endpoints answer a small JSON document;
/// this leaves room for unknown fields without buffering an unbounded body.
const MAX_TOKEN_BODY: usize = MAX_ERROR_BODY;

/// The tag on the credential-plane requests below.
///
/// `Transport` reads `Prepared.protocol` only when it frames a response stream
/// (`Transport::stream`); the unary send used here never looks at it, and a
/// token endpoint has no chat protocol at all. A fixed placeholder is therefore
/// inert, and it buys the single shared client — destination policy and
/// connection pool included — instead of forking a second HTTP client for two
/// small POSTs.
const TOKEN_PROTOCOL: ProtocolId = ProtocolId::OpenAiChat;

/// Why one candidate's Cursor bearer could not be produced.
///
/// Every variant names a credential-plane verdict and carries no token, no API
/// key and no JWT payload: the value travels to the relay's attempt log and, when
/// every candidate fails, into the client's error body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CursorTokenError {
    /// No usable credential: the row is gone, is not a Cursor row, holds a
    /// bundle that no longer decodes, or the caller carried a credential of
    /// another kind.
    Missing,
    /// The backend refused the credential (`shouldLogout`, 401/403). Only a new
    /// login or a corrected API key recovers the account.
    Expired,
    /// The store could not read or write the row. A storage failure, not an
    /// account verdict: a retry later can succeed.
    Store,
    /// The backend could not be reached (connect, TLS, timeout).
    Transport,
    /// The backend answered 429 or 5xx: a transient credential-plane failure.
    Unavailable,
    /// The backend answered, but not with a usable token.
    Client,
}

impl CursorTokenError {
    /// Whether waiting and retrying can never help: the credential itself is the
    /// problem, so the relay fails over without blaming the request.
    #[must_use]
    pub fn is_permanent(&self) -> bool {
        matches!(self, Self::Missing | Self::Expired)
    }

    /// The HTTP status the downstream client sees when every candidate failed.
    #[must_use]
    pub fn client_status(&self) -> u16 {
        match self {
            Self::Expired => 401,
            Self::Missing => 500,
            Self::Store | Self::Transport | Self::Unavailable | Self::Client => 502,
        }
    }

    /// Stable machine code for the client error body and the request row.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Missing => "cursor_credentials_missing",
            Self::Expired => "cursor_credentials_expired",
            Self::Store => "cursor_credential_store_failed",
            Self::Transport => "cursor_backend_unreachable",
            Self::Unavailable | Self::Client => "cursor_token_refresh_failed",
        }
    }
}

impl std::fmt::Display for CursorTokenError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Missing => {
                "the Cursor account has no usable stored credential; log the account in again"
            }
            Self::Expired => {
                "the Cursor backend no longer accepts this account's credential; log the account in again"
            }
            Self::Store => "the Cursor account's stored credential could not be read",
            Self::Transport => "the Cursor backend could not be reached for a token request",
            Self::Unavailable => "the Cursor backend is temporarily unavailable for a token request",
            Self::Client => "the Cursor backend issued no usable token for this account",
        })
    }
}

impl std::error::Error for CursorTokenError {}

/// One resolved bearer plus the header decoration that must travel with it.
///
/// The access token is a secret, so Debug redacts it; `Debug` here only exists
/// for diagnostics that need the coordinates.
pub struct CursorBearer {
    access_token: String,
    expires_at: DateTime<Utc>,
    team_id: Option<String>,
}

impl CursorBearer {
    /// The value for `Authorization: Bearer …` (secret).
    #[must_use]
    pub fn access_token(&self) -> &str {
        &self.access_token
    }

    /// The team the login selected, if any: the dispatch path sends it as
    /// `x-cursor-team-id`.
    #[must_use]
    pub fn team_id(&self) -> Option<&str> {
        self.team_id.as_deref()
    }
}

impl std::fmt::Debug for CursorBearer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CursorBearer")
            .field("access_token", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .field("team_id", &self.team_id)
            .finish()
    }
}

/// Whether a caller may trust the credential it arrived with.
#[derive(Clone, Copy)]
enum Freshness<'a> {
    /// Ordinary dispatch: a bearer that is fresh by the clock is used as is.
    Check,
    /// After the backend rejected `rejected`: a bearer that still carries that
    /// value cannot be trusted even when the clock says otherwise.
    Force { rejected: &'a str },
}

/// The process's Cursor bearer cache: one lazily refreshed bearer per Cursor
/// key, shared by dispatch and model probing.
pub struct CursorTokens {
    transport: Transport,
    /// Backend origin. A constant in production; the test stub's origin when a
    /// test drives the manager against a local server.
    backend: String,
    /// Resolved bearers. A hit costs one lookup and one `Arc` clone.
    bearers: DashMap<i64, Arc<CursorBearer>>,
    /// Keys whose credential the backend refused, with the instant of the
    /// verdict. Membership is advisory for [`DEAD_TTL`].
    dead: DashMap<i64, Instant>,
    /// One gate per key: the single-flight boundary of a refresh. The map owns
    /// `Arc`s so a waiter that queued behind a completed refresh still holds a
    /// valid gate while the entry is reused.
    gates: DashMap<i64, Arc<Mutex<()>>>,
}

impl CursorTokens {
    /// Build the manager over the shared transport. The transport is stateless,
    /// so a second manager would only split the bearer cache in two — callers
    /// share one manager instead.
    #[must_use]
    pub fn new(transport: Transport) -> Self {
        Self {
            transport,
            backend: BACKEND_URL.to_owned(),
            bearers: DashMap::new(),
            dead: DashMap::new(),
            gates: DashMap::new(),
        }
    }

    /// The bearer to authenticate with right now.
    ///
    /// A refused key answers from the verdict cache (no lock, no I/O, no log); a
    /// fresh bearer answers from the cache (no lock, no I/O); anything else
    /// refreshes under the key's single-flight gate. `credential` is the shape
    /// the caller already holds: this manager never reads the row for a fresh
    /// OAuth bundle and never reads it at all for a `static` key.
    pub async fn resolve(
        &self,
        pool: &PgPool,
        key_id: i64,
        credential: &KeyCredential<'_>,
        dns: crate::upstream::Dns,
    ) -> Result<Arc<CursorBearer>, CursorTokenError> {
        if let Some(verdict) = self.dead_verdict(key_id) {
            return Err(verdict);
        }
        if let Some(bearer) = self.adoptable(key_id, Freshness::Check) {
            return Ok(bearer);
        }
        self.resolve_locked(pool, key_id, credential, Freshness::Check, dns)
            .await
    }

    /// Resolve past the freshness check: the backend just rejected `rejected`,
    /// the bearer this attempt presented, so a cached bearer that still carries
    /// it is replaced even if its clock claim says otherwise. Still
    /// single-flight, so concurrent 401s of one key share one refresh.
    pub async fn resolve_forced(
        &self,
        pool: &PgPool,
        key_id: i64,
        credential: &KeyCredential<'_>,
        rejected: &str,
        dns: crate::upstream::Dns,
    ) -> Result<Arc<CursorBearer>, CursorTokenError> {
        if let Some(verdict) = self.dead_verdict(key_id) {
            return Err(verdict);
        }
        self.resolve_locked(pool, key_id, credential, Freshness::Force { rejected }, dns)
            .await
    }

    /// Install a bundle the caller just wrote to the store (login, imported
    /// bundle), so the first dispatch after it needs no refresh. The bundle's own
    /// `expires_at` is trusted here: whoever wrote it decoded the JWT already.
    /// Clears a remembered refusal, because a new bundle is a new grant.
    pub fn adopt(&self, key_id: i64, bundle: &CursorOAuth) -> Arc<CursorBearer> {
        self.install(
            key_id,
            bundle.access_token.clone(),
            bundle.expires_at,
            bundle.team_id.clone(),
        )
    }

    /// Drop one key's cached bearer and any remembered refusal. The next resolve
    /// refreshes from the credential the caller carries; a delete or a
    /// credential replace wants exactly that.
    pub fn forget(&self, key_id: i64) {
        self.bearers.remove(&key_id);
        self.dead.remove(&key_id);
    }

    /// The transport the manager dials with, for the probes that reuse its
    /// destination policy and connection pool.
    #[must_use]
    pub fn transport(&self) -> &Transport {
        &self.transport
    }

    /// Exchange a not-yet-saved API key for a bearer, caching nothing: the
    /// save-time validation of a `static` Cursor key, which has no row and so
    /// no cache slot yet. The same exchange the dispatch path performs.
    pub async fn probe_static(
        &self,
        api_key: &str,
        dns: crate::upstream::Dns,
    ) -> Result<CursorBearer, CursorTokenError> {
        let (status, answer) = self
            .post(EXCHANGE_PATH, b"{}".to_vec(), Some(api_key), dns)
            .await?;
        let access_token = classify_exchange(status, &answer)?;
        let expires_at = jwt_expiry(&access_token).ok_or(CursorTokenError::Client)?;
        Ok(CursorBearer {
            access_token,
            expires_at,
            team_id: None,
        })
    }

    /// The remembered verdict for `key_id`, if the backend already refused it and
    /// the verdict has not aged out.
    fn dead_verdict(&self, key_id: i64) -> Option<CursorTokenError> {
        let at = self.dead.get(&key_id)?;
        (at.elapsed() < DEAD_TTL).then_some(CursorTokenError::Expired)
    }

    /// The bearer the cache already holds, when this call may trust it: fresh by
    /// the clock for an ordinary dispatch, or moved past the rejected value for a
    /// forced one. A clone of the `Arc`, never of the token.
    fn adoptable(&self, key_id: i64, mode: Freshness<'_>) -> Option<Arc<CursorBearer>> {
        let bearer = self.bearers.get(&key_id)?;
        let usable = match mode {
            Freshness::Check => bearer.fresh_for(Utc::now(), skew()),
            Freshness::Force { rejected } => bearer.access_token != rejected,
        };
        usable.then(|| Arc::clone(bearer.value()))
    }

    /// The gate for `key_id`, created on first use.
    fn gate(&self, key_id: i64) -> Arc<Mutex<()>> {
        if let Some(gate) = self.gates.get(&key_id) {
            return Arc::clone(gate.value());
        }
        let gate = Arc::new(Mutex::new(()));
        Arc::clone(self.gates.entry(key_id).or_insert(gate).value())
    }

    /// Cache one bearer, clearing any remembered refusal: a bearer in hand means
    /// the credential works.
    fn install(
        &self,
        key_id: i64,
        access_token: String,
        expires_at: DateTime<Utc>,
        team_id: Option<String>,
    ) -> Arc<CursorBearer> {
        let bearer = Arc::new(CursorBearer {
            access_token,
            expires_at,
            team_id,
        });
        self.dead.remove(&key_id);
        self.bearers.insert(key_id, Arc::clone(&bearer));
        bearer
    }

    /// Remember that the backend refused this key's credential and drop the
    /// bearer that cannot work. Returns whether the verdict is new, so the caller
    /// logs its cause once instead of once per dispatched request.
    fn mark_dead(&self, key_id: i64) -> bool {
        self.bearers.remove(&key_id);
        self.dead.insert(key_id, Instant::now()).is_none()
    }

    /// The refresh path proper, called with the key's gate held.
    async fn resolve_locked(
        &self,
        pool: &PgPool,
        key_id: i64,
        credential: &KeyCredential<'_>,
        mode: Freshness<'_>,
        dns: crate::upstream::Dns,
    ) -> Result<Arc<CursorBearer>, CursorTokenError> {
        let gate = self.gate(key_id);
        let _guard = gate.lock().await;
        // Rechecking under the gate is what keeps a burst of attempts on one
        // account down to a single upstream call.
        if let Some(verdict) = self.dead_verdict(key_id) {
            return Err(verdict);
        }
        if let Some(bearer) = self.adoptable(key_id, mode) {
            return Ok(bearer);
        }
        // A stored bundle that is still fresh (and, after a 401, is not the
        // token that was just refused) is the bearer: the row's writer decoded
        // its JWT, so there is nothing to ask the backend for. Without this a
        // cache miss — every key's first dispatch after a process start —
        // would refresh a token with weeks left on it.
        if let KeyCredential::CursorOauth(bundle) = credential {
            let usable = match mode {
                Freshness::Check => true,
                Freshness::Force { rejected } => bundle.access_token != rejected,
            };
            if usable && bundle.expires_at - Utc::now() > skew() {
                return Ok(self.adopt(key_id, bundle));
            }
        }
        let outcome = match credential {
            KeyCredential::CursorOauth(bundle) => {
                self.refresh_oauth(pool, key_id, bundle, dns).await
            }
            KeyCredential::Static(api_key) => self.exchange_static(key_id, api_key, dns).await,
            // A Kiro, OpenCode or OpenAI bundle never authenticates a Cursor
            // row: the credential module refuses to store one, and a caller
            // that hands one over has the wrong key.
            KeyCredential::KiroOidc(_)
            | KeyCredential::OpencodeOauth(_)
            | KeyCredential::OpenaiOauth(_) => Err(CursorTokenError::Missing),
        };
        match outcome {
            Ok(bearer) => Ok(bearer),
            Err(error) => {
                if error == CursorTokenError::Expired && self.mark_dead(key_id) {
                    tracing::warn!(
                        key_id,
                        "Cursor refused this account's credential; log the account in again"
                    );
                }
                Err(error)
            }
        }
    }

    /// Refresh one OAuth bundle and write the new access token back.
    ///
    /// The refresh token is *not* rotated by the vendor: the answer carries no
    /// replacement, so the stored one is carried over verbatim. The write-back is
    /// guarded by the exact bundle this refresh started from; a lost swap means
    /// another writer (or another process) already produced a newer bundle, which
    /// is adopted instead of overwritten.
    async fn refresh_oauth(
        &self,
        pool: &PgPool,
        key_id: i64,
        stored: &CursorOAuth,
        dns: crate::upstream::Dns,
    ) -> Result<Arc<CursorBearer>, CursorTokenError> {
        let grant = serde_json::json!({
            "grant_type": "refresh_token",
            "client_id": CLIENT_ID,
            "refresh_token": stored.refresh_token,
        });
        let body = serde_json::to_vec(&grant).map_err(|_| CursorTokenError::Client)?;
        let (status, answer) = self.post(REFRESH_PATH, body, None, dns).await?;
        let access_token = match classify_refresh(status, &answer)? {
            GrantAnswer::Revoked => return Err(CursorTokenError::Expired),
            GrantAnswer::Token(access_token) => access_token,
        };
        let expires_at = match jwt_expiry(&access_token) {
            Some(expires_at) => expires_at,
            None => {
                // Without the claim there is no honest expiry to cache, and a
                // token refreshed on every request would be worse than a clear
                // failure. The token itself is never printed.
                tracing::warn!(
                    key_id,
                    "Cursor handed out an access token whose JWT exp could not be read; candidate skipped"
                );
                return Err(CursorTokenError::Client);
            }
        };
        let next = CursorOAuth {
            access_token,
            refresh_token: stored.refresh_token.clone(),
            expires_at,
            email: stored.email.clone(),
            team_id: stored.team_id.clone(),
        };
        match compare_and_swap(pool, key_id, stored, &next).await {
            Ok(true) => {}
            Ok(false) => {
                // A concurrent writer won the swap and its bundle is the one the
                // row now holds; adopting it keeps a single working credential
                // instead of overwriting it with this attempt's token.
                match stored_bundle(pool, key_id).await {
                    Ok(Some(winner)) if winner != *stored => {
                        tracing::warn!(
                            key_id,
                            "Cursor refresh lost the compare-and-swap; adopting the newer stored bundle"
                        );
                        return Ok(self.adopt(key_id, &winner));
                    }
                    Ok(_) => {}
                    Err(error) => tracing::warn!(
                        key_id,
                        error = %format!("{error:#}"),
                        "Cursor bundle reread after a lost compare-and-swap failed; serving the refreshed bearer"
                    ),
                }
            }
            Err(error) => {
                // The token in hand is valid even though its write-back failed; a
                // restart then refreshes again, which Cursor's non-rotating
                // refresh token makes harmless.
                tracing::warn!(
                    key_id,
                    error = %format!("{error:#}"),
                    "Cursor bundle write-back failed; serving the in-memory bearer"
                );
            }
        }
        Ok(self.adopt(key_id, &next))
    }

    /// Exchange one `static` row's Cursor API key for an access token.
    ///
    /// The token is cached in memory until its JWT `exp` minus the skew and is
    /// deliberately **not** persisted: the row's credential is the API key, and a
    /// derived token in the row would be a second authority to keep in sync.
    async fn exchange_static(
        &self,
        key_id: i64,
        api_key: &str,
        dns: crate::upstream::Dns,
    ) -> Result<Arc<CursorBearer>, CursorTokenError> {
        let (status, answer) = self
            .post(EXCHANGE_PATH, b"{}".to_vec(), Some(api_key), dns)
            .await?;
        let access_token = classify_exchange(status, &answer)?;
        let expires_at = match jwt_expiry(&access_token) {
            Some(expires_at) => expires_at,
            None => {
                tracing::warn!(
                    key_id,
                    "Cursor API-key exchange returned a token whose JWT exp could not be read; candidate skipped"
                );
                return Err(CursorTokenError::Client);
            }
        };
        // A `static` key names no team: the exchange answer carries none.
        Ok(self.install(key_id, access_token, expires_at, None))
    }

    /// POST one credential-plane document and read the answer whole.
    ///
    /// `bearer` is the API key the exchange endpoint authenticates with; the
    /// refresh endpoint takes no `Authorization` at all and must not be sent one.
    async fn post(
        &self,
        path: &str,
        body: Vec<u8>,
        bearer: Option<&str>,
        dns: crate::upstream::Dns,
    ) -> Result<(u16, Vec<u8>), CursorTokenError> {
        let prepared = Prepared {
            protocol: TOKEN_PROTOCOL,
            url: format!("{}{path}", self.backend),
            content_type: "application/json",
            body: body.into(),
            stream: false,
            headers: Vec::new(),
            cursor: None,
        };
        let deadline = Instant::now() + TOKEN_TIMEOUT;
        let response = match bearer {
            Some(api_key) => {
                let headers = [("authorization", format!("Bearer {api_key}"))];
                self.transport
                    .send_with_headers(&prepared, dns, &headers, &[], deadline)
                    .await
            }
            None => self.transport.send(&prepared, dns, deadline).await,
        }
        .map_err(map_transport_error)?;
        let status = response.status().as_u16();
        let answer = self
            .transport
            .read_body(response, MAX_TOKEN_BODY, deadline)
            .await
            .map_err(map_transport_error)?;
        Ok((status, answer))
    }
}

impl CursorBearer {
    /// Whether this bearer keeps more than `skew` of validity at `now`.
    fn fresh_for(&self, now: DateTime<Utc>, skew: Duration) -> bool {
        self.expires_at - now > skew
    }
}

/// One credential endpoint's answer, reduced to what the manager acts on.
enum GrantAnswer {
    /// The backend issued an access token.
    Token(String),
    /// The backend refused the credential: only a new login (or a corrected API
    /// key) recovers the account.
    Revoked,
}

/// Read a `/oauth/token` answer.
///
/// The verdict comes from `shouldLogout` and the status, never from the presence
/// of an `access_token` alone: the vendor answers a revoked grant with
/// `shouldLogout: true` (and, in evidence, a 2xx body). A 401/403 is the same
/// verdict by status; a 400 is the endpoint rejecting the grant it was handed; a
/// 429 or 5xx is transient and worth a retry later.
fn classify_refresh(status: u16, body: &[u8]) -> Result<GrantAnswer, CursorTokenError> {
    let parsed: serde_json::Value = serde_json::from_slice(body).unwrap_or_default();
    if parsed
        .get("shouldLogout")
        .and_then(serde_json::Value::as_bool)
        == Some(true)
    {
        return Ok(GrantAnswer::Revoked);
    }
    match status {
        200..=299 => {
            let token = parsed
                .get("access_token")
                .and_then(serde_json::Value::as_str)
                .filter(|token| !token.trim().is_empty());
            match token {
                Some(token) => Ok(GrantAnswer::Token(token.to_owned())),
                None => Err(CursorTokenError::Client),
            }
        }
        400 | 401 | 403 => Ok(GrantAnswer::Revoked),
        429 | 500..=599 => Err(CursorTokenError::Unavailable),
        _ => Err(CursorTokenError::Client),
    }
}

/// Read an `/auth/exchange_user_api_key` answer: an access token, or a status
/// that says the key itself is refused.
fn classify_exchange(status: u16, body: &[u8]) -> Result<String, CursorTokenError> {
    match status {
        200..=299 => {
            let parsed: serde_json::Value =
                serde_json::from_slice(body).map_err(|_| CursorTokenError::Client)?;
            parsed
                .get("accessToken")
                .and_then(serde_json::Value::as_str)
                .filter(|token| !token.trim().is_empty())
                .map(str::to_owned)
                .ok_or(CursorTokenError::Client)
        }
        // The endpoint answers an invalid or device-restricted API key with
        // 401/403, and a 403 `sign_in_policy_violation` is an MDM policy refusal:
        // none of them is fixed by retrying.
        401 | 403 => Err(CursorTokenError::Expired),
        429 | 500..=599 => Err(CursorTokenError::Unavailable),
        _ => Err(CursorTokenError::Client),
    }
}

/// The `exp` claim of a JWT, as an absolute instant.
///
/// The signature is deliberately not verified: this process decodes only its own
/// token, and only to decide when to refresh it. Whether a token is *accepted* is
/// the backend's judgement, never this claim's, so an unverified `exp` cannot
/// widen any authorization. Any malformed segment is `None`, and callers fail
/// closed rather than caching a token with no known expiry.
pub(crate) fn jwt_expiry(token: &str) -> Option<DateTime<Utc>> {
    let payload = token.split('.').nth(1)?;
    let decoded = base64url_decode(payload)?;
    let claims: serde_json::Value = serde_json::from_slice(&decoded).ok()?;
    let seconds = claims.get("exp")?.as_i64()?;
    DateTime::from_timestamp(seconds, 0)
}

/// Decode one base64url segment (RFC 4648 §5: `-`/`_`, padding optional).
///
/// Hand-written because the crate has no base64 dependency and one JWT segment is
/// the only decode this binary needs. Non-alphabet bytes, a dangling 6-bit tail
/// and an impossible length are all errors — a silently truncated payload would
/// decode into nonsense claims.
fn base64url_decode(input: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len() / 4 * 3);
    let mut accumulator: u32 = 0;
    let mut bits: u32 = 0;
    for byte in input.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' | b'+' => 62,
            b'_' | b'/' => 63,
            b'=' => break,
            _ => return None,
        };
        accumulator = (accumulator << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((accumulator >> bits) as u8);
            accumulator &= (1u32 << bits) - 1;
        }
    }
    if accumulator != 0 {
        return None;
    }
    Some(out)
}

/// One key's stored bundle, read fresh from the row (see
/// [`crate::store::cursor_oauth`]).
async fn stored_bundle(pool: &PgPool, key_id: i64) -> anyhow::Result<Option<CursorOAuth>> {
    crate::store::cursor_oauth(pool, key_id).await
}

/// Replace one account's bundle when the stored one is still `expected`
/// (compare-and-swap; see [`crate::store::replace_cursor_oauth`]). `false`
/// means a concurrent writer won, so the caller serves from memory and adopts
/// the newer row instead of overwriting it.
async fn compare_and_swap(
    pool: &PgPool,
    key_id: i64,
    expected: &CursorOAuth,
    next: &CursorOAuth,
) -> anyhow::Result<bool> {
    crate::store::replace_cursor_oauth(pool, key_id, expected, next).await
}

/// Reduce one transport failure to the relay-facing verdict. The transport's own
/// message never travels: it could quote the request URL.
fn map_transport_error(error: TransportError) -> CursorTokenError {
    match error {
        TransportError::Connect | TransportError::Timeout | TransportError::ClientGone => {
            CursorTokenError::Transport
        }
        TransportError::InvalidBody
        | TransportError::BodyTooLarge
        | TransportError::Status { .. } => CursorTokenError::Client,
    }
}

/// The shared refresh margin as a duration.
fn skew() -> Duration {
    Duration::seconds(REFRESH_SKEW_SECS)
}
