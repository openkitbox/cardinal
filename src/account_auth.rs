//! Portal authentication. The store owns atomic challenge consumption and issuance.

use std::{sync::Arc, time::Duration};

use argon2::Argon2;
use argon2::password_hash::phc::PasswordHash;
use argon2::password_hash::{Error as PasswordError, PasswordHasher as _, PasswordVerifier as _};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jiff::{SignedDuration, Timestamp};
use salvo::http::{Body as _, ParseError, StatusCode, header};
use salvo::prelude::{Depot, FlowCtrl, Json, Request, Response, Router, handler};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest as _, Sha256};
use sqlx::PgPool;
use tokio::sync::Semaphore;

use crate::account_mail::{MailKind, Mailer};
use crate::auth_limits::{AuthLimits, Operation};
use crate::config::PortalConfig;
use crate::store::{self, PortalSession};

const MAX_BODY: usize = 8192;
const MAX_PASSWORD: usize = 1024;
const MIN_PASSWORD: usize = 12;
const SESSION_PREFIX: &str = "ps_";
const TOKEN_BYTES: usize = 32;
const TOKEN_CHARS: usize = 43;
const SESSION_LIFETIME: SignedDuration = SignedDuration::from_hours(24 * 7);
const CHALLENGE_LIFETIME: SignedDuration = SignedDuration::from_mins(30);
// Unknown or disabled accounts take the same Argon2id path, but cannot sign in.
const DUMMY_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$MjAxOTAxMDEwMDAwMDAwMA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

#[derive(Clone)]
pub(crate) struct AuthState(Arc<State>);

struct State {
    pool: PgPool,
    admin_digest: String,
    customer_group: Option<String>,
    mailer: Option<Mailer>,
    limits: AuthLimits,
    password_slots: Arc<Semaphore>,
}

impl AuthState {
    pub(crate) async fn new(pool: PgPool, config: PortalConfig, admin_key: &str) -> Self {
        Self(Arc::new(State {
            pool,
            admin_digest: crate::db::sha256_hex(admin_key),
            customer_group: config
                .default_customer_group
                .filter(|group| !group.trim().is_empty()),
            mailer: match config.mail.as_ref() {
                Some(mail) => Mailer::new(mail).await,
                None => None,
            },
            limits: AuthLimits::default(),
            password_slots: Arc::new(Semaphore::new(4)),
        }))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmailBody {
    email: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CompleteBody {
    token: String,
    password: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginBody {
    email: String,
    password: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyLoginBody {
    key: String,
}
#[derive(Serialize)]
struct SessionResponse {
    token: String,
    expires_at: Timestamp,
}

#[derive(Clone, Copy, Debug)]
enum AuthError {
    InvalidInput,
    InvalidToken,
    Unauthorized,
    TooLarge,
    RequiresJson,
    Timeout,
    RateLimit,
    Unavailable,
}

type AuthResult<T> = Result<T, AuthError>;

impl AuthError {
    fn render(self, response: &mut Response) {
        let (status, code) = match self {
            Self::InvalidInput => (StatusCode::BAD_REQUEST, "invalid_input"),
            Self::InvalidToken => (StatusCode::BAD_REQUEST, "invalid_token"),
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "invalid_credentials"),
            Self::TooLarge => (StatusCode::PAYLOAD_TOO_LARGE, "body_too_large"),
            Self::RequiresJson => (StatusCode::UNSUPPORTED_MEDIA_TYPE, "json_required"),
            Self::Timeout => (StatusCode::REQUEST_TIMEOUT, "body_timeout"),
            Self::RateLimit => (StatusCode::TOO_MANY_REQUESTS, "rate_limited"),
            Self::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, "auth_unavailable"),
        };
        response.status_code(status);
        response.render(Json(serde_json::json!({"error": code})));
    }
}

impl From<sqlx::Error> for AuthError {
    fn from(error: sqlx::Error) -> Self {
        let code = error
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code);
        tracing::warn!(
            sqlstate = code.as_deref(),
            "portal database operation failed"
        );
        Self::Unavailable
    }
}

#[handler]
async fn guard(depot: &mut Depot, response: &mut Response, ctrl: &mut FlowCtrl) {
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    if let Err(error) = state(depot).and_then(|state| {
        state
            .limits
            .request()
            .then_some(())
            .ok_or(AuthError::RateLimit)
    }) {
        error.render(response);
        ctrl.skip_rest();
    }
}

fn state(depot: &Depot) -> AuthResult<&State> {
    depot
        .get_typed::<AuthState>()
        .map(|state| state.0.as_ref())
        .map_err(|_| AuthError::Unavailable)
}

async fn json_body<T: DeserializeOwned>(request: &mut Request) -> AuthResult<T> {
    if request
        .headers()
        .get_all(header::CONTENT_TYPE)
        .iter()
        .count()
        != 1
        || !request.content_type().is_some_and(|kind| {
            kind.type_() == "application" && kind.subtype() == "json" && kind.suffix().is_none()
        })
    {
        return Err(AuthError::RequiresJson);
    }
    let bytes = tokio::time::timeout(
        Duration::from_secs(5),
        request.payload_with_max_size(MAX_BODY),
    )
    .await
    .map_err(|_| AuthError::Timeout)?
    .map_err(|error| match error {
        ParseError::PayloadTooLarge => AuthError::TooLarge,
        _ => AuthError::InvalidInput,
    })?;
    if bytes
        .iter()
        .copied()
        .find(|byte| !byte.is_ascii_whitespace())
        != Some(b'{')
    {
        return Err(AuthError::InvalidInput);
    }
    serde_json::from_slice(bytes).map_err(|_| AuthError::InvalidInput)
}

fn normalized_email(raw: &str) -> AuthResult<String> {
    let email = store::normalize_email(raw);
    let (local, domain) = email.split_once('@').ok_or(AuthError::InvalidInput)?;
    let valid_local = local.len() <= 64
        && local.split('.').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"!#$%&'*+-/=?^_`{|}~".contains(&c))
        });
    let valid_domain = domain.contains('.')
        && domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-')
        });
    if email.len() <= 254 && valid_local && valid_domain {
        Ok(email)
    } else {
        Err(AuthError::InvalidInput)
    }
}

fn canonical_fragment(fragment: &str) -> bool {
    let mut bytes = [0; TOKEN_BYTES];
    fragment.len() == TOKEN_CHARS
        && matches!(
            URL_SAFE_NO_PAD.decode_slice(fragment, &mut bytes),
            Ok(TOKEN_BYTES)
        )
}

pub(crate) fn digest(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

fn random_fragment() -> AuthResult<String> {
    let mut bytes = [0; TOKEN_BYTES];
    getrandom::fill(&mut bytes).map_err(|_| {
        tracing::error!("portal OS random source failed");
        AuthError::Unavailable
    })?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

/// True for the reserved portal namespace, even when the token is malformed.
/// Do not fall back to API Key authentication for these values.
pub(crate) fn is_portal_session_token(token: &str) -> bool {
    token.starts_with(SESSION_PREFIX)
}

fn session_digest(token: &str) -> Option<[u8; 32]> {
    let fragment = token.strip_prefix(SESSION_PREFIX)?;
    canonical_fragment(fragment).then(|| digest(token))
}

/// Resolve a strictly canonical `ps_` bearer value. `Ok(None)` means malformed
/// or inactive (including revoked, expired and disabled); a DB failure is `Err`.
pub(crate) async fn lookup_portal_session(
    pool: &PgPool,
    token: &str,
) -> sqlx::Result<Option<PortalSession>> {
    let Some(digest) = session_digest(token) else {
        return Ok(None);
    };
    store::lookup_session(pool, &digest).await
}

impl State {
    fn limit(&self, op: Operation, identity: &str) -> AuthResult<()> {
        self.limits
            .identity(op, digest(identity))
            .then_some(())
            .ok_or(AuthError::RateLimit)
    }

    async fn customer_group(&self) -> AuthResult<Option<&str>> {
        let Some(group) = self.customer_group.as_deref() else {
            return Ok(None);
        };
        Ok(store::configured_group(&self.pool, group)
            .await?
            .map(|_| group))
    }

    async fn password_job<T: Send + 'static>(
        &self,
        job: impl FnOnce() -> Result<T, PasswordError> + Send + 'static,
    ) -> AuthResult<T> {
        // The permit lives in the blocking job even if the HTTP caller leaves.
        let permit = Arc::clone(&self.password_slots)
            .try_acquire_owned()
            .map_err(|_| AuthError::RateLimit)?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            job()
        })
        .await
        .ok()
        .and_then(Result::ok)
        .ok_or_else(|| {
            tracing::error!("portal password operation failed");
            AuthError::Unavailable
        })
    }
}

#[handler]
async fn register(request: &mut Request, depot: &mut Depot, response: &mut Response) {
    finish(
        response,
        initiate(request, depot, MailKind::Registration).await,
        StatusCode::ACCEPTED,
    );
}

#[handler]
async fn forgot(request: &mut Request, depot: &mut Depot, response: &mut Response) {
    finish(
        response,
        initiate(request, depot, MailKind::PasswordReset).await,
        StatusCode::ACCEPTED,
    );
}

async fn initiate(request: &mut Request, depot: &Depot, kind: MailKind) -> AuthResult<()> {
    let body: EmailBody = json_body(request).await?;
    let email = normalized_email(&body.email)?;
    let auth = depot
        .get_typed::<AuthState>()
        .map_err(|_| AuthError::Unavailable)?;
    let state = &auth.0;
    if state.mailer.is_none() {
        return Err(AuthError::Unavailable);
    }
    let operation = match kind {
        MailKind::Registration => Operation::Register,
        MailKind::PasswordReset => Operation::Forgot,
    };
    state.limit(operation, &email)?;
    if matches!(kind, MailKind::Registration) && state.customer_group().await?.is_none() {
        return Err(AuthError::Unavailable);
    }
    // Queue every accepted address alike, before checking eligibility. This
    // keeps both provider latency and the eventual result off the HTTP path.
    if !state.limits.mail() {
        return Err(AuthError::RateLimit);
    }
    let fragment = random_fragment()?;
    let auth = auth.clone();
    tokio::spawn(async move {
        deliver_challenge(&auth.0, kind, &email, &fragment).await;
    });
    Ok(())
}

async fn deliver_challenge(state: &State, kind: MailKind, email: &str, fragment: &str) {
    let Some(mailer) = &state.mailer else { return };
    let digest = digest(fragment);
    let expires = Timestamp::now() + CHALLENGE_LIFETIME;
    let issued = match kind {
        MailKind::Registration => {
            store::issue_registration_challenge(&state.pool, email, &digest, expires).await
        }
        MailKind::PasswordReset => {
            store::issue_password_reset_challenge(&state.pool, email, &digest, expires).await
        }
    };
    match issued {
        Ok(true) => mailer.send(kind, email, fragment).await,
        Ok(false) => {}
        Err(error) => {
            let _failure = AuthError::from(error);
        }
    }
}

#[handler]
async fn register_complete(request: &mut Request, depot: &mut Depot, response: &mut Response) {
    finish(
        response,
        complete(request, depot, MailKind::Registration).await,
        StatusCode::NO_CONTENT,
    );
}

#[handler]
async fn reset(request: &mut Request, depot: &mut Depot, response: &mut Response) {
    finish(
        response,
        complete(request, depot, MailKind::PasswordReset).await,
        StatusCode::NO_CONTENT,
    );
}

async fn complete(request: &mut Request, depot: &Depot, kind: MailKind) -> AuthResult<()> {
    let CompleteBody { token, password } = json_body(request).await?;
    if !canonical_fragment(&token) {
        return Err(AuthError::InvalidToken);
    }
    if !(MIN_PASSWORD..=MAX_PASSWORD).contains(&password.len()) {
        return Err(AuthError::InvalidInput);
    }
    let state = state(depot)?;
    let group = match kind {
        MailKind::Registration => {
            state.limit(Operation::Complete, &token)?;
            if state.mailer.is_none() {
                return Err(AuthError::InvalidToken);
            }
            Some(
                state
                    .customer_group()
                    .await?
                    .ok_or(AuthError::InvalidToken)?,
            )
        }
        MailKind::PasswordReset => {
            state.limit(Operation::Reset, &token)?;
            None
        }
    };
    let hash = state
        .password_job(move || {
            Argon2::default()
                .hash_password(password.as_bytes())
                .map(|hash| hash.to_string())
        })
        .await?;
    let digest = digest(&token);
    let completed = match group {
        Some(group) => store::complete_registration(&state.pool, &digest, &hash, group)
            .await?
            .is_some(),
        None => store::complete_password_reset(&state.pool, &digest, &hash).await?,
    };
    completed.then_some(()).ok_or(AuthError::InvalidToken)
}

#[handler]
async fn login(request: &mut Request, depot: &mut Depot, response: &mut Response) {
    render_session(response, account_login(request, depot).await);
}

async fn account_login(request: &mut Request, depot: &Depot) -> AuthResult<SessionResponse> {
    let LoginBody { email, password } = json_body(request).await?;
    let email = normalized_email(&email)?;
    if password.len() > MAX_PASSWORD {
        return Err(AuthError::InvalidInput);
    }
    let state = state(depot)?;
    state.limit(Operation::Login, &email)?;
    let (identity, hash) = match store::lookup_account_credential(&state.pool, &email).await? {
        Some(credential) => (
            Some((credential.user_id, credential.password_version)),
            credential.password_hash,
        ),
        None => (None, DUMMY_HASH.to_owned()),
    };
    let matches = state
        .password_job(move || {
            let parsed = PasswordHash::new(&hash)?;
            match Argon2::default().verify_password(password.as_bytes(), &parsed) {
                Ok(()) => Ok(true),
                Err(PasswordError::PasswordInvalid) => Ok(false),
                Err(error) => Err(error),
            }
        })
        .await?;
    let Some((user_id, version)) = identity.filter(|_| matches) else {
        return Err(AuthError::Unauthorized);
    };
    issue_session(&state.pool, user_id, SessionKind::Account { version }).await
}

#[handler]
async fn key_login(request: &mut Request, depot: &mut Depot, response: &mut Response) {
    render_session(response, ordinary_key_login(request, depot).await);
}

async fn ordinary_key_login(request: &mut Request, depot: &Depot) -> AuthResult<SessionResponse> {
    let KeyLoginBody { key } = json_body(request).await?;
    let key = key.trim();
    if key.is_empty()
        || key.len() > 512
        || !key.bytes().all(|byte| byte.is_ascii_graphic())
        || is_portal_session_token(key)
    {
        return Err(AuthError::Unauthorized);
    }
    let state = state(depot)?;
    state.limit(Operation::KeyLogin, key)?;
    if crate::admin::constant_time_eq(&crate::db::sha256_hex(key), &state.admin_digest) {
        return Err(AuthError::Unauthorized);
    }
    let principal = store::authenticate_principal(&state.pool, key)
        .await
        .map_err(|_| {
            tracing::warn!("portal key lookup failed");
            AuthError::Unavailable
        })?
        .ok_or(AuthError::Unauthorized)?;
    if crate::api::refusal(&principal, Timestamp::now()).is_some() {
        return Err(AuthError::Unauthorized);
    }
    issue_session(
        &state.pool,
        principal.user_id,
        SessionKind::Key {
            key_id: principal.key_id,
        },
    )
    .await
}

enum SessionKind {
    Account { version: i64 },
    Key { key_id: i64 },
}

async fn issue_session(
    pool: &PgPool,
    user_id: i64,
    kind: SessionKind,
) -> AuthResult<SessionResponse> {
    let token = format!("{SESSION_PREFIX}{}", random_fragment()?);
    let digest = digest(&token);
    let expires_at = Timestamp::now() + SESSION_LIFETIME;
    let inserted = match kind {
        SessionKind::Account { version } => {
            store::create_account_session(pool, user_id, version, &digest, expires_at).await?
        }
        SessionKind::Key { key_id } => {
            store::create_key_session(pool, user_id, key_id, &digest, expires_at).await?
        }
    };
    inserted
        .then_some(SessionResponse { token, expires_at })
        .ok_or(AuthError::Unauthorized)
}

#[handler]
async fn logout(request: &mut Request, depot: &mut Depot, response: &mut Response) {
    finish(
        response,
        revoke(request, depot).await,
        StatusCode::NO_CONTENT,
    );
}

async fn revoke(request: &mut Request, depot: &Depot) -> AuthResult<()> {
    // Network requests use ReqBody::Hyper even when the body is empty. Check
    // the stream itself rather than the enum variant. Logout deliberately
    // rejects every declared or actual body, including JSON `{}`.
    reject_logout_body(request)?;
    let mut values = request.headers().get_all(header::AUTHORIZATION).iter();
    let (scheme, token) = values
        .next()
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split_once(' '))
        .ok_or(AuthError::Unauthorized)?;
    if values.next().is_some()
        || !scheme.eq_ignore_ascii_case("bearer")
        || session_digest(token).is_none()
    {
        return Err(AuthError::Unauthorized);
    }
    let pool = &state(depot)?.pool;
    // Valid-looking but inactive sessions may be logged out again. Non-portal
    // credentials never take this path and a database failure stays retryable.
    if lookup_portal_session(pool, token).await?.is_some() {
        store::revoke_session(pool, &digest(token)).await?;
    }
    Ok(())
}

fn reject_logout_body(request: &Request) -> AuthResult<()> {
    let headers = request.headers();
    if !request.body().is_end_stream()
        || headers.contains_key(header::CONTENT_TYPE)
        || headers.contains_key(header::TRANSFER_ENCODING)
    {
        return Err(AuthError::RequiresJson);
    }

    let mut content_lengths = headers.get_all(header::CONTENT_LENGTH).iter();
    let Some(content_length) = content_lengths.next() else {
        return Ok(());
    };
    if content_lengths.next().is_some() {
        return Err(AuthError::RequiresJson);
    }
    let content_length = content_length
        .to_str()
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or(AuthError::RequiresJson)?;
    if content_length == 0 {
        Ok(())
    } else {
        Err(AuthError::RequiresJson)
    }
}

fn finish(response: &mut Response, result: AuthResult<()>, status: StatusCode) {
    match result {
        Ok(()) => {
            response.status_code(status);
        }
        Err(error) => error.render(response),
    }
}

fn render_session(response: &mut Response, result: AuthResult<SessionResponse>) {
    match result {
        Ok(session) => response.render(Json(session)),
        Err(error) => error.render(response),
    }
}

pub(crate) fn router(state: AuthState) -> Router {
    Router::with_path("auth")
        .hoop(salvo::affix_state::inject(state))
        .hoop(guard)
        .push(Router::with_path("register").post(register))
        .push(Router::with_path("register/complete").post(register_complete))
        .push(Router::with_path("login").post(login))
        .push(Router::with_path("key-login").post(key_login))
        .push(Router::with_path("logout").post(logout))
        .push(Router::with_path("password/forgot").post(forgot))
        .push(Router::with_path("password/reset").post(reset))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_auth_tokens_are_canonical_and_reserve_the_namespace() {
        let valid = format!("ps_{}", "A".repeat(TOKEN_CHARS));
        assert!(session_digest(&valid).is_some());
        for invalid in [
            format!("{valid}="),
            format!("ps_{}B", "A".repeat(42)),
            "ps_invalid".to_owned(),
        ] {
            assert!(is_portal_session_token(&invalid));
            assert!(session_digest(&invalid).is_none());
        }
        assert!(!is_portal_session_token("sk-anything"));
    }
}
