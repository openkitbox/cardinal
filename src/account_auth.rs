//! Portal authentication. The store owns atomic challenge consumption and issuance.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use argon2::Argon2;
use argon2::password_hash::phc::PasswordHash;
use argon2::password_hash::{Error as PasswordError, PasswordHasher as _, PasswordVerifier as _};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jiff::{SignedDuration, Timestamp};
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use reqwest::{Client, Url};
use salvo::http::{Body as _, ParseError, StatusCode, header};
use salvo::prelude::{Depot, FlowCtrl, Json, Request, Response, Router, handler};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use sqlx::PgPool;
use tokio::sync::Semaphore;

use crate::account_mail::{MailKind, Mailer};
use crate::auth_limits::{AuthLimits, Operation};
use crate::config::PortalConfig;
use crate::store::{self, AuthProviderRow, PortalSession};

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
const GOOGLE_AUTHORIZE: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN: &str = "https://oauth2.googleapis.com/token";
const GOOGLE_JWKS: &str = "https://www.googleapis.com/oauth2/v3/certs";
const GOOGLE_ISSUERS: [&str; 2] = ["https://accounts.google.com", "accounts.google.com"];
const GOOGLE_SCOPE: &str = "openid email";
const GITHUB_AUTHORIZE: &str = "https://github.com/login/oauth/authorize";
const GITHUB_TOKEN: &str = "https://github.com/login/oauth/access_token";
const GITHUB_USER: &str = "https://api.github.com/user";
const GITHUB_EMAILS: &str = "https://api.github.com/user/emails";
const GITHUB_SCOPE: &str = "read:user user:email";
const OAUTH_RESPONSE_LIMIT: usize = 64 * 1024;
const OAUTH_FIELD_LIMIT: usize = 512;
const JWKS_TTL: Duration = Duration::from_secs(300);

#[derive(Clone)]
pub(crate) struct AuthState(Arc<State>);

/// A rebuildable view of DB-backed portal configuration. Settings and providers
/// are read in one reload pass and swapped together, so a handler never pairs
/// a mailer from one pass with a provider table from another. The two reads are
/// separate queries, not one transactionally consistent database snapshot.
pub(crate) struct PortalRuntime {
    /// `None` when the configured mail transport is incomplete or unreachable.
    pub(crate) mailer: Option<Mailer>,
    /// OAuth exchange reads this table; every browser-facing projection must
    /// omit `client_secret` and `extra`.
    pub(crate) providers: HashMap<String, AuthProviderRow>,
}

struct CachedJwks {
    set: Arc<JwkSet>,
    fetched: Instant,
}

struct State {
    pool: PgPool,
    admin_digest: String,
    customer_group: Option<String>,
    bff_digest: Option<String>,
    /// Dev-only: permit loopback HTTP endpoint overrides from `extra.endpoints`.
    allow_insecure_upstream: bool,
    limits: AuthLimits,
    password_slots: Arc<Semaphore>,
    oauth_client: Client,
    jwks: tokio::sync::RwLock<HashMap<String, CachedJwks>>,
    runtime: tokio::sync::RwLock<Arc<PortalRuntime>>,
    /// Serializes load+swap so two admin writes cannot land in the runtime in
    /// the reverse order from their database commits.
    reload_lock: tokio::sync::Mutex<()>,
}

impl AuthState {
    /// Load the first snapshot from the database. A failure here is fatal at
    /// startup: there is no older snapshot to fall back to.
    pub(crate) async fn new(
        pool: PgPool,
        config: PortalConfig,
        admin_key: &str,
        allow_insecure_upstream: bool,
    ) -> anyhow::Result<Self> {
        let runtime = Self::load_runtime(&pool).await?;
        let oauth_client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(8))
            .no_proxy()
            .build()
            .context("build OAuth HTTP client")?;
        Ok(Self(Arc::new(State {
            pool,
            admin_digest: crate::db::sha256_hex(admin_key),
            customer_group: config
                .default_customer_group
                .filter(|group| !group.trim().is_empty()),
            bff_digest: config
                .bff_secret
                .filter(|secret| !secret.is_empty())
                .map(|secret| crate::db::sha256_hex(&secret)),
            allow_insecure_upstream,
            limits: AuthLimits::default(),
            password_slots: Arc::new(Semaphore::new(4)),
            oauth_client,
            jwks: tokio::sync::RwLock::new(HashMap::new()),
            runtime: tokio::sync::RwLock::new(Arc::new(runtime)),
            reload_lock: tokio::sync::Mutex::new(()),
        })))
    }

    /// Re-read settings and providers, rebuild the runtime, then swap it in in
    /// one step. Loads are serialized with swaps so concurrent reloads cannot
    /// install an older generation last. On any error the previous snapshot
    /// stays live; callers must surface the failure instead of reporting a
    /// partially applied update.
    pub(crate) async fn reload(&self) -> anyhow::Result<()> {
        let _reload_guard = self.0.reload_lock.lock().await;
        let next = Arc::new(
            Self::load_runtime(&self.0.pool)
                .await
                .context("portal runtime reload failed; previous snapshot retained")?,
        );
        *self.0.runtime.write().await = next;
        Ok(())
    }

    /// Cheap, generation-consistent handle for auth handlers and T3's OAuth
    /// exchange handlers.
    pub(crate) async fn snapshot(&self) -> Arc<PortalRuntime> {
        Arc::clone(&*self.0.runtime.read().await)
    }

    /// Constant-time check of a BFF-supplied secret against the configured
    /// digest. No configured secret means nothing can authenticate.
    pub(crate) fn bff_secret_matches(&self, provided: &str) -> bool {
        self.0.bff_digest.as_ref().is_some_and(|digest| {
            crate::admin::constant_time_eq(&crate::db::sha256_hex(provided), digest)
        })
    }

    async fn load_runtime(pool: &PgPool) -> anyhow::Result<PortalRuntime> {
        let settings = store::get_portal_settings(pool)
            .await
            .context("load portal settings")?;
        let rows = store::list_auth_providers(pool)
            .await
            .context("load auth providers")?;
        let mailer = Mailer::from_settings(&settings).await;
        let providers = rows
            .into_iter()
            .map(|row| (row.provider.clone(), row))
            .collect();
        Ok(PortalRuntime { mailer, providers })
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OAuthExchangeBody {
    provider: String,
    code: String,
    code_verifier: String,
    /// Only needed when the authorization request carried an OIDC nonce.
    #[serde(default)]
    nonce: Option<String>,
}

#[derive(Serialize)]
struct PublicOAuthProvider {
    provider: String,
    client_id: String,
    authorize_url: String,
    scope: String,
    redirect_uri: String,
}

struct VerifiedIdentity {
    subject: String,
    email: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProviderKind {
    Google,
    GitHub,
}

impl ProviderKind {
    fn from_name(name: &str) -> Option<Self> {
        if name.eq_ignore_ascii_case("google") {
            Some(Self::Google)
        } else if name.eq_ignore_ascii_case("github") {
            Some(Self::GitHub)
        } else {
            None
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Google => "google",
            Self::GitHub => "github",
        }
    }

    fn authorize_url(self) -> &'static str {
        match self {
            Self::Google => GOOGLE_AUTHORIZE,
            Self::GitHub => GITHUB_AUTHORIZE,
        }
    }

    fn scope(self) -> &'static str {
        match self {
            Self::Google => GOOGLE_SCOPE,
            Self::GitHub => GITHUB_SCOPE,
        }
    }
}

/// Trusted production endpoints, with opt-in loopback overrides for local E2E.
struct ProviderEndpoints {
    authorize: String,
    token: String,
    userinfo: String,
    emails: String,
    jwks: String,
    issuer: Option<String>,
}

impl ProviderEndpoints {
    fn resolve(
        kind: ProviderKind,
        row: &AuthProviderRow,
        allow_insecure_upstream: bool,
    ) -> AuthResult<Self> {
        let mut endpoints = match kind {
            ProviderKind::Google => Self {
                authorize: kind.authorize_url().to_owned(),
                token: GOOGLE_TOKEN.to_owned(),
                userinfo: String::new(),
                emails: String::new(),
                jwks: GOOGLE_JWKS.to_owned(),
                issuer: None,
            },
            ProviderKind::GitHub => Self {
                authorize: kind.authorize_url().to_owned(),
                token: GITHUB_TOKEN.to_owned(),
                userinfo: GITHUB_USER.to_owned(),
                emails: GITHUB_EMAILS.to_owned(),
                jwks: String::new(),
                issuer: None,
            },
        };
        if allow_insecure_upstream
            && let Some(overrides) = row.extra.get("endpoints").and_then(Value::as_object)
        {
            for (field, target) in [
                ("authorize", &mut endpoints.authorize),
                ("token", &mut endpoints.token),
                ("userinfo", &mut endpoints.userinfo),
                ("emails", &mut endpoints.emails),
                ("jwks", &mut endpoints.jwks),
            ] {
                if let Some(value) = overrides.get(field) {
                    if value.is_null() {
                        continue;
                    }
                    let raw = value.as_str().ok_or(AuthError::InvalidInput)?;
                    *target = dev_endpoint(raw)?.to_string();
                }
            }
            if let Some(value) = overrides.get("issuer").filter(|value| !value.is_null()) {
                let issuer = value.as_str().ok_or(AuthError::InvalidInput)?;
                if issuer.is_empty()
                    || issuer.len() > OAUTH_FIELD_LIMIT
                    || issuer.chars().any(char::is_control)
                {
                    return Err(AuthError::InvalidInput);
                }
                endpoints.issuer = Some(issuer.to_owned());
            }
        }
        Ok(endpoints)
    }
}

#[derive(Deserialize)]
struct GoogleTokenResponse {
    id_token: String,
}

#[derive(Deserialize)]
struct GoogleClaims {
    sub: String,
    email: String,
    email_verified: bool,
    #[serde(default)]
    nonce: Option<String>,
}

#[derive(Deserialize)]
struct GithubTokenResponse {
    access_token: Option<String>,
    scope: Option<String>,
    error: Option<String>,
}

#[derive(Deserialize)]
struct GithubEmail {
    email: String,
    primary: bool,
    verified: bool,
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

fn dev_endpoint(raw: &str) -> AuthResult<Url> {
    let url = Url::parse(raw).map_err(|_| AuthError::InvalidInput)?;
    let loopback = url
        .host_str()
        .map(|host| host.trim_matches(['[', ']']))
        .and_then(|host| host.parse::<IpAddr>().ok())
        .is_some_and(|address| address.is_loopback());
    if url.scheme() != "http"
        || !loopback
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(AuthError::InvalidInput);
    }
    Ok(url)
}

fn validate_oauth_body(body: &OAuthExchangeBody) -> AuthResult<()> {
    for field in [&body.provider, &body.code, &body.code_verifier] {
        if field.is_empty()
            || field.len() > OAUTH_FIELD_LIMIT
            || field.chars().any(char::is_control)
        {
            return Err(AuthError::InvalidInput);
        }
    }
    // RFC 7636 code verifier: 43-128 unreserved characters. The challenge is
    // computed by the browser; the gateway only forwards the verifier.
    if !(43..=128).contains(&body.code_verifier.len())
        || !body
            .code_verifier
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-._~".contains(&byte))
    {
        return Err(AuthError::InvalidInput);
    }
    if let Some(nonce) = body.nonce.as_deref()
        && (nonce.is_empty()
            || nonce.len() > OAUTH_FIELD_LIMIT
            || nonce.chars().any(char::is_control))
    {
        return Err(AuthError::InvalidInput);
    }
    Ok(())
}

fn authorize_bff(request: &Request, auth: &AuthState) -> AuthResult<()> {
    let mut values = request.headers().get_all(header::AUTHORIZATION).iter();
    let value = values
        .next()
        .and_then(|value| value.to_str().ok())
        .ok_or(AuthError::Unauthorized)?;
    let (scheme, token) = value.split_once(' ').ok_or(AuthError::Unauthorized)?;
    if values.next().is_some()
        || !scheme.eq_ignore_ascii_case("bearer")
        || token.is_empty()
        || token.len() > OAUTH_FIELD_LIMIT
        || !token.bytes().all(|byte| byte.is_ascii_graphic())
        || !auth.bff_secret_matches(token)
    {
        return Err(AuthError::Unauthorized);
    }
    Ok(())
}

async fn oauth_json<T: DeserializeOwned>(response: reqwest::Response) -> AuthResult<T> {
    let status = response.status();
    let bytes = response
        .bytes()
        .await
        .map_err(|_| AuthError::Unauthorized)?;
    if bytes.len() > OAUTH_RESPONSE_LIMIT {
        return Err(AuthError::Unauthorized);
    }
    if !status.is_success() {
        return Err(AuthError::Unauthorized);
    }
    serde_json::from_slice(&bytes).map_err(|_| AuthError::Unauthorized)
}

async fn oauth_get_json<T: DeserializeOwned>(
    client: &Client,
    url: &str,
    access_token: &str,
) -> AuthResult<T> {
    let response = client
        .get(url)
        .header("accept", "application/json")
        .header("user-agent", "cardinal-portal")
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|_| AuthError::Unauthorized)?;
    oauth_json(response).await
}

async fn fetch_jwks(state: &State, url: &str, force: bool) -> AuthResult<Arc<JwkSet>> {
    if !force {
        let cached = state.jwks.read().await;
        if let Some(entry) = cached.get(url)
            && entry.fetched.elapsed() < JWKS_TTL
        {
            return Ok(Arc::clone(&entry.set));
        }
    }
    let response = state
        .oauth_client
        .get(url)
        .send()
        .await
        .map_err(|_| AuthError::Unauthorized)?;
    let set: JwkSet = oauth_json(response).await?;
    let set = Arc::new(set);
    state.jwks.write().await.insert(
        url.to_owned(),
        CachedJwks {
            set: Arc::clone(&set),
            fetched: Instant::now(),
        },
    );
    Ok(set)
}

async fn verify_google_id_token(
    state: &State,
    endpoints: &ProviderEndpoints,
    client_id: &str,
    id_token: &str,
    nonce: Option<&str>,
) -> AuthResult<VerifiedIdentity> {
    let header = decode_header(id_token).map_err(|_| AuthError::Unauthorized)?;
    if header.alg != Algorithm::RS256 {
        return Err(AuthError::Unauthorized);
    }
    let kid = header
        .kid
        .as_deref()
        .filter(|kid| !kid.is_empty() && kid.len() <= OAUTH_FIELD_LIMIT)
        .ok_or(AuthError::Unauthorized)?;
    let mut set = fetch_jwks(state, &endpoints.jwks, false).await?;
    if set.find(kid).is_none() {
        // A newly rotated signing key must work before the TTL elapses.
        set = fetch_jwks(state, &endpoints.jwks, true).await?;
    }
    let jwk = set.find(kid).ok_or(AuthError::Unauthorized)?;
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&[client_id]);
    let mut issuers = GOOGLE_ISSUERS.to_vec();
    if let Some(issuer) = endpoints.issuer.as_deref() {
        issuers.push(issuer);
    }
    validation.set_issuer(&issuers);
    validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
    let key = DecodingKey::from_jwk(jwk).map_err(|_| AuthError::Unauthorized)?;
    let claims = decode::<GoogleClaims>(id_token, &key, &validation)
        .map_err(|_| AuthError::Unauthorized)?
        .claims;
    let nonce_matches = match (nonce, claims.nonce.as_deref()) {
        (None, None) => true,
        (Some(expected), Some(actual)) => crate::admin::constant_time_eq(expected, actual),
        _ => false,
    };
    if !nonce_matches || !claims.email_verified {
        return Err(AuthError::Unauthorized);
    }
    Ok(VerifiedIdentity {
        subject: claims.sub,
        email: normalized_email(&claims.email)?,
    })
}

async fn exchange_google_code(
    state: &State,
    endpoints: &ProviderEndpoints,
    row: &AuthProviderRow,
    body: &OAuthExchangeBody,
) -> AuthResult<VerifiedIdentity> {
    let response = state
        .oauth_client
        .post(&endpoints.token)
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", body.code.as_str()),
            ("client_id", row.client_id.as_str()),
            ("client_secret", row.client_secret.as_str()),
            ("redirect_uri", row.redirect_uri.as_str()),
            ("code_verifier", body.code_verifier.as_str()),
        ])
        .send()
        .await
        .map_err(|_| AuthError::Unauthorized)?;
    let token: GoogleTokenResponse = oauth_json(response).await?;
    if token.id_token.is_empty() || token.id_token.len() > OAUTH_RESPONSE_LIMIT {
        return Err(AuthError::Unauthorized);
    }
    verify_google_id_token(
        state,
        endpoints,
        &row.client_id,
        &token.id_token,
        body.nonce.as_deref(),
    )
    .await
}

async fn exchange_github_code(
    state: &State,
    endpoints: &ProviderEndpoints,
    row: &AuthProviderRow,
    body: &OAuthExchangeBody,
) -> AuthResult<VerifiedIdentity> {
    let response = state
        .oauth_client
        .post(&endpoints.token)
        .header("accept", "application/json")
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", body.code.as_str()),
            ("client_id", row.client_id.as_str()),
            ("client_secret", row.client_secret.as_str()),
            ("redirect_uri", row.redirect_uri.as_str()),
            ("code_verifier", body.code_verifier.as_str()),
        ])
        .send()
        .await
        .map_err(|_| AuthError::Unauthorized)?;
    let token: GithubTokenResponse = oauth_json(response).await?;
    if token.error.as_deref() == Some("unverified_user_email") {
        tracing::warn!("GitHub rejected an unverified email");
    }
    if token.error.is_some() {
        return Err(AuthError::Unauthorized);
    }
    let access_token = token
        .access_token
        .as_deref()
        .filter(|token| !token.is_empty() && token.len() <= OAUTH_FIELD_LIMIT)
        .ok_or(AuthError::Unauthorized)?;
    let granted: Vec<&str> = token
        .scope
        .as_deref()
        .unwrap_or_default()
        .split([' ', ','])
        .filter(|scope| !scope.is_empty())
        .collect();
    if !granted.contains(&"user:email") || !granted.contains(&"read:user") {
        return Err(AuthError::Unauthorized);
    }
    let user: Value =
        oauth_get_json(&state.oauth_client, &endpoints.userinfo, access_token).await?;
    let subject = match user.get("id") {
        Some(Value::Number(number)) => number
            .as_u64()
            .map(|id| id.to_string())
            .ok_or(AuthError::Unauthorized)?,
        Some(Value::String(id))
            if !id.is_empty()
                && id.len() <= OAUTH_FIELD_LIMIT
                && id.bytes().all(|byte| byte.is_ascii_digit()) =>
        {
            id.clone()
        }
        _ => return Err(AuthError::Unauthorized),
    };
    let emails: Vec<GithubEmail> =
        oauth_get_json(&state.oauth_client, &endpoints.emails, access_token).await?;
    let verified = emails
        .into_iter()
        .find(|email| email.primary && email.verified)
        .ok_or(AuthError::Unauthorized)?;
    Ok(VerifiedIdentity {
        subject,
        email: normalized_email(&verified.email)?,
    })
}

#[handler]
async fn oauth_providers(depot: &mut Depot, response: &mut Response) {
    let result = async {
        let auth = depot
            .get_typed::<AuthState>()
            .map_err(|_| AuthError::Unavailable)?;
        let snapshot = auth.snapshot().await;
        let mut providers = Vec::new();
        for row in snapshot.providers.values() {
            if !row.enabled {
                continue;
            }
            let Some(kind) = ProviderKind::from_name(&row.provider) else {
                continue;
            };
            let Ok(endpoints) =
                ProviderEndpoints::resolve(kind, row, auth.0.allow_insecure_upstream)
            else {
                // A rejected dev override must not leak an endpoint to the GUI.
                continue;
            };
            providers.push(PublicOAuthProvider {
                provider: kind.as_str().to_owned(),
                client_id: row.client_id.clone(),
                authorize_url: endpoints.authorize,
                scope: kind.scope().to_owned(),
                redirect_uri: row.redirect_uri.clone(),
            });
        }
        providers.sort_by(|left, right| left.provider.cmp(&right.provider));
        Ok::<_, AuthError>(providers)
    }
    .await;
    match result {
        Ok(providers) => response.render(Json(providers)),
        Err(error) => error.render(response),
    }
}

#[handler]
async fn oauth_exchange(request: &mut Request, depot: &mut Depot, response: &mut Response) {
    render_session(response, oauth_authenticate(request, depot).await);
}

async fn oauth_authenticate(request: &mut Request, depot: &Depot) -> AuthResult<SessionResponse> {
    let auth = depot
        .get_typed::<AuthState>()
        .map_err(|_| AuthError::Unavailable)?;
    authorize_bff(request, auth)?;
    let body: OAuthExchangeBody = json_body(request).await?;
    validate_oauth_body(&body)?;
    let state = &auth.0;
    let snapshot = auth.snapshot().await;
    let row = snapshot
        .providers
        .get(&body.provider)
        .filter(|row| row.enabled)
        .ok_or(AuthError::Unauthorized)?;
    let kind = ProviderKind::from_name(&row.provider).ok_or(AuthError::Unauthorized)?;
    let endpoints = ProviderEndpoints::resolve(kind, row, state.allow_insecure_upstream)?;
    let identity = match kind {
        ProviderKind::Google => exchange_google_code(state, &endpoints, row, &body).await?,
        ProviderKind::GitHub => exchange_github_code(state, &endpoints, row, &body).await?,
    };
    state.limit(
        Operation::Login,
        &format!("{}:{}:{}", kind.as_str(), identity.subject, identity.email),
    )?;
    let group = state
        .customer_group()
        .await?
        .ok_or(AuthError::Unauthorized)?;
    // A subject hit reuses the existing user and never consumes a new hash.
    let hash =
        if store::lookup_oauth_identity_user_id(&state.pool, kind.as_str(), &identity.subject)
            .await?
            .is_some()
        {
            String::new()
        } else {
            let mut random = [0u8; TOKEN_BYTES];
            getrandom::fill(&mut random).map_err(|_| {
                tracing::error!("portal OS random source failed");
                AuthError::Unavailable
            })?;
            // The credential exists only to satisfy the account login schema; nobody
            // knows the random bytes behind this hash.
            state
                .password_job(move || {
                    Argon2::default()
                        .hash_password(&random)
                        .map(|hash| hash.to_string())
                })
                .await?
        };
    let outcome = store::find_or_create_oauth_identity(
        &state.pool,
        kind.as_str(),
        &identity.subject,
        &identity.email,
        true,
        group,
        &hash,
    )
    .await
    .map_err(|_| AuthError::Unavailable)?
    .ok_or(AuthError::Unauthorized)?;
    let user_id = outcome.user_id();
    let credential = store::lookup_account_credential_by_user_id(&state.pool, user_id)
        .await?
        .ok_or(AuthError::Unauthorized)?;
    issue_session(
        &state.pool,
        user_id,
        SessionKind::Account {
            version: credential.password_version,
        },
    )
    .await
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
    if auth.snapshot().await.mailer.is_none() {
        return Err(AuthError::Unavailable);
    }
    let state = &auth.0;
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
        deliver_challenge(&auth, kind, &email, &fragment).await;
    });
    Ok(())
}

async fn deliver_challenge(auth: &AuthState, kind: MailKind, email: &str, fragment: &str) {
    let runtime = auth.snapshot().await;
    let Some(mailer) = &runtime.mailer else {
        return;
    };
    let digest = digest(fragment);
    let expires = Timestamp::now() + CHALLENGE_LIFETIME;
    let issued = match kind {
        MailKind::Registration => {
            store::issue_registration_challenge(&auth.0.pool, email, &digest, expires).await
        }
        MailKind::PasswordReset => {
            store::issue_password_reset_challenge(&auth.0.pool, email, &digest, expires).await
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
    let auth = depot
        .get_typed::<AuthState>()
        .map_err(|_| AuthError::Unavailable)?;
    let group = match kind {
        MailKind::Registration => {
            state.limit(Operation::Complete, &token)?;
            if auth.snapshot().await.mailer.is_none() {
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
        .push(Router::with_path("oauth/providers").get(oauth_providers))
        .push(Router::with_path("oauth/exchange").post(oauth_exchange))
        .push(Router::with_path("logout").post(logout))
        .push(Router::with_path("password/forgot").post(forgot))
        .push(Router::with_path("password/reset").post(reset))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::PortalSettingsInput;
    use sqlx::ConnectOptions as _;
    use sqlx::migrate::MigrateDatabase;
    use sqlx::postgres::{PgPoolOptions, Postgres};

    async fn portal_test_db() -> (PgPool, String) {
        let base = std::env::var("CARDINAL_TEST_DATABASE_URL")
            .expect("set CARDINAL_TEST_DATABASE_URL to an isolated test cluster");
        let (options, _) = crate::db::parse_pg_options(&base).unwrap();
        let name = format!("cardinal_runtime_{}", uuid::Uuid::new_v4().simple());
        let options = options.database(&name);
        let dsn = options.to_url_lossy().to_string();
        Postgres::create_database(&dsn).await.unwrap();
        let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
        sqlx::query("CREATE EXTENSION IF NOT EXISTS timescaledb")
            .execute(&pool)
            .await
            .unwrap();
        let mut migrator = crate::migrator();
        migrator.dangerous_set_table_name("_sqlx_migrations_gateway".to_owned());
        migrator.run(&pool).await.unwrap();
        (pool, dsn)
    }

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

    #[test]
    fn account_auth_provider_endpoints_only_trust_loopback_overrides_in_dev() {
        let mut row = AuthProviderRow {
            provider: "google".to_owned(),
            client_id: "client".to_owned(),
            client_secret: "secret".to_owned(),
            redirect_uri: "https://portal.example.com/callback".to_owned(),
            enabled: true,
            extra: serde_json::json!({"endpoints": {"token": "http://127.0.0.1:9999/token"}}),
            updated_at: Timestamp::now(),
        };
        let production = ProviderEndpoints::resolve(ProviderKind::Google, &row, false).unwrap();
        assert_eq!(production.token, GOOGLE_TOKEN);
        assert_eq!(production.authorize, GOOGLE_AUTHORIZE);
        let dev = ProviderEndpoints::resolve(ProviderKind::Google, &row, true).unwrap();
        assert_eq!(dev.token, "http://127.0.0.1:9999/token");
        row.extra = serde_json::json!({"endpoints": {"token": "https://evil.example/token"}});
        assert!(ProviderEndpoints::resolve(ProviderKind::Google, &row, true).is_err());
    }

    #[tokio::test]
    async fn account_auth_incomplete_mail_config_disables_delivery_without_an_error() {
        let (pool, dsn) = portal_test_db().await;
        let partial = PortalSettingsInput {
            mail_transport: "http",
            mail_url: "http://127.0.0.1:9/emails",
            mail_token: "",
            mail_from: "Cardinal <auth@example.com>",
            mail_origin: "http://127.0.0.1:3000",
            smtp_host: "",
            smtp_port: 587,
            smtp_username: "",
            smtp_password: "",
            smtp_tls: "starttls",
            smtp_from: "",
        };
        store::put_portal_settings(&pool, &partial).await.unwrap();

        let auth = AuthState::new(pool.clone(), PortalConfig::default(), "admin-key", false)
            .await
            .expect("incomplete mail settings must not abort startup");
        assert!(auth.snapshot().await.mailer.is_none());

        let complete = PortalSettingsInput {
            mail_token: "mail-token",
            ..partial
        };
        store::put_portal_settings(&pool, &complete).await.unwrap();
        auth.reload().await.expect("complete settings reload");
        assert!(auth.snapshot().await.mailer.is_some());

        // A malformed URL disables delivery; it is not a reload failure that
        // would leave the previous, still-working mailer in place.
        let invalid = PortalSettingsInput {
            mail_url: "not-a-url",
            ..complete
        };
        store::put_portal_settings(&pool, &invalid).await.unwrap();
        auth.reload()
            .await
            .expect("invalid mail URL disables delivery");
        assert!(auth.snapshot().await.mailer.is_none());

        // A real load failure retains the live snapshot and says so.
        let retained = auth.snapshot().await;
        sqlx::query("DROP TABLE portal_settings")
            .execute(&pool)
            .await
            .unwrap();
        let error = auth.reload().await.expect_err("missing table fails reload");
        assert!(
            format!("{error:#}").contains("previous snapshot retained"),
            "{error:#}"
        );
        assert!(Arc::ptr_eq(&retained, &auth.snapshot().await));

        drop(auth);
        pool.close().await;
        Postgres::drop_database(&dsn).await.unwrap();
    }
}
