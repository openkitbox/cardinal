//! The OpenAI account protocol the Codex CLI speaks: the device-code login
//! (`/api/accounts/deviceauth/*`), the token endpoint that both completes a
//! login (`authorization_code`) and rotates a refresh token, all on
//! `auth.openai.com`.
//!
//! Protocol only — no database, no login session, no polling loop, no token
//! cache. The login registry decides when to poll and the token manager decides
//! when to refresh; both call these functions and act on the reduced results
//! ([`DeviceGrant`], [`PollVerdict`], [`TokenSet`], [`AuthError`]) instead of
//! on vendor JSON. Only the issuer origin is dialed (redirects are refused), and
//! no token reaches an error message or a log line: [`AuthError`] carries no
//! request or response text, and the logs record the operation, the status and
//! the body's byte length only.
//!
//! The wire facts come from the Codex CLI's public client (oh-my-pi
//! `registry/oauth/openai-codex.ts`) and have not been exercised against the
//! live issuer.

use std::time::Duration;

use chrono::DateTime;
use chrono::TimeDelta;
use chrono::Utc;
use futures::StreamExt as _;
use reqwest::StatusCode;

use super::OpenaiOAuth;
use super::token_identity;

/// The Codex CLI's public OAuth client; a login started here is a Codex CLI
/// login as far as the issuer can tell.
pub const CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";

/// The only origin this module dials.
pub const ISSUER: &str = "https://auth.openai.com";

/// Where the operator enters the user code.
pub const VERIFICATION_URL: &str = "https://auth.openai.com/codex/device";

const USERCODE_PATH: &str = "/api/accounts/deviceauth/usercode";
const DEVICE_TOKEN_PATH: &str = "/api/accounts/deviceauth/token";
const TOKEN_PATH: &str = "/oauth/token";

/// The redirect URI a device-flow code exchange must quote.
const DEVICE_REDIRECT_URI: &str = "https://auth.openai.com/deviceauth/callback";

/// One round trip's budget, body read included.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

/// Poll interval assumed when the issuer omits or garbles `interval`.
const DEFAULT_INTERVAL_SECONDS: u64 = 5;

/// Largest answer body read. Every answer is a small JSON document (the biggest
/// carries three JWTs); a runaway endpoint must not fill memory.
const MAX_BODY: usize = 256 << 10;

const OP_USERCODE: &str = "deviceauth/usercode";
const OP_DEVICE_TOKEN: &str = "deviceauth/token";
const OP_EXCHANGE: &str = "oauth/token (authorization_code)";
const OP_REFRESH: &str = "oauth/token (refresh_token)";
const OP_IDENTITY: &str = "login identity";

/// Why an issuer call failed. Carries no request or response text.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    /// The request never produced a complete response (connect, TLS, timeout,
    /// body read).
    #[error("{operation}: the OpenAI auth service could not be reached")]
    Transport { operation: &'static str },
    /// The issuer answered a status the protocol gives no meaning to.
    #[error("{operation}: the OpenAI auth service answered HTTP {status}")]
    Status {
        operation: &'static str,
        status: StatusCode,
    },
    /// A success answer that lacks what the login or refresh needs, or an
    /// answer that is not the expected document.
    #[error("{operation}: the OpenAI auth service's answer was not usable")]
    Protocol { operation: &'static str },
}

impl AuthError {
    /// Whether the issuer refused the request itself (a 4xx other than 408 and
    /// 429): a revoked or already-used refresh token, a dead device grant. Only
    /// a new login helps. `false` for transport failures, 5xx, throttling and
    /// protocol errors, where asking again later can still work.
    #[must_use]
    pub fn is_rejection(&self) -> bool {
        match self {
            Self::Status { status, .. } => {
                status.is_client_error()
                    && *status != StatusCode::REQUEST_TIMEOUT
                    && *status != StatusCode::TOO_MANY_REQUESTS
            }
            Self::Transport { .. } | Self::Protocol { .. } => false,
        }
    }
}

/// A device grant the operator still has to approve at [`VERIFICATION_URL`].
///
/// `device_auth_id` is half of what the poll redeems, so it is a secret for as
/// long as the grant lives: Debug omits it.
pub struct DeviceGrant {
    /// The grant handle the poll sends (secret while pending).
    pub device_auth_id: String,
    /// The short code the operator enters.
    pub user_code: String,
    /// How long the issuer asks the poller to wait between polls.
    pub interval: Duration,
}

impl std::fmt::Debug for DeviceGrant {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DeviceGrant")
            .field("user_code", &self.user_code)
            .field("interval", &self.interval)
            .finish_non_exhaustive()
    }
}

/// What one poll said.
#[derive(Debug)]
pub enum PollVerdict {
    /// The operator has not approved yet (403/404); keep polling.
    Pending,
    /// The operator approved; trade this for tokens with
    /// [`Client::exchange_code`].
    Approved(DeviceApproval),
}

/// The authorization code and PKCE verifier an approved device grant yields.
/// Both are secrets until exchanged: Debug omits them.
pub struct DeviceApproval {
    authorization_code: String,
    code_verifier: String,
}

impl std::fmt::Debug for DeviceApproval {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DeviceApproval")
            .finish_non_exhaustive()
    }
}

/// One token-endpoint success, reduced to what callers persist.
///
/// All three tokens are secrets: Debug omits them.
pub struct TokenSet {
    /// Bearer for the Codex backend.
    pub access_token: String,
    /// The refresh token to store: the one the issuer returned, or — when a
    /// refresh answer carries none — the one the caller refreshed with.
    pub refresh_token: String,
    /// The OIDC ID token, when the issuer sent one (it may carry the plan).
    pub id_token: Option<String>,
    /// When `access_token` stops being accepted.
    pub expires_at: DateTime<Utc>,
}

impl std::fmt::Debug for TokenSet {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TokenSet")
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

impl TokenSet {
    /// The bundle a fresh login persists. The workspace id is mandatory — a
    /// request cannot be made without it — so a token pair that names none
    /// fails the login instead of storing an unusable account.
    pub fn into_bundle(self) -> Result<OpenaiOAuth, AuthError> {
        let identity = token_identity(&self.access_token, self.id_token.as_deref());
        let account_id = identity.account_id.ok_or_else(|| {
            tracing::warn!(
                operation = OP_IDENTITY,
                "OpenAI tokens carry no chatgpt_account_id"
            );
            AuthError::Protocol {
                operation: OP_IDENTITY,
            }
        })?;
        Ok(OpenaiOAuth {
            access_token: self.access_token,
            refresh_token: self.refresh_token,
            expires_at: self.expires_at,
            account_id,
            email: identity.email,
            plan_type: identity.plan_type,
        })
    }

    /// The bundle a refresh persists: the new tokens and expiry, with each
    /// identity field taken from the new tokens when they name it and kept
    /// from `stored` when they do not.
    #[must_use]
    pub fn refresh_bundle(self, stored: &OpenaiOAuth) -> OpenaiOAuth {
        let identity = token_identity(&self.access_token, self.id_token.as_deref());
        OpenaiOAuth {
            access_token: self.access_token,
            refresh_token: self.refresh_token,
            expires_at: self.expires_at,
            account_id: identity
                .account_id
                .unwrap_or_else(|| stored.account_id.clone()),
            email: identity.email.or_else(|| stored.email.clone()),
            plan_type: identity.plan_type.or_else(|| stored.plan_type.clone()),
        }
    }
}

/// Body of the usercode request.
#[derive(serde::Serialize)]
struct UsercodeRequest<'a> {
    client_id: &'a str,
}

/// Body of the device-token poll.
#[derive(serde::Serialize)]
struct DevicePollRequest<'a> {
    device_auth_id: &'a str,
    user_code: &'a str,
}

/// The usercode answer. `interval` arrives as a number or a numeric string.
#[derive(serde::Deserialize)]
struct UsercodeBody {
    #[serde(default)]
    device_auth_id: Option<String>,
    #[serde(default)]
    user_code: Option<String>,
    #[serde(default)]
    interval: Option<serde_json::Value>,
}

/// The approved device-token answer.
#[derive(serde::Deserialize)]
struct DeviceApprovalBody {
    #[serde(default)]
    authorization_code: Option<String>,
    #[serde(default)]
    code_verifier: Option<String>,
}

/// A token-endpoint success; both grants share the shape.
#[derive(serde::Deserialize)]
struct TokenBody {
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    id_token: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
}

/// `Some(text)` when `value` holds non-blank text.
fn non_blank(value: Option<String>) -> Option<String> {
    value.filter(|text| !text.trim().is_empty())
}

/// The poll interval a usercode answer asks for: a positive number or numeric
/// string of seconds, else the default.
fn parse_interval(value: Option<&serde_json::Value>) -> Duration {
    let seconds = match value {
        Some(serde_json::Value::Number(number)) => number.as_u64(),
        Some(serde_json::Value::String(text)) => text.trim().parse::<u64>().ok(),
        _ => None,
    };
    Duration::from_secs(
        seconds
            .filter(|seconds| *seconds > 0)
            .unwrap_or(DEFAULT_INTERVAL_SECONDS),
    )
}

/// Reduce a token-endpoint body to a [`TokenSet`]. `fallback_refresh` is the
/// refresh token to keep when the answer carries none (a refresh); a code
/// exchange passes `None` and so requires one.
fn parse_token_set(
    body: &[u8],
    operation: &'static str,
    now: DateTime<Utc>,
    fallback_refresh: Option<&str>,
) -> Result<TokenSet, AuthError> {
    let protocol = || AuthError::Protocol { operation };
    let parsed: TokenBody = serde_json::from_slice(body).map_err(|_| protocol())?;
    let access_token = non_blank(parsed.access_token).ok_or_else(protocol)?;
    let refresh_token = match non_blank(parsed.refresh_token) {
        Some(token) => token,
        None => fallback_refresh.ok_or_else(protocol)?.to_owned(),
    };
    let expires_in = parsed
        .expires_in
        .filter(|seconds| *seconds > 0)
        .and_then(|seconds| i64::try_from(seconds).ok())
        .and_then(TimeDelta::try_seconds)
        .ok_or_else(protocol)?;
    let expires_at = now.checked_add_signed(expires_in).ok_or_else(protocol)?;
    Ok(TokenSet {
        access_token,
        refresh_token,
        id_token: non_blank(parsed.id_token),
        expires_at,
    })
}

/// An `application/x-www-form-urlencoded` body. `reqwest`'s `form` feature is
/// not enabled in this crate, so the encoding goes through the `url` crate's
/// serializer that `reqwest::Url` exposes.
fn form_body(fields: &[(&str, &str)]) -> String {
    let mut scratch = reqwest::Url::parse("https://form.invalid/").expect("constant URL parses");
    scratch.query_pairs_mut().extend_pairs(fields);
    scratch.query().unwrap_or_default().to_owned()
}

/// The issuer HTTP client: a connection pool, a timeout and the issuer origin.
/// Stateless otherwise — every account-specific value is a call argument.
pub struct Client {
    http: Option<reqwest::Client>,
    issuer: String,
}

impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}

impl Client {
    /// Build the client against the production issuer. Resolver or HTTP client
    /// construction failure leaves the client unavailable: encrypted DNS is
    /// mandatory, so there is no system-DNS fallback.
    #[must_use]
    pub fn new() -> Self {
        Self::with_issuer(ISSUER)
    }

    fn with_issuer(issuer: &str) -> Self {
        let http = match crate::upstream::dns::Resolvers::new() {
            Ok(resolvers) => reqwest::Client::builder()
                .timeout(REQUEST_TIMEOUT)
                .redirect(reqwest::redirect::Policy::none())
                .dns_resolver(std::sync::Arc::clone(
                    // The OpenAI issuer is fixed overseas; login has no provider row yet.
                    resolvers.resolver(crate::upstream::Dns::Overseas),
                ))
                .build()
                .map_err(|error| anyhow::anyhow!(error)),
            Err(error) => Err(error),
        };
        let http = match http {
            Ok(http) => Some(http),
            Err(error) => {
                tracing::warn!(%error, "OpenAI auth client is unavailable: encrypted resolver setup failed");
                None
            }
        };
        Self {
            http,
            issuer: issuer.trim_end_matches('/').to_owned(),
        }
    }

    fn http(&self, operation: &'static str) -> Result<&reqwest::Client, AuthError> {
        self.http.as_ref().ok_or(AuthError::Transport { operation })
    }

    /// Start a device login: show the operator `user_code` and
    /// [`VERIFICATION_URL`], then call [`Self::poll_device`] every `interval`.
    pub async fn start_device(&self) -> Result<DeviceGrant, AuthError> {
        let request = self
            .http(OP_USERCODE)?
            .post(format!("{}{USERCODE_PATH}", self.issuer))
            .json(&UsercodeRequest {
                client_id: CLIENT_ID,
            });
        let (status, body) = self.round_trip(OP_USERCODE, request).await?;
        require_success(OP_USERCODE, status, body.len())?;
        let protocol = || AuthError::Protocol {
            operation: OP_USERCODE,
        };
        let parsed: UsercodeBody = serde_json::from_slice(&body).map_err(|_| protocol())?;
        Ok(DeviceGrant {
            device_auth_id: non_blank(parsed.device_auth_id).ok_or_else(protocol)?,
            user_code: non_blank(parsed.user_code).ok_or_else(protocol)?,
            interval: parse_interval(parsed.interval.as_ref()),
        })
    }

    /// Ask once whether the operator approved. 403 and 404 mean not yet; any
    /// other non-success status ends the login.
    pub async fn poll_device(
        &self,
        device_auth_id: &str,
        user_code: &str,
    ) -> Result<PollVerdict, AuthError> {
        let request = self
            .http(OP_DEVICE_TOKEN)?
            .post(format!("{}{DEVICE_TOKEN_PATH}", self.issuer))
            .json(&DevicePollRequest {
                device_auth_id,
                user_code,
            });
        let (status, body) = self.round_trip(OP_DEVICE_TOKEN, request).await?;
        if status == StatusCode::FORBIDDEN || status == StatusCode::NOT_FOUND {
            return Ok(PollVerdict::Pending);
        }
        require_success(OP_DEVICE_TOKEN, status, body.len())?;
        let protocol = || AuthError::Protocol {
            operation: OP_DEVICE_TOKEN,
        };
        let parsed: DeviceApprovalBody = serde_json::from_slice(&body).map_err(|_| protocol())?;
        Ok(PollVerdict::Approved(DeviceApproval {
            authorization_code: non_blank(parsed.authorization_code).ok_or_else(protocol)?,
            code_verifier: non_blank(parsed.code_verifier).ok_or_else(protocol)?,
        }))
    }

    /// Trade an approved device grant for tokens. `now` anchors `expires_at`.
    pub async fn exchange_code(
        &self,
        approval: &DeviceApproval,
        now: DateTime<Utc>,
    ) -> Result<TokenSet, AuthError> {
        let form = form_body(&[
            ("grant_type", "authorization_code"),
            ("client_id", CLIENT_ID),
            ("code", &approval.authorization_code),
            ("code_verifier", &approval.code_verifier),
            ("redirect_uri", DEVICE_REDIRECT_URI),
        ]);
        let body = self.token_request(OP_EXCHANGE, form).await?;
        parse_token_set(&body, OP_EXCHANGE, now, None)
    }

    /// Trade a refresh token for a new access token. An answer without a new
    /// refresh token keeps `refresh_token` in the returned [`TokenSet`], so the
    /// caller always has a refresh token to persist. A 4xx
    /// ([`AuthError::is_rejection`]) means the grant is dead. `now` anchors
    /// `expires_at`.
    pub async fn refresh(
        &self,
        refresh_token: &str,
        now: DateTime<Utc>,
    ) -> Result<TokenSet, AuthError> {
        let form = form_body(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", CLIENT_ID),
        ]);
        let body = self.token_request(OP_REFRESH, form).await?;
        parse_token_set(&body, OP_REFRESH, now, Some(refresh_token))
    }

    /// POST one form to the token endpoint and return the success body.
    async fn token_request(
        &self,
        operation: &'static str,
        form: String,
    ) -> Result<Vec<u8>, AuthError> {
        let request = self
            .http(operation)?
            .post(format!("{}{TOKEN_PATH}", self.issuer))
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(form);
        let (status, body) = self.round_trip(operation, request).await?;
        require_success(operation, status, body.len())?;
        Ok(body)
    }

    /// Send one request and read the whole answer under the size cap.
    async fn round_trip(
        &self,
        operation: &'static str,
        request: reqwest::RequestBuilder,
    ) -> Result<(StatusCode, Vec<u8>), AuthError> {
        let transport = || AuthError::Transport { operation };
        let response = request
            .timeout(REQUEST_TIMEOUT)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|_| transport())?;
        let status = response.status();
        let mut stream = response.bytes_stream();
        let mut body = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| transport())?;
            if body.len() + chunk.len() > MAX_BODY {
                tracing::warn!(
                    operation,
                    status = status.as_u16(),
                    "OpenAI auth answer exceeds the size cap"
                );
                return Err(AuthError::Protocol { operation });
            }
            body.extend_from_slice(&chunk);
        }
        Ok((status, body))
    }
}

/// Turn a non-2xx status into [`AuthError::Status`], logging only the
/// operation, the status and the body length (the body may echo a token).
fn require_success(
    operation: &'static str,
    status: StatusCode,
    body_len: usize,
) -> Result<(), AuthError> {
    if status.is_success() {
        return Ok(());
    }
    tracing::warn!(
        operation,
        status = status.as_u16(),
        body_bytes = body_len,
        "OpenAI auth request refused"
    );
    Err(AuthError::Status { operation, status })
}
