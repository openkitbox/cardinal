//! The OpenCode Console protocol: the device-code login the vendor's CLI runs
//! (`opencode auth login`), the token endpoint that both completes a device
//! grant and rotates a refresh token, and the two account lookups the console
//! serves (`/api/user`, `/api/orgs`).
//!
//! Protocol only — no database, no login session, no token cache. The session
//! registry owns the polling cadence and the relay owns credential freshness;
//! both call these functions and act on the reduced verdicts ([`DeviceCode`],
//! [`TokenGrant`], [`AuthError`]) instead of on vendor JSON. Only the console
//! origin is ever dialed ([`is_opencode_console_url`]), and no token reaches an
//! error message or a log line: the persisted bundle is built by the caller.

use std::time::Duration;

use chrono::DateTime;
use chrono::TimeDelta;
use chrono::Utc;
use reqwest::StatusCode;

use super::is_opencode_console_url;

/// The OAuth client the console knows. It is the vendor CLI's id, so a login
/// started here is indistinguishable from `opencode auth login` on the
/// console side — devices are granted to exactly one well-known client.
pub const CLIENT_ID: &str = "opencode-cli";

/// The console origin every call dials, and the only `server` value accepted.
pub const DEFAULT_SERVER: &str = "https://opencode.ai/console";

/// The `grant_type` of a device-code poll (RFC 8628's URN), verified against
/// the live console on 2026-11-03: the bare `"device_code"` value is rejected
/// with an empty `400`, while the URN answers the documented
/// `400 {"error":"authorization_pending"}`. The vendor CLI polls with this
/// value too (`packages/core/src/plugin/provider/opencode.ts`, `poll`).
const DEVICE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";

/// The `grant_type` of a refresh.
const REFRESH_GRANT_TYPE: &str = "refresh_token";

/// One console round trip's budget. Device/token answers and the two account
/// lookups are small and quick; a stalled console must not pin a login session
/// (the poller has its own `expires_in` deadline, this is the transport bound).
const CONSOLE_TIMEOUT: Duration = Duration::from_secs(20);

/// Poll interval assumed when the console omits `interval` (RFC 8628's floor).
const DEFAULT_INTERVAL: u64 = 5;

/// Longest token lifetime accepted from the console. A far-future `expires_at`
/// would never be refreshed and would quietly serve an expired bearer, so an
/// implausible `expires_in` is a decode failure instead of a stored value.
const MAX_TOKEN_LIFETIME_SECONDS: u64 = 30 * 24 * 60 * 60;

/// How much vendor diagnostic text is quoted in an error or a log line.
const ERROR_SNIPPET: usize = 200;

/// The console endpoint each call names in diagnostics; they double as the
/// operation label so a failure reads `auth/device/token: … HTTP 500`.
const OP_DEVICE_CODE: &str = "auth/device/code";
const OP_TOKEN: &str = "auth/device/token";
const OP_ACCOUNT: &str = "api/user";
const OP_ORGS: &str = "api/orgs";

/// A device-code grant the user still has to approve in the browser.
///
/// `device_code` is the half of the grant that the poller trades for tokens, so
/// it is a secret for as long as the grant lives: Debug redacts it.
pub struct DeviceCode {
    /// The credential the token endpoint redeems (secret while pending).
    pub device_code: String,
    /// The short code the browser asks the user to confirm.
    pub user_code: String,
    /// Absolute URL resolved onto the console origin, safe to show and click.
    pub verification_url: String,
    /// Seconds the console keeps the grant open.
    pub expires_in: u64,
    /// Seconds the console asks the poller to wait between attempts.
    pub interval: u64,
}

impl std::fmt::Debug for DeviceCode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DeviceCode")
            .field("device_code", &"<redacted>")
            .field("user_code", &self.user_code)
            .field("verification_url", &self.verification_url)
            .field("expires_in", &self.expires_in)
            .field("interval", &self.interval)
            .finish()
    }
}

/// One device-token or refresh answer, reduced to what callers act on.
///
/// The vendor reports a not-yet-approved device grant as a 400 carrying
/// `{"error": "<code>"}`, so the verdict — not the HTTP status — is what moves
/// a login forward.
#[derive(Debug)]
pub enum TokenGrant {
    /// The console issued a token pair.
    Ready(ReadyToken),
    /// The user has not approved the grant yet; keep polling.
    Pending,
    /// The console asked the poller to back off; wait longer, then poll again.
    SlowDown,
    /// The grant or the refresh token is dead; a new login is required.
    Expired,
}

/// A freshly issued token pair, still in wire shape (`expires_in` in seconds).
///
/// Both tokens are secrets; Debug redacts them.
pub struct ReadyToken {
    /// Bearer for the inference endpoints (secret).
    pub access_token: String,
    /// Console refresh token, rotated on every refresh (secret).
    pub refresh_token: String,
    /// Seconds of validity the console grants `access_token`.
    pub expires_in: u64,
    /// Organization workspace id, when the login was organization-scoped.
    pub org_id: Option<String>,
}

impl ReadyToken {
    /// When this pair stops being accepted, relative to the caller's clock.
    ///
    /// The parser already bounds `expires_in` to a plausible lifetime; the
    /// saturating conversions only keep a hand-built token from wrapping into
    /// the past or panicking.
    #[must_use]
    pub fn expires_at(&self, now: DateTime<Utc>) -> DateTime<Utc> {
        let seconds = i64::try_from(self.expires_in).unwrap_or(i64::MAX);
        now + TimeDelta::try_seconds(seconds).unwrap_or(TimeDelta::MAX)
    }
}

impl std::fmt::Debug for ReadyToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ReadyToken")
            .field("access_token", &"<redacted>")
            .field("refresh_token", &"<redacted>")
            .field("expires_in", &self.expires_in)
            .field("org_id", &self.org_id)
            .finish()
    }
}

/// The account a console token belongs to (display only — never auth).
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct Account {
    pub id: String,
    pub email: String,
}

/// One organization the account can act in (display only — never auth).
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct Organization {
    pub id: String,
    pub name: String,
}

/// Everything a console call can fail with: every variant names the operation
/// and the origin, plus the HTTP status and the vendor's own error code where
/// the wire supplied them — never a token or an `authorization` header value.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    /// The `server` is not the console origin, so no request was made.
    #[error("{operation}: refusing to dial {origin:?}, which is not the OpenCode Console origin")]
    Server {
        operation: &'static str,
        origin: String,
    },
    /// The console wants the organization's SSO proven in the browser; the
    /// current token (or the login being completed) cannot be used and only a
    /// new login after the browser step helps.
    #[error(
        "{operation}: organization SSO must be completed in the browser, then log in again (org {org_id:?})"
    )]
    SsoRequired {
        operation: &'static str,
        /// The organization the console named, when it named one.
        org_id: Option<String>,
    },
    /// The request never produced a response (connect, TLS, timeout).
    #[error("{operation}: request to {origin} failed: {source}")]
    Transport {
        operation: &'static str,
        origin: String,
        #[source]
        source: reqwest::Error,
    },
    /// The encrypted resolver or HTTP client could not be constructed.
    #[error("{operation}: request to {origin} is unavailable because encrypted DNS setup failed")]
    Unavailable {
        operation: &'static str,
        origin: String,
    },
    /// A non-success status that is not a grant verdict.
    #[error("{operation}: {origin} answered HTTP {status}{}", detail_suffix(.detail))]
    Status {
        operation: &'static str,
        origin: String,
        status: StatusCode,
        /// The vendor's error code / description, when the body named one.
        detail: Option<String>,
    },
    /// The console says the session behind the token is gone
    /// (`401 {"_tag":"Unauthorized"}`): the access token was revoked or has
    /// expired, and only a refresh (or a new login) recovers.
    #[error("{operation}: the console reports the session is no longer signed in")]
    Unauthorized {
        operation: &'static str,
        origin: String,
    },
    /// A success body that does not decode into the expected shape — wire
    /// drift between this binary and the console, surfaced loudly.
    #[error("{operation}: undecodable answer from {origin}: {detail}")]
    Decode {
        operation: &'static str,
        origin: String,
        detail: String,
    },
    /// The console's `verification_uri_complete` did not resolve onto the
    /// console origin, so the login cannot be shown to the user. The value is
    /// carried verbatim; it holds no token.
    #[error("{operation}: unusable verification URL {value:?} from {origin}")]
    VerificationUrl {
        operation: &'static str,
        origin: String,
        value: String,
    },
}

/// Render [`AuthError::Status`]'s optional vendor detail as a message suffix.
fn detail_suffix(detail: &Option<String>) -> String {
    match detail {
        Some(detail) => format!(" ({detail})"),
        None => String::new(),
    }
}

/// Resolve the console's `verification_uri_complete` against the console
/// origin.
///
/// The vendor sends a relative path (`/console/device?...`) that must be read
/// against `{server}/`; whatever comes back must stay on the console origin
/// (same scheme, host and port, no userinfo) so a login page from a foreign
/// host is never shown as "the OpenCode login".
pub fn resolve_verification_url(server: &str, value: &str) -> anyhow::Result<String> {
    anyhow::ensure!(
        is_opencode_console_url(server),
        "OpenCode console origin required, got {server:?}"
    );
    let value = value.trim();
    anyhow::ensure!(!value.is_empty(), "verification URL is empty");
    let base = reqwest::Url::parse(&format!("{server}/"))?;
    let resolved = base.join(value)?;
    anyhow::ensure!(
        matches!(resolved.scheme(), "http" | "https"),
        "verification URL must be http(s), got {:?}",
        resolved.scheme()
    );
    anyhow::ensure!(
        resolved.username().is_empty() && resolved.password().is_none(),
        "verification URL must not carry credentials"
    );
    anyhow::ensure!(
        same_origin(&base, &resolved),
        "verification URL {resolved:?} does not stay on the console origin {base:?}"
    );
    Ok(resolved.into())
}

/// Whether two URLs name the same origin (scheme, host, port).
fn same_origin(base: &reqwest::Url, other: &reqwest::Url) -> bool {
    base.scheme() == other.scheme()
        && base.port_or_known_default() == other.port_or_known_default()
        && base
            .host_str()
            .zip(other.host_str())
            .is_some_and(|(base_host, other_host)| base_host.eq_ignore_ascii_case(other_host))
}

/// One token-endpoint answer as the console sends it: either a token pair or an
/// `error` code — the pending and revoked cases arrive as a 400. Both grants
/// share this shape.
#[derive(serde::Deserialize)]
struct TokenBody {
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    org_id: Option<String>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    error_description: Option<String>,
}

/// A console body discriminated by `_tag`: the organization-SSO refusal
/// (`SsoRequired`, whose org is camelCase here, unlike the bundle's `org_id`)
/// and the revoked-session answer (`Unauthorized`).
#[derive(serde::Deserialize)]
struct TaggedBody {
    #[serde(default, rename = "_tag")]
    tag: Option<String>,
    #[serde(default, rename = "orgId")]
    org_id: Option<String>,
}

/// A device-code answer as the console sends it.
#[derive(serde::Deserialize)]
struct DeviceCodeBody {
    #[serde(default)]
    device_code: Option<String>,
    #[serde(default)]
    user_code: Option<String>,
    #[serde(default)]
    verification_uri_complete: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    interval: Option<u64>,
}

/// A vendor error body on an endpoint that is not the token endpoint.
#[derive(serde::Deserialize)]
struct VendorError {
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    error_description: Option<String>,
}

/// The vendor's own diagnostic text from a body, bounded; `None` when the body
/// carries none (an HTML error page, an empty body).
fn vendor_detail(body: &str) -> Option<String> {
    let parsed: VendorError = serde_json::from_str(body).ok()?;
    let detail = parsed.error.or(parsed.error_description)?;
    let detail: String = detail.chars().take(ERROR_SNIPPET).collect();
    Some(detail)
}

/// The 403 `_tag: "SsoRequired"` answer, which any console call can produce.
fn sso_required(status: StatusCode, body: &str, operation: &'static str) -> Option<AuthError> {
    if status != StatusCode::FORBIDDEN {
        return None;
    }
    let parsed: TaggedBody = serde_json::from_str(body).ok()?;
    if parsed.tag.as_deref() != Some("SsoRequired") {
        return None;
    }
    Some(AuthError::SsoRequired {
        operation,
        org_id: parsed.org_id,
    })
}

/// The 401 `_tag: "Unauthorized"` answer the console sends when the session
/// behind the access token was revoked or expired, including when a refresh is
/// refused.
fn unauthorized(
    status: StatusCode,
    body: &str,
    operation: &'static str,
    origin: &str,
) -> Option<AuthError> {
    if status != StatusCode::UNAUTHORIZED {
        return None;
    }
    let parsed: TaggedBody = serde_json::from_str(body).ok()?;
    if parsed.tag.as_deref() != Some("Unauthorized") {
        return None;
    }
    Some(AuthError::Unauthorized {
        operation,
        origin: origin.to_owned(),
    })
}

/// Read one token-endpoint answer into a [`TokenGrant`].
///
/// The `error` code decides the verdict (and a 401 `_tag: "Unauthorized"` is
/// the revoked-session answer instead), while the status alone does not, because
/// the console answers a still-pending device grant with a **400**
/// `{"_tag":"DeviceTokenError","error":"authorization_pending",…}` (verified
/// against the live console, 2026-11-03). `authorization_pending` keeps
/// polling, `slow_down` asks for a longer wait, `expired_token` /
/// `access_denied` / `invalid_grant` are terminal, and any unrecognised code is
/// pending plus one warning — a new vendor code must not kill a login.
pub fn parse_token_grant(
    status: StatusCode,
    body: &str,
    origin: &str,
) -> Result<TokenGrant, AuthError> {
    if let Some(error) = sso_required(status, body, OP_TOKEN) {
        return Err(error);
    }
    // A revoked session answers the refresh with a 401 `Unauthorized` instead
    // of an `invalid_grant` code: same verdict, so it takes the same path.
    if let Some(error) = unauthorized(status, body, OP_TOKEN, origin) {
        return Err(error);
    }
    let parsed: TokenBody = match serde_json::from_str(body) {
        Ok(parsed) => parsed,
        Err(error) if status.is_success() => {
            return Err(AuthError::Decode {
                operation: OP_TOKEN,
                origin: origin.to_owned(),
                detail: error.to_string(),
            });
        }
        Err(_) => {
            return Err(AuthError::Status {
                operation: OP_TOKEN,
                origin: origin.to_owned(),
                status,
                detail: vendor_detail(body),
            });
        }
    };
    if let Some(code) = parsed.error.as_deref() {
        return Ok(match code {
            "authorization_pending" => TokenGrant::Pending,
            "slow_down" => TokenGrant::SlowDown,
            "expired_token" | "access_denied" | "invalid_grant" => TokenGrant::Expired,
            other => {
                tracing::warn!(
                    origin = %origin,
                    status = %status,
                    code = other,
                    "unrecognised OpenCode console grant error; treating it as pending"
                );
                TokenGrant::Pending
            }
        });
    }
    if !status.is_success() {
        let detail = parsed
            .error_description
            .map(|detail| detail.chars().take(ERROR_SNIPPET).collect());
        return Err(AuthError::Status {
            operation: OP_TOKEN,
            origin: origin.to_owned(),
            status,
            detail,
        });
    }
    Ok(TokenGrant::Ready(ready_token(parsed, origin)?))
}

/// Reduce a decoded token answer to the pair, rejecting answers a caller could
/// only misuse (missing tokens, an implausible lifetime).
fn ready_token(body: TokenBody, origin: &str) -> Result<ReadyToken, AuthError> {
    let access_token = body
        .access_token
        .filter(|token| !token.trim().is_empty())
        .ok_or_else(|| AuthError::Decode {
            operation: OP_TOKEN,
            origin: origin.to_owned(),
            detail: "token answer carries no access_token".to_owned(),
        })?;
    let refresh_token = body
        .refresh_token
        .filter(|token| !token.trim().is_empty())
        .ok_or_else(|| AuthError::Decode {
            operation: OP_TOKEN,
            origin: origin.to_owned(),
            detail: "token answer carries no refresh_token".to_owned(),
        })?;
    let granted = body.expires_in;
    let expires_in = granted
        .filter(|seconds| (1..=MAX_TOKEN_LIFETIME_SECONDS).contains(seconds))
        .ok_or_else(|| AuthError::Decode {
            operation: OP_TOKEN,
            origin: origin.to_owned(),
            detail: format!(
                "token lifetime {granted:?}s is outside 1..={MAX_TOKEN_LIFETIME_SECONDS}s"
            ),
        })?;
    Ok(ReadyToken {
        access_token,
        refresh_token,
        expires_in,
        org_id: body.org_id,
    })
}

/// Read a device-code answer.
fn parse_device_code(
    status: StatusCode,
    body: &str,
    origin: &str,
) -> Result<DeviceCode, AuthError> {
    if !status.is_success() {
        return Err(AuthError::Status {
            operation: OP_DEVICE_CODE,
            origin: origin.to_owned(),
            status,
            detail: vendor_detail(body),
        });
    }
    let parsed: DeviceCodeBody = serde_json::from_str(body).map_err(|error| AuthError::Decode {
        operation: OP_DEVICE_CODE,
        origin: origin.to_owned(),
        detail: error.to_string(),
    })?;
    let device_code = parsed
        .device_code
        .filter(|code| !code.trim().is_empty())
        .ok_or_else(|| AuthError::Decode {
            operation: OP_DEVICE_CODE,
            origin: origin.to_owned(),
            detail: "device-code answer carries no device_code".to_owned(),
        })?;
    let user_code = parsed
        .user_code
        .filter(|code| !code.trim().is_empty())
        .ok_or_else(|| AuthError::Decode {
            operation: OP_DEVICE_CODE,
            origin: origin.to_owned(),
            detail: "device-code answer carries no user_code".to_owned(),
        })?;
    let raw_url = parsed
        .verification_uri_complete
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| AuthError::Decode {
            operation: OP_DEVICE_CODE,
            origin: origin.to_owned(),
            detail: "device-code answer carries no verification_uri_complete".to_owned(),
        })?;
    let verification_url =
        resolve_verification_url(origin, &raw_url).map_err(|_| AuthError::VerificationUrl {
            operation: OP_DEVICE_CODE,
            origin: origin.to_owned(),
            value: raw_url,
        })?;
    let expires_in = parsed
        .expires_in
        .filter(|seconds| *seconds > 0)
        .ok_or_else(|| AuthError::Decode {
            operation: OP_DEVICE_CODE,
            origin: origin.to_owned(),
            detail: "device-code answer carries no usable expires_in".to_owned(),
        })?;
    Ok(DeviceCode {
        device_code,
        user_code,
        verification_url,
        expires_in,
        // Never 0: the poller would spin against the console.
        interval: parsed.interval.unwrap_or(DEFAULT_INTERVAL).max(1),
    })
}

/// One console HTTP client.
///
/// Stateless on purpose: the server, the device code and the tokens are
/// per-call arguments, because the login registry and the credential cache each
/// decide which account a call is for and when it happens. The client holds
/// only the connection pool and the timeout.
pub struct Client {
    http: Option<reqwest::Client>,
}

impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}

impl Client {
    /// Build the console client. Resolver or HTTP client construction failure
    /// leaves the client unavailable: encrypted DNS is mandatory, so there is
    /// no system-DNS fallback.
    pub fn new() -> Self {
        let http = match crate::upstream::dns::Resolvers::new() {
            Ok(resolvers) => reqwest::Client::builder()
                .timeout(CONSOLE_TIMEOUT)
                .redirect(reqwest::redirect::Policy::none())
                .dns_resolver(std::sync::Arc::clone(
                    // The OpenCode console is fixed overseas; login has no provider row yet.
                    resolvers.resolver(crate::upstream::Dns::Overseas),
                ))
                .build()
                .map_err(|error| anyhow::anyhow!(error)),
            Err(error) => Err(error),
        };
        let http = match http {
            Ok(http) => Some(http),
            Err(error) => {
                tracing::warn!(%error, "OpenCode console client is unavailable: encrypted resolver setup failed");
                None
            }
        };
        Self { http }
    }

    fn http(&self, operation: &'static str, origin: &str) -> Result<&reqwest::Client, AuthError> {
        self.http.as_ref().ok_or_else(|| AuthError::Unavailable {
            operation,
            origin: origin.to_owned(),
        })
    }

    /// Start a device-code login: the caller shows `user_code` and
    /// `verification_url`, then polls [`Self::poll_device_token`] every
    /// `interval` seconds until the grant resolves or `expires_in` passes.
    pub async fn device_code(&self, server: &str) -> Result<DeviceCode, AuthError> {
        let origin = console_origin(server, OP_DEVICE_CODE)?;
        let body = serde_json::json!({
            "client_id": CLIENT_ID,
            "supports_org_scope": true,
        });
        let request = self
            .http(OP_DEVICE_CODE, origin)?
            .post(format!("{origin}/{OP_DEVICE_CODE}"))
            .json(&body);
        let (status, text) = self.round_trip(OP_DEVICE_CODE, origin, request).await?;
        parse_device_code(status, &text, origin)
    }

    /// Poll the token endpoint once for a pending device grant.
    pub async fn poll_device_token(
        &self,
        server: &str,
        device_code: &str,
    ) -> Result<TokenGrant, AuthError> {
        let origin = console_origin(server, OP_TOKEN)?;
        let body = serde_json::json!({
            "grant_type": DEVICE_GRANT_TYPE,
            "device_code": device_code,
            "client_id": CLIENT_ID,
        });
        self.token_request(origin, body).await
    }

    /// Exchange a refresh token for a new pair.
    ///
    /// The console rotates the refresh token on every success, so concurrent
    /// refreshes of one account invalidate each other — the credential cache
    /// is what serialises them. `Expired` means the grant was revoked
    /// (`invalid_grant`) and only a new login helps; any other non-`Ready`
    /// verdict means no token was issued this round.
    pub async fn refresh(
        &self,
        server: &str,
        refresh_token: &str,
    ) -> Result<TokenGrant, AuthError> {
        let origin = console_origin(server, OP_TOKEN)?;
        let body = serde_json::json!({
            "grant_type": REFRESH_GRANT_TYPE,
            "refresh_token": refresh_token,
            "client_id": CLIENT_ID,
        });
        self.token_request(origin, body).await
    }

    /// Fetch the account the token belongs to (email/id for display).
    pub async fn fetch_account(
        &self,
        server: &str,
        access_token: &str,
    ) -> Result<Account, AuthError> {
        let origin = console_origin(server, OP_ACCOUNT)?;
        let text = self.bearer_get(origin, OP_ACCOUNT, access_token).await?;
        serde_json::from_str(&text).map_err(|error| AuthError::Decode {
            operation: OP_ACCOUNT,
            origin: origin.to_owned(),
            detail: error.to_string(),
        })
    }

    /// List the organizations the token can act in (display only).
    pub async fn fetch_organizations(
        &self,
        server: &str,
        access_token: &str,
    ) -> Result<Vec<Organization>, AuthError> {
        let origin = console_origin(server, OP_ORGS)?;
        let text = self.bearer_get(origin, OP_ORGS, access_token).await?;
        serde_json::from_str(&text).map_err(|error| AuthError::Decode {
            operation: OP_ORGS,
            origin: origin.to_owned(),
            detail: error.to_string(),
        })
    }

    /// POST one grant body to the token endpoint and reduce the answer.
    async fn token_request(
        &self,
        origin: &str,
        body: serde_json::Value,
    ) -> Result<TokenGrant, AuthError> {
        let request = self
            .http(OP_TOKEN, origin)?
            .post(format!("{origin}/{OP_TOKEN}"))
            .json(&body);
        let (status, text) = self.round_trip(OP_TOKEN, origin, request).await?;
        parse_token_grant(status, &text, origin)
    }

    /// GET one console account endpoint with the access token as a bearer and
    /// return its body text.
    async fn bearer_get(
        &self,
        origin: &str,
        operation: &'static str,
        access_token: &str,
    ) -> Result<String, AuthError> {
        let request = self
            .http(operation, origin)?
            .get(format!("{origin}/{operation}"))
            .bearer_auth(access_token);
        let (status, text) = self.round_trip(operation, origin, request).await?;
        if let Some(error) = sso_required(status, &text, operation) {
            return Err(error);
        }
        if let Some(error) = unauthorized(status, &text, operation, origin) {
            return Err(error);
        }
        if !status.is_success() {
            return Err(AuthError::Status {
                operation,
                origin: origin.to_owned(),
                status,
                detail: vendor_detail(&text),
            });
        }
        Ok(text)
    }

    /// Send one request and read the whole answer. The console is a fixed,
    /// TLS-verified origin and every endpoint answers a small JSON document, so
    /// the body is read as text rather than streamed.
    async fn round_trip(
        &self,
        operation: &'static str,
        origin: &str,
        request: reqwest::RequestBuilder,
    ) -> Result<(StatusCode, String), AuthError> {
        let response = request
            .timeout(CONSOLE_TIMEOUT)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|source| AuthError::Transport {
                operation,
                origin: origin.to_owned(),
                source,
            })?;
        let status = response.status();
        let text = response
            .text()
            .await
            .map_err(|source| AuthError::Transport {
                operation,
                origin: origin.to_owned(),
                source,
            })?;
        Ok((status, text))
    }
}

/// Validate `server` and hand back the origin without a trailing slash.
fn console_origin<'a>(server: &'a str, operation: &'static str) -> Result<&'a str, AuthError> {
    if is_opencode_console_url(server) {
        Ok(server.trim_end_matches('/'))
    } else {
        Err(AuthError::Server {
            operation,
            origin: server.to_owned(),
        })
    }
}
