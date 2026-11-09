//! The Cursor browser-login client (plan §2.1.2, D5).
//!
//! A login is a handoff: the gateway mints a PKCE-style pair — a random
//! `verifier`, its SHA-256 `challenge` — and a session `uuid`, hands the
//! operator a URL on `cursor.com` carrying the challenge and the uuid, and
//! polls `GET /auth/poll?uuid=&verifier=` until the browser's sign-in lands
//! the token pair there. The verifier never enters the URL: it is shown only
//! to the poll, so a third party who sees the uuid cannot collect the tokens.
//!
//! This module is the wire half only — the URL, the poll request, the
//! answer's shape — with no session state (`login`) and no orchestration
//! (`admin_ops`). It never reads the local Cursor app's stores (plan D5: the
//! gateway is a server; the operator's own browser signs in once).
//!
//! No token is logged here: a poll answer is parsed for its fields and the
//! error type carries none of its text.

use reqwest::StatusCode;
use sha2::Digest as _;
use uuid::Uuid;

use crate::protocol::cursor::API_ORIGIN;

/// The site the operator signs in on.
pub const LOGIN_ORIGIN: &str = "https://cursor.com";
/// The login page.
const LOGIN_PATH: &str = "/loginDeepControl";
/// The poll endpoint on the API origin.
const POLL_PATH: &str = "/auth/poll";
/// The account-identity endpoint (email, decoration only).
const ME_PATH: &str = "/aiserver.v1.DashboardService/GetMe";
/// One request's own timeout.
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);
/// The device-policy refusal the poll answers with (terminal).
const POLICY_VIOLATION: &str = "sign_in_policy_violation";

/// One login's secret pair and session id.
pub struct Challenge {
    verifier: String,
    uuid: Uuid,
}

impl std::fmt::Debug for Challenge {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Challenge")
            .field("uuid", &self.uuid)
            .finish_non_exhaustive()
    }
}

impl Default for Challenge {
    fn default() -> Self {
        Self::new()
    }
}

impl Challenge {
    /// A fresh pair: 32 random bytes as the verifier (two v4 uuids — the
    /// workspace's random source, 244 random bits), a v4 uuid as the id.
    #[must_use]
    pub fn new() -> Self {
        let mut bytes = [0u8; 32];
        bytes[..16].copy_from_slice(Uuid::new_v4().as_bytes());
        bytes[16..].copy_from_slice(Uuid::new_v4().as_bytes());
        Self {
            verifier: base64url_encode(&bytes),
            uuid: Uuid::new_v4(),
        }
    }

    /// The session id the URL and the poll both carry.
    #[must_use]
    pub fn uuid(&self) -> Uuid {
        self.uuid
    }

    /// The verifier, for the poll only.
    #[must_use]
    pub fn verifier(&self) -> &str {
        &self.verifier
    }

    /// `base64url(sha256(verifier))`, without padding and without an `S256`
    /// prefix — the vendor's own spelling.
    #[must_use]
    pub fn challenge(&self) -> String {
        base64url_encode(&sha2::Sha256::digest(self.verifier.as_bytes()))
    }

    /// The URL the operator opens: the challenge and the uuid, `mode=login`,
    /// and the CLI's redirect target (the form the headless host uses).
    #[must_use]
    pub fn login_url(&self) -> String {
        format!(
            "{LOGIN_ORIGIN}{LOGIN_PATH}?challenge={}&uuid={}&mode=login&redirectTarget=cli",
            self.challenge(),
            self.uuid
        )
    }
}

/// What one poll said.
#[derive(Debug)]
pub enum PollVerdict {
    /// The browser has not signed in yet (404).
    Waiting,
    /// The token pair landed.
    Ready(ReadyToken),
    /// The account's device policy refused this sign-in; no retry can help.
    PolicyRefused,
}

/// The poll's answer once the sign-in landed. No expiry is given: the
/// access token's JWT `exp` is the only clock.
pub struct ReadyToken {
    pub access_token: String,
    pub refresh_token: String,
    /// The team the operator chose at sign-in, when it was a team login.
    pub team_id: Option<String>,
}

impl std::fmt::Debug for ReadyToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ReadyToken")
            .field("team_id", &self.team_id)
            .finish_non_exhaustive()
    }
}

/// Why a login request failed. Carries no request or response text.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    /// The request never produced a response (connect, TLS, timeout).
    #[error("{operation}: the Cursor backend could not be reached")]
    Transport { operation: &'static str },
    /// The backend answered a status the protocol gives no meaning to.
    #[error("{operation}: the Cursor backend answered HTTP {status}")]
    Status {
        operation: &'static str,
        status: StatusCode,
    },
    /// The backend answered 2xx with a body missing the fields a login needs.
    #[error("{operation}: the Cursor backend's answer was not a token pair")]
    Decode { operation: &'static str },
}

impl AuthError {
    /// Whether waiting and asking again can help: the backend unreachable,
    /// or answering 5xx/429.
    #[must_use]
    pub fn is_transient(&self) -> bool {
        match self {
            Self::Transport { .. } => true,
            Self::Status { status, .. } => {
                status.is_server_error() || *status == StatusCode::TOO_MANY_REQUESTS
            }
            Self::Decode { .. } => false,
        }
    }
}

const OP_POLL: &str = "auth/poll";
const OP_ME: &str = "GetMe";

/// The login HTTP client: a connection pool and a timeout, nothing per
/// account. The backend origin is a field so a test can point it at a stub.
pub struct Client {
    http: Option<reqwest::Client>,
    backend: String,
}

impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}

impl Client {
    /// Build the client against the production backend. Resolver or HTTP
    /// client construction failure leaves the client unavailable: encrypted
    /// DNS is mandatory, so there is no system-DNS fallback.
    #[must_use]
    pub fn new() -> Self {
        Self::with_backend(API_ORIGIN)
    }

    /// Build the client against `backend` (a test stub's origin).
    #[must_use]
    pub fn with_backend(backend: &str) -> Self {
        let http = match crate::upstream::dns::Resolvers::new() {
            Ok(resolvers) => reqwest::Client::builder()
                .timeout(REQUEST_TIMEOUT)
                .redirect(reqwest::redirect::Policy::none())
                .dns_resolver(std::sync::Arc::clone(
                    // The Cursor console is fixed overseas; login has no provider row yet.
                    resolvers.resolver(crate::upstream::Dns::Overseas),
                ))
                .build()
                .map_err(|error| anyhow::anyhow!(error)),
            Err(error) => Err(error),
        };
        let http = match http {
            Ok(http) => Some(http),
            Err(error) => {
                tracing::warn!(%error, "Cursor login client is unavailable: encrypted resolver setup failed");
                None
            }
        };
        Self {
            http,
            backend: backend.trim_end_matches('/').to_owned(),
        }
    }

    fn http(&self) -> Option<&reqwest::Client> {
        self.http.as_ref()
    }

    /// Ask once whether the sign-in landed. No `Authorization` and only the
    /// client-type header: the poll is anonymous by design.
    pub async fn poll(&self, challenge: &Challenge) -> Result<PollVerdict, AuthError> {
        let response = self
            .http()
            .ok_or(AuthError::Transport { operation: OP_POLL })?
            .get(format!("{}{POLL_PATH}", self.backend))
            .query(&[
                ("uuid", challenge.uuid().to_string()),
                ("verifier", challenge.verifier().to_owned()),
            ])
            .header(
                "x-cursor-client-type",
                crate::protocol::cursor::request::CLIENT_TYPE,
            )
            .header("x-ghost-mode", "true")
            .send()
            .await
            .map_err(|_| AuthError::Transport { operation: OP_POLL })?;
        let status = response.status();
        let body = response
            .bytes()
            .await
            .map_err(|_| AuthError::Transport { operation: OP_POLL })?;
        match status {
            StatusCode::NOT_FOUND => Ok(PollVerdict::Waiting),
            StatusCode::FORBIDDEN if names_policy_violation(&body) => {
                Ok(PollVerdict::PolicyRefused)
            }
            status if status.is_success() => parse_ready(&body)
                .map(PollVerdict::Ready)
                .ok_or(AuthError::Decode { operation: OP_POLL }),
            status => Err(AuthError::Status {
                operation: OP_POLL,
                status,
            }),
        }
    }

    /// The signed-in account's email, for the account card. Best effort: a
    /// failure is `None`, and the login is committed regardless.
    pub async fn email(&self, access_token: &str, team_id: Option<&str>) -> Option<String> {
        let http = self.http()?;
        let mut request = http
            .post(format!("{}{ME_PATH}", self.backend))
            .header("content-type", "application/json")
            .header(
                "connect-protocol-version",
                crate::protocol::cursor::request::CONNECT_PROTOCOL_VERSION,
            )
            .header(
                "x-cursor-client-version",
                crate::protocol::cursor::request::client_version(),
            )
            .header(
                "x-cursor-client-type",
                crate::protocol::cursor::request::CLIENT_TYPE,
            )
            .header("x-ghost-mode", "true")
            .bearer_auth(access_token)
            .body("{}");
        if let Some(team_id) = team_id {
            request = request.header("x-cursor-team-id", team_id);
        }
        let response = match request.send().await {
            Ok(response) => response,
            Err(_) => {
                tracing::warn!(
                    operation = OP_ME,
                    "Cursor account lookup failed after login"
                );
                return None;
            }
        };
        if !response.status().is_success() {
            tracing::warn!(
                operation = OP_ME,
                status = response.status().as_u16(),
                "Cursor account lookup was refused after login"
            );
            return None;
        }
        let body: serde_json::Value = response.json().await.ok()?;
        body.get("email")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|email| !email.is_empty())
            .map(str::to_owned)
    }
}

/// Unpadded base64url (RFC 4648 §5), the alphabet both the verifier and the
/// challenge are spelled in.
fn base64url_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let mut word = 0u32;
        for (index, byte) in chunk.iter().enumerate() {
            word |= u32::from(*byte) << (16 - 8 * index);
        }
        for index in 0..=chunk.len() {
            let sextet = (word >> (18 - 6 * index)) & 0x3f;
            out.push(char::from(ALPHABET[sextet as usize]));
        }
    }
    out
}

/// Whether a 403 body is the device-policy refusal.
fn names_policy_violation(body: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|value| {
            value
                .get("error")
                .and_then(serde_json::Value::as_str)
                .map(|error| error == POLICY_VIOLATION)
        })
        .unwrap_or(false)
}

/// The token pair of a 200 poll: `{accessToken, refreshToken, authId?,
/// selectedTeamId?}`. Both tokens are required; the team id is a number or
/// a string, kept as text.
fn parse_ready(body: &[u8]) -> Option<ReadyToken> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    let text = |name: &str| {
        value
            .get(name)
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|token| !token.is_empty())
            .map(str::to_owned)
    };
    let access_token = text("accessToken")?;
    let refresh_token = text("refreshToken")?;
    let team_id = match value.get("selectedTeamId") {
        Some(serde_json::Value::Number(number)) => Some(number.to_string()),
        Some(serde_json::Value::String(text)) if !text.trim().is_empty() => {
            Some(text.trim().to_owned())
        }
        _ => None,
    }
    // Team id 0 is "no team" in the vendor's own clients.
    .filter(|team_id| team_id != "0");
    Some(ReadyToken {
        access_token,
        refresh_token,
        team_id,
    })
}
