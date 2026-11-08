//! The credential kinds a `gateway_provider_keys` row may carry: `static` (a
//! plaintext api_key), `kiro_oidc` (a Kiro AWS SSO OIDC bundle),
//! `opencode_oauth` (an OpenCode Console device-flow bundle), `cursor_oauth`
//! (a Cursor browser-login bundle) and `openai_oauth` (an OpenAI Codex /
//! ChatGPT-subscription device-flow bundle).
//!
//! This is the create-time decision point shared by the admin surface, the
//! store and the relay. Nothing here performs I/O: it decides which of the two
//! credential columns a request fills and validates that the payload matches
//! the declared kind, so a mismatched pair never reaches the store.
//!
//! The kinds mirror the `auth_kind` CHECK constraint one to one
//! (migrations/0007, migrations/0017, migrations/0021, migrations/0022): adding a kind is a
//! schema change plus a variant here, never an inference from the row's other
//! columns.

use anyhow::anyhow;
use chrono::DateTime;
use chrono::Duration;
use chrono::Utc;

use crate::kiro::KiroOAuth;
use crate::openai::OpenaiOAuth;
use crate::opencode::OpencodeOAuth;

/// The longest access-token lifetime a stored Cursor bundle may claim. Cursor
/// publishes no metadata, so a bundle's `expires_at` is decoded from the access
/// token's JWT `exp` claim; a claim further out than this is a misread token,
/// not a credential to keep, and would never be refreshed.
const MAX_CURSOR_TOKEN_LIFETIME: Duration = Duration::days(730);

/// How a `gateway_provider_keys` row authenticates upstream, mirroring the
/// `auth_kind` CHECK constraint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthKind {
    /// The row's plaintext `api_key` (every provider without an account login).
    Static,
    /// The row's `oauth` bundle: Kiro AWS SSO OIDC.
    KiroOidc,
    /// The row's `oauth` bundle: OpenCode Console device-flow tokens.
    OpencodeOauth,
    /// The row's `oauth` bundle: Cursor browser-login tokens.
    CursorOauth,
    /// The row's `oauth` bundle: OpenAI Codex (ChatGPT subscription) tokens.
    OpenaiOauth,
}

impl AuthKind {
    /// The column spelling, which is also the string an admin request carries.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Static => "static",
            Self::KiroOidc => "kiro_oidc",
            Self::OpencodeOauth => "opencode_oauth",
            Self::CursorOauth => "cursor_oauth",
            Self::OpenaiOauth => "openai_oauth",
        }
    }

    /// Parse the column/request spelling. Unknown values fail loudly, so a typo
    /// can never silently fall back to `static`.
    pub fn parse(value: &str) -> anyhow::Result<Self> {
        match value {
            "static" => Ok(Self::Static),
            "kiro_oidc" => Ok(Self::KiroOidc),
            "opencode_oauth" => Ok(Self::OpencodeOauth),
            "cursor_oauth" => Ok(Self::CursorOauth),
            "openai_oauth" => Ok(Self::OpenaiOauth),
            other => Err(anyhow!(
                "unknown auth_kind {other:?} (expected \"static\", \"kiro_oidc\", \"opencode_oauth\", \"cursor_oauth\" or \"openai_oauth\")"
            )),
        }
    }
}

/// One Cursor account's OAuth bundle, persisted as snake_case JSON with an
/// RFC3339 `expires_at`.
///
/// The vendor's login and refresh answers carry no lifetime at all, so
/// `expires_at` is decoded from the access token's JWT `exp` claim by whoever
/// writes the bundle; the token manager only compares it against the clock.
/// Cursor does not rotate the refresh token, so `refresh_token` outlives every
/// refresh of `access_token` and is only replaced by a new login.
///
/// `email` and `team_id` are display/auth-decoration taken from the login
/// answer (`selectedTeamId`); `team_id` is the value the dispatch path sends as
/// `x-cursor-team-id`. Both tokens are secrets, so Debug redacts them.
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct CursorOAuth {
    /// Bearer for the Cursor backend (secret).
    pub access_token: String,
    /// Refresh token the `/oauth/token` grant redeems (secret; never rotated).
    pub refresh_token: String,
    /// UTC instant at which `access_token` stops being accepted, decoded from
    /// its JWT `exp`.
    pub expires_at: DateTime<Utc>,
    /// Account email as the login answer reported it (decoration only).
    pub email: Option<String>,
    /// Selected team id, sent as `x-cursor-team-id` on dispatch (never a
    /// credential on its own).
    pub team_id: Option<String>,
}

impl CursorOAuth {
    /// Every stored bundle must be usable: both tokens present, and an expiry
    /// the vendor's own token shape could produce. An already-expired bundle is
    /// accepted — the token manager refreshes it — but one claiming a lifetime
    /// beyond [`MAX_CURSOR_TOKEN_LIFETIME`] means the `exp` claim was misread.
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.access_token.trim().is_empty(),
            "Cursor OAuth access_token must not be empty"
        );
        anyhow::ensure!(
            !self.refresh_token.trim().is_empty(),
            "Cursor OAuth refresh_token must not be empty"
        );
        anyhow::ensure!(
            self.expires_at <= Utc::now() + MAX_CURSOR_TOKEN_LIFETIME,
            "Cursor OAuth expires_at {} is beyond the {MAX_CURSOR_TOKEN_LIFETIME} lifetime bound",
            self.expires_at
        );
        Ok(())
    }
}

/// Debug redacts both tokens: either one keeps the account alive, and this value
/// travels through logs and error paths.
impl std::fmt::Debug for CursorOAuth {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CursorOAuth")
            .field("access_token", &"<redacted>")
            .field("refresh_token", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .field("email", &self.email)
            .field("team_id", &self.team_id)
            .finish()
    }
}

/// The credential an admin key-create request settles on, already validated
/// against the target provider.
///
/// `Static` borrows the request's plaintext key; the OAuth variants own their
/// bundle because it is decoded from the request's raw `oauth` JSON according
/// to the declared `auth_kind` — the payload's type is not known before the
/// kind is parsed. That decode happens once per create request, never on the
/// dispatch path.
///
/// Debug is hand-written: a derived one would print the plaintext API key into
/// any log line or error path that formats the value (both bundle types redact
/// their own tokens).
pub enum KeyCredential<'a> {
    /// The existing credential shape: a plaintext API key.
    Static(&'a str),
    /// A Kiro OIDC bundle; the row stores no api_key.
    KiroOidc(KiroOAuth),
    /// An OpenCode Console bundle; the row stores no api_key.
    OpencodeOauth(OpencodeOAuth),
    /// A Cursor browser-login bundle; the row stores no api_key.
    CursorOauth(CursorOAuth),
    /// An OpenAI Codex (ChatGPT subscription) bundle; the row stores no
    /// api_key.
    OpenaiOauth(OpenaiOAuth),
}

impl std::fmt::Debug for KeyCredential<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Static(_) => formatter.write_str("KeyCredential::Static(<redacted>)"),
            Self::KiroOidc(oauth) => formatter.debug_tuple("KiroOidc").field(oauth).finish(),
            Self::OpencodeOauth(oauth) => {
                formatter.debug_tuple("OpencodeOauth").field(oauth).finish()
            }
            Self::CursorOauth(oauth) => formatter.debug_tuple("CursorOauth").field(oauth).finish(),
            Self::OpenaiOauth(oauth) => formatter.debug_tuple("OpenaiOauth").field(oauth).finish(),
        }
    }
}

/// Decide and validate a key-create request's credential (pure — the caller
/// resolves the provider row and passes its protocol).
///
/// Rules, in order:
/// - absent `auth_kind` keeps the pre-existing meaning, `static`;
/// - a `kiro` provider only ever authenticates with `kiro_oidc` (its relay path
///   speaks AWS SSO OIDC, so a static row there could never dispatch), and a
///   `kiro_oidc` credential only ever belongs to a `kiro` provider;
/// - a `cursor_oauth` credential only ever belongs to a `cursor` provider, the
///   only kernel that speaks the Cursor backend;
/// - an `openai_oauth` credential only ever belongs to an `openai_responses`
///   provider (the Codex backend speaks the Responses dialect; migrations/0022
///   adds no protocol, the kind alone marks the account login);
/// - a static key needs a non-empty `api_key` and must NOT carry `oauth`;
/// - an OAuth kind needs no api_key and a complete bundle of its own shape: the
///   raw `oauth` payload is decoded as that kind's bundle, never sniffed;
/// - any other `auth_kind` is rejected.
pub fn resolve_key_credential<'a>(
    protocol: &str,
    auth_kind: Option<&str>,
    api_key: Option<&'a str>,
    oauth: Option<&serde_json::Value>,
) -> anyhow::Result<KeyCredential<'a>> {
    let auth_kind = match auth_kind {
        Some(value) => AuthKind::parse(value)?,
        None => AuthKind::Static,
    };
    match auth_kind {
        AuthKind::Static => {
            anyhow::ensure!(
                protocol != "kiro",
                "a provider with protocol \"kiro\" requires auth_kind \"kiro_oidc\""
            );
            anyhow::ensure!(oauth.is_none(), "auth_kind \"static\" must not carry oauth");
            let api_key = api_key.unwrap_or_default();
            anyhow::ensure!(!api_key.trim().is_empty(), "api_key must not be empty");
            Ok(KeyCredential::Static(api_key))
        }
        AuthKind::KiroOidc => {
            anyhow::ensure!(
                protocol == "kiro",
                "auth_kind \"kiro_oidc\" requires a provider with protocol \"kiro\" (got {protocol:?})"
            );
            anyhow::ensure!(
                api_key.is_none_or(|key| key.trim().is_empty()),
                "a Kiro OIDC key must not carry an api_key"
            );
            let oauth = oauth.ok_or_else(|| anyhow!("auth_kind \"kiro_oidc\" requires oauth"))?;
            let oauth: KiroOAuth = decode_bundle(oauth, auth_kind)?;
            oauth.validate()?;
            Ok(KeyCredential::KiroOidc(oauth))
        }
        AuthKind::OpencodeOauth => {
            // The Kiro kernel owns `protocol = "kiro"`; an OpenCode bearer must
            // never be routed to it.
            anyhow::ensure!(
                protocol != "kiro",
                "auth_kind \"opencode_oauth\" is not a Kiro credential (provider protocol {protocol:?})"
            );
            anyhow::ensure!(
                api_key.is_none_or(|key| key.trim().is_empty()),
                "an OpenCode OAuth key must not carry an api_key"
            );
            let oauth =
                oauth.ok_or_else(|| anyhow!("auth_kind \"opencode_oauth\" requires oauth"))?;
            let oauth: OpencodeOAuth = decode_bundle(oauth, auth_kind)?;
            oauth.validate()?;
            Ok(KeyCredential::OpencodeOauth(oauth))
        }
        AuthKind::CursorOauth => {
            // The Cursor kernel owns `protocol = "cursor"`; the bundle is only
            // ever sent to the Cursor backend, so a foreign provider must not
            // hold one.
            anyhow::ensure!(
                protocol == "cursor",
                "auth_kind \"cursor_oauth\" requires a provider with protocol \"cursor\" (got {protocol:?})"
            );
            anyhow::ensure!(
                api_key.is_none_or(|key| key.trim().is_empty()),
                "a Cursor OAuth key must not carry an api_key"
            );
            let oauth =
                oauth.ok_or_else(|| anyhow!("auth_kind \"cursor_oauth\" requires oauth"))?;
            let oauth: CursorOAuth = decode_bundle(oauth, auth_kind)?;
            oauth.validate()?;
            Ok(KeyCredential::CursorOauth(oauth))
        }
        AuthKind::OpenaiOauth => {
            // The Codex backend speaks the Responses dialect, so the bundle only
            // belongs to a provider of that protocol; any other kernel would
            // send the bearer somewhere that cannot use it.
            anyhow::ensure!(
                protocol == "openai_responses",
                "auth_kind \"openai_oauth\" requires a provider with protocol \"openai_responses\" (got {protocol:?})"
            );
            anyhow::ensure!(
                api_key.is_none_or(|key| key.trim().is_empty()),
                "an OpenAI OAuth key must not carry an api_key"
            );
            let oauth =
                oauth.ok_or_else(|| anyhow!("auth_kind \"openai_oauth\" requires oauth"))?;
            let oauth: OpenaiOAuth = decode_bundle(oauth, auth_kind)?;
            oauth.validate()?;
            Ok(KeyCredential::OpenaiOauth(oauth))
        }
    }
}

/// Decode the raw `oauth` payload as the bundle its declared kind owns. The
/// kind decides the shape, so a payload of the other kind fails here instead of
/// being half-misread at dispatch time.
fn decode_bundle<T>(oauth: &serde_json::Value, auth_kind: AuthKind) -> anyhow::Result<T>
where
    T: serde::de::DeserializeOwned,
{
    serde_json::from_value(oauth.clone()).map_err(|error| {
        anyhow!(
            "oauth is not a valid {} bundle: {error}",
            auth_kind.as_str()
        )
    })
}
