//! The credential kinds a `gateway_provider_keys` row may carry: `static` (a
//! plaintext api_key), `kiro_oidc` (a Kiro AWS SSO OIDC bundle) and
//! `opencode_oauth` (an OpenCode Console device-flow bundle).
//!
//! This is the create-time decision point shared by the admin surface, the
//! store and the relay. Nothing here performs I/O: it decides which of the two
//! credential columns a request fills and validates that the payload matches
//! the declared kind, so a mismatched pair never reaches the store.
//!
//! The kinds mirror the `auth_kind` CHECK constraint one to one
//! (migrations/0007, migrations/0017): adding a kind is a schema change plus a
//! variant here, never an inference from the row's other columns.

use anyhow::anyhow;

use crate::kiro::KiroOAuth;
use crate::opencode::OpencodeOAuth;

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
}

impl AuthKind {
    /// The column spelling, which is also the string an admin request carries.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Static => "static",
            Self::KiroOidc => "kiro_oidc",
            Self::OpencodeOauth => "opencode_oauth",
        }
    }

    /// Parse the column/request spelling. Unknown values fail loudly, so a typo
    /// can never silently fall back to `static`.
    pub fn parse(value: &str) -> anyhow::Result<Self> {
        match value {
            "static" => Ok(Self::Static),
            "kiro_oidc" => Ok(Self::KiroOidc),
            "opencode_oauth" => Ok(Self::OpencodeOauth),
            other => Err(anyhow!(
                "unknown auth_kind {other:?} (expected \"static\", \"kiro_oidc\" or \"opencode_oauth\")"
            )),
        }
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
}

impl std::fmt::Debug for KeyCredential<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Static(_) => formatter.write_str("KeyCredential::Static(<redacted>)"),
            Self::KiroOidc(oauth) => formatter.debug_tuple("KiroOidc").field(oauth).finish(),
            Self::OpencodeOauth(oauth) => {
                formatter.debug_tuple("OpencodeOauth").field(oauth).finish()
            }
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
