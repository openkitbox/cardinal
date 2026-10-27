//! Native Kiro upstream support: the OAuth credential bundle shared by the
//! admin surface, the store and (later) the relay, plus the KAS wire profile
//! ([`profile`]) that owns the client identity and retry-header grammar.
//!
//! Kiro authenticates with AWS SSO OIDC (device-code / Builder ID), not an
//! API key: a key row of `auth_kind = "kiro_oidc"` carries
//! [`KiroOAuth`] in `gateway_provider_keys.oauth` instead of `api_key`.
//! This module owns the credential shape and the pure create-time decision
//! between the two credential kinds; nothing here performs I/O.

use anyhow::anyhow;

mod credentials;
pub mod profile;

pub use credentials::{
    AuthMethod, KiroOAuth, kas_endpoint_matches, parse_import_credentials, valid_region,
};
pub use profile::KasCall;

/// How a `gateway_provider_keys` row authenticates upstream, mirroring the
/// `auth_kind` CHECK constraint (migrations/0007).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AuthKind {
    /// The row's plaintext `api_key` (every non-Kiro provider).
    Static,
    /// The row's `oauth` bundle (Kiro only).
    KiroOidc,
}

impl AuthKind {
    fn parse(value: &str) -> anyhow::Result<Self> {
        match value {
            "static" => Ok(Self::Static),
            "kiro_oidc" => Ok(Self::KiroOidc),
            other => Err(anyhow!(
                "unknown auth_kind {other:?} (expected \"static\" or \"kiro_oidc\")"
            )),
        }
    }
}

/// The credential an admin create-key request settles on, already validated
/// against the target provider. Borrowed from the request body: the caller
/// writes it and drops it.
///
/// Debug is hand-written: a derived one would print the plaintext API key
/// into any log line or error path that formats the value.
#[derive(Clone, Copy)]
pub enum KeyCredential<'a> {
    /// The existing credential shape: a plaintext API key.
    Static(&'a str),
    /// A Kiro OIDC bundle; the row stores no api_key.
    KiroOidc(&'a KiroOAuth),
}

impl std::fmt::Debug for KeyCredential<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Static(_) => formatter.write_str("KeyCredential::Static(<redacted>)"),
            Self::KiroOidc(oauth) => formatter.debug_tuple("KiroOidc").field(oauth).finish(),
        }
    }
}

/// Decide and validate a key-create request's credential (pure — the caller
/// resolves the provider row and passes its protocol).
///
/// Rules, in order:
/// - absent `auth_kind` keeps the pre-existing meaning, `static`;
/// - a `kiro` provider only ever authenticates with `kiro_oidc` (its relay
///   path speaks AWS SSO OIDC, so a static row there could never dispatch);
/// - a static key needs a non-empty `api_key` and must NOT carry `oauth`;
/// - `kiro_oidc` needs a `kiro` provider, no api_key, and a complete bundle;
/// - any other `auth_kind` is rejected.
pub fn resolve_key_credential<'a>(
    protocol: &str,
    auth_kind: Option<&str>,
    api_key: Option<&'a str>,
    oauth: Option<&'a KiroOAuth>,
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
            oauth.validate()?;
            Ok(KeyCredential::KiroOidc(oauth))
        }
    }
}
