//! The OpenCode Console account credential: the device-flow token bundle an
//! `auth_kind = "opencode_oauth"` row persists in
//! `gateway_provider_keys.oauth`.
//!
//! Pure data — shape and freshness decisions only, no I/O and no vendor
//! knowledge. The console protocol client lives in [`auth`], the in-memory
//! registry of in-flight device logins in [`login`]; the orchestration that
//! drives a login lives in [`crate::admin_ops::Admin`]. Everything that reads a
//! credential starts here.

pub mod auth;
pub mod login;

use chrono::DateTime;
use chrono::Duration;
use chrono::Utc;

/// One OpenCode Console account's OAuth bundle, persisted as snake_case JSON
/// with an RFC3339 `expires_at`.
///
/// `access_token` is what the inference endpoints accept as a bearer, so both
/// tokens are secrets: a leaked refresh token keeps the account alive. The
/// optional metadata fields come from the console at login and are read for
/// display only — except `org_id`, which organization accounts also send as
/// `x-opencode-org-id` on inference requests.
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct OpencodeOAuth {
    /// Bearer token for the inference endpoints (secret).
    pub access_token: String,
    /// Console refresh token, rotated on every refresh (secret).
    pub refresh_token: String,
    /// UTC instant at which `access_token` stops being accepted.
    pub expires_at: DateTime<Utc>,
    /// The console origin that minted the bundle (`https://opencode.ai/console`);
    /// every login and refresh call goes only here.
    pub server: String,
    /// Organization workspace id, when the login was organization-scoped.
    pub org_id: Option<String>,
    /// Organization display name (decoration only, never for auth).
    pub org_name: Option<String>,
    /// Account email as the console reported it (decoration only).
    pub email: Option<String>,
}

impl OpencodeOAuth {
    /// Whether the access token keeps more than `skew` of validity at `now` —
    /// the refresh margin every caller shares. A bundle expiring inside the
    /// skew counts as stale, so a request never races the expiry.
    #[must_use]
    pub fn fresh_for(&self, now: DateTime<Utc>, skew: Duration) -> bool {
        self.expires_at - now > skew
    }

    /// Every stored bundle must be usable and must point at the console origin:
    /// the tokens are only ever sent there, so a foreign `server` is rejected
    /// at the write path instead of being trusted at dispatch time.
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.access_token.trim().is_empty(),
            "OpenCode OAuth access_token must not be empty"
        );
        anyhow::ensure!(
            !self.refresh_token.trim().is_empty(),
            "OpenCode OAuth refresh_token must not be empty"
        );
        anyhow::ensure!(
            is_opencode_console_url(&self.server),
            "OpenCode OAuth server must be https://opencode.ai/console (got {:?})",
            self.server
        );
        Ok(())
    }
}

/// Whether `server` is the OpenCode Console origin: HTTPS on 443, host
/// `opencode.ai`, path `/console`, with no userinfo, query or fragment.
///
/// Only this origin is ever dialed for device login and token refresh, so the
/// check is an exact host — a suffix match would also accept
/// `opencode.ai.example.com`.
#[must_use]
pub fn is_opencode_console_url(server: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(server) else {
        return false;
    };
    url.scheme() == "https"
        && url.port_or_known_default() == Some(443)
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && url
            .host_str()
            .is_some_and(|host| host.eq_ignore_ascii_case("opencode.ai"))
        && url.path().trim_end_matches('/') == "/console"
}

/// Debug redacts both tokens: this value travels through error paths and logs,
/// and either token grants the account. Only the non-secret coordinates stay
/// visible for diagnostics.
impl std::fmt::Debug for OpencodeOAuth {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OpencodeOAuth")
            .field("access_token", &"<redacted>")
            .field("refresh_token", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .field("server", &self.server)
            .field("org_id", &self.org_id)
            .finish_non_exhaustive()
    }
}
