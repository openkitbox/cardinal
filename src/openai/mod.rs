//! The OpenAI Codex (ChatGPT subscription) account credential: the device-flow
//! token bundle an `auth_kind = "openai_oauth"` row persists in
//! `gateway_provider_keys.oauth`.
//!
//! Pure data — shape and freshness decisions plus the JWT identity decode, no
//! I/O and no vendor knowledge. The in-memory registry of in-flight device
//! logins lives in [`login`]; the orchestration that drives a login lives in
//! [`crate::admin_ops::Admin`]. Everything that reads a credential starts here.

pub mod auth;
pub mod login;

use chrono::DateTime;
use chrono::Duration;
use chrono::Utc;

/// The JWT claim object that carries the ChatGPT workspace and plan.
const AUTH_CLAIM: &str = "https://api.openai.com/auth";
/// The JWT claim object that carries the account email.
const PROFILE_CLAIM: &str = "https://api.openai.com/profile";

/// One ChatGPT account's OAuth bundle, persisted as snake_case JSON with an
/// RFC3339 `expires_at`.
///
/// `access_token` is what the Codex backend accepts as a bearer, so both
/// tokens are secrets: a leaked refresh token keeps the account alive.
/// `account_id` is the ChatGPT workspace the token draws limits from and is
/// sent on every upstream request; `email` and `plan_type` are display-only.
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct OpenaiOAuth {
    /// Bearer token for the Codex backend (secret).
    pub access_token: String,
    /// Refresh token, rotated on refresh (secret).
    pub refresh_token: String,
    /// UTC instant at which `access_token` stops being accepted.
    pub expires_at: DateTime<Utc>,
    /// The ChatGPT workspace id (`chatgpt-account-id` header value).
    pub account_id: String,
    /// Account email as the token named it (decoration only).
    #[serde(default)]
    pub email: Option<String>,
    /// Subscription plan as the token named it (decoration only).
    #[serde(default)]
    pub plan_type: Option<String>,
}

impl OpenaiOAuth {
    /// Whether the access token keeps more than `skew` of validity at `now` —
    /// the refresh margin every caller shares. A bundle expiring inside the
    /// skew counts as stale, so a request never races the expiry.
    #[must_use]
    pub fn fresh_for(&self, now: DateTime<Utc>, skew: Duration) -> bool {
        self.expires_at - now > skew
    }

    /// Every stored bundle must be usable: both tokens and the workspace id
    /// are required to make a request.
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.access_token.trim().is_empty(),
            "OpenAI OAuth access_token must not be empty"
        );
        anyhow::ensure!(
            !self.refresh_token.trim().is_empty(),
            "OpenAI OAuth refresh_token must not be empty"
        );
        anyhow::ensure!(
            !self.account_id.trim().is_empty(),
            "OpenAI OAuth account_id must not be empty"
        );
        Ok(())
    }
}

/// Debug redacts both tokens: this value travels through error paths and logs,
/// and either token grants the account. Only the non-secret coordinates stay
/// visible for diagnostics.
impl std::fmt::Debug for OpenaiOAuth {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OpenaiOAuth")
            .field("access_token", &"<redacted>")
            .field("refresh_token", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .field("account_id", &self.account_id)
            .field("email", &self.email)
            .field("plan_type", &self.plan_type)
            .finish()
    }
}

/// The identity slice a token's claims name. Every field is `None` when the
/// token does not carry it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TokenIdentity {
    /// The ChatGPT workspace id (`chatgpt_account_id`).
    pub account_id: Option<String>,
    /// The account email, trimmed and lowercased.
    pub email: Option<String>,
    /// The subscription plan, trimmed and lowercased.
    pub plan_type: Option<String>,
}

/// The identity a login's tokens name. Each field comes from the access token
/// first and falls back to the ID token (the plan, for one, may appear only
/// there). A token that is not a decodable JWT contributes nothing — never an
/// error — so the caller decides whether a missing `account_id` is fatal.
///
/// The signature is deliberately not verified: the claims are read from tokens
/// this process just received from the issuer, for display and to name the
/// workspace header; whether a token is accepted is the backend's judgement.
#[must_use]
pub fn token_identity(access_token: &str, id_token: Option<&str>) -> TokenIdentity {
    let access = jwt_claims(access_token);
    let id = id_token.and_then(jwt_claims);
    let pick = |claim: &str, field: &str, lowercase: bool| -> Option<String> {
        [access.as_ref(), id.as_ref()]
            .into_iter()
            .flatten()
            .find_map(|claims| claim_text(claims, claim, field, lowercase))
    };
    TokenIdentity {
        account_id: pick(AUTH_CLAIM, "chatgpt_account_id", false),
        email: pick(PROFILE_CLAIM, "email", true),
        plan_type: pick(AUTH_CLAIM, "chatgpt_plan_type", true),
    }
}

/// `claims[claim][field]` as trimmed text; blank counts as absent.
fn claim_text(
    claims: &serde_json::Value,
    claim: &str,
    field: &str,
    lowercase: bool,
) -> Option<String> {
    let text = claims.get(claim)?.get(field)?.as_str()?.trim();
    if text.is_empty() {
        return None;
    }
    Some(if lowercase {
        text.to_lowercase()
    } else {
        text.to_owned()
    })
}

/// The claims object of a three-segment JWT; `None` for anything else.
fn jwt_claims(token: &str) -> Option<serde_json::Value> {
    let mut segments = token.split('.');
    let (_header, payload, _signature) = (segments.next()?, segments.next()?, segments.next()?);
    if segments.next().is_some() {
        return None;
    }
    let decoded = base64url_decode(payload)?;
    serde_json::from_slice(&decoded).ok()
}

/// Decode one base64 segment: the URL-safe alphabet, with the standard `+`/`/`
/// and trailing padding tolerated.
///
/// Hand-written because the crate has no base64 dependency and a JWT segment
/// is the only decode this module needs (the same decoder as
/// `upstream::cursor_tokens`, which keeps its copy private). Non-alphabet
/// bytes and a dangling non-zero tail are errors, so a truncated payload never
/// decodes into nonsense claims.
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
            out.push(u8::try_from(accumulator >> bits).ok()?);
            accumulator &= (1u32 << bits) - 1;
        }
    }
    if accumulator != 0 {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::OpenaiOAuth;

    #[test]
    fn deserializes_legacy_bundle_without_optional_identity_fields() {
        let value = serde_json::json!({
            "access_token": "access",
            "refresh_token": "refresh",
            "expires_at": "2026-01-01T00:00:00Z",
            "account_id": "acct_123"
        });

        let bundle: OpenaiOAuth = serde_json::from_value(value).expect("legacy bundle decodes");

        assert_eq!(bundle.email, None);
        assert_eq!(bundle.plan_type, None);
    }
}
