//! Gateway key terms: validation of the label, expiry and quota a key is
//! created or edited with. Pure functions shared by the admin API and the
//! self-service API; handlers only wrap the error message in a 400.
//!
//! Rules: a label is non-empty after trimming and at most
//! [`MAX_LABEL_CHARS`] characters; a quota is a non-negative decimal USD
//! string (see [`crate::billing::parse_usd`]) stored as micro-USD, a
//! cumulative cap that never resets; an expiry must lie after `now`.
//!
//! [`create`] and [`patch`] turn a create request or a [`PatchBody`] into
//! the store values both APIs write; they stay free of I/O.

use chrono::DateTime;
use chrono::Utc;
use serde::Deserialize;

use crate::store::GatewayKeyPatch;
use crate::store::KeyTerms;

/// Longest label, in characters.
pub const MAX_LABEL_CHARS: usize = 64;

/// The trimmed label, or why it is refused.
pub fn label(text: &str) -> Result<&str, &'static str> {
    let label = text.trim();
    if label.is_empty() {
        return Err("label is required");
    }
    if label.chars().count() > MAX_LABEL_CHARS {
        return Err("label must be at most 64 characters");
    }
    Ok(label)
}

/// The quota in micro-USD (`None` = unlimited), or why it is refused.
pub fn quota(quota_usd: Option<&str>) -> Result<Option<i64>, &'static str> {
    let Some(text) = quota_usd else {
        return Ok(None);
    };
    match crate::billing::parse_usd(text.trim()) {
        Some(microus) if microus >= 0 => Ok(Some(microus)),
        Some(_) => Err("quota_usd must not be negative"),
        None => Err("quota_usd must be a decimal USD string with at most 6 decimals"),
    }
}

/// The expiry (`None` = never expires), or why it is refused: a key cannot
/// be given an expiry at or before `now`.
pub fn expiry(
    expires_at: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> Result<Option<DateTime<Utc>>, &'static str> {
    match expires_at {
        Some(at) if at <= now => Err("expires_at must be in the future"),
        other => Ok(other),
    }
}

/// The trimmed label and validated terms of a key being created, or why
/// they are refused.
pub fn create<'a>(
    label_text: &'a str,
    expires_at: Option<DateTime<Utc>>,
    quota_usd: Option<&str>,
    now: DateTime<Utc>,
) -> Result<(&'a str, KeyTerms), &'static str> {
    let label = label(label_text)?;
    let terms = KeyTerms {
        expires_at: expiry(expires_at, now)?,
        quota_microus: quota(quota_usd)?,
    };
    Ok((label, terms))
}

/// The JSON body of a key PATCH, shared by `PATCH /api/gateway-keys/{id}`
/// and `PATCH /user/keys/{id}`.
#[derive(Debug, Deserialize)]
pub struct PatchBody {
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
    /// Three-state: absent = untouched, null = never expires, RFC 3339 = set.
    #[serde(default, deserialize_with = "crate::tri_state::deserialize")]
    pub expires_at: Option<Option<DateTime<Utc>>>,
    /// Three-state: absent = untouched, null = unlimited, decimal USD
    /// string = set the cap.
    #[serde(default, deserialize_with = "crate::tri_state::deserialize")]
    pub quota_usd: Option<Option<String>>,
}

/// Validate a key PATCH body into a store patch, or the 400 message.
pub fn patch(body: &PatchBody, now: DateTime<Utc>) -> Result<GatewayKeyPatch<'_>, &'static str> {
    Ok(GatewayKeyPatch {
        label: body.label.as_deref().map(label).transpose()?,
        enabled: body.enabled,
        expires_at: body
            .expires_at
            .map(|expires_at| expiry(expires_at, now))
            .transpose()?,
        quota_microus: body
            .quota_usd
            .as_ref()
            .map(|cap| quota(cap.as_deref()))
            .transpose()?,
    })
}
