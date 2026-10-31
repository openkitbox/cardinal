//! Vendor quota / balance probing (admin plane), a sibling of [`crate::probe`].
//!
//! Hardcoded BY PROVIDER NAME (the `relay::capabilities` convention): names
//! are normalized by `relay::capabilities::provider_kind` — the vendor is the
//! first '-'-segment, a "code" segment marks the Coding Plan variant, and a
//! region suffix ("-intl") only changes the base_url host, never the quota
//! knowledge. "glm" (either variant) exposes plan quota windows, "deepseek"
//! and the kimi platform expose a prepaid balance, kimi Code exposes its
//! weekly quota plus short-rate windows, opencode Go its rolling/weekly/
//! monthly plan usage (Zen is pay-as-you-go — no source); any other name has
//! no vendor source and falls back to a speculative sub2api relay probe
//! (`/v1/usage`) — except the official vendors (anthropic, openai, gemini,
//! kiro), whose APIs expose no key balance.
//! The endpoint URL is derived from the provider row's base_url (scheme +
//! host + port) plus the table's fixed path, so a row pointing at a mock
//! server is probed there.
//!
//! Quota is decorative information for the GUI: an unknown provider name, an
//! invalid base_url, or a failed/unparseable probe all yield `None` — never
//! an error. Failures are logged (warn) and the card simply shows no meter.

mod commandcode;
mod deepseek;
mod endpoint;
mod glm;
mod key_quota;
mod kimi;
mod kiro;
mod monthly_anchor;
mod opencode;
mod sub2api;

pub use endpoint::fetch_quota;
pub use key_quota::KeyQuota;
pub use key_quota::QuotaWindow;
pub use kiro::fetch_kiro_quota;
pub use monthly_anchor::apply_monthly_anchor;
pub use monthly_anchor::next_monthly_reset;
