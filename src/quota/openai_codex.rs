//! OpenAI Codex (ChatGPT subscription) usage windows from `wham/usage`.
//!
//! The answer is `{"plan_type", "rate_limit": {"allowed", "limit_reached",
//! "primary_window": W, "secondary_window": W}, "credits": {...},
//! "spend_control": {...}}` with `W = {"used_percent", "limit_window_seconds",
//! "reset_after_seconds", "reset_at"}`. The primary window is the short one
//! (5 hours on paid plans), the secondary the weekly one; both are mapped to
//! [`QuotaWindow`]s so Smart routing ranks the account like any other.
//!
//! Wire facts come from oh-my-pi's `usage/openai-codex.ts` and its test
//! fixtures and have not been exercised against the live endpoint. Credit-billed
//! seats (`rate_limit: null`, a `spend_control` cap instead) and the
//! `additional_rate_limits` meters (Spark) are not read: they yield no window.

use chrono::{DateTime, Duration, TimeZone as _, Utc};
use serde_json::Value;

use super::KeyQuota;
use super::QuotaWindow;
use super::endpoint::sort_windows;
use crate::upstream::OpenaiBearer;

const USAGE_URL: &str = "https://chatgpt.com/backend-api/wham/usage";

/// Probe one Codex account's plan windows.
///
/// The caller resolves the bearer first (`OpenaiTokens::resolve`), so this
/// module never touches the credential store. One attempt, no retry; a
/// non-2xx status, a timeout, an unreadable body or an answer without a window
/// all yield `None`, logged with the key id, status and byte count ONLY — the
/// answer is account data and the request carries a bearer.
pub async fn fetch_openai_codex_quota(
    bearer: &OpenaiBearer,
    key_id: i64,
    transport: &crate::upstream::transport::Transport,
    dns: crate::upstream::Dns,
) -> Option<KeyQuota> {
    let (status, body) = match crate::probe::codex_get(USAGE_URL, bearer, transport, dns).await {
        Ok(answer) => answer,
        Err(error) => {
            tracing::warn!(key_id, %error, "Codex quota probe: request failed");
            return None;
        }
    };
    if !(200..300).contains(&status) {
        tracing::warn!(
            key_id,
            status,
            bytes = body.len(),
            "Codex quota probe: upstream rejected the call"
        );
        return None;
    }
    let quota = parse_codex_usage(body.as_bytes(), Utc::now());
    if quota.is_none() {
        tracing::warn!(
            key_id,
            status,
            bytes = body.len(),
            "Codex quota probe: no usage window in the answer"
        );
    }
    quota
}

/// Map one `wham/usage` answer to plan windows; `None` for unparseable JSON, a
/// missing `rate_limit`, or no window carrying `used_percent`.
///
/// `limit_reached` is account-wide and does not name the binding window, so the
/// fullest window(s) are lifted to 100%. It is not applied when paid credits
/// still fund overage (`credits.unlimited|has_credits`, neither the credit
/// overage nor the spend control reached): Codex keeps serving such an account
/// past its plan windows, and a card showing it exhausted would park it in
/// Smart routing until the weekly reset.
pub(crate) fn parse_codex_usage(body: &[u8], now: DateTime<Utc>) -> Option<KeyQuota> {
    let root: Value = serde_json::from_slice(body).ok()?;
    let rate_limit = root.get("rate_limit")?.as_object()?;
    let mut windows: Vec<QuotaWindow> =
        [("primary_window", "主窗口"), ("secondary_window", "副窗口")]
            .into_iter()
            .filter_map(|(key, fallback_name)| window(rate_limit.get(key)?, fallback_name, now))
            .collect();
    if windows.is_empty() {
        return None;
    }
    let limit_reached = rate_limit.get("limit_reached").and_then(Value::as_bool) == Some(true);
    if limit_reached && !credits_fund_overage(&root) {
        let fullest = windows.iter().map(|w| w.used_pct).fold(0., f64::max);
        for window in windows.iter_mut().filter(|w| w.used_pct >= fullest) {
            window.used_pct = 100.;
        }
    }
    sort_windows(&mut windows);
    Some(KeyQuota {
        windows,
        balance: None,
        plan: None,
        details: Vec::new(),
    })
}

fn window(value: &Value, fallback_name: &str, now: DateTime<Utc>) -> Option<QuotaWindow> {
    let used_pct = value.get("used_percent")?.as_f64()?.clamp(0., 100.);
    let period_seconds = value
        .get("limit_window_seconds")
        .and_then(Value::as_f64)
        .filter(|seconds| *seconds > 0.);
    // Unlike opencode Go, an idle account reports its real reset: `reset_at`
    // stayed fixed across probes at 0% while `reset_after_seconds` counted
    // down (live pro account, 2026-11-08). Keeping it gives Smart routing its
    // time anchor and the card its trend chart.
    let resets_at = reset_time(value, now);
    Some(QuotaWindow {
        name: period_seconds.map_or_else(|| fallback_name.to_owned(), window_name),
        used_pct,
        resets_at,
        period_minutes: period_seconds.map(|seconds| (seconds / 60.) as i64),
        total: None,
        used: None,
    })
}

/// "5h" under a day (rounded to whole hours, at least 1), "7d" from a day up.
fn window_name(seconds: f64) -> String {
    if seconds >= 86_400. {
        format!("{}d", (seconds / 86_400.).round() as i64)
    } else {
        format!("{}h", ((seconds / 3_600.).round() as i64).max(1))
    }
}

/// `reset_at` is an epoch instant (seconds, or milliseconds above 1e12 — the
/// reference accepts both); `reset_after_seconds` is relative to `now`.
fn reset_time(value: &Value, now: DateTime<Utc>) -> Option<DateTime<Utc>> {
    if let Some(reset_at) = value.get("reset_at").and_then(Value::as_f64) {
        let millis = if reset_at > 1e12 {
            reset_at
        } else {
            reset_at * 1000.
        };
        if let Some(instant) = Utc.timestamp_millis_opt(millis as i64).single() {
            return Some(instant);
        }
    }
    let after = value.get("reset_after_seconds").and_then(Value::as_f64)?;
    now.checked_add_signed(Duration::milliseconds((after * 1000.) as i64))
}

fn credits_fund_overage(root: &Value) -> bool {
    let flag = |parent: &str, key: &str| {
        root.get(parent)
            .and_then(|block| block.get(key))
            .and_then(Value::as_bool)
    };
    let funded =
        flag("credits", "unlimited") == Some(true) || flag("credits", "has_credits") == Some(true);
    funded
        && flag("credits", "overage_limit_reached") != Some(true)
        && flag("spend_control", "reached") != Some(true)
}
