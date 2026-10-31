use chrono::{DateTime, Utc};

use super::KeyQuota;
use super::QuotaWindow;

/// sub2api relay usage (`GET /v1/usage`, Wei-Shaw/sub2api
/// `gateway_handler.go`). Recognized only when `mode` is `quota_limited` or
/// `unrestricted` and `isValid` is a boolean — any other JSON is not sub2api.
/// Shapes (all money in `unit`, normally USD):
/// - wallet: `{"mode":"unrestricted","balance":9.96,"unit":"USD",…}`;
/// - subscription: `{"mode":"unrestricted","subscription":{"daily_usage_usd",
///   "daily_limit_usd"|null, weekly…, monthly…, "weekly_window_start"}}` —
///   only the weekly window has a derivable reset (start + 7 days);
/// - quota-limited key: `{"mode":"quota_limited","quota":{"limit","used"},
///   "rate_limits":[{"window":"5h"|"1d"|"7d","limit","used","reset_at"?}]}`.
///
/// Every shape may also carry `planName`, `status`, `expires_at` (top level
/// for a key, inside `subscription` for a plan) and the key-scoped
/// `usage.{today,total}` counters; those become `details` lines.
pub(super) fn parse_sub2api_usage(body: &str) -> Option<KeyQuota> {
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "snake_case")]
    enum Mode {
        QuotaLimited,
        Unrestricted,
    }
    #[derive(serde::Deserialize)]
    struct Response {
        // Presence-checked only: together they identify a sub2api reply.
        #[serde(rename = "mode")]
        _mode: Mode,
        #[serde(rename = "isValid")]
        _is_valid: bool,
        #[serde(rename = "planName")]
        plan_name: Option<String>,
        status: Option<String>,
        expires_at: Option<DateTime<Utc>>,
        unit: Option<String>,
        balance: Option<f64>,
        quota: Option<Quota>,
        #[serde(default)]
        rate_limits: Vec<RateLimit>,
        subscription: Option<Subscription>,
        usage: Option<Usage>,
    }
    #[derive(serde::Deserialize)]
    struct Usage {
        today: Option<Counters>,
        total: Option<Counters>,
    }
    #[derive(serde::Deserialize)]
    struct Counters {
        #[serde(default)]
        requests: i64,
        #[serde(default)]
        total_tokens: i64,
        /// What the relay actually charged (`cost` is the list price).
        #[serde(default)]
        actual_cost: f64,
    }
    #[derive(serde::Deserialize)]
    struct Quota {
        limit: f64,
        used: f64,
    }
    #[derive(serde::Deserialize)]
    struct RateLimit {
        window: String,
        limit: f64,
        used: f64,
        reset_at: Option<DateTime<Utc>>,
    }
    #[derive(serde::Deserialize)]
    struct Subscription {
        #[serde(default)]
        daily_usage_usd: f64,
        #[serde(default)]
        weekly_usage_usd: f64,
        #[serde(default)]
        monthly_usage_usd: f64,
        daily_limit_usd: Option<f64>,
        weekly_limit_usd: Option<f64>,
        monthly_limit_usd: Option<f64>,
        weekly_window_start: Option<DateTime<Utc>>,
        expires_at: Option<DateTime<Utc>>,
    }
    let response: Response = serde_json::from_str(body).ok()?;
    let unit = response.unit.as_deref().unwrap_or("USD");
    let money = |amount: f64| match unit {
        "USD" => format!("${amount:.2}"),
        "CNY" => format!("¥{amount:.2}"),
        other => format!("{amount:.2} {other}"),
    };
    let window = |name: &str, used: f64, limit: f64, resets_at, period_minutes| {
        (limit > 0.).then(|| QuotaWindow {
            name: name.to_string(),
            used_pct: (100. * used.max(0.) / limit).clamp(0., 100.),
            resets_at,
            period_minutes,
            total: Some(money(limit)),
        })
    };
    let mut windows = Vec::new();
    for limit in &response.rate_limits {
        let (name, period_minutes) = match limit.window.as_str() {
            "5h" => ("5 小时", 300),
            "1d" => ("今日", 1440),
            "7d" => ("7 天", 7 * 1440),
            _ => continue,
        };
        windows.extend(window(
            name,
            limit.used,
            limit.limit,
            limit.reset_at,
            Some(period_minutes),
        ));
    }
    if let Some(quota) = &response.quota {
        windows.extend(window("总额度", quota.used, quota.limit, None, None));
    }
    if let Some(subscription) = &response.subscription {
        let now = Utc::now();
        let weekly_reset = subscription
            .weekly_window_start
            .map(|start| start + chrono::Duration::days(7))
            .filter(|reset| *reset > now);
        for (name, used, limit, resets_at, period_minutes) in [
            (
                "今日",
                subscription.daily_usage_usd,
                subscription.daily_limit_usd,
                None,
                1440,
            ),
            (
                "本周",
                subscription.weekly_usage_usd,
                subscription.weekly_limit_usd,
                weekly_reset,
                7 * 1440,
            ),
            (
                "本月",
                subscription.monthly_usage_usd,
                subscription.monthly_limit_usd,
                None,
                30 * 1440,
            ),
        ] {
            let Some(limit) = limit else { continue };
            windows.extend(window(name, used, limit, resets_at, Some(period_minutes)));
        }
    }
    let balance = response.balance.map(money);
    let now = Utc::now();
    let mut details = Vec::new();
    // Plan line: name, a non-active status, and the expiry with days left.
    let expires_at = response
        .expires_at
        .or(response.subscription.as_ref().and_then(|s| s.expires_at));
    let mut plan = Vec::new();
    if let Some(name) = response
        .plan_name
        .as_deref()
        .filter(|name| !name.is_empty())
    {
        plan.push(format!("套餐 {name}"));
    }
    match response.status.as_deref() {
        Some("quota_exhausted") => plan.push("额度已用尽".to_string()),
        Some("expired") => plan.push("已过期".to_string()),
        _ => {}
    }
    if let Some(expires_at) = expires_at {
        let days = (expires_at - now).num_days();
        let date = expires_at.format("%Y-%m-%d");
        plan.push(match days {
            d if d < 0 => format!("{date} 到期（已过期）"),
            d => format!("{date} 到期（剩 {d} 天）"),
        });
    }
    if !plan.is_empty() {
        details.push(plan.join(" · "));
    }
    let counters = |label: &str, counters: &Counters| {
        format!(
            "{label} {} 次 · {} · {}",
            counters.requests,
            compact_count(counters.total_tokens),
            money(counters.actual_cost),
        )
    };
    if let Some(usage) = &response.usage {
        if let Some(today) = &usage.today {
            details.push(counters("今日", today));
        }
        if let Some(total) = &usage.total {
            details.push(counters("累计", total));
        }
    }
    if windows.is_empty() && balance.is_none() && details.is_empty() {
        return None;
    }
    Some(KeyQuota {
        windows,
        balance,
        details,
    })
}

/// A token count in compact form: "987", "45.1K", "1.10M", "2.35B".
fn compact_count(count: i64) -> String {
    let value = count as f64;
    match count.abs() {
        n if n >= 1_000_000_000 => format!("{:.2}B", value / 1e9),
        n if n >= 1_000_000 => format!("{:.2}M", value / 1e6),
        n if n >= 1_000 => format!("{:.1}K", value / 1e3),
        _ => count.to_string(),
    }
}
