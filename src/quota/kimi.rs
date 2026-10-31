use chrono::{DateTime, Utc};

use super::Balance;
use super::KeyQuota;
use super::QuotaWindow;

/// Kimi balance (`/v1/users/me/balance`):
/// `{"data":{"available_balance":"12.34"}}` — Kimi bills in CNY.
pub(super) fn parse_kimi_balance(body: &str) -> Option<KeyQuota> {
    #[derive(serde::Deserialize)]
    struct Response {
        data: Option<Data>,
    }
    #[derive(serde::Deserialize)]
    struct Data {
        available_balance: String,
    }
    let response: Response = serde_json::from_str(body).ok()?;
    let amount: f64 = response
        .data?
        .available_balance
        .trim()
        .parse()
        .ok()
        .filter(|amount: &f64| amount.is_finite())?;
    Some(KeyQuota {
        windows: Vec::new(),
        balance: Some(Balance {
            amount,
            symbol: "¥".to_string(),
        }),
        details: Vec::new(),
    })
}

/// Kimi Code usages (`/coding/v1/usages`):
/// `{"usage":{"limit":"100","used":"12","resetTime":"<RFC3339>"}, "limits":[
/// {"window":{"duration":300,"timeUnit":"TIME_UNIT_MINUTE"},
///  "detail":{"limit":"100","remaining":"88","resetTime":"…"}}],
///  "usages":{"limit_5h":{"used_ratio":0.455,"reset_time":"<RFC3339>"},
///            "limit_month_total":{"used_ratio":1,"reset_time":"…"},
///            "limit_month_code":{"used_ratio":1,"reset_time":"…"}}}` —
/// `usage` is the legacy weekly quota (older responses), each `limits[]`
/// entry a short-rate window named from its span, and `usages` (newer
/// responses) carries ratio-based windows: the 5-hour window plus the
/// monthly buckets the subscription plans added. Numbers arrive as strings
/// OR plain numbers; a missing `used` reads as `limit - remaining`.
pub(super) fn parse_kimi_code_usages(body: &str) -> Option<KeyQuota> {
    #[derive(serde::Deserialize)]
    struct Response {
        usage: Option<Window>,
        #[serde(default)]
        limits: Vec<Limit>,
        #[serde(default)]
        usages: Usages,
    }
    #[derive(serde::Deserialize, Default)]
    struct Usages {
        limit_5h: Option<Ratio>,
        limit_month_total: Option<Ratio>,
        limit_month_code: Option<Ratio>,
    }
    /// A ratio-based window (`used_ratio` 0–1 + `reset_time`), the newer shape.
    #[derive(serde::Deserialize)]
    struct Ratio {
        used_ratio: Option<f64>,
        reset_time: Option<String>,
    }
    #[derive(serde::Deserialize)]
    struct Window {
        limit: Option<Num>,
        used: Option<Num>,
        remaining: Option<Num>,
        #[serde(rename = "resetTime")]
        reset_time: Option<String>,
    }
    #[derive(serde::Deserialize)]
    struct Limit {
        window: Option<Span>,
        detail: Option<Window>,
    }
    #[derive(serde::Deserialize)]
    struct Span {
        duration: Option<Num>,
        #[serde(rename = "timeUnit")]
        time_unit: Option<String>,
    }
    /// The vendor sends quota numbers as strings and plain numbers alike.
    #[derive(serde::Deserialize)]
    #[serde(untagged)]
    enum Num {
        Text(String),
        Number(f64),
    }
    impl Num {
        fn value(&self) -> Option<f64> {
            match self {
                Num::Text(text) => text.trim().parse::<f64>().ok(),
                Num::Number(number) => Some(*number),
            }
        }
    }
    fn quota_window(name: String, window: &Window, period_minutes: i64) -> Option<QuotaWindow> {
        let limit = window.limit.as_ref()?.value()?;
        if limit <= 0.0 {
            return None;
        }
        let used = window.used.as_ref().and_then(Num::value).or_else(|| {
            window
                .remaining
                .as_ref()
                .and_then(Num::value)
                .map(|remaining| limit - remaining)
        })?;
        let resets_at = window
            .reset_time
            .as_deref()
            .and_then(|text| DateTime::parse_from_rfc3339(text).ok())
            .map(|reset| reset.with_timezone(&Utc));
        Some(QuotaWindow {
            name,
            used_pct: (used / limit * 100.).clamp(0., 100.),
            resets_at,
            period_minutes: Some(period_minutes),
            total: None,
        })
    }
    /// A span reads as whole days when it divides evenly (≥ 1 天), else whole
    /// hours (≥ 1 小时), else minutes — with its length in minutes alongside.
    fn span_name(span: &Span) -> Option<(String, i64)> {
        let duration = span.duration.as_ref()?.value()?;
        let minutes = duration
            * match span.time_unit.as_deref() {
                Some("TIME_UNIT_MINUTE") => 1.,
                Some("TIME_UNIT_HOUR") => 60.,
                Some("TIME_UNIT_DAY") => 1440.,
                _ => return None,
            };
        if minutes <= 0. {
            // A zero/negative window is no window at all — skip it rather than
            // rendering "0 分钟" on the card.
            return None;
        }
        let name = if minutes >= 1440. && minutes % 1440. == 0. {
            format!("{} 天", (minutes / 1440.) as i64)
        } else if minutes >= 60. && minutes % 60. == 0. {
            format!("{} 小时", (minutes / 60.) as i64)
        } else {
            format!("{} 分钟", minutes as i64)
        };
        Some((name, minutes as i64))
    }
    /// A month is not a fixed length; 30 days is the sort-key approximation.
    const MONTH_MINUTES: i64 = 30 * 1440;
    fn ratio_window(name: &str, ratio: &Ratio, period_minutes: i64) -> Option<QuotaWindow> {
        let resets_at = ratio
            .reset_time
            .as_deref()
            .and_then(|text| DateTime::parse_from_rfc3339(text).ok())
            .map(|reset| reset.with_timezone(&Utc));
        Some(QuotaWindow {
            name: name.to_string(),
            used_pct: (ratio.used_ratio? * 100.).clamp(0., 100.),
            resets_at,
            period_minutes: Some(period_minutes),
            total: None,
        })
    }
    let response: Response = serde_json::from_str(body).ok()?;
    let mut windows = Vec::new();
    if let Some(month_total) = &response.usages.limit_month_total {
        windows.extend(ratio_window("本月", month_total, MONTH_MINUTES));
    }
    if let Some(month_code) = &response.usages.limit_month_code {
        windows.extend(ratio_window("本月 Code", month_code, MONTH_MINUTES));
    }
    if let Some(usage) = &response.usage {
        windows.extend(quota_window("本周".to_string(), usage, 7 * 1440));
    }
    for limit in &response.limits {
        let (Some(span), Some(detail)) = (&limit.window, &limit.detail) else {
            continue;
        };
        if let Some((name, minutes)) = span_name(span) {
            windows.extend(quota_window(name, detail, minutes));
        }
    }
    // The ratio-based 5-hour window only fills in when `limits[]` did not
    // describe one (same quota, less detail).
    if !windows.iter().any(|window| window.name.ends_with("小时"))
        && let Some(five_hour) = &response.usages.limit_5h
    {
        windows.extend(ratio_window("5 小时", five_hour, 300));
    }
    if windows.is_empty() {
        None
    } else {
        Some(KeyQuota {
            windows,
            balance: None,
            details: Vec::new(),
        })
    }
}
