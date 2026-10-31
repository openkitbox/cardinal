use chrono::{DateTime, Utc};

use super::Balance;
use super::KeyQuota;
use super::QuotaWindow;

/// Command Code credits (`GET /alpha/billing/credits`): the key's plan
/// windows and the dollars left on the month's credits —
/// `{"credits":{"planId":"individual-…","monthlyCredits":…,"purchasedCredits":…,
///  "freeCredits":…}, "windowLimits":{"fiveHour":{"used":…,"cap":…,
///  "resetAt":<unix s|ms>},"weekly":{…}}}`. A plan key (Studio / sign-in)
/// carries the two windows; a pay-as-you-go key has only the balance.
pub(super) fn parse_commandcode_quota(body: &str) -> Option<KeyQuota> {
    #[derive(serde::Deserialize)]
    struct Response {
        credits: Option<Credits>,
        #[serde(rename = "windowLimits")]
        windows: Option<Windows>,
    }
    #[derive(serde::Deserialize)]
    struct Credits {
        #[serde(rename = "planId")]
        plan_id: Option<String>,
        #[serde(rename = "monthlyCredits")]
        monthly: Option<serde_json::Value>,
        #[serde(rename = "purchasedCredits")]
        purchased: Option<serde_json::Value>,
        #[serde(rename = "freeCredits")]
        free: Option<serde_json::Value>,
    }
    #[derive(serde::Deserialize)]
    struct Windows {
        #[serde(rename = "fiveHour")]
        five_hour: Option<Window>,
        weekly: Option<Window>,
    }
    #[derive(serde::Deserialize)]
    struct Window {
        used: Option<serde_json::Value>,
        cap: Option<serde_json::Value>,
        #[serde(rename = "resetAt")]
        reset_at: Option<serde_json::Value>,
    }
    // Amounts/times arrive as numbers OR strings (the vendor serialises the
    // same shape both ways across vintages).
    fn number(value: &serde_json::Value) -> Option<f64> {
        match value {
            serde_json::Value::Number(number) => number.as_f64(),
            serde_json::Value::String(text) => text.trim().parse().ok(),
            _ => None,
        }
    }
    fn reset_time(value: &serde_json::Value) -> Option<DateTime<Utc>> {
        let millis = match value {
            serde_json::Value::String(text) => {
                return DateTime::parse_from_rfc3339(text)
                    .ok()
                    .map(|time| time.with_timezone(&Utc));
            }
            serde_json::Value::Number(number) => number.as_i64()? as f64,
            _ => return None,
        };
        if millis <= 0. {
            return None;
        }
        let millis = if millis < 1e12 {
            millis * 1000.
        } else {
            millis
        };
        DateTime::from_timestamp_millis(millis as i64)
    }
    let response: Response = serde_json::from_str(body).ok()?;
    // The two rate windows. The vendor sizes them as fixed fractions of the
    // month's pool (5-hour a fifth, weekly a half) — the only signal for the
    // monthly allowance when the reply names no plan.
    let mut windows = Vec::new();
    let mut implied_monthly = None::<f64>;
    if let Some(limits) = &response.windows {
        for (window, name, period_minutes, fraction) in [
            (limits.five_hour.as_ref(), "5 小时", 300i64, 5.),
            (limits.weekly.as_ref(), "本周", 7 * 1440, 2.),
        ] {
            let Some(window) = window else { continue };
            let (Some(used), Some(cap)) = (window.used.as_ref(), window.cap.as_ref()) else {
                continue;
            };
            let (Some(used), Some(cap)) = (number(used), number(cap)) else {
                continue;
            };
            if cap <= 0. {
                continue;
            }
            windows.push(QuotaWindow {
                name: name.to_string(),
                used_pct: (100. * used.max(0.) / cap).clamp(0., 100.),
                resets_at: window.reset_at.as_ref().and_then(reset_time),
                period_minutes: Some(period_minutes),
                total: None,
            });
            implied_monthly = Some(cap * fraction);
        }
    }
    let mut balance = None::<Balance>;
    // The month's credits: a progress-bar window when a full allowance is known
    // — from the vendor's plan table (a reply that names its plan) or derived
    // from the rate windows — else a bare balance. The reply itself never sends
    // the full allowance.
    if let Some(credits) = response.credits {
        let pools = [
            credits.monthly.as_ref(),
            credits.purchased.as_ref(),
            credits.free.as_ref(),
        ];
        let reported = pools.iter().any(Option::is_some);
        let left = pools
            .into_iter()
            .flatten()
            .map(|value| number(value).unwrap_or(0.))
            .sum::<f64>();
        let cap = commandcode_plan_cap(credits.plan_id.as_deref()).or(implied_monthly);
        match cap {
            Some(cap) if cap > 0. && left > 0. => windows.push(QuotaWindow {
                name: "本月".to_string(),
                used_pct: (100. * (cap - left).max(0.) / cap).clamp(0., 100.),
                resets_at: None, // the vendor never exposes a monthly reset instant
                period_minutes: Some(30 * 1440),
                total: Some(format!("${cap:.2}")),
            }),
            // A depleted pool is a real reading too: record it as $0 so the
            // balance history sees the spend-down, not a missing probe.
            _ if reported => {
                balance = Some(Balance {
                    amount: left.max(0.),
                    symbol: "$".to_string(),
                });
            }
            _ => {}
        }
    }
    if windows.is_empty() && balance.is_none() {
        None
    } else {
        Some(KeyQuota {
            windows,
            balance,
            details: Vec::new(),
        })
    }
}

/// Command Code's monthly credit allowance by plan — the vendor's documented
/// plan table (its `getPlanInfo`), which the `/alpha/billing/credits` reply
/// never carries. Keyed by `planId` prefix.
fn commandcode_plan_cap(plan_id: Option<&str>) -> Option<f64> {
    let plan_id = plan_id?.to_lowercase().replace('_', "-");
    const PLANS: &[(&str, f64)] = &[
        ("individual-provider", 15.),
        ("individual-pro-v1", 80.),
        ("individual-goat", 70.),
        ("individual-ultra", 300.),
        ("individual-max", 150.),
        ("individual-pro", 30.),
        ("individual-go", 10.),
        ("teams-pro", 40.),
    ];
    PLANS
        .iter()
        .find(|(prefix, _)| plan_id.starts_with(prefix))
        .map(|(_, cap)| *cap)
}
