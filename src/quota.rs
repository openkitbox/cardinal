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
//! no quota source.
//! The endpoint URL is derived from the provider row's base_url (scheme +
//! host + port) plus the table's fixed path, so a row pointing at a mock
//! server is probed there.
//!
//! Quota is decorative information for the GUI: an unknown provider name, an
//! invalid base_url, or a failed/unparseable probe all yield `None` — never
//! an error. Failures are logged (warn) and the card simply shows no meter.

use chrono::{DateTime, Utc};

/// One probe attempt's budget (mirrors `probe`'s model-list probing).
const PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(8);
/// Quota/balance payloads are a few small objects; 8 MiB caps abuse/misconfig
/// (mirrors `probe`).
const MAX_BODY: usize = 8 << 20;

/// One quota window of a vendor plan (e.g. a 5-hour token window or the
/// weekly window): how much of the allowance is spent and when it resets.
/// Serialize/Deserialize: readings persist as JSONB snapshots
/// (gateway_key_quota_snapshots) for the GUI's instant first paint.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct QuotaWindow {
    /// Display name ("5 小时", "本周").
    pub name: String,
    /// Share of the window already used, 0–100.
    pub used_pct: f64,
    /// When the window resets, when the vendor says so.
    pub resets_at: Option<DateTime<Utc>>,
    /// Approximate window length in minutes — a SORT KEY only (a month is not
    /// a fixed number of minutes), so cards render shortest period first
    /// regardless of which vendor/parser produced the reading. Snapshots
    /// written before this field existed read as `None` and sort last until
    /// the next probe rewrites them.
    #[serde(default)]
    pub period_minutes: Option<i64>,
    /// The window's full allowance ("$70.00") for a money-window (a credit
    /// pool), so the card can render "remaining / total" instead of a bare
    /// percent. Omit the unit when the window name already carries it.
    /// `None` for a window without a known total (e.g. a rate window's count
    /// is already folded into `used_pct`).
    #[serde(default)]
    pub total: Option<String>,
}

/// What one key's vendor account reports: plan quota windows and/or a prepaid
/// balance. Either side may be empty when the vendor exposes neither.
///
/// Persisted as JSONB in `gateway_key_quota_snapshots`: evolution rule is
/// append-only fields carrying `#[serde(default)]` — anything stricter breaks
/// every stored snapshot row until the next successful probe rewrites it.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct KeyQuota {
    #[serde(default)]
    pub windows: Vec<QuotaWindow>,
    /// Display-ready balance ("¥12.34").
    #[serde(default)]
    pub balance: Option<String>,
}

/// One vendor quota endpoint: full URL, auth flavour, response parser.
struct Endpoint {
    url: String,
    /// GLM's monitor endpoint takes the bare key (no `Bearer ` prefix).
    bare_auth: bool,
    parse: fn(&str) -> Option<KeyQuota>,
}

/// Probe one key's quota/balance at its provider. `None` when the provider
/// name has no quota source, the base_url is not a valid http(s) URL, or the
/// fetch/parse failed (logged — callers treat quota as decorative).
pub async fn fetch_quota(provider_name: &str, base_url: &str, api_key: &str) -> Option<KeyQuota> {
    let endpoint = quota_endpoint(provider_name, base_url)?;
    let client = reqwest::Client::new();
    let request = client
        .get(&endpoint.url)
        .timeout(PROBE_TIMEOUT)
        .header(reqwest::header::ACCEPT, "application/json");
    let request = match endpoint.bare_auth {
        true => request.header(reqwest::header::AUTHORIZATION, api_key),
        false => request.bearer_auth(api_key),
    };
    let body = async {
        let response = request.send().await?;
        let status = response.status();
        let body = read_bounded(response).await?;
        anyhow::ensure!(status.is_success(), "{status}");
        Ok::<_, anyhow::Error>(body)
    }
    .await;
    match body {
    Ok(body) => (endpoint.parse)(&body)
      .map(|mut quota| {
        sort_windows(&mut quota.windows);
        quota
      })
      .or_else(|| {
        // An empty-but-valid response (e.g. `{}` — account in a transient
        // state) is not a parse failure; only log body when it has content.
        if body.trim().len() > 2 {
          tracing::warn!(provider = provider_name, url = %endpoint.url, body = %body, "quota probe: unparseable response");
        } else {
          tracing::debug!(provider = provider_name, url = %endpoint.url, body = %body, "quota probe: empty response");
        }
        None
      }),
    Err(error) => {
      tracing::warn!(provider = provider_name, url = %endpoint.url, error = %format!("{error:#}"), "quota probe failed");
      None
    }
  }
}

/// Canonical card order, shortest window first: parsers emit in vendor
/// payload order (which differs per vendor and per response vintage), so the
/// sort lives at this single choke point. Windows without a period
/// (snapshots predating `period_minutes`) sort last; the sort is stable, so
/// same-period windows (e.g. Kimi's two monthly buckets) keep parser order.
fn sort_windows(windows: &mut [QuotaWindow]) {
    windows.sort_by_key(|window| window.period_minutes.unwrap_or(i64::MAX));
}

/// The quota endpoint for a provider row, or `None` when the name has no
/// quota source or the base_url is not a valid http(s) URL.
fn quota_endpoint(provider_name: &str, base_url: &str) -> Option<Endpoint> {
    let origin = crate::relay::capabilities::origin_of(base_url)?;
    Some(
        match crate::relay::capabilities::provider_kind(provider_name) {
            ("glm", _) => Endpoint {
                url: format!("{origin}/api/monitor/usage/quota/limit"),
                bare_auth: true,
                parse: parse_glm_quota,
            },
            ("deepseek", _) => Endpoint {
                url: format!("{origin}/user/balance"),
                bare_auth: false,
                parse: parse_deepseek_balance,
            },
            ("kimi", false) => Endpoint {
                url: format!("{origin}/v1/users/me/balance"),
                bare_auth: false,
                parse: parse_kimi_balance,
            },
            ("kimi", true) => Endpoint {
                url: format!("{origin}/coding/v1/usages"),
                bare_auth: false,
                parse: parse_kimi_code_usages,
            },
            // OpenCode Go only: Zen (`/zen`) is pay-as-you-go and has no quota
            // windows.
            ("opencode", _) => {
                let base = base_url.trim_end_matches('/');
                if !(base.ends_with("/zen/go") || base.contains("/zen/go/")) {
                    return None;
                }
                Endpoint {
                    url: format!("{origin}/zen/go/v1/usage"),
                    bare_auth: false,
                    parse: parse_opencode_go_quota,
                }
            }
            // Command Code: a plan key (Studio / sign-in) reports its 5-hour and
            // weekly windows plus the dollars left on the month's credits; a
            // pay-as-you-go key has no windows (and only ever a balance).
            ("commandcode", _) => Endpoint {
                url: format!("{origin}/alpha/billing/credits"),
                bare_auth: false,
                parse: parse_commandcode_quota,
            },
            _ => return None,
        },
    )
}

/// Read a response body with a hard byte cap (mirrors `probe::read_bounded` —
/// a runaway or hostile endpoint must not fill memory).
async fn read_bounded(response: reqwest::Response) -> anyhow::Result<String> {
    use futures::StreamExt as _;
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        body.extend_from_slice(&chunk?);
        anyhow::ensure!(body.len() <= MAX_BODY, "配额响应超过 {MAX_BODY} 字节上限");
    }
    Ok(String::from_utf8_lossy(&body).into_owned())
}

/// GLM plan quota (`/api/monitor/usage/quota/limit`):
/// `{"success":true,"data":{"level":"pro","limits":[{"type":"TOKENS_LIMIT",
/// "unit":3,"number":5,"percentage":12,"nextResetTime":<ms>}, …,
/// {"type":"TIME_LIMIT","unit":5,"number":1,"usage":4000,"currentValue":4,
///  "percentage":1,"nextResetTime":<ms>}]}}`.
/// Kept windows: unit 3 = an N-hour model-token window (`number` is the hour
/// count, ≤0 reads as the standard 5), unit 6 = the weekly model-token window,
/// and the `TIME_LIMIT` row = the monthly MCP tool-call quota (its `type`
/// says so; `number` is the month count, so "1 个月" reads as "本月"). A
/// window without `percentage` has no reading and is skipped.
fn parse_glm_quota(body: &str) -> Option<KeyQuota> {
    #[derive(serde::Deserialize)]
    struct Response {
        success: bool,
        data: Option<Data>,
    }
    #[derive(serde::Deserialize)]
    struct Data {
        #[serde(default)]
        limits: Vec<Limit>,
    }
    #[derive(serde::Deserialize)]
    struct Limit {
        #[serde(rename = "type")]
        kind: Option<String>,
        unit: Option<i64>,
        number: Option<i64>,
        percentage: Option<f64>,
        #[serde(rename = "nextResetTime")]
        next_reset_time: Option<i64>,
    }
    let response: Response = serde_json::from_str(body).ok()?;
    if !response.success {
        return None;
    }
    let windows = response
        .data?
        .limits
        .into_iter()
        .filter_map(|limit| {
            let used_pct = limit.percentage?.clamp(0., 100.);
            let resets_at = limit
                .next_reset_time
                .and_then(DateTime::from_timestamp_millis);
            // TIME_LIMIT rows are the monthly MCP tool-call quota — kept as its own
            // window; unit-3/unit-6 rows are the model-token windows.
            let (name, period_minutes) = match (limit.kind.as_deref(), limit.unit?) {
                (Some("TIME_LIMIT"), _) => ("本月 MCP".to_string(), 30 * 1440),
                (_, 3) => {
                    let hours = limit.number.filter(|hours| *hours > 0).unwrap_or(5);
                    (format!("{hours} 小时"), hours * 60)
                }
                (_, 6) => ("本周".to_string(), 7 * 1440),
                _ => return None,
            };
            Some(QuotaWindow {
                name,
                used_pct,
                resets_at,
                period_minutes: Some(period_minutes),
                total: None,
            })
        })
        .collect::<Vec<_>>();
    if windows.is_empty() {
        // An empty "success" reading (transient vendor payload, or every window
        // filtered out) is not a reading: keep the previous snapshot instead of
        // overwriting it with nothing.
        return None;
    }
    Some(KeyQuota {
        windows,
        balance: None,
    })
}

/// DeepSeek balance (`/user/balance`):
/// `{"balance_infos":[{"currency":"CNY","total_balance":"12.34"}]}` — the
/// first entry, with the currency folded to its symbol; the amount is
/// normalized to two decimals (an unparseable amount is no reading, not
/// "¥abc").
fn parse_deepseek_balance(body: &str) -> Option<KeyQuota> {
    #[derive(serde::Deserialize)]
    struct Response {
        #[serde(default)]
        balance_infos: Vec<BalanceInfo>,
    }
    #[derive(serde::Deserialize)]
    struct BalanceInfo {
        currency: String,
        total_balance: String,
    }
    let response: Response = serde_json::from_str(body).ok()?;
    let first = response.balance_infos.into_iter().next()?;
    let symbol = match first.currency.as_str() {
        "CNY" => "¥",
        "USD" => "$",
        _ => return None,
    };
    let amount: f64 = first.total_balance.trim().parse().ok()?;
    Some(KeyQuota {
        windows: Vec::new(),
        balance: Some(format!("{symbol}{amount:.2}")),
    })
}

/// Kimi balance (`/v1/users/me/balance`):
/// `{"data":{"available_balance":"12.34"}}` — Kimi bills in CNY.
fn parse_kimi_balance(body: &str) -> Option<KeyQuota> {
    #[derive(serde::Deserialize)]
    struct Response {
        data: Option<Data>,
    }
    #[derive(serde::Deserialize)]
    struct Data {
        available_balance: String,
    }
    let response: Response = serde_json::from_str(body).ok()?;
    let amount: f64 = response.data?.available_balance.trim().parse().ok()?;
    Some(KeyQuota {
        windows: Vec::new(),
        balance: Some(format!("¥{amount:.2}")),
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
fn parse_kimi_code_usages(body: &str) -> Option<KeyQuota> {
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
        })
    }
}

/// OpenCode Go plan usage (`/zen/go/v1/usage`):
/// `{"usage":{"rolling":{"status":"ok","percent":37,"resetsAt":"<RFC3339>"},
///            "weekly":{…},"monthly":{"status":"rate-limited","percent":100,…}}}`
/// — rolling is the 5-hour window, weekly 7 days, monthly the month. A window
/// at 0% reports resetsAt as now-plus-its-length, a time nothing happens at,
/// so its reset is left out.
fn parse_opencode_go_quota(body: &str) -> Option<KeyQuota> {
    #[derive(serde::Deserialize)]
    struct Response {
        #[serde(default)]
        usage: std::collections::HashMap<String, Window>,
    }
    #[derive(serde::Deserialize)]
    struct Window {
        percent: Option<f64>,
        #[serde(rename = "resetsAt")]
        resets_at: Option<String>,
    }
    let response: Response = serde_json::from_str(body).ok()?;
    let windows = [
        ("rolling", "5 小时", 300),
        ("weekly", "7 天", 7 * 1440),
        ("monthly", "本月", 30 * 1440),
    ]
    .into_iter()
    .filter_map(|(key, name, period_minutes)| {
        let window = response.usage.get(key)?;
        let used_pct = window.percent?.clamp(0., 100.);
        let resets_at = if used_pct > 0. {
            window
                .resets_at
                .as_deref()
                .and_then(|text| DateTime::parse_from_rfc3339(text).ok())
                .map(|reset| reset.with_timezone(&Utc))
        } else {
            None
        };
        Some(QuotaWindow {
            name: name.to_string(),
            used_pct,
            resets_at,
            period_minutes: Some(period_minutes as i64),
            total: None,
        })
    })
    .collect::<Vec<_>>();
    if windows.is_empty() {
        None
    } else {
        Some(KeyQuota {
            windows,
            balance: None,
        })
    }
}

/// Command Code credits (`GET /alpha/billing/credits`): the key's plan
/// windows and the dollars left on the month's credits —
/// `{"credits":{"planId":"individual-…","monthlyCredits":…,"purchasedCredits":…,
///  "freeCredits":…}, "windowLimits":{"fiveHour":{"used":…,"cap":…,
///  "resetAt":<unix s|ms>},"weekly":{…}}}`. A plan key (Studio / sign-in)
/// carries the two windows; a pay-as-you-go key has only the balance.
fn parse_commandcode_quota(body: &str) -> Option<KeyQuota> {
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
    let mut balance = None::<String>;
    // The month's credits: a progress-bar window when a full allowance is known
    // — from the vendor's plan table (a reply that names its plan) or derived
    // from the rate windows — else a bare balance. The reply itself never sends
    // the full allowance.
    if let Some(credits) = response.credits {
        let left = [
            credits.monthly.as_ref(),
            credits.purchased.as_ref(),
            credits.free.as_ref(),
        ]
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
            _ => {
                if left > 0. {
                    balance = Some(format!("${left:.2}"));
                }
            }
        }
    }
    if windows.is_empty() && balance.is_none() {
        None
    } else {
        Some(KeyQuota { windows, balance })
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

// ---------- Kiro (GetUsageLimits) ----------

/// One prepared quota call: the protocol DTO, the credential header (kept out
/// of [`crate::protocol::Prepared::headers`] by the transport's contract) and
/// the query pairs the transport appends to the URL.
struct KiroUsageCall {
    prepared: crate::protocol::Prepared,
    auth: Vec<(&'static str, String)>,
    query: Vec<(&'static str, String)>,
}

/// Build the Rust shell's `GetUsageLimits` call.
///
/// The row's `base_url` is the KAS runtime root, but this operation lives on
/// the credential's AWS region host instead — so the URL is derived from the
/// OAuth bundle's `api_region`, never from operator-editable configuration.
/// That region becomes a hostname and a bearer travels with the call, so
/// anything outside AWS' region grammar is refused outright (fail closed).
///
/// Wire shape mirrors the reference `kiro2claude` (`getUsageLimits`), with one
/// deliberate deviation: `isEmailRequired` is `false` in both the query string
/// and the body. The reference asks for the account email because its
/// `/kiro/usage` endpoint exists to show it; cardinal reads nothing out of
/// `userInfo`, and the vendor only returns PII when asked — so it never asks.
/// `profileArn` stays doubly written when the bundle carries one.
fn kiro_usage_request(
    api_region: &str,
    profile_arn: Option<&str>,
    bearer: &str,
) -> Option<KiroUsageCall> {
    if !crate::kiro::valid_region(api_region) {
        return None;
    }
    let mut body = serde_json::Map::new();
    body.insert("isEmailRequired".to_owned(), serde_json::Value::Bool(false));
    let mut query = vec![("isEmailRequired", "false".to_string())];
    if let Some(profile_arn) = profile_arn {
        body.insert(
            "profileArn".to_owned(),
            serde_json::Value::String(profile_arn.to_owned()),
        );
        query.push(("profileArn", profile_arn.to_owned()));
    }
    // Single attempt, but the grammar still comes from its one owner:
    // `retry_headers` renders `attempt=1; max=1`, and `kiro = false` leaves
    // `x-kiro-attempt` off (the reference has no capture evidence for it on
    // this endpoint — adding an uncaptured header would change the profile).
    let mut headers = crate::kiro::profile::usage_static_headers();
    headers.extend(crate::kiro::profile::retry_headers(
        &uuid::Uuid::new_v4().to_string(),
        1,
        1,
        false,
        chrono::Utc::now(),
    ));
    Some(KiroUsageCall {
        prepared: crate::protocol::Prepared {
            protocol: crate::protocol::ProtocolId::Kiro,
            url: format!(
                "https://{}/",
                crate::kiro::profile::runtime_host(api_region)
            ),
            content_type: "application/x-amz-json-1.0",
            body: bytes::Bytes::from(serde_json::Value::Object(body).to_string()),
            stream: false,
            headers,
        },
        auth: vec![("authorization", format!("Bearer {bearer}"))],
        query,
    })
}

/// Probe one Kiro key's monthly credits.
///
/// The credential comes from the shared [`crate::upstream::KiroTokens`] — the
/// same single-flight instance dispatch uses, so a probe can refresh a stale
/// bearer and persist it, and a concurrent chat reuses that one refresh. The
/// call itself is one attempt with no retry (a probe must never mint vendor
/// traffic of its own); a rejected status, an unreadable body, malformed JSON,
/// or an answer with no `CREDIT` row all yield `None`, logged with the status
/// and byte count ONLY — the answer may carry the account email and directory
/// user id, and neither may reach a log line.
pub async fn fetch_kiro_quota(
    pool: &sqlx::PgPool,
    tokens: &crate::upstream::KiroTokens,
    key: &crate::store::ProviderKeyRow,
) -> Option<KeyQuota> {
    let context = match tokens.access_token(pool, key).await {
        Ok(context) => context,
        Err(error) => {
            tracing::warn!(key_id = key.id, error = %error, "Kiro quota probe: credential unavailable");
            return None;
        }
    };
    if context.profile_arn.is_none() {
        tracing::debug!(
            key_id = key.id,
            "Kiro quota probe: no profileArn; the vendor may reject GetUsageLimits"
        );
    }
    let Some(call) = kiro_usage_request(
        &context.api_region,
        context.profile_arn.as_deref(),
        context.bearer(),
    ) else {
        tracing::warn!(key_id = key.id, api_region = %context.api_region, "Kiro quota probe: credential's API region cannot form a usage host");
        return None;
    };
    let transport = tokens.transport();
    let deadline = std::time::Instant::now() + PROBE_TIMEOUT;
    let response = match transport
        .send_with_headers(&call.prepared, &call.auth, &call.query, deadline)
        .await
    {
        Ok(response) => response,
        Err(error) => {
            tracing::warn!(key_id = key.id, %error, "Kiro quota probe: send failed");
            return None;
        }
    };
    let status = response.status().as_u16();
    let body = match transport.read_body(response, MAX_BODY, deadline).await {
        Ok(body) => body,
        Err(error) => {
            tracing::warn!(key_id = key.id, status, %error, "Kiro quota probe: response unreadable");
            return None;
        }
    };
    if !(200..300).contains(&status) {
        // Status and size only: the vendor's error body can echo request data.
        tracing::warn!(
            key_id = key.id,
            status,
            bytes = body.len(),
            "Kiro quota probe: upstream rejected the call"
        );
        return None;
    }
    let quota = parse_kiro_quota(&String::from_utf8_lossy(&body));
    if quota.is_none() {
        tracing::warn!(
            key_id = key.id,
            status,
            bytes = body.len(),
            "Kiro quota probe: no CREDIT window in the answer"
        );
    }
    quota
}

/// Kiro monthly credits (`POST /?isEmailRequired=false`, target
/// `AmazonCodeWhispererService.GetUsageLimits`):
/// `{"usageBreakdownList":[{"resourceType":"CREDIT","currentUsage":5469,
///   "currentUsageWithPrecision":5469.38,"usageLimit":10000,
///   "usageLimitWithPrecision":10000,"nextDateReset":1777593600}],
///   "nextDateReset":1777593600, ...}`.
///
/// Only a `CREDIT` breakdown is a credits reading (`TOKENS` rows describe the
/// plan's other unit). The precision fields win over the integers when present
/// — one credit is a whole invocation, so `currentUsage: 5469` truncates the
/// real 5469.38 — and a non-positive allowance is no reading at all rather than
/// a division by zero or a fictional 0% meter. Bonuses and free-trial
/// allowances are deliberately NOT folded in: they are separate pools with
/// their own expiry, and the card shows the plan's own allowance. The reset
/// instant comes from the breakdown, then the document-level `nextDateReset`
/// (Unix seconds, the vendor's only shape); the window itself is a month,
/// approximated as 30 days for the sort key like every other monthly window.
fn parse_kiro_quota(body: &str) -> Option<KeyQuota> {
    #[derive(serde::Deserialize)]
    struct Response {
        #[serde(rename = "usageBreakdownList", default)]
        breakdowns: Vec<Breakdown>,
        #[serde(rename = "nextDateReset")]
        next_reset: Option<serde_json::Value>,
    }
    #[derive(serde::Deserialize)]
    struct Breakdown {
        #[serde(rename = "resourceType")]
        resource_type: Option<String>,
        #[serde(rename = "currentUsageWithPrecision")]
        used_precision: Option<f64>,
        #[serde(rename = "currentUsage")]
        used: Option<f64>,
        #[serde(rename = "usageLimitWithPrecision")]
        limit_precision: Option<f64>,
        #[serde(rename = "usageLimit")]
        limit: Option<f64>,
        #[serde(rename = "nextDateReset")]
        next_reset: Option<serde_json::Value>,
    }
    /// Precision first, integer second: only an absent precision field falls
    /// back (a genuine `0` is a reading, not a missing value).
    fn amount(precision: Option<f64>, integer: Option<f64>) -> Option<f64> {
        precision.or(integer).filter(|value| value.is_finite())
    }
    /// The vendor's reset instant: Unix seconds as a number or a numeric string.
    fn unix_seconds(value: &serde_json::Value) -> Option<DateTime<Utc>> {
        let seconds = match value {
            serde_json::Value::Number(number) => number
                .as_i64()
                .or_else(|| number.as_f64().map(|seconds| seconds as i64))?,
            serde_json::Value::String(text) => text.trim().parse().ok()?,
            _ => return None,
        };
        (seconds > 0)
            .then(|| DateTime::from_timestamp(seconds, 0))
            .flatten()
    }
    let response: Response = serde_json::from_str(body).ok()?;
    let credit = response.breakdowns.iter().find_map(|breakdown| {
        if breakdown.resource_type.as_deref() != Some("CREDIT") {
            return None;
        }
        let limit = amount(breakdown.limit_precision, breakdown.limit)?;
        if limit <= 0.0 {
            return None;
        }
        let used = amount(breakdown.used_precision, breakdown.used)?;
        Some((breakdown, limit, used))
    })?;
    let (credit, limit, used) = credit;
    let used_pct = (used * 100. / limit).clamp(0., 100.);
    let mut windows = vec![QuotaWindow {
        name: "本月 Credits".to_string(),
        // Whole credits carry at most two decimals, so the percent is
        // rounded to 1e-4: a stored reading stays stable (the fixture's
        // 5469.38/10000 is exactly 54.6938, not 54.693800000000004).
        used_pct: (used_pct * 10_000.).round() / 10_000.,
        resets_at: credit
            .next_reset
            .as_ref()
            .or(response.next_reset.as_ref())
            .and_then(unix_seconds),
        period_minutes: Some(30 * 1440),
        // No unit suffix: the window name already says Credits, and the card
        // renders "remaining/total", so a suffix would be printed twice.
        total: Some(credit_amount(limit)),
    }];
    sort_windows(&mut windows);
    Some(KeyQuota {
        windows,
        balance: None,
    })
}

/// A credit count as the card shows it: whole credits without a decimal tail
/// ("10000"), a fractional allowance as the vendor gave it ("500.5").
fn credit_amount(amount: f64) -> String {
    if amount.fract() == 0. {
        format!("{amount:.0}")
    } else {
        format!("{amount}")
    }
}

// ---------- user-anchored monthly reset (quota_overrides) ----------

/// The next monthly reset at UTC midnight of `day`, strictly after `now`.
/// Days past the 28th are rejected — February has no 30th, and an anchor that
/// cannot exist every month is a config error, not something to clamp.
pub fn next_monthly_reset(day: u32, now: DateTime<Utc>) -> Option<DateTime<Utc>> {
    use chrono::Datelike as _;
    if !(1..=28).contains(&day) {
        return None;
    }
    let this_month = now.date_naive().with_day(day)?;
    let this_month = this_month.and_hms_opt(0, 0, 0)?.and_utc();
    Some(if this_month > now {
        this_month
    } else {
        this_month
            .date_naive()
            .checked_add_months(chrono::Months::new(1))?
            .and_hms_opt(0, 0, 0)?
            .and_utc()
    })
}

/// Fill the vendor-hidden monthly reset from the key's configured anchor: a
/// long window (period ≥ 28 days) whose probe carried no reset instant —
/// CommandCode's credits month — gets the next anchor midnight. Windows the
/// vendor did date itself are never touched.
pub fn apply_monthly_anchor(quota: &mut KeyQuota, day: u32, now: DateTime<Utc>) {
    let Some(resets_at) = next_monthly_reset(day, now) else {
        return;
    };
    for window in &mut quota.windows {
        if window.resets_at.is_none()
            && window
                .period_minutes
                .is_some_and(|period| period >= 28 * 1440)
        {
            window.resets_at = Some(resets_at);
        }
    }
}
