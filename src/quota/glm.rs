use chrono::DateTime;

use super::KeyQuota;
use super::QuotaWindow;

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
pub(super) fn parse_glm_quota(body: &str) -> Option<KeyQuota> {
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
        details: Vec::new(),
    })
}
