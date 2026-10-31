use chrono::{DateTime, Utc};

use super::KeyQuota;
use super::QuotaWindow;

/// OpenCode Go plan usage (`/zen/go/v1/usage`):
/// `{"usage":{"rolling":{"status":"ok","percent":37,"resetsAt":"<RFC3339>"},
///            "weekly":{…},"monthly":{"status":"rate-limited","percent":100,…}}}`
/// — rolling is the 5-hour window, weekly 7 days, monthly the month. A window
/// at 0% reports resetsAt as now-plus-its-length, a time nothing happens at,
/// so its reset is left out.
pub(super) fn parse_opencode_go_quota(body: &str) -> Option<KeyQuota> {
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
            details: Vec::new(),
        })
    }
}
