use std::fmt;

use chrono::{DateTime, Utc};

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

/// A prepaid account balance: numeric amount plus its currency symbol.
/// The numeric amount feeds balance history; `Display` is the card text.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Balance {
    pub amount: f64,
    pub symbol: String,
}

impl fmt::Display for Balance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{:.2}", self.symbol, self.amount)
    }
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
    /// Prepaid balance as reported by the vendor (renders as "¥12.34").
    #[serde(default)]
    pub balance: Option<Balance>,
    /// Display-ready info lines beyond meters and balance (plan name, expiry,
    /// today's / lifetime usage), rendered verbatim in vendor order. Only
    /// the sub2api relay source fills them today.
    #[serde(default)]
    pub details: Vec<String>,
}
