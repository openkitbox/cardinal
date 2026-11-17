//! WorkBuddy account credits meter probe.
//!
//! WorkBuddy's vendor quota lives on its billing meter API, not on the generic
//! `/v1/usage` relay path: it is a POST with an `{code, msg, data}` envelope,
//! authenticated by the account OAuth bundle (bearer + uid + domain). This
//! module owns the three calls (resource summary, paid/free cycle lists, and
//! the enterprise fallback) and the mapping from their answers to one
//! `KeyQuota` window that Smart routing can rank.
//!
//! Personal accounts name their main credit pool in `SubscriptionPackageCode`
//! (or, when unnamed, the largest package with a known cycle); enterprise
//! accounts answer the summary with no packages and must be read from the
//! enterprise meter instead. Only the main pool becomes a window: Smart takes
//! the minimum over a key's windows, so bonus/addon pools would change which
//! key gets traffic. A reading without a FUTURE reset instant is no reading at
//! all — otherwise Smart would rank it as "unknown quota" and the key would
//! never receive traffic.
//!
//! Failures are decorative: they yield `None`, logged with status/byte counts
//! and fixed messages only. Neither credentials nor the vendor's answer text
//! ever reach a log line.

use chrono::DateTime;
use chrono::NaiveDateTime;
use chrono::TimeDelta;
use chrono::Utc;
use sqlx::PgPool;

use super::KeyQuota;
use super::QuotaWindow;
use super::endpoint::MAX_BODY;
use super::endpoint::PROBE_TIMEOUT;

use crate::protocol::Prepared;
use crate::protocol::ProtocolId;
use crate::relay::capabilities::Build;
use crate::relay::capabilities::WorkbuddyCredential;
use crate::relay::capabilities::workbuddy::host_allowed;
use crate::relay::capabilities::workbuddy_headers;
use crate::store::ProviderKeyRow;
use crate::upstream::Dns;
use crate::upstream::transport::Transport;
use crate::upstream::workbuddy_tokens::WorkbuddyTokens;
use crate::workbuddy::auth::envelope;

const MONTH_MINUTES: i64 = 30 * 1440;

/// Probe one WorkBuddy key's account credits through the vendor's billing
/// meter, using the same single-flight OAuth bundle as dispatch.
///
/// Either kind of account starts with the resource summary: a personal
/// account's packages need the paid/free cycle lists for their reset anchor,
/// while an enterprise account's empty package list sends us to the enterprise
/// meter. Every failure is a quiet `None`; no credential or answer text is
/// logged.
pub async fn fetch_workbuddy_quota(
    pool: &PgPool,
    tokens: &WorkbuddyTokens,
    key: &ProviderKeyRow,
    build: Build,
    dns: Dns,
    transport: &Transport,
) -> Option<KeyQuota> {
    let bundle = match tokens.resolve_with_build(pool, key.id, dns, build).await {
        Ok(bundle) => bundle,
        Err(error) => {
            tracing::warn!(key_id = key.id, error = %error, "WorkBuddy quota probe: credential unavailable");
            return None;
        }
    };
    let mut headers = workbuddy_headers(
        build,
        WorkbuddyCredential::Account {
            access_token: &bundle.access_token,
            uid: &bundle.uid,
            domain: bundle.domain.as_deref(),
        },
        None,
    );
    // The shared header builder fails closed on an untrusted domain by
    // dropping the auth headers. Without them every meter call would be an
    // anonymous 401, so stop here instead.
    if !headers.iter().any(|(name, _)| *name == "authorization") {
        tracing::warn!(
            key_id = key.id,
            "WorkBuddy quota probe: credential domain rejected; no meter call"
        );
        return None;
    }
    // The vendor's own client names the enterprise on every request; without
    // these two headers the meter answers as the personal account and an
    // enterprise token gets the "uid or enterpriseID is empty" refusal.
    if let Some(enterprise_id) = bundle
        .enterprise_id
        .as_deref()
        .map(str::trim)
        .filter(|id| !id.is_empty())
    {
        headers.push(("x-enterprise-id", enterprise_id.to_owned()));
        headers.push(("x-tenant-id", enterprise_id.to_owned()));
    }
    let base = build.endpoint().trim_end_matches('/');
    let host = reqwest::Url::parse(base)
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))?;
    if !host_allowed(build, &host) {
        tracing::warn!(
            key_id = key.id,
            "WorkBuddy quota probe: meter host not allowed for build"
        );
        return None;
    }

    let now = Utc::now();
    let summary = post_meter(
        transport,
        dns,
        &format!("{base}/billing/meter/get-user-resource-summary"),
        &serde_json::json!({}),
        &headers,
        key.id,
        "resource summary",
    )
    .await?;
    let has_packages = field(&summary, "Packages")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|packages| !packages.is_empty());
    let quota = if has_packages {
        let codes: Vec<&str> = field(&summary, "Packages")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|package| text(field(package, "PackageCode")))
            .collect();
        if codes.is_empty() {
            return None;
        }
        let day = (now + TimeDelta::hours(8)).format("%Y-%m-%d").to_string();
        let paid = post_meter(
            transport,
            dns,
            &format!("{base}/billing/meter/get-user-resource-paid-packages"),
            &serde_json::json!({
                "PageNumber": 1, "PageSize": 200, "Status": [0, 3],
                "PackageCodes": codes, "NeedRenewInfo": true,
            }),
            &headers,
            key.id,
            "paid packages",
        )
        .await?;
        let free = post_meter(
            transport,
            dns,
            &format!("{base}/billing/meter/get-user-resource-free-packages"),
            &serde_json::json!({
                "PageNumber": 1, "PageSize": 200, "Status": [0, 3],
                "PackageCodes": codes,
                "SlicePeriodStartTime": format!("{day} 00:00:00"),
                "SlicePeriodEndTime": format!("{day} 23:59:59"),
            }),
            &headers,
            key.id,
            "free packages",
        )
        .await?;
        parse_personal_quota(&summary, &paid, &free, now)
    } else {
        let usage = post_meter(
            transport,
            dns,
            &format!("{base}/billing/meter/get-enterprise-user-usage"),
            &serde_json::json!({}),
            &headers,
            key.id,
            "enterprise usage",
        )
        .await?;
        parse_enterprise_quota(&usage, now)
    };
    if quota.is_none() {
        tracing::debug!(
            key_id = key.id,
            "WorkBuddy quota probe: meter produced no usable credit window"
        );
    }
    quota
}

/// One POST to the billing meter, returning the envelope's `data`.
///
/// Only the request URL, status and byte count may reach a log line: the
/// vendor's error bodies can echo account metadata, and the headers carry the
/// OAuth token.
async fn post_meter(
    transport: &Transport,
    dns: Dns,
    url: &str,
    body: &serde_json::Value,
    headers: &[(&'static str, String)],
    key_id: i64,
    operation: &'static str,
) -> Option<serde_json::Value> {
    let prepared = Prepared {
        protocol: ProtocolId::OpenAiChat,
        url: url.to_owned(),
        content_type: "application/json",
        body: bytes::Bytes::from(body.to_string()),
        stream: false,
        headers: Vec::new(),
        cursor: None,
    };
    let deadline = std::time::Instant::now() + PROBE_TIMEOUT;
    let response = match transport
        .send_with_headers(&prepared, dns, headers, &[], deadline)
        .await
    {
        Ok(response) => response,
        Err(error) => {
            tracing::warn!(key_id, operation, %error, "WorkBuddy quota probe: meter send failed");
            return None;
        }
    };
    let status = response.status().as_u16();
    let bytes = match transport.read_body(response, MAX_BODY, deadline).await {
        Ok(bytes) => bytes,
        Err(error) => {
            tracing::warn!(key_id, operation, status, %error, "WorkBuddy quota probe: meter response unreadable");
            return None;
        }
    };
    if !(200..300).contains(&status) {
        tracing::warn!(
            key_id,
            operation,
            status,
            bytes = bytes.len(),
            "WorkBuddy quota probe: meter rejected the call"
        );
        return None;
    }
    let Ok(text) = std::str::from_utf8(&bytes) else {
        tracing::warn!(
            key_id,
            operation,
            bytes = bytes.len(),
            "WorkBuddy quota probe: meter response is not UTF-8"
        );
        return None;
    };
    match envelope(text) {
        Ok(data) => Some(data),
        Err(error) => {
            tracing::debug!(key_id, operation, %error, "WorkBuddy quota probe: meter returned no data");
            None
        }
    }
}

fn field<'a>(value: &'a serde_json::Value, key: &str) -> Option<&'a serde_json::Value> {
    value.get(key).filter(|value| !value.is_null())
}

fn text(value: Option<&serde_json::Value>) -> Option<&str> {
    value?
        .as_str()
        .map(str::trim)
        .filter(|text| !text.is_empty())
}

/// WorkBuddy sends quantities as numeric strings with precision noise
/// (`"500.00000000"`, `"89.19999997"`), sometimes as bare numbers.
fn amount(value: Option<&serde_json::Value>) -> Option<f64> {
    let number = match value? {
        serde_json::Value::Number(number) => number.as_f64()?,
        serde_json::Value::String(text) => text.trim().parse::<f64>().ok()?,
        _ => return None,
    };
    number.is_finite().then_some(number)
}

fn display(value: Option<&serde_json::Value>) -> Option<String> {
    match value? {
        serde_json::Value::String(text) => {
            let text = text.trim();
            (!text.is_empty()).then(|| text.to_owned())
        }
        serde_json::Value::Number(number) => Some(number.to_string()),
        _ => None,
    }
}

/// The meter writes local wall-clock strings in UTC+8; convert to UTC.
fn local_utc8(value: Option<&serde_json::Value>) -> Option<DateTime<Utc>> {
    let naive = NaiveDateTime::parse_from_str(text(value)?, "%Y-%m-%d %H:%M:%S").ok()?;
    Some(naive.and_utc() - TimeDelta::hours(8))
}

fn epoch_ms(value: Option<&serde_json::Value>) -> Option<DateTime<Utc>> {
    let millis: i64 = match value? {
        serde_json::Value::Number(number) => number.as_i64()?,
        serde_json::Value::String(text) => text.trim().parse().ok()?,
        _ => return None,
    };
    DateTime::from_timestamp_millis(millis)
}

fn accounts(value: &serde_json::Value) -> &[serde_json::Value] {
    field(value, "Accounts")
        .and_then(serde_json::Value::as_array)
        .map_or(&[], Vec::as_slice)
}

fn single_window(
    used_pct: f64,
    total: String,
    resets_at: DateTime<Utc>,
    period_minutes: i64,
) -> KeyQuota {
    KeyQuota {
        windows: vec![QuotaWindow {
            name: "积分".to_owned(),
            // Round to 1e-4 like Kiro: a stored reading stays stable instead
            // of wobbling in its last floating-point digits on every probe.
            used_pct: (used_pct.clamp(0., 100.) * 10_000.).round() / 10_000.,
            resets_at: Some(resets_at),
            period_minutes: Some(period_minutes),
            total: Some(total),
            used: None,
        }],
        balance: None,
        plan: None,
        details: Vec::new(),
        codex_resets: None,
    }
}

/// One named credit pool with the cycle anchor Smart needs to rank it.
struct Candidate<'a> {
    code: &'a str,
    used: f64,
    total: f64,
    total_text: String,
    end: DateTime<Utc>,
    period_minutes: i64,
}

/// Map a personal account's resource summary plus its paid/free cycle lists to
/// one quota window.
///
/// The primary pool is the subscription named by `SubscriptionPackageCode`, or
/// — when no subscription is named — the package with the largest positive
/// capacity that has a cycle anchor. Other pools (bonus, addon, daily slice)
/// are deliberately not windows: Smart takes the minimum over a key's windows.
/// A pool whose reset is not in the future is no reading at all.
fn parse_personal_quota(
    summary: &serde_json::Value,
    paid: &serde_json::Value,
    free: &serde_json::Value,
    now: DateTime<Utc>,
) -> Option<KeyQuota> {
    let packages = field(summary, "Packages")?.as_array()?;
    let subscription = text(field(summary, "SubscriptionPackageCode"));
    let cycles: Vec<&serde_json::Value> = accounts(paid).iter().chain(accounts(free)).collect();

    let candidates: Vec<Candidate<'_>> = packages
        .iter()
        .filter_map(|package| {
            let code = text(field(package, "PackageCode"))?;
            let total_capacity = field(package, "CycleTotalCapacity");
            let total = amount(total_capacity)?;
            if total <= 0. {
                return None;
            }
            let cycle = *cycles
                .iter()
                .find(|account| text(field(account, "PackageCode")) == Some(code))?;
            let end = local_utc8(field(cycle, "CycleEndTime"))
                .or_else(|| epoch_ms(field(cycle, "DeductionEndTime")))
                .or_else(|| local_utc8(field(cycle, "ExpiredTime")))?;
            let period_minutes = match local_utc8(field(cycle, "CycleStartTime")) {
                Some(start) if start < end => (end - start).num_minutes().max(1),
                _ => MONTH_MINUTES,
            };
            let used = amount(field(package, "CycleUsedCapacity")).unwrap_or(0.);
            Some(Candidate {
                code,
                used,
                total,
                total_text: display(total_capacity)?,
                end,
                period_minutes,
            })
        })
        .collect();

    let chosen = match subscription {
        Some(code) => candidates
            .into_iter()
            .find(|candidate| candidate.code == code)?,
        None => candidates
            .into_iter()
            .max_by(|a, b| a.total.total_cmp(&b.total))?,
    };
    if chosen.end <= now {
        return None;
    }
    Some(single_window(
        chosen.used * 100. / chosen.total,
        chosen.total_text,
        chosen.end,
        chosen.period_minutes,
    ))
}

/// Map an enterprise account's meter answer to one quota window.
fn parse_enterprise_quota(usage: &serde_json::Value, now: DateTime<Utc>) -> Option<KeyQuota> {
    let limit_field = field(usage, "limitNum");
    let limit = amount(limit_field)?;
    if limit <= 0. {
        return None;
    }
    let used = amount(field(usage, "credit")).unwrap_or(0.);
    let reset = local_utc8(field(usage, "cycleResetTime"))?;
    if reset <= now {
        return None;
    }
    let period_minutes = match local_utc8(field(usage, "cycleStartTime")) {
        Some(start) if start < reset => (reset - start).num_minutes().max(1),
        _ => MONTH_MINUTES,
    };
    Some(single_window(
        used * 100. / limit,
        display(limit_field)?,
        reset,
        period_minutes,
    ))
}
