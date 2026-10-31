use chrono::{DateTime, Utc};

use super::KeyQuota;
use super::QuotaWindow;

use super::endpoint::MAX_BODY;
use super::endpoint::PROBE_TIMEOUT;
use super::endpoint::sort_windows;

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
        details: Vec::new(),
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
