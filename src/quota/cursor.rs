//! Cursor plan usage: what the Cursor CLI's own `/usage` screen shows, read
//! from the same dashboard RPCs it reads (bundle `2026.11.05-86047df`,
//! `src/utils/usage.ts`): `DashboardService/GetCurrentPeriodUsage` for the
//! plan's included usage and the on-demand spend, `GetHardLimit` for the
//! account's on-demand ceiling and `GetPlanInfo` for the plan's name — the
//! last two best effort, as in the CLI.
//!
//! Money is in cents in `GetCurrentPeriodUsage` and in whole dollars in
//! `GetHardLimit`; int64 fields arrive as JSON strings (Connect's proto3 JSON
//! mapping), int32 and double fields as numbers. An enterprise account has no
//! `planUsage`: the CLI then sums the billing cycle's aggregated events, and
//! so does this probe (`GetMe` → `GetMonthlyBillingCycle` →
//! `GetAggregatedUsageEvents`), as a details line rather than a meter —
//! mirrored from the CLI, not yet exercised against a live enterprise account.
//!
//! The answers carry no secret, but the bearer that fetches them does: every
//! log line carries the status and byte count only.

use std::time::Instant;

use bytes::Bytes;
use chrono::{DateTime, Utc};
use serde_json::Value;

use super::KeyQuota;
use super::QuotaWindow;
use super::endpoint::MAX_BODY;
use super::endpoint::PROBE_TIMEOUT;
use super::endpoint::sort_windows;
use crate::credentials::KeyCredential;
use crate::protocol::cursor::request as cursor_request;
use crate::upstream::cursor_tokens::CursorBearer;
use crate::upstream::transport::Transport;

const PERIOD_USAGE_PATH: &str = "aiserver.v1.DashboardService/GetCurrentPeriodUsage";
const HARD_LIMIT_PATH: &str = "aiserver.v1.DashboardService/GetHardLimit";
const PLAN_INFO_PATH: &str = "aiserver.v1.DashboardService/GetPlanInfo";
const ME_PATH: &str = "aiserver.v1.DashboardService/GetMe";
const BILLING_CYCLE_PATH: &str = "aiserver.v1.DashboardService/GetMonthlyBillingCycle";
const AGGREGATED_EVENTS_PATH: &str = "aiserver.v1.DashboardService/GetAggregatedUsageEvents";

/// The hard limit the backend reports for "no ceiling" (the CLI's test).
const UNLIMITED_HARD_LIMIT: f64 = i32::MAX as f64;

/// Probe one Cursor account's plan usage.
///
/// The bearer comes from the shared [`crate::upstream::CursorTokens`] — the
/// manager dispatch uses, so a probe never mints a second refresh and a
/// refreshed bearer is persisted once. An account key resolves from its
/// stored bundle, a static key through the exchange. Every vendor failure
/// yields `None` (quota is decorative) and is logged with status and size
/// only.
pub async fn fetch_cursor_quota(
    pool: &sqlx::PgPool,
    tokens: &crate::upstream::CursorTokens,
    key: &crate::store::ProviderKeyRow,
) -> Option<KeyQuota> {
    let credential = match key.cursor_oauth() {
        Some(bundle) => KeyCredential::CursorOauth(bundle),
        None => KeyCredential::Static(key.api_key.as_deref()?),
    };
    let bearer = match tokens.resolve(pool, key.id, &credential).await {
        Ok(bearer) => bearer,
        Err(error) => {
            tracing::warn!(key_id = key.id, error = %error, "Cursor quota probe: credential unavailable");
            return None;
        }
    };
    let transport = tokens.transport();
    let (usage, hard_limit, plan) = tokio::join!(
        call(
            transport,
            &bearer,
            key.id,
            PERIOD_USAGE_PATH,
            Bytes::from_static(b"{}")
        ),
        call(
            transport,
            &bearer,
            key.id,
            HARD_LIMIT_PATH,
            Bytes::from_static(b"{}")
        ),
        call(
            transport,
            &bearer,
            key.id,
            PLAN_INFO_PATH,
            Bytes::from_static(b"{}")
        ),
    );
    let usage = usage?;
    let plan_name = plan
        .as_ref()
        .and_then(|plan| plan.pointer("/planInfo/planName"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_owned);
    if usage.get("planUsage").is_some_and(|plan| plan.is_object()) {
        return parse_cursor_quota(&usage, hard_limit.as_ref(), plan.as_ref(), plan_name);
    }
    // No plan usage: an enterprise seat. The CLI reads the cycle's spend from
    // the aggregated events of this member; the reading is a details line.
    let me = call(
        transport,
        &bearer,
        key.id,
        ME_PATH,
        Bytes::from_static(b"{}"),
    )
    .await?;
    if me.get("isEnterpriseUser").and_then(Value::as_bool) != Some(true) {
        tracing::debug!(
            key_id = key.id,
            "Cursor quota probe: no plan usage for this account"
        );
        return None;
    }
    let (team_id, user_id) = match (
        me.get("teamId").and_then(number),
        me.get("userId").and_then(number),
    ) {
        (Some(team_id), Some(user_id)) if team_id > 0. && user_id > 0. => (team_id, user_id),
        _ => return None,
    };
    let cycle = call(
        transport,
        &bearer,
        key.id,
        BILLING_CYCLE_PATH,
        Bytes::from_static(b"{}"),
    )
    .await?;
    let start = cycle.get("startDateEpochMillis").and_then(number)?;
    let end = cycle.get("endDateEpochMillis").and_then(number)?;
    let body = serde_json::json!({
        "teamId": team_id,
        "userId": user_id,
        "startDate": format!("{start:.0}"),
        "endDate": format!("{end:.0}"),
    });
    let aggregated = call(
        transport,
        &bearer,
        key.id,
        AGGREGATED_EVENTS_PATH,
        body.to_string().into(),
    )
    .await?;
    let spent = aggregated
        .get("totalCostCents")
        .and_then(number)
        .unwrap_or(0.)
        .max(0.);
    let mut details = Vec::new();
    details.push(format!(
        "{} 套餐",
        plan_name.as_deref().unwrap_or("Enterprise")
    ));
    details.push(format!("本周期消费 ${:.2}", spent / 100.));
    if let Some(resets_at) = epoch_millis(end) {
        details.push(format!("重置 {}", resets_at.format("%m-%d")));
    }
    Some(KeyQuota {
        windows: Vec::new(),
        balance: None,
        details,
    })
}

/// One unary dashboard call: the parsed JSON answer, or `None` for any
/// transport failure, non-2xx status or unparseable body.
async fn call(
    transport: &Transport,
    bearer: &CursorBearer,
    key_id: i64,
    path: &str,
    body: Bytes,
) -> Option<Value> {
    let prepared = cursor_request::unary_json(path, body);
    let headers = cursor_request::unary_headers(bearer.access_token(), bearer.team_id());
    let deadline = Instant::now() + PROBE_TIMEOUT;
    let response = match transport
        .send_with_headers(&prepared, &headers, &[], deadline)
        .await
    {
        Ok(response) => response,
        Err(error) => {
            tracing::warn!(key_id, path, %error, "Cursor quota probe: send failed");
            return None;
        }
    };
    let status = response.status().as_u16();
    let body = match transport.read_body(response, MAX_BODY, deadline).await {
        Ok(body) => body,
        Err(error) => {
            tracing::warn!(key_id, path, status, %error, "Cursor quota probe: response unreadable");
            return None;
        }
    };
    if !(200..300).contains(&status) {
        tracing::warn!(
            key_id,
            path,
            status,
            bytes = body.len(),
            "Cursor quota probe: upstream rejected the call"
        );
        return None;
    }
    match serde_json::from_slice::<Value>(&body) {
        Ok(value) if value.is_object() => Some(value),
        _ => {
            tracing::warn!(
                key_id,
                path,
                status,
                bytes = body.len(),
                "Cursor quota probe: answer is not a JSON object"
            );
            None
        }
    }
}

/// The on-demand ceiling as the CLI classifies it from `spendLimitUsage` and
/// `GetHardLimit`.
#[derive(Clone, Copy, Debug, PartialEq)]
enum OnDemand {
    /// A ceiling in cents.
    Fixed(f64),
    /// Usage-based billing on with no ceiling.
    Unlimited,
    /// Usage-based billing off.
    Disabled,
    /// Not enough information.
    Unavailable,
}

/// The CLI's decision tree (`src/utils/usage.ts`): an explicit individual
/// limit wins; a team member reads the team's hard limit or pooled limit; a
/// personal account reads its own hard limit, where `i32::MAX` dollars means
/// "no ceiling". `hard_limit` is `None` only when the RPC failed: in an
/// answer, an absent `hardLimit` is proto3 JSON's zero (a plain int32 is
/// omitted at its default), i.e. no on-demand ceiling set.
fn on_demand(spend_limit: Option<&Value>, hard_limit: Option<&Value>) -> OnDemand {
    let individual_limit = spend_limit
        .and_then(|value| value.get("individualLimit"))
        .and_then(number);
    let explicit = individual_limit.map(|limit| {
        if limit > 0. {
            OnDemand::Fixed(limit)
        } else {
            OnDemand::Disabled
        }
    });
    let no_usage_based = hard_limit
        .and_then(|value| value.get("noUsageBasedAllowed"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let hard_limit_dollars =
        hard_limit.map(|value| value.get("hardLimit").and_then(number).unwrap_or(0.));
    let is_team = spend_limit
        .and_then(|value| value.get("limitType"))
        .and_then(Value::as_str)
        == Some("team");
    if is_team {
        if let Some(explicit) = explicit {
            return explicit;
        }
        return match hard_limit_dollars {
            Some(limit) if no_usage_based || limit <= 0. => OnDemand::Disabled,
            Some(_) => OnDemand::Unlimited,
            None => {
                let pooled = spend_limit
                    .and_then(|value| value.get("pooledLimit"))
                    .and_then(number)
                    .unwrap_or(0.);
                if pooled > 0. {
                    OnDemand::Unlimited
                } else {
                    OnDemand::Unavailable
                }
            }
        };
    }
    match hard_limit_dollars {
        None => explicit.unwrap_or(OnDemand::Unavailable),
        Some(_) if no_usage_based => OnDemand::Disabled,
        Some(limit) if limit >= UNLIMITED_HARD_LIMIT => OnDemand::Unlimited,
        Some(limit) if limit > 0. => OnDemand::Fixed(limit * 100.),
        Some(_) => OnDemand::Disabled,
    }
}

/// `GetCurrentPeriodUsage` (+ the best-effort `GetHardLimit` / `GetPlanInfo`)
/// as a card: the plan's included usage as a money window, a fixed on-demand
/// ceiling as a second window, unlimited on-demand spend as a details line,
/// the plan name first in the details.
fn parse_cursor_quota(
    usage: &Value,
    hard_limit: Option<&Value>,
    plan: Option<&Value>,
    plan_name: Option<String>,
) -> Option<KeyQuota> {
    let plan_usage = usage.get("planUsage")?;
    let cycle_start = usage.get("billingCycleStart").and_then(number);
    let cycle_end = usage
        .get("billingCycleEnd")
        .and_then(number)
        .filter(|end| *end > 0.)
        .or_else(|| {
            plan.and_then(|plan| plan.pointer("/planInfo/billingCycleEnd"))
                .and_then(number)
        });
    let resets_at = cycle_end.and_then(epoch_millis);
    // The cycle's length is the sort key; a month when the backend named no
    // start (the included allowance is a per-cycle pool).
    let period_minutes = match (cycle_start, cycle_end) {
        (Some(start), Some(end)) if end > start => Some(((end - start) / 60_000.) as i64),
        _ => Some(30 * 1440),
    };
    let mut windows = Vec::new();
    let mut details = Vec::new();
    if let Some(name) = plan_name {
        details.push(format!("{name} 套餐"));
    }
    let included_limit = plan_usage.get("limit").and_then(number).unwrap_or(0.);
    let included_spend = plan_usage
        .get("includedSpend")
        .and_then(number)
        .unwrap_or(0.);
    let total_pct = plan_usage.get("totalPercentUsed").and_then(number);
    // The meter's share must be in the same terms as the total it is drawn
    // against (the card derives "remaining" from `used_pct × total`), so the
    // two cent amounts of this message decide it. The backend's own
    // `totalPercentUsed` has an undocumented denominator (a live Pro account
    // answered 0.0087 beside 4/2000 cents) and only fills in when no
    // allowance is named.
    let used_pct = if included_limit > 0. {
        Some(included_spend * 100. / included_limit)
    } else {
        total_pct
    };
    if let Some(used_pct) = used_pct {
        windows.push(QuotaWindow {
            name: "本期额度".to_string(),
            used_pct: (used_pct.clamp(0., 100.) * 100.).round() / 100.,
            resets_at,
            period_minutes,
            total: (included_limit > 0.).then(|| format!("${:.2}", included_limit / 100.)),
        });
    }
    let spend_limit = usage
        .get("spendLimitUsage")
        .filter(|value| value.is_object());
    let on_demand_used = spend_limit
        .and_then(|value| value.get("individualUsed"))
        .and_then(number)
        .unwrap_or(0.)
        .max(0.);
    let on_demand = on_demand(spend_limit, hard_limit);
    // Amounts only (cents); nothing here identifies the account.
    tracing::debug!(
        included_limit_cents = included_limit,
        included_spend_cents = included_spend,
        total_pct = ?total_pct,
        on_demand_used_cents = on_demand_used,
        ?on_demand,
        "Cursor quota probe: plan usage"
    );
    match on_demand {
        OnDemand::Fixed(limit_cents) => windows.push(QuotaWindow {
            name: "按量".to_string(),
            used_pct: ((on_demand_used * 100. / limit_cents).clamp(0., 100.) * 100.).round() / 100.,
            resets_at,
            period_minutes,
            total: Some(format!("${:.2}", limit_cents / 100.)),
        }),
        OnDemand::Unlimited => {
            details.push(format!("按量已用 ${:.2}（无上限）", on_demand_used / 100.));
        }
        OnDemand::Disabled | OnDemand::Unavailable => {
            if on_demand_used > 0. {
                details.push(format!("按量已用 ${:.2}", on_demand_used / 100.));
            }
        }
    }
    if windows.is_empty() && details.is_empty() {
        return None;
    }
    sort_windows(&mut windows);
    Some(KeyQuota {
        windows,
        balance: None,
        details,
    })
}

/// A Connect JSON number: int32/double arrive as numbers, int64 as strings.
fn number(value: &Value) -> Option<f64> {
    match value {
        Value::Number(number) => number.as_f64().filter(|value| value.is_finite()),
        Value::String(text) => text.trim().parse::<f64>().ok().filter(|v| v.is_finite()),
        _ => None,
    }
}

/// Milliseconds since the epoch as an instant; zero or negative is "unknown".
fn epoch_millis(millis: f64) -> Option<DateTime<Utc>> {
    (millis > 0.)
        .then(|| DateTime::from_timestamp_millis(millis as i64))
        .flatten()
}
