//! Cursor plan usage: what the Cursor CLI's own `/usage` screen shows, read
//! from the same dashboard RPCs it reads (bundle `2026.11.05-86047df`,
//! `src/utils/usage.ts`): `DashboardService/GetCurrentPeriodUsage` for the
//! plan's included usage and the on-demand spend, `GetHardLimit` for the
//! account's on-demand ceiling and `GetPlanInfo` for the plan's name — the
//! last two best effort, as in the CLI. A personal account additionally
//! reads `GetAggregatedUsageEvents` with an empty request (the current
//! billing cycle), best effort, for the amount spent in each bucket; a team
//! login and every static key skip it, because the aggregation scope of an
//! empty request under a team is unverified (the IDE passes team and user
//! ids) and a figure that might be the whole team's is worse than none.
//!
//! The included allowance is two meters when the backend reports both
//! `autoPercentUsed` and `apiPercentUsed` (proto3 `optional` doubles, so a
//! bucket at zero is still present), named as the usage page names them:
//! "Cursor Models" (auto) and "Other Models" (api). Those two shares are the
//! backend's own and their denominator is undocumented — a live Pro account
//! answered `apiPercentUsed` 0.356 beside 4 of 2000 cents, which is 0.2% —
//! so the share is taken as given and deliberately not derived from the
//! amount beside it. The spent amounts
//! follow the usage page's bucketing of the aggregated events by `tier`:
//! auto is tier 2, or a `default` intent without a tier; a `default` intent
//! at tier 1 is spillover and counts toward Other Models together with every
//! non-default intent at tier 1 or without a tier. Buckets that do not add
//! up to the answer's own `totalCostCents` are dropped rather than shown
//! short. A plan whose included usage resets weekly
//! (`planInfo.includedUsagePeriod`) resets at `includedUsageResetsAt` rather
//! than at the billing cycle's end, and then carries no amount at all (the
//! aggregation covers the cycle, not the week); the on-demand window always
//! follows the billing cycle. The aggregation is issued before either of
//! those two cases is known, trading one wasted call for the parallel join.
//!
//! Two meters instead of one also changes dispatch: Smart ranks a key by its
//! tightest window ([`crate::relay::smart`]), so a Cursor key is now bound by
//! whichever bucket is fuller. The trend chart keys its series by window name
//! ([`crate::store::quota::quota_history_insert`]), so the rename starts the
//! two buckets as fresh series and leaves the old `本期额度` samples to age
//! out of the 45-day window; no migration, the series are not comparable
//! anyway (a bucket's share is not the plan's).
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
    dns: crate::upstream::Dns,
) -> Option<KeyQuota> {
    let credential = match key.cursor_oauth() {
        Some(bundle) => KeyCredential::CursorOauth(bundle),
        None => KeyCredential::Static(key.api_key.as_deref()?),
    };
    let bearer = match tokens.resolve(pool, key.id, &credential, dns).await {
        Ok(bearer) => bearer,
        Err(error) => {
            tracing::warn!(key_id = key.id, error = %error, "Cursor quota probe: credential unavailable");
            return None;
        }
    };
    let transport = tokens.transport();
    // Only a personal OAuth login may read the empty-body aggregation: it is
    // the one case whose scope is known to be this account alone. A static
    // key's exchange answer names no team even when the account sits in one
    // (`CursorTokens::exchange_static`), so its `team_id` cannot clear the
    // guard.
    let personal =
        matches!(credential, KeyCredential::CursorOauth(_)) && bearer.team_id().is_none();
    let (usage, hard_limit, plan, aggregated) = tokio::join!(
        call(
            transport,
            &bearer,
            key.id,
            dns,
            PERIOD_USAGE_PATH,
            Bytes::from_static(b"{}")
        ),
        call(
            transport,
            &bearer,
            key.id,
            dns,
            HARD_LIMIT_PATH,
            Bytes::from_static(b"{}")
        ),
        call(
            transport,
            &bearer,
            key.id,
            dns,
            PLAN_INFO_PATH,
            Bytes::from_static(b"{}")
        ),
        async {
            if !personal {
                return None;
            }
            call(
                transport,
                &bearer,
                key.id,
                dns,
                AGGREGATED_EVENTS_PATH,
                Bytes::from_static(b"{}"),
            )
            .await
        },
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
        return parse_cursor_quota(
            &usage,
            hard_limit.as_ref(),
            plan.as_ref(),
            aggregated.as_ref(),
            plan_name,
            key.id,
        );
    }
    // No plan usage: an enterprise seat. The CLI reads the cycle's spend from
    // the aggregated events of this member; the reading is a details line.
    let me = call(
        transport,
        &bearer,
        key.id,
        dns,
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
        dns,
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
    let member_aggregated = call(
        transport,
        &bearer,
        key.id,
        dns,
        AGGREGATED_EVENTS_PATH,
        body.to_string().into(),
    )
    .await?;
    let spent = member_aggregated
        .get("totalCostCents")
        .and_then(number)
        .unwrap_or(0.)
        .max(0.);
    let mut details = Vec::new();
    details.push(format!("本周期消费 ${:.2}", spent / 100.));
    if let Some(resets_at) = epoch_millis(end) {
        details.push(format!("重置 {}", resets_at.format("%m-%d")));
    }
    Some(KeyQuota {
        windows: Vec::new(),
        balance: None,
        plan: Some(plan_name.unwrap_or_else(|| "Enterprise".to_owned())),
        details,
    })
}

/// One unary dashboard call: the parsed JSON answer, or `None` for any
/// transport failure, non-2xx status or unparseable body.
async fn call(
    transport: &Transport,
    bearer: &CursorBearer,
    key_id: i64,
    dns: crate::upstream::Dns,
    path: &str,
    body: Bytes,
) -> Option<Value> {
    let prepared = cursor_request::unary_json(path, body);
    let headers = cursor_request::unary_headers(bearer.access_token(), bearer.team_id());
    let deadline = Instant::now() + PROBE_TIMEOUT;
    let response = match transport
        .send_with_headers(&prepared, dns, &headers, &[], deadline)
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

/// What a billing cycle's aggregated events cost, split into the two meters
/// of the usage page.
#[derive(Clone, Copy)]
struct BucketSpend {
    /// Cursor Models, in cents.
    auto_cents: f64,
    /// Other Models (including spillover), in cents.
    api_cents: f64,
}

/// How far the two buckets may drift from the answer's own total before the
/// reading is refused, in cents — float noise only, far below the cent the
/// card renders.
const SPEND_SUM_TOLERANCE_CENTS: f64 = 0.005;

/// The cents spent on Cursor Models (auto) and on Other Models (api) in a
/// `GetAggregatedUsageEvents` answer, bucketed as the usage page buckets
/// them (see the module doc); spillover counts toward Other Models.
///
/// `None` when the buckets do not add up to the answer's own
/// `totalCostCents`: a row these rules do not recognise (a tier beyond the
/// two, a renamed field) would otherwise render as a confident amount that
/// is silently too low.
fn bucket_spend_cents(aggregated: &Value, key_id: i64) -> Option<BucketSpend> {
    let mut spend = BucketSpend {
        auto_cents: 0.,
        api_cents: 0.,
    };
    let rows = aggregated
        .get("aggregations")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    for row in rows {
        let Some(cents) = row.get("totalCents").and_then(number) else {
            continue;
        };
        let tier = row.get("tier").and_then(number).map(|tier| tier as i64);
        let default_intent = row.get("modelIntent").and_then(Value::as_str) == Some("default");
        let auto = tier == Some(2) || (tier.is_none() && default_intent);
        let spillover = default_intent && tier == Some(1);
        let api = !default_intent && (tier == Some(1) || tier.is_none());
        if auto {
            spend.auto_cents += cents;
        } else if spillover || api {
            spend.api_cents += cents;
        }
    }
    // An empty cycle answers with neither rows nor a total (proto3 JSON omits
    // both at their default), which agrees with two empty buckets.
    let total_cents = aggregated
        .get("totalCostCents")
        .and_then(number)
        .unwrap_or(0.);
    let drift = spend.auto_cents + spend.api_cents - total_cents;
    if drift.abs() > SPEND_SUM_TOLERANCE_CENTS {
        // Amounts and the key only; nothing here identifies the account.
        tracing::warn!(
            key_id,
            auto_cents = spend.auto_cents,
            api_cents = spend.api_cents,
            total_cents,
            "Cursor quota probe: aggregated spend does not add up to its total; amounts dropped"
        );
        return None;
    }
    Some(spend)
}

/// A meter's share, clamped to 0–100 and kept to two decimals. The usage
/// page rounds to whole percents (and shows any spend below 1% as 1%); a
/// card that also carries the amount is better served by the exact share.
fn meter_pct(pct: f64) -> f64 {
    (pct.clamp(0., 100.) * 100.).round() / 100.
}

/// `GetCurrentPeriodUsage` (+ the best-effort `GetHardLimit` / `GetPlanInfo`
/// / `GetAggregatedUsageEvents`) as a card: the plan's included usage as the
/// two bucket meters with their spent amounts (one money window when the
/// backend names no buckets), a fixed on-demand ceiling as another window,
/// unlimited on-demand spend as a details line, and the plan's name as the
/// reading's `plan` badge.
fn parse_cursor_quota(
    usage: &Value,
    hard_limit: Option<&Value>,
    plan: Option<&Value>,
    aggregated: Option<&Value>,
    plan_name: Option<String>,
    key_id: i64,
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
    // The included allowance of a weekly plan resets on its own schedule.
    let weekly_reset = plan
        .filter(|plan| {
            plan.pointer("/planInfo/includedUsagePeriod")
                .and_then(Value::as_str)
                == Some("INCLUDED_USAGE_PERIOD_WEEKLY")
        })
        .and_then(|plan| plan.pointer("/planInfo/includedUsageResetsAt"))
        .and_then(number)
        .and_then(epoch_millis);
    let (included_resets_at, included_period_minutes) = match weekly_reset {
        Some(resets_at) => (Some(resets_at), Some(7 * 1440)),
        None => (resets_at, period_minutes),
    };
    let mut windows = Vec::new();
    let mut details = Vec::new();
    let included_limit = plan_usage.get("limit").and_then(number).unwrap_or(0.);
    let included_spend = plan_usage
        .get("includedSpend")
        .and_then(number)
        .unwrap_or(0.);
    let total_pct = plan_usage.get("totalPercentUsed").and_then(number);
    let auto_pct = plan_usage.get("autoPercentUsed").and_then(number);
    let api_pct = plan_usage.get("apiPercentUsed").and_then(number);
    // The aggregated events cover the billing cycle, so their amounts belong
    // to a weekly allowance's meters only if the two periods coincide — they
    // do not: a weekly meter beside a month's spend would read as one figure.
    let bucket_cents = aggregated
        .filter(|_| weekly_reset.is_none())
        .and_then(|aggregated| bucket_spend_cents(aggregated, key_id));
    if let (Some(auto_pct), Some(api_pct)) = (auto_pct, api_pct) {
        // The backend already split the allowance into the two buckets the
        // usage page shows; it names no per-bucket ceiling, so each meter
        // carries its spent amount alone.
        let buckets = [
            (
                "Cursor Models",
                auto_pct,
                bucket_cents.map(|spend| spend.auto_cents),
            ),
            (
                "Other Models",
                api_pct,
                bucket_cents.map(|spend| spend.api_cents),
            ),
        ];
        for (name, pct, spent_cents) in buckets {
            windows.push(QuotaWindow {
                name: name.to_string(),
                used_pct: meter_pct(pct),
                resets_at: included_resets_at,
                period_minutes: included_period_minutes,
                total: None,
                used: spent_cents.map(|cents| format!("${:.2}", cents.max(0.) / 100.)),
            });
        }
    } else {
        // The share and the allowance must be in the same terms, so the two
        // cent amounts of this message decide it. The backend's own
        // `totalPercentUsed` has an undocumented denominator (a live Pro
        // account answered 0.0087 beside 4/2000 cents) and only fills in when
        // no allowance is named.
        let used_pct = if included_limit > 0. {
            Some(included_spend * 100. / included_limit)
        } else {
            total_pct
        };
        if let Some(used_pct) = used_pct {
            windows.push(QuotaWindow {
                name: "本期额度".to_string(),
                used_pct: meter_pct(used_pct),
                resets_at: included_resets_at,
                period_minutes: included_period_minutes,
                total: (included_limit > 0.).then(|| format!("${:.2}", included_limit / 100.)),
                used: None,
            });
        }
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
        auto_spend_cents = ?bucket_cents.map(|spend| spend.auto_cents),
        api_spend_cents = ?bucket_cents.map(|spend| spend.api_cents),
        on_demand_used_cents = on_demand_used,
        ?on_demand,
        "Cursor quota probe: plan usage"
    );
    match on_demand {
        OnDemand::Fixed(limit_cents) => windows.push(QuotaWindow {
            name: "按量".to_string(),
            used_pct: meter_pct(on_demand_used * 100. / limit_cents),
            resets_at,
            period_minutes,
            total: Some(format!("${:.2}", limit_cents / 100.)),
            used: None,
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
    if windows.is_empty() && details.is_empty() && plan_name.is_none() {
        return None;
    }
    sort_windows(&mut windows);
    Some(KeyQuota {
        windows,
        balance: None,
        plan: plan_name,
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
