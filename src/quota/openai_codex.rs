//! OpenAI Codex (ChatGPT subscription) usage windows from `wham/usage`.
//!
//! The answer is `{"plan_type", "rate_limit": {"allowed", "limit_reached",
//! "primary_window": W, "secondary_window": W}, "credits": {...},
//! "spend_control": {...}}` with `W = {"used_percent", "limit_window_seconds",
//! "reset_after_seconds", "reset_at"}`. The primary window is the short one
//! (5 hours on paid plans), the secondary the weekly one; both are mapped to
//! [`QuotaWindow`]s so Smart routing ranks the account like any other.
//!
//! Wire facts come from oh-my-pi's `usage/openai-codex.ts` and its test
//! fixtures and have not been exercised against the live endpoint. Credit-billed
//! seats (`rate_limit: null`, a `spend_control` cap instead) have no rate window;
//! their reset-credit details are still retained when the endpoint supplies them.
//! The `additional_rate_limits` meters (Spark) are not read.

use chrono::{DateTime, Duration, TimeZone as _, Utc};
use serde_json::Value;

use super::KeyQuota;
use super::QuotaWindow;
use super::endpoint::sort_windows;
use super::key_quota::{CodexResetDisplay, CodexResetSummary};
use crate::upstream::OpenaiBearer;

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use reqwest::Method;

    use super::{
        CodexResetOutcome, RESET_CONSUME_URL, RESET_DETAILS_URL, parse_codex_reset_details,
        parse_codex_reset_outcome, parse_codex_usage,
    };

    fn test_bearer() -> crate::openai::OpenaiOAuth {
        crate::openai::OpenaiOAuth {
            access_token: "test-access-token".to_owned(),
            refresh_token: "test-refresh-token".to_owned(),
            expires_at: Utc::now(),
            account_id: "test-account".to_owned(),
            email: None,
            plan_type: None,
        }
    }

    #[test]
    fn reset_details_request_contract_is_exact_without_secret_values() {
        let client = reqwest::Client::new();
        let request = crate::probe::codex_request(
            &client,
            Method::GET,
            RESET_DETAILS_URL,
            &test_bearer(),
            None,
        )
        .build()
        .expect("reset details request should build");

        assert_eq!(request.method(), Method::GET);
        assert_eq!(request.url().as_str(), RESET_DETAILS_URL);
        assert_eq!(request.headers().len(), 5);
        assert_eq!(
            request.headers().get("chatgpt-account-id").unwrap(),
            "test-account"
        );
        assert_eq!(request.headers().get("accept").unwrap(), "application/json");
        assert_eq!(request.headers().get("originator").unwrap(), "cardinal");
        assert_eq!(
            request.headers().get("version").unwrap(),
            crate::relay::capabilities::codex::CLIENT_VERSION
        );
        assert!(request.headers().get("authorization").is_some());
        assert!(!request.url().as_str().contains("test-access-token"));
    }

    #[test]
    fn reset_consume_request_contract_serializes_body_and_headers() {
        let client = reqwest::Client::new();
        let body = br#"{"redeem_request_id":"request-1","credit_id":"credit-1"}"#;
        let request = crate::probe::codex_request(
            &client,
            Method::POST,
            RESET_CONSUME_URL,
            &test_bearer(),
            Some(body),
        )
        .build()
        .expect("reset consume request should build");

        assert_eq!(request.method(), Method::POST);
        assert_eq!(request.url().as_str(), RESET_CONSUME_URL);
        assert_eq!(request.headers().len(), 6);
        assert_eq!(
            request.headers().get("content-type").unwrap(),
            "application/json"
        );
        assert_eq!(
            request.body().and_then(|body| body.as_bytes()),
            Some(body.as_slice())
        );
        assert!(!String::from_utf8_lossy(body).contains("test-access-token"));
        assert!(!String::from_utf8_lossy(body).contains("test-refresh-token"));
    }

    #[tokio::test]
    async fn consume_rejects_oversized_body_before_transport() {
        let bearer = test_bearer();
        let transport = crate::upstream::transport::Transport::new(
            crate::upstream::transport::Limits::default(),
        )
        .expect("default transport should build");
        let error = crate::probe::codex_post(
            RESET_CONSUME_URL,
            &bearer,
            &[0; 16 * 1024 + 1],
            &transport,
            crate::upstream::Dns::Overseas,
        )
        .await
        .expect_err("oversized reset request must be rejected");

        assert_eq!(error.to_string(), "Codex request is too large");
    }

    #[test]
    fn reset_details_keep_available_count_and_tolerate_bad_expiry() {
        let body = br#"{
          "available_count": 7,
          "credits": [
            {"id":"credit-1","status":"available","reset_type":"primary","granted_at":"2026-11-01T00:00:00Z","expires_at":"not-a-date","title":"Primary","description":"A reset"},
            {"id":"credit-2","status":"redeemed","reset_type":"weekly","granted_at":null,"expires_at":"2026-12-01T00:00:00Z"}
          ]
        }"#;
        let details = parse_codex_reset_details(body).expect("details should parse");
        assert_eq!(details.available_count, 7);
        assert_eq!(details.credits.len(), 2);
        assert_eq!(details.credits[0].id, "credit-1");
        assert!(details.credits[0].expires_at.is_none());
    }

    #[test]
    fn consume_outcomes_are_mapped_without_echoing_wire_body() {
        assert_eq!(
            parse_codex_reset_outcome(br#"{"status":"reset","windows_reset":["primary"]}"#)
                .expect("reset outcome"),
            CodexResetOutcome::Reset {
                windows_reset: vec!["primary".to_owned()]
            }
        );
        assert_eq!(
            parse_codex_reset_outcome(br#"{"outcome":"already_redeemed"}"#)
                .expect("already redeemed outcome"),
            CodexResetOutcome::AlreadyRedeemed
        );
        assert_eq!(
            parse_codex_reset_outcome(br#"{"status":"vendor_changed"}"#)
                .expect("unknown is a typed result"),
            CodexResetOutcome::Unknown
        );
        assert_eq!(
            parse_codex_reset_outcome(br#"{"outcome":"nothing_to_reset"}"#)
                .expect("nothing-to-reset outcome"),
            CodexResetOutcome::NothingToReset
        );
        assert_eq!(
            parse_codex_reset_outcome(br#"{"status":"no_credit"}"#).expect("no-credit outcome"),
            CodexResetOutcome::NoCredit
        );
    }

    #[test]
    fn consume_request_omits_absent_credit_id() {
        let request = super::CodexResetConsumeRequest {
            redeem_request_id: "request-1".to_owned(),
            credit_id: None,
        };
        let json = serde_json::to_value(request).expect("request serializes");
        assert_eq!(json, serde_json::json!({"redeem_request_id":"request-1"}));
    }

    #[test]
    fn consume_request_includes_selected_credit_id() {
        let request = super::CodexResetConsumeRequest {
            redeem_request_id: "request-1".to_owned(),
            credit_id: Some("credit-1".to_owned()),
        };
        let json = serde_json::to_value(request).expect("request serializes");
        assert_eq!(
            json,
            serde_json::json!({"redeem_request_id":"request-1","credit_id":"credit-1"})
        );
    }

    #[test]
    fn selected_credit_must_be_listed_as_available() {
        let details = super::CodexResetDetails {
            available_count: 1,
            credits: vec![super::CodexResetCredit {
                id: "credit-1".to_owned(),
                status: "available".to_owned(),
                reset_type: None,
                granted_at: None,
                expires_at: None,
                title: None,
                description: None,
            }],
        };
        assert!(super::validate_codex_reset_credit(&details, None).is_ok());
        assert!(super::validate_codex_reset_credit(&details, Some("credit-1")).is_ok());
        assert!(super::validate_codex_reset_credit(&details, Some("credit-2")).is_err());

        let mut redeemed = details.clone();
        redeemed.credits[0].status = "redeemed".to_owned();
        assert!(super::validate_codex_reset_credit(&redeemed, Some("credit-1")).is_err());
    }

    #[test]
    fn unknown_consume_outcome_is_not_accepted_as_success() {
        let outcome = super::parse_codex_reset_outcome(br#"{"status":"vendor_changed"}"#)
            .expect("unknown outcome remains parseable for classification");
        assert_eq!(outcome, super::CodexResetOutcome::Unknown);
    }

    #[test]
    fn credit_billed_usage_keeps_a_quota_row_for_reset_details() {
        let quota = parse_codex_usage(
            br#"{"rate_limit":null,"spend_control":{"limit":10,"used":2}}"#,
            Utc::now(),
        )
        .expect("credit-billed account should remain observable");
        assert!(quota.windows.is_empty());
        assert!(quota.codex_resets.is_none());
    }
}

const USAGE_URL: &str = "https://chatgpt.com/backend-api/wham/usage";
const RESET_DETAILS_URL: &str = "https://chatgpt.com/backend-api/wham/rate-limit-reset-credits";
const RESET_CONSUME_URL: &str =
    "https://chatgpt.com/backend-api/wham/rate-limit-reset-credits/consume";

/// A short-lived request to consume one upstream credit. `credit_id` is omitted
/// when the upstream is asked to choose a credit itself.
#[derive(Clone, Debug, serde::Serialize)]
pub struct CodexResetConsumeRequest {
    pub redeem_request_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credit_id: Option<String>,
}

/// Safe, body-free representation of a consume result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CodexResetOutcome {
    Reset { windows_reset: Vec<String> },
    AlreadyRedeemed,
    NothingToReset,
    NoCredit,
    Unknown,
}

/// One reset credit returned by the short-lived details action.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodexResetCredit {
    pub id: String,
    pub status: String,
    pub reset_type: Option<String>,
    pub granted_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub title: Option<String>,
    pub description: Option<String>,
}

/// The upstream's authoritative count plus the credits it included in this page.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodexResetDetails {
    pub available_count: u32,
    pub credits: Vec<CodexResetCredit>,
}

/// Map one `wham/usage` answer to plan windows. Credit-billed answers with
/// `rate_limit: null` produce an empty quota row so supplementary reset details
/// can still be attached by [`fetch_openai_codex_quota`]. Other unparseable
/// answers, missing rate limits, or answers without a usable window return
/// `None`.
///
/// `limit_reached` is account-wide and does not name the binding window, so the
/// fullest window(s) are lifted to 100%. It is not applied when paid credits
/// still fund overage (`credits.unlimited|has_credits`, neither the credit
/// overage nor the spend control reached): Codex keeps serving such an account
/// past its plan windows, and a card showing it exhausted would park it in
/// Smart routing until the weekly reset.
pub(crate) fn parse_codex_usage(body: &[u8], now: DateTime<Utc>) -> Option<KeyQuota> {
    let root: Value = serde_json::from_slice(body).ok()?;
    if root.get("rate_limit").is_some_and(Value::is_null)
        && root.get("spend_control").is_some_and(Value::is_object)
    {
        return Some(KeyQuota {
            windows: Vec::new(),
            balance: None,
            plan: None,
            details: Vec::new(),
            codex_resets: None,
        });
    }
    let rate_limit = root.get("rate_limit")?.as_object()?;
    let mut windows: Vec<QuotaWindow> =
        [("primary_window", "主窗口"), ("secondary_window", "副窗口")]
            .into_iter()
            .filter_map(|(key, fallback_name)| window(rate_limit.get(key)?, fallback_name, now))
            .collect();
    if windows.is_empty() {
        return None;
    }
    let limit_reached = rate_limit.get("limit_reached").and_then(Value::as_bool) == Some(true);
    if limit_reached && !credits_fund_overage(&root) {
        let fullest = windows.iter().map(|w| w.used_pct).fold(0., f64::max);
        for window in windows.iter_mut().filter(|w| w.used_pct >= fullest) {
            window.used_pct = 100.;
        }
    }
    sort_windows(&mut windows);
    Some(KeyQuota {
        windows,
        balance: None,
        plan: None,
        details: Vec::new(),
        codex_resets: None,
    })
}

/// Probe one Codex account's usage windows and supplementary reset-credit
/// details. The caller resolves the bearer first, so this module never touches
/// the credential store. A reset-details failure does not discard otherwise
/// valid usage windows.
pub async fn fetch_openai_codex_quota(
    bearer: &OpenaiBearer,
    key_id: i64,
    transport: &crate::upstream::transport::Transport,
    dns: crate::upstream::Dns,
) -> Option<KeyQuota> {
    let (status, body) = match crate::probe::codex_get(USAGE_URL, bearer, transport, dns).await {
        Ok(answer) => answer,
        Err(error) => {
            tracing::warn!(key_id, %error, "Codex quota probe: request failed");
            return None;
        }
    };
    if !(200..300).contains(&status) {
        tracing::warn!(
            key_id,
            status,
            bytes = body.len(),
            "Codex quota probe: upstream rejected the call"
        );
        return None;
    }
    let Some(mut quota) = parse_codex_usage(body.as_bytes(), Utc::now()) else {
        tracing::warn!(
            key_id,
            status,
            bytes = body.len(),
            "Codex quota probe: no usage window in the answer"
        );
        return None;
    };
    match fetch_openai_codex_resets(bearer, transport, dns).await {
        Ok(details) => {
            quota.codex_resets = Some(CodexResetSummary {
                available_count: details.available_count,
                credits: details
                    .credits
                    .into_iter()
                    .map(|credit| CodexResetDisplay {
                        status: credit.status,
                        reset_type: credit.reset_type,
                        granted_at: credit.granted_at,
                        expires_at: credit.expires_at,
                        title: credit.title,
                        description: credit.description,
                    })
                    .collect(),
            })
        }
        Err(error) => tracing::warn!(key_id, %error, "Codex reset-credit probe unavailable"),
    }
    Some(quota)
}

/// Fetch reset-credit details for an authenticated Codex account.
pub async fn fetch_openai_codex_resets(
    bearer: &OpenaiBearer,
    transport: &crate::upstream::transport::Transport,
    dns: crate::upstream::Dns,
) -> anyhow::Result<CodexResetDetails> {
    let (status, body) = crate::probe::codex_get(RESET_DETAILS_URL, bearer, transport, dns).await?;
    if !(200..300).contains(&status) {
        anyhow::bail!("Codex reset-credit service rejected the request (HTTP {status})");
    }
    parse_codex_reset_details(body.as_bytes())
}

/// Consume one credit. The caller supplies and, if necessary, reuses the same
/// `redeem_request_id`; this function never retries an irreversible operation.
pub async fn consume_openai_codex_reset(
    bearer: &OpenaiBearer,
    request: &CodexResetConsumeRequest,
    transport: &crate::upstream::transport::Transport,
    dns: crate::upstream::Dns,
) -> anyhow::Result<CodexResetOutcome> {
    let body =
        serde_json::to_vec(request).map_err(|_| anyhow::anyhow!("Codex reset request invalid"))?;
    let (status, response) =
        crate::probe::codex_post(RESET_CONSUME_URL, bearer, &body, transport, dns).await?;
    if !(200..300).contains(&status) {
        anyhow::bail!("Codex reset-credit service rejected the request (HTTP {status})");
    }
    let outcome = parse_codex_reset_outcome(response.as_bytes())?;
    if matches!(outcome, CodexResetOutcome::Unknown) {
        anyhow::bail!("Codex reset-credit service returned an unknown outcome");
    }
    Ok(outcome)
}

/// Return whether an explicitly selected credit is present and currently usable.
/// An omitted selection is accepted because the upstream may choose a credit.
pub fn validate_codex_reset_credit(
    details: &CodexResetDetails,
    credit_id: Option<&str>,
) -> anyhow::Result<()> {
    let Some(credit_id) = credit_id else {
        return Ok(());
    };
    if details
        .credits
        .iter()
        .any(|credit| credit.id == credit_id && credit.status == "available")
    {
        Ok(())
    } else {
        anyhow::bail!("selected reset credit is unavailable")
    }
}

/// Parse the details endpoint without retaining an upstream body or bearer.
pub fn parse_codex_reset_details(body: &[u8]) -> anyhow::Result<CodexResetDetails> {
    let root: Value =
        serde_json::from_slice(body).map_err(|_| anyhow::anyhow!("Codex reset details invalid"))?;
    let payload = root
        .get("reset_credits")
        .filter(|value| value.is_object())
        .unwrap_or(&root);
    let available_count = payload
        .get("available_count")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow::anyhow!("Codex reset details missing count"))?;
    let available_count = u32::try_from(available_count)
        .map_err(|_| anyhow::anyhow!("Codex reset details count out of range"))?;
    let credits = payload
        .get("credits")
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(parse_reset_credit).collect())
        .unwrap_or_default();
    Ok(CodexResetDetails {
        available_count,
        credits,
    })
}

fn parse_reset_credit(value: &Value) -> Option<CodexResetCredit> {
    let id = value.get("id")?.as_str()?.trim();
    let status = value.get("status")?.as_str()?.trim();
    if id.is_empty() || status.is_empty() {
        return None;
    }
    Some(CodexResetCredit {
        id: id.to_owned(),
        status: status.to_owned(),
        reset_type: string_field(value, "reset_type"),
        granted_at: date_field(value, "granted_at"),
        expires_at: date_field(value, "expires_at"),
        title: string_field(value, "title"),
        description: string_field(value, "description"),
    })
}

fn string_field(value: &Value, field: &str) -> Option<String> {
    value.get(field).and_then(Value::as_str).map(str::to_owned)
}

fn date_field(value: &Value, field: &str) -> Option<DateTime<Utc>> {
    value
        .get(field)
        .and_then(Value::as_str)
        .and_then(|text| DateTime::parse_from_rfc3339(text).ok())
        .map(|date| date.with_timezone(&Utc))
}

/// Convert the small, documented result vocabulary to a body-free domain value.
pub fn parse_codex_reset_outcome(body: &[u8]) -> anyhow::Result<CodexResetOutcome> {
    let root: Value =
        serde_json::from_slice(body).map_err(|_| anyhow::anyhow!("Codex reset result invalid"))?;
    let outcome = root
        .get("outcome")
        .or_else(|| root.get("status"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    Ok(match outcome {
        "reset" => CodexResetOutcome::Reset {
            windows_reset: root
                .get("windows_reset")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default(),
        },
        "already_redeemed" => CodexResetOutcome::AlreadyRedeemed,
        "nothing_to_reset" => CodexResetOutcome::NothingToReset,
        "no_credit" => CodexResetOutcome::NoCredit,
        _ => CodexResetOutcome::Unknown,
    })
}

fn window(value: &Value, fallback_name: &str, now: DateTime<Utc>) -> Option<QuotaWindow> {
    let used_pct = value.get("used_percent")?.as_f64()?.clamp(0., 100.);
    let period_seconds = value
        .get("limit_window_seconds")
        .and_then(Value::as_f64)
        .filter(|seconds| *seconds > 0.);
    // Unlike opencode Go, an idle account reports its real reset: `reset_at`
    // stayed fixed across probes at 0% while `reset_after_seconds` counted
    // down (live pro account, 2026-11-08). Keeping it gives Smart routing its
    // time anchor and the card its trend chart.
    let resets_at = reset_time(value, now);
    Some(QuotaWindow {
        name: period_seconds.map_or_else(|| fallback_name.to_owned(), window_name),
        used_pct,
        resets_at,
        period_minutes: period_seconds.map(|seconds| (seconds / 60.) as i64),
        total: None,
        used: None,
    })
}

/// "5h" under a day (rounded to whole hours, at least 1), "7d" from a day up.
fn window_name(seconds: f64) -> String {
    if seconds >= 86_400. {
        format!("{}d", (seconds / 86_400.).round() as i64)
    } else {
        format!("{}h", ((seconds / 3_600.).round() as i64).max(1))
    }
}

/// `reset_at` is an epoch instant (seconds, or milliseconds above 1e12 — the
/// reference accepts both); `reset_after_seconds` is relative to `now`.
fn reset_time(value: &Value, now: DateTime<Utc>) -> Option<DateTime<Utc>> {
    if let Some(reset_at) = value.get("reset_at").and_then(Value::as_f64) {
        let millis = if reset_at > 1e12 {
            reset_at
        } else {
            reset_at * 1000.
        };
        if let Some(instant) = Utc.timestamp_millis_opt(millis as i64).single() {
            return Some(instant);
        }
    }
    let after = value.get("reset_after_seconds").and_then(Value::as_f64)?;
    now.checked_add_signed(Duration::milliseconds((after * 1000.) as i64))
}

fn credits_fund_overage(root: &Value) -> bool {
    let flag = |parent: &str, key: &str| {
        root.get(parent)
            .and_then(|block| block.get(key))
            .and_then(Value::as_bool)
    };
    let funded =
        flag("credits", "unlimited") == Some(true) || flag("credits", "has_credits") == Some(true);
    funded
        && flag("credits", "overage_limit_reached") != Some(true)
        && flag("spend_control", "reached") != Some(true)
}
