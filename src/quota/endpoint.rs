//! The name-keyed quota endpoint table and the plain-HTTP probe that
//! fetches and parses one key's reading.

use super::KeyQuota;
use super::QuotaWindow;

use super::commandcode::parse_commandcode_quota;
use super::deepseek::parse_deepseek_balance;
use super::glm::parse_glm_quota;
use super::kimi::parse_kimi_balance;
use super::kimi::parse_kimi_code_usages;
use super::opencode::parse_opencode_go_quota;
use super::sub2api::parse_sub2api_usage;

/// One probe attempt's budget (mirrors `probe`'s model-list probing).
pub(super) const PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(8);
/// Quota/balance payloads are a few small objects; 8 MiB caps abuse/misconfig
/// (mirrors `probe`).
pub(super) const MAX_BODY: usize = 8 << 20;

/// One vendor quota endpoint: full URL, auth flavour, response parser.
struct Endpoint {
    url: String,
    /// GLM's monitor endpoint takes the bare key (no `Bearer ` prefix).
    bare_auth: bool,
    /// A guess (the sub2api fallback for unknown names): most upstreams do not
    /// answer it, so a failure is expected and logs at debug, not warn.
    speculative: bool,
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
        if body.trim().len() > 2 && !endpoint.speculative {
          tracing::warn!(provider = provider_name, url = %endpoint.url, body = %body, "quota probe: unparseable response");
        } else {
          tracing::debug!(provider = provider_name, url = %endpoint.url, body = %body, "quota probe: empty response");
        }
        None
      }),
    Err(error) if endpoint.speculative => {
      tracing::debug!(provider = provider_name, url = %endpoint.url, error = %format!("{error:#}"), "quota probe (sub2api fallback) failed");
      None
    }
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
pub(super) fn sort_windows(windows: &mut [QuotaWindow]) {
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
                speculative: false,
                parse: parse_glm_quota,
            },
            ("deepseek", _) => Endpoint {
                url: format!("{origin}/user/balance"),
                bare_auth: false,
                speculative: false,
                parse: parse_deepseek_balance,
            },
            ("kimi", false) => Endpoint {
                url: format!("{origin}/v1/users/me/balance"),
                bare_auth: false,
                speculative: false,
                parse: parse_kimi_balance,
            },
            ("kimi", true) => Endpoint {
                url: format!("{origin}/coding/v1/usages"),
                bare_auth: false,
                speculative: false,
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
                    speculative: false,
                    parse: parse_opencode_go_quota,
                }
            }
            // Command Code: a plan key (Studio / sign-in) reports its 5-hour and
            // weekly windows plus the dollars left on the month's credits; a
            // pay-as-you-go key has no windows (and only ever a balance).
            ("commandcode", _) => Endpoint {
                url: format!("{origin}/alpha/billing/credits"),
                bare_auth: false,
                speculative: false,
                parse: parse_commandcode_quota,
            },
            // Official vendor APIs expose no per-key balance.
            ("anthropic" | "openai" | "gemini" | "kiro", _) => return None,
            // Any other (custom) name: many third-party relays run sub2api,
            // whose `/v1/usage` reports the key's wallet / quota / plan.
            _ => Endpoint {
                url: format!("{origin}/v1/usage"),
                bare_auth: false,
                speculative: true,
                parse: parse_sub2api_usage,
            },
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
