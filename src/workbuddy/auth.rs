use std::time::Duration;

use chrono::DateTime;
use chrono::TimeDelta;
use chrono::Utc;

use crate::protocol::Prepared;
use crate::upstream::Dns;
use crate::upstream::transport::Transport;

use crate::relay::capabilities::workbuddy::Build;
use crate::relay::capabilities::workbuddy::validate_base_origin;
use crate::relay::capabilities::workbuddy::validate_login_url;

use super::oauth::WorkbuddyOAuth;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_BODY: usize = 256 << 10;

/// Build identity for the WorkBuddy plugin client. The known desktop builds
/// are `workbuddy`/`5.9.3` (China) and `workbuddy-ai`/`5.9.3` (international).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BuildInfo {
    pub platform: &'static str,
    pub app: &'static str,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum WorkbuddyError {
    #[error("{operation}: WorkBuddy backend could not be reached")]
    Transport { operation: &'static str },
    #[error("WorkBuddy backend returned an error envelope")]
    Envelope { code: i64 },
    #[error("{operation}: WorkBuddy response had an invalid shape")]
    Shape { operation: &'static str },
    #[error("{operation}: WorkBuddy protocol error")]
    Protocol { operation: String },
}

/// Extract and validate the WorkBuddy response envelope, returning its data.
pub fn envelope(text: &str) -> Result<serde_json::Value, WorkbuddyError> {
    let value: serde_json::Value =
        serde_json::from_str(text).map_err(|_| WorkbuddyError::Shape {
            operation: "envelope",
        })?;
    let object = value.as_object().ok_or(WorkbuddyError::Shape {
        operation: "envelope",
    })?;
    let code = object
        .get("code")
        .and_then(serde_json::Value::as_i64)
        .ok_or(WorkbuddyError::Shape {
            operation: "envelope",
        })?;
    if code != 0 {
        tracing::warn!(code, "WorkBuddy backend returned an error envelope");
        return Err(WorkbuddyError::Envelope { code });
    }
    object.get("data").cloned().ok_or(WorkbuddyError::Shape {
        operation: "envelope",
    })
}

/// What one token poll returned.
pub enum TokenPoll {
    Pending,
    Ready(WorkbuddyOAuth),
}

/// What one account poll returned.
pub enum AccountPoll {
    Pending,
    Ready(String),
}

/// Login URL and vendor state returned by [`Client::start`].
pub struct LoginStart {
    pub state: String,
    pub auth_url: String,
}

/// Stateless WorkBuddy HTTP client using Cardinal's bounded transport.
pub struct Client {
    transport: Transport,
    dns: Dns,
}

impl Client {
    pub fn new(transport: Transport, dns: Dns) -> Self {
        Self { transport, dns }
    }

    pub(crate) fn with_dns(&self, dns: Dns) -> Self {
        Self {
            transport: self.transport.clone(),
            dns,
        }
    }

    /// Start a browser login using the requested desktop build identity.
    pub async fn start(&self, base: &str, build: BuildInfo) -> Result<LoginStart, WorkbuddyError> {
        validate_base(base, build)?;
        let data = self
            .call(
                "auth/state",
                &format!("{}/v2/plugin/auth/state", trim_base(base)),
                serde_json::json!({}),
                plugin_headers(build, None, None),
                vec![("platform", build.platform.to_owned())],
            )
            .await?;
        let state = text_field(&data, "state", "auth/state")?;
        let auth_url = text_field(&data, "authUrl", "auth/state")?;
        let Some(selected) = Build::for_platform(build.platform) else {
            return Err(invalid_host("WorkBuddy build"));
        };
        if !validate_login_url(selected, &auth_url) {
            return Err(invalid_host("authUrl"));
        }
        let auth_url = decorate_login_url(
            &auth_url,
            build.app,
            &uuid::Uuid::new_v4().simple().to_string(),
        )?;
        Ok(LoginStart { state, auth_url })
    }

    /// Poll a token. A refresh token is required here even though the vendor
    /// sometimes omits it: Cardinal persists bundles that can refresh, so an
    /// incomplete answer is rejected rather than stored.
    pub async fn poll_token(
        &self,
        base: &str,
        build: BuildInfo,
        state: &str,
    ) -> Result<TokenPoll, WorkbuddyError> {
        validate_base(base, build)?;
        let result = self
            .call_get(
                "auth/token",
                &format!("{}/v2/plugin/auth/token", trim_base(base)),
                plugin_headers(build, None, None),
                vec![("state", state.to_owned())],
            )
            .await;
        let data = match result {
            Ok(data) => data,
            Err(WorkbuddyError::Envelope { code: 11217, .. }) => return Ok(TokenPoll::Pending),
            Err(error) => return Err(error),
        };
        token_from(&data, build, Utc::now()).map(TokenPoll::Ready)
    }

    /// Poll the account identity associated with an access token.
    pub async fn poll_account(
        &self,
        base: &str,
        build: BuildInfo,
        state: &str,
        access_token: &str,
    ) -> Result<AccountPoll, WorkbuddyError> {
        validate_base(base, build)?;
        let result = self
            .call_get(
                "login/account",
                &format!("{}/v2/plugin/login/account", trim_base(base)),
                plugin_headers(
                    build,
                    Some(access_token),
                    Some(endpoint_host(
                        Build::for_platform(build.platform)
                            .ok_or_else(|| invalid_host("WorkBuddy build"))?,
                    )),
                ),
                vec![("state", state.to_owned())],
            )
            .await;
        let data = match result {
            Ok(data) => data,
            Err(WorkbuddyError::Envelope { code: 12151, .. }) => return Ok(AccountPoll::Pending),
            Err(error) => return Err(error),
        };
        account_from(&data).map(AccountPoll::Ready)
    }

    /// Refresh the current bundle, merging omitted token and identity fields
    /// exactly as the vendor client does: returned non-empty values win, while
    /// omitted refresh/domain/type/expiry values remain from `current`.
    pub async fn refresh(
        &self,
        base: &str,
        current: &WorkbuddyOAuth,
    ) -> Result<WorkbuddyOAuth, WorkbuddyError> {
        let build = crate::relay::capabilities::workbuddy::host_build_from_value(base)
            .ok_or_else(|| invalid_host("WorkBuddy base URL"))?;
        if !validate_base_origin(build, base) {
            return Err(invalid_host("WorkBuddy base URL"));
        }
        let domain = current
            .domain
            .as_deref()
            .map(|domain| {
                crate::relay::capabilities::workbuddy::normalize_credential_origin(build, domain)
                    .ok_or_else(|| invalid_host("stored OAuth domain"))
            })
            .transpose()?;
        let data = self
            .call_raw(
                "auth/token/refresh",
                &format!("{}/v2/plugin/auth/token/refresh", trim_base(base)),
                serde_json::json!({}),
                vec![
                    ("x-refresh-token", current.refresh_token.clone()),
                    ("x-auth-refresh-source", "plugin".to_owned()),
                    (
                        "x-domain",
                        domain
                            .as_deref()
                            .unwrap_or_else(|| endpoint_host(build))
                            .to_owned(),
                    ),
                ],
                Vec::new(),
            )
            .await?;
        merge_refresh(&data, current, build, domain.as_deref(), Utc::now())
    }

    async fn call(
        &self,
        operation: &'static str,
        url: &str,
        body: serde_json::Value,
        headers: Vec<(&'static str, String)>,
        query: Vec<(&'static str, String)>,
    ) -> Result<serde_json::Value, WorkbuddyError> {
        self.call_raw(operation, url, body, headers, query).await
    }

    async fn call_raw(
        &self,
        operation: &'static str,
        url: &str,
        body: serde_json::Value,
        headers: Vec<(&'static str, String)>,
        query: Vec<(&'static str, String)>,
    ) -> Result<serde_json::Value, WorkbuddyError> {
        let prepared = Prepared {
            protocol: crate::protocol::ProtocolId::OpenAiChat,
            url: url.to_owned(),
            content_type: "application/json",
            body: bytes::Bytes::from(body.to_string()),
            stream: false,
            headers: Vec::new(),
            cursor: None,
        };
        let deadline = std::time::Instant::now() + REQUEST_TIMEOUT;
        let response = self
            .transport
            .send_with_headers(&prepared, self.dns, &headers, &query, deadline)
            .await
            .map_err(|_| WorkbuddyError::Transport { operation })?;
        self.finish(operation, response, deadline).await
    }

    /// GET variant for the browser-login poll endpoints. The vendor answers
    /// POST to `auth/token` and `login/account` with 404; the desktop client
    /// polls them with GET, so token/account polling must use this path while
    /// state creation and refresh stay POST.
    async fn call_get(
        &self,
        operation: &'static str,
        url: &str,
        headers: Vec<(&'static str, String)>,
        query: Vec<(&'static str, String)>,
    ) -> Result<serde_json::Value, WorkbuddyError> {
        let deadline = std::time::Instant::now() + REQUEST_TIMEOUT;
        let response = self
            .transport
            .send_get_with_headers(url, self.dns, &headers, &query, deadline)
            .await
            .map_err(|_| WorkbuddyError::Transport { operation })?;
        self.finish(operation, response, deadline).await
    }

    async fn finish(
        &self,
        operation: &'static str,
        response: reqwest::Response,
        deadline: std::time::Instant,
    ) -> Result<serde_json::Value, WorkbuddyError> {
        let status = response.status();
        let body = self
            .transport
            .read_body(response, MAX_BODY, deadline)
            .await
            .map_err(|_| WorkbuddyError::Transport { operation })?;
        if !status.is_success() {
            return Err(WorkbuddyError::Protocol {
                operation: format!("{operation} returned HTTP {}", status.as_u16()),
            });
        }
        let text = std::str::from_utf8(&body).map_err(|_| WorkbuddyError::Shape { operation })?;
        envelope(text)
    }
}

/// Add the desktop login page's browser parameters to a vendor-authored URL.
///
/// WorkBuddy's own client and the reference plugin append `version` (the
/// desktop app version, which gates sign-in options such as WeCom) and
/// `loginSessionId` before opening the page. The vendor's bare `authUrl` omits
/// both. This function is called only after [`validate_login_url`] has pinned
/// the URL to an allowed HTTPS login host, so it only appends query pairs and
/// cannot widen the SSRF boundary.
fn decorate_login_url(
    auth_url: &str,
    app: &str,
    session_id: &str,
) -> Result<String, WorkbuddyError> {
    let mut url = reqwest::Url::parse(auth_url.trim()).map_err(|_| WorkbuddyError::Shape {
        operation: "auth/state",
    })?;
    url.query_pairs_mut()
        .append_pair("version", app)
        .append_pair("loginSessionId", session_id);
    Ok(url.to_string())
}

fn trim_base(base: &str) -> &str {
    base.trim_end_matches('/')
}

fn plugin_headers(
    build: BuildInfo,
    bearer: Option<&str>,
    domain: Option<&str>,
) -> Vec<(&'static str, String)> {
    let mut headers = vec![
        ("accept", "application/json".to_owned()),
        ("user-agent", format!("WorkBuddy/{}", build.app)),
        ("x-no-user-id", "true".to_owned()),
        ("x-no-enterprise-id", "true".to_owned()),
        ("x-no-department-info", "true".to_owned()),
    ];
    if bearer.is_none() {
        headers.push(("x-no-authorization", "true".to_owned()));
    }
    if let Some(token) = bearer {
        headers.push(("authorization", format!("Bearer {token}")));
    }
    if let Some(domain) = domain {
        headers.push(("x-domain", domain.to_owned()));
    }
    headers
}

fn endpoint_host(build: Build) -> &'static str {
    match build {
        Build::China => "copilot.tencent.com",
        Build::International => "www.workbuddy.ai",
    }
}

fn validate_base(base: &str, build: BuildInfo) -> Result<(), WorkbuddyError> {
    let Some(selected) = Build::for_platform(build.platform) else {
        return Err(invalid_host("WorkBuddy build"));
    };
    if !validate_base_origin(selected, base) {
        return Err(invalid_host("WorkBuddy base URL"));
    }
    Ok(())
}

fn invalid_host(what: &'static str) -> WorkbuddyError {
    WorkbuddyError::Protocol {
        operation: format!("{what} is not an allowed HTTPS host"),
    }
}

fn text_field(
    data: &serde_json::Value,
    field: &'static str,
    operation: &'static str,
) -> Result<String, WorkbuddyError> {
    data.get(field)
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(str::to_owned)
        .ok_or(WorkbuddyError::Shape { operation })
}

fn epoch_field(
    data: &serde_json::Value,
    absolute: &str,
    relative: &str,
    now: DateTime<Utc>,
) -> Result<Option<DateTime<Utc>>, ()> {
    if let Some(value) = data.get(absolute).and_then(number_value)
        && value > 0
    {
        let millis = if value > 10_000_000_000 {
            value
        } else {
            value.checked_mul(1000).ok_or(())?
        };
        return DateTime::from_timestamp_millis(millis).ok_or(()).map(Some);
    }
    let Some(seconds) = data.get(relative).and_then(number_value).filter(|v| *v > 0) else {
        return Ok(None);
    };
    let delta = TimeDelta::try_seconds(seconds).ok_or(())?;
    now.checked_add_signed(delta).ok_or(()).map(Some)
}

fn number_value(value: &serde_json::Value) -> Option<i64> {
    value
        .as_i64()
        .or_else(|| value.as_str().and_then(|text| text.trim().parse().ok()))
}

fn token_from(
    data: &serde_json::Value,
    build: BuildInfo,
    now: DateTime<Utc>,
) -> Result<WorkbuddyOAuth, WorkbuddyError> {
    let access_token = text_field(data, "accessToken", "auth/token")?;
    let refresh_token = text_field(data, "refreshToken", "auth/token")?;
    let expires_at = epoch_field(data, "expiresAt", "expiresIn", now)
        .map_err(|_| WorkbuddyError::Shape {
            operation: "auth/token",
        })?
        .ok_or(WorkbuddyError::Shape {
            operation: "auth/token",
        })?;
    let selected =
        Build::for_platform(build.platform).ok_or_else(|| invalid_host("WorkBuddy build"))?;
    let domain = optional_text(data, "domain")
        .map(|domain| {
            crate::relay::capabilities::workbuddy::normalize_credential_origin(selected, &domain)
                .ok_or_else(|| invalid_host("OAuth domain"))
        })
        .transpose()?;
    Ok(WorkbuddyOAuth {
        access_token,
        refresh_token,
        expires_at,
        refresh_expires_at: epoch_field(data, "refreshExpiresAt", "refreshExpiresIn", now)
            .map_err(|_| WorkbuddyError::Shape {
                operation: "auth/token",
            })?,
        uid: String::new(),
        domain: domain.or_else(|| Some(endpoint_host(selected).to_owned())),
        token_type: optional_text(data, "tokenType"),
        enterprise_id: optional_text(data, "enterpriseId"),
    })
}

fn merge_refresh(
    data: &serde_json::Value,
    current: &WorkbuddyOAuth,
    build: Build,
    current_domain: Option<&str>,
    now: DateTime<Utc>,
) -> Result<WorkbuddyOAuth, WorkbuddyError> {
    let access_token = text_field(data, "accessToken", "auth/token/refresh")?;
    let refresh_token =
        optional_text(data, "refreshToken").unwrap_or_else(|| current.refresh_token.clone());
    let expires_at = epoch_field(data, "expiresAt", "expiresIn", now)
        .map_err(|_| WorkbuddyError::Shape {
            operation: "auth/token/refresh",
        })?
        .unwrap_or(current.expires_at);
    let refresh_expires_at = epoch_field(data, "refreshExpiresAt", "refreshExpiresIn", now)
        .map_err(|_| WorkbuddyError::Shape {
            operation: "auth/token/refresh",
        })?
        .or(current.refresh_expires_at);
    let domain = optional_text(data, "domain")
        .as_deref()
        .or(current_domain)
        .and_then(|domain| {
            crate::relay::capabilities::workbuddy::normalize_credential_origin(build, domain)
        });
    if domain.is_none() {
        return Err(invalid_host("OAuth domain"));
    }
    Ok(WorkbuddyOAuth {
        access_token,
        refresh_token,
        expires_at,
        refresh_expires_at,
        uid: current.uid.clone(),
        domain,
        token_type: optional_text(data, "tokenType").or_else(|| current.token_type.clone()),
        enterprise_id: current.enterprise_id.clone(),
    })
}

fn optional_text(data: &serde_json::Value, field: &str) -> Option<String> {
    data.get(field)
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(str::to_owned)
}

fn account_from(data: &serde_json::Value) -> Result<String, WorkbuddyError> {
    text_field(data, "uid", "login/account")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn china_build() -> BuildInfo {
        BuildInfo {
            platform: "workbuddy",
            app: "5.9.3",
        }
    }

    #[test]
    fn login_url_carries_desktop_version_and_session_id() {
        let decorated = decorate_login_url(
            "https://www.workbuddy.cn/login?platform=workbuddy&state=abc",
            "5.9.3",
            "session-123",
        )
        .expect("decorate authUrl");
        let url = reqwest::Url::parse(&decorated).expect("valid decorated URL");
        assert_eq!(url.host_str(), Some("www.workbuddy.cn"));
        assert_eq!(url.path(), "/login");
        let pairs: Vec<(String, String)> = url
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        assert!(pairs.contains(&("state".to_owned(), "abc".to_owned())));
        assert!(pairs.contains(&("version".to_owned(), "5.9.3".to_owned())));
        assert!(pairs.contains(&("loginSessionId".to_owned(), "session-123".to_owned())));
    }

    #[test]
    fn envelope_returns_data() {
        let data = envelope(r#"{"code":0,"data":{"state":"s"}}"#).expect("valid envelope");
        assert_eq!(data["state"], "s");
    }

    #[test]
    fn envelope_maps_pending_code() {
        let error = envelope(r#"{"code":11217,"msg":"pending","data":{}}"#)
            .expect_err("pending envelope is an error");
        assert_eq!(error, WorkbuddyError::Envelope { code: 11217 });
    }

    #[test]
    fn malformed_envelope_is_shape_error() {
        assert!(matches!(
            envelope("not json"),
            Err(WorkbuddyError::Shape { .. })
        ));
    }

    #[test]
    fn envelope_display_does_not_include_vendor_message() {
        let error =
            envelope(r#"{"code":500,"msg":"token=secret-value must never be exposed","data":{}}"#)
                .expect_err("vendor error envelope is rejected");

        let display = error.to_string();
        assert_eq!(display, "WorkBuddy backend returned an error envelope");
        assert!(!display.contains("secret-value"));
    }

    #[test]
    fn large_expiry_is_shape_error() {
        let data = serde_json::json!({
            "accessToken":"a", "refreshToken":"r", "expiresAt": i64::MAX
        });
        assert!(matches!(
            token_from(&data, china_build(), Utc::now()),
            Err(WorkbuddyError::Shape {
                operation: "auth/token"
            })
        ));
    }

    #[test]
    fn absolute_expiry_wins() {
        let now = Utc::now();
        let data = serde_json::json!({
            "accessToken":"a", "refreshToken":"r",
            "expiresAt": (now.timestamp_millis() + 60_000), "expiresIn": 1
        });
        let token = token_from(&data, china_build(), now).expect("token shape");
        assert!(token.expires_at > now + TimeDelta::seconds(30));
    }

    #[test]
    fn token_requires_access_and_refresh() {
        let missing_access = serde_json::json!({"refreshToken":"r", "expiresIn":10});
        assert!(matches!(
            token_from(&missing_access, china_build(), Utc::now()),
            Err(WorkbuddyError::Shape { .. })
        ));
        let missing_refresh = serde_json::json!({"accessToken":"a", "expiresIn":10});
        assert!(matches!(
            token_from(&missing_refresh, china_build(), Utc::now()),
            Err(WorkbuddyError::Shape { .. })
        ));
    }

    #[test]
    fn account_uid_is_ready() {
        let uid = account_from(&serde_json::json!({"uid":"u"})).expect("uid");
        assert_eq!(uid, "u");
    }
}
