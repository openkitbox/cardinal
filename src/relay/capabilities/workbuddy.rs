//! WorkBuddy vendor capability rows for the China and international builds.
//!
//! The China build serves OpenAI Chat and Claude messages, while the
//! international build serves only OpenAI Chat. In particular, the
//! international build's `/v1/messages` endpoint returned 404 in the
//! reference implementation's live test.

use crate::protocol::ProtocolId;
use crate::providers::AuthScheme;

use super::{Capability, bearer};

/// WorkBuddy's two product builds and their protocol host contracts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Build {
    China,
    International,
}

impl Build {
    pub(crate) fn of(provider_name: &str) -> Option<Self> {
        let mut segments = provider_name.split('-');
        if segments.next() != Some("workbuddy") {
            return None;
        }
        if segments.any(|segment| segment == "intl") {
            Some(Self::International)
        } else {
            Some(Self::China)
        }
    }

    pub(crate) fn endpoint(self) -> &'static str {
        match self {
            Self::China => "https://copilot.tencent.com",
            Self::International => "https://www.workbuddy.ai",
        }
    }

    pub(crate) fn for_platform(platform: &str) -> Option<Self> {
        match platform {
            "workbuddy" => Some(Self::China),
            "workbuddy-ai" => Some(Self::International),
            _ => None,
        }
    }

    pub(crate) fn platform(self) -> &'static str {
        match self {
            Self::China => "workbuddy",
            Self::International => "workbuddy-ai",
        }
    }

    pub(crate) fn app(self) -> &'static str {
        "5.9.3"
    }

    pub(crate) fn cli(self) -> &'static str {
        "2.165.0"
    }

    pub(crate) fn app_name(self) -> &'static str {
        match self {
            Self::China => "WorkBuddy",
            Self::International => self.platform(),
        }
    }
}

/// WorkBuddy desktop 5.9.3.42398134 constants as used by the reference client.
pub(crate) fn is_workbuddy(provider_name: &str) -> bool {
    Build::of(provider_name).is_some()
}

pub(crate) fn capabilities(provider_name: &str, base: &str) -> Vec<Capability> {
    if !is_workbuddy(provider_name) {
        return Vec::new();
    }
    let Some(build) = Build::of(provider_name) else {
        return Vec::new();
    };
    let mut rows = vec![bearer(
        ProtocolId::OpenAiChat,
        format!("{base}/v2/chat/completions"),
    )];
    if build == Build::China {
        rows.push(Capability {
            protocol: ProtocolId::AnthropicMessages,
            endpoint: format!("{base}/v1/messages"),
            stream_endpoint: None,
            auth_scheme: AuthScheme::Bearer,
            claude_only: true,
        });
    }
    rows
}

pub(crate) fn validate_base_url(provider_name: &str, base: &str) -> anyhow::Result<()> {
    let build = Build::of(provider_name)
        .ok_or_else(|| anyhow::anyhow!("invalid WorkBuddy provider name"))?;
    anyhow::ensure!(
        validate_base_origin(build, base),
        "workbuddy base_url 必须是对应站点的 HTTPS 根 origin"
    );
    Ok(())
}

/// Whether a credential may be sent to the selected WorkBuddy host.
pub(crate) fn host_allowed(build: Build, host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    match build {
        Build::China => {
            host == "copilot.tencent.com"
                // Personal-account tokens report the console host as their
                // domain (Magpie: native.test.mjs / usage.test.mjs). It is the
                // China counterpart of the international main domain below.
                || host == "www.workbuddy.cn"
                || host == "workbuddy.cn"
                || host.ends_with(".sso.copilot.tencent.com")
                || host.ends_with(".copilot.qq.com")
                || host.ends_with(".sso.codebuddy.cn")
        }
        Build::International => host == "www.workbuddy.ai" || host == "workbuddy.ai",
    }
}

pub(crate) fn host_build(host: &str) -> Option<Build> {
    [Build::China, Build::International]
        .into_iter()
        .find(|build| host_allowed(*build, host))
}

/// Validate a WorkBuddy origin or domain before it is used with credentials.
///
/// The login service accepts either a bare host or an HTTPS origin, but never a
/// path, port, userinfo, query, or fragment. Keeping this policy here prevents
/// the HTTP client and token manager from growing subtly different SSRF gates.
pub(crate) fn validate_credential_host(build: Build, value: &str) -> bool {
    let value = value.trim();
    if value.is_empty() {
        return false;
    }
    let parsed = if value.contains("://") {
        reqwest::Url::parse(value).ok()
    } else {
        reqwest::Url::parse(&format!("https://{value}")).ok()
    };
    let Some(url) = parsed else {
        return false;
    };
    let authority = value
        .split_once("://")
        .map_or(value, |(_, rest)| rest)
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();
    if authority.contains('@') || authority.contains(':') {
        return false;
    }
    url.scheme() == "https"
        && url.username().is_empty()
        && url.password().is_none()
        && url.port().is_none()
        && (url.path().is_empty() || url.path() == "/")
        && url.query().is_none()
        && url.fragment().is_none()
        && url.host_str().is_some_and(|host| host_allowed(build, host))
}

/// Validate the configured provider endpoint. Unlike credential domains, a
/// provider base is never accepted in its shorthand (bare-host) form.
pub(crate) fn validate_base_origin(build: Build, value: &str) -> bool {
    let value = value.trim();
    let Some(url) = reqwest::Url::parse(value).ok() else {
        return false;
    };
    let authority = value
        .split_once("://")
        .map_or(value, |(_, rest)| rest)
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();
    if authority.contains('@') || authority.contains(':') {
        return false;
    }
    url.scheme() == "https"
        && url.username().is_empty()
        && url.password().is_none()
        && url.port().is_none()
        && url.path() == "/"
        && url.query().is_none()
        && url.fragment().is_none()
        && url.host_str().is_some_and(|host| host_allowed(build, host))
}

/// Hosts a WorkBuddy browser login URL may use.
///
/// Deliberately separate from [`host_allowed`], which gates where credentials
/// may be *sent*: a login URL is only opened by the admin's browser and never
/// receives credentials, so this list covers the vendor's actual login pages
/// only. The China flow lands on `www.workbuddy.cn`; the API host is kept for
/// the legacy `/console/client-login` path.
fn login_host_allowed(build: Build, host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    match build {
        Build::China => {
            host == "www.workbuddy.cn" || host == "workbuddy.cn" || host == "copilot.tencent.com"
        }
        Build::International => host == "www.workbuddy.ai" || host == "workbuddy.ai",
    }
}

/// Validate a vendor URL that is intended to be opened by a browser.
///
/// Browser login URLs are not credential origins: Cardinal never fetches them
/// and never sends credentials to them, so the SSRF gate lives in the credential
/// host checks. Here the URL is pinned to the selected build's login host and to
/// https, with no smuggled authority, port, or fragment. A query and the vendor's
/// `/login` (current) or `/console` (legacy) path are allowed.
pub(crate) fn validate_login_url(build: Build, value: &str) -> bool {
    let Some(url) = reqwest::Url::parse(value.trim()).ok() else {
        return false;
    };
    let authority = value
        .trim()
        .split_once("://")
        .map_or(value.trim(), |(_, rest)| rest)
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();
    if authority.contains('@') || authority.contains(':') {
        return false;
    }
    let path = url.path();
    url.scheme() == "https"
        && url.username().is_empty()
        && url.password().is_none()
        && url.port().is_none()
        && url
            .host_str()
            .is_some_and(|host| login_host_allowed(build, host))
        && (path == "/login" || path == "/console" || path.starts_with("/console/"))
        && url.fragment().is_none()
}

pub(crate) fn host_build_from_value(value: &str) -> Option<Build> {
    let value = value.trim();
    let parsed = if value.contains("://") {
        reqwest::Url::parse(value).ok()
    } else {
        reqwest::Url::parse(&format!("https://{value}")).ok()
    }?;
    let authority = value
        .split_once("://")
        .map_or(value, |(_, rest)| rest)
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();
    if authority.contains('@') || authority.contains(':') {
        return None;
    }
    if parsed.scheme() != "https"
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.port().is_some()
        || (!parsed.path().is_empty() && parsed.path() != "/")
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return None;
    }
    parsed.host_str().and_then(host_build)
}

pub(crate) fn normalize_credential_origin(build: Build, value: &str) -> Option<String> {
    let value = value.trim();
    let parsed = if value.contains("://") {
        reqwest::Url::parse(value).ok()
    } else {
        reqwest::Url::parse(&format!("https://{value}")).ok()
    }?;
    if !validate_credential_host(build, value) {
        return None;
    }
    let host = parsed.host_str()?;
    Some(format!("https://{host}"))
}

pub enum WorkbuddyCredential<'a> {
    Key(&'a str),
    Account {
        access_token: &'a str,
        uid: &'a str,
        domain: Option<&'a str>,
    },
}

const NAMESPACE: uuid::Uuid = uuid::Uuid::from_u128(0x776f_726b_6275_6464_795f_7365_7373_696f);

pub(crate) fn headers(
    build: Build,
    credential: WorkbuddyCredential<'_>,
    session_seed: Option<&str>,
) -> Vec<(&'static str, String)> {
    let mut headers = vec![
        (
            "user-agent",
            format!(
                "WorkBuddy/{} {}/{} CLI/{}",
                build.app(),
                build.app_name(),
                build.app(),
                build.cli()
            ),
        ),
        ("x-product", "SaaS".to_owned()),
        ("x-ide-type", "WorkBuddy".to_owned()),
        ("x-ide-name", "WorkBuddy".to_owned()),
        ("x-ide-version", build.app().to_owned()),
        ("x-requested-with", "XMLHttpRequest".to_owned()),
        ("x-agent-intent", "craft".to_owned()),
        ("x-agent-purpose", "conversation".to_owned()),
        ("x-agent-type", "main".to_owned()),
        ("x-agent-runtime", "local-agent".to_owned()),
        ("accept", "application/json".to_owned()),
    ];
    match credential {
        WorkbuddyCredential::Key(key) => {
            headers.insert(0, ("authorization", format!("Bearer {key}")));
            headers.push(("x-api-key", key.to_owned()));
            headers.push((
                "x-user-id",
                format!("anonymous_{}", last_characters(key, 8)),
            ));
        }
        WorkbuddyCredential::Account {
            access_token,
            uid,
            domain,
        } => {
            if domain.is_some_and(|domain| !validate_credential_host(build, domain)) {
                return headers;
            }
            headers.insert(0, ("authorization", format!("Bearer {access_token}")));
            headers.push(("x-user-id", uid.to_owned()));
            headers.push((
                "x-domain",
                domain.unwrap_or_else(|| endpoint_host(build)).to_owned(),
            ));
        }
    }
    headers.push(("x-request-id", uuid::Uuid::new_v4().to_string()));
    headers.push((
        "x-conversation-message-id",
        uuid::Uuid::new_v4().to_string(),
    ));
    if let Some(seed) = session_seed {
        let conversation_id = uuid::Uuid::new_v5(&NAMESPACE, seed.as_bytes()).to_string();
        headers.push(("x-conversation-id", conversation_id.clone()));
        headers.push(("x-conversation-request-id", conversation_id));
    }
    headers
}

fn endpoint_host(build: Build) -> &'static str {
    let endpoint = build.endpoint();
    endpoint.strip_prefix("https://").unwrap_or(endpoint)
}

fn last_characters(value: &str, count: usize) -> String {
    value
        .chars()
        .rev()
        .take(count)
        .collect::<String>()
        .chars()
        .rev()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay::capabilities::{capabilities as vendor_capabilities, select};

    fn header<'a>(headers: &'a [(&'static str, String)], name: &str) -> Option<&'a str> {
        headers
            .iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| value.as_str())
    }

    #[test]
    fn china_has_chat_and_claude_rows() {
        let rows = capabilities("workbuddy", "https://copilot.tencent.com");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].protocol, ProtocolId::OpenAiChat);
        assert_eq!(
            rows[0].endpoint,
            "https://copilot.tencent.com/v2/chat/completions"
        );
        assert!(!rows[0].claude_only);
        assert_eq!(rows[1].protocol, ProtocolId::AnthropicMessages);
        assert_eq!(rows[1].endpoint, "https://copilot.tencent.com/v1/messages");
        assert!(rows[1].claude_only);
    }

    #[test]
    fn international_has_only_chat_row() {
        let rows = capabilities("workbuddy-intl", "https://www.workbuddy.ai");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].protocol, ProtocolId::OpenAiChat);
        assert_eq!(
            rows[0].endpoint,
            "https://www.workbuddy.ai/v2/chat/completions"
        );
        assert!(!rows[0].claude_only);
    }

    #[test]
    fn selection_prefers_claude_row_and_translates_other_models() {
        let china = vendor_capabilities(
            "workbuddy",
            ProtocolId::OpenAiChat.as_str(),
            "https://copilot.tencent.com",
            "bearer",
        );
        let selected = select(&china, ProtocolId::AnthropicMessages, "claude-opus-5.5")
            .expect("China should serve Claude through the messages row");
        assert_eq!(selected.protocol, ProtocolId::AnthropicMessages);
        let selected = select(&china, ProtocolId::AnthropicMessages, "glm-5.3")
            .expect("non-Claude Anthropic traffic should translate to chat");
        assert_eq!(selected.protocol, ProtocolId::OpenAiChat);
        let international = vendor_capabilities(
            "workbuddy-intl",
            ProtocolId::OpenAiChat.as_str(),
            "https://www.workbuddy.ai",
            "bearer",
        );
        let selected = select(
            &international,
            ProtocolId::AnthropicMessages,
            "claude-opus-5.5",
        )
        .expect("international Anthropic traffic should translate to chat");
        assert_eq!(selected.protocol, ProtocolId::OpenAiChat);
    }

    #[test]
    fn validates_site_root_only() {
        assert!(validate_base_url("workbuddy", "https://copilot.tencent.com").is_ok());
        assert!(validate_base_url("workbuddy-intl", "https://www.workbuddy.ai").is_ok());
        assert!(validate_base_url("workbuddy", "").is_err());
        assert!(validate_base_url("workbuddy", "https://copilot.tencent.com/v2").is_err());
        assert!(validate_base_url("workbuddy", "https://www.workbuddy.ai").is_err());
        assert!(validate_base_url("workbuddy", "copilot.tencent.com").is_err());
    }

    #[test]
    fn credential_host_rejects_auth_url_like_values() {
        for value in [
            "https://copilot.tencent.com:443",
            "https://copilot.tencent.com/login",
            "https://copilot.tencent.com/?next=evil.example",
            "https://copilot.tencent.com/#fragment",
            "https://user@copilot.tencent.com",
        ] {
            assert!(
                !validate_credential_host(Build::China, value),
                "must reject credential host value {value}"
            );
        }
    }

    #[test]
    fn validates_workbuddy_base_origin_and_build_host() {
        assert!(validate_base_url("workbuddy", "https://copilot.tencent.com").is_ok());
        assert!(validate_base_url("workbuddy-intl", "https://www.workbuddy.ai").is_ok());
        assert!(validate_base_url("workbuddy", "https://evil.example.com").is_err());
        assert!(validate_base_url("workbuddy-intl", "https://www.workbuddy.ai/v2").is_err());
        assert!(validate_base_url("workbuddy", "https://copilot.tencent.com:443").is_err());
        assert!(validate_base_url("workbuddy", "https://copilot.tencent.com?x=y").is_err());
        assert!(validate_base_url("workbuddy", "https://copilot.tencent.com/#x").is_err());
        assert!(validate_base_url("workbuddy", "https://user@copilot.tencent.com").is_err());
    }

    #[test]
    fn login_url_is_separate_from_credential_origin() {
        // Real /v2/plugin/auth/state responses: the browser login page lives on
        // www.workbuddy.cn (China) or www.workbuddy.ai (international), path
        // /login — not on the API host, and not under /console.
        let cn_login = "https://www.workbuddy.cn/login?platform=workbuddy&state=opaque";
        assert!(validate_login_url(Build::China, cn_login));
        assert!(!validate_credential_host(Build::China, cn_login));
        assert!(validate_login_url(
            Build::International,
            "https://www.workbuddy.ai/login?platform=workbuddy-ai&state=opaque"
        ));
        // The legacy console path on the API host stays accepted for China.
        assert!(validate_login_url(
            Build::China,
            "https://copilot.tencent.com/console/client-login?state=opaque"
        ));
        // Cross-build, wrong path, smuggled authority/port, and non-https are
        // still rejected.
        assert!(!validate_login_url(Build::International, cn_login));
        assert!(!validate_login_url(
            Build::China,
            "https://www.workbuddy.cn/other/login?state=opaque"
        ));
        assert!(!validate_login_url(
            Build::China,
            "https://www.workbuddy.cn:443/login"
        ));
        assert!(!validate_login_url(
            Build::China,
            "https://user@www.workbuddy.cn/login"
        ));
        assert!(!validate_login_url(
            Build::China,
            "https://www.workbuddy.cn/login#fragment"
        ));
        assert!(!validate_login_url(
            Build::China,
            "http://www.workbuddy.cn/login"
        ));
        assert!(!validate_login_url(
            Build::China,
            "https://evil.example/login"
        ));
    }

    #[test]
    fn credential_origin_normalizes_bare_and_https_hosts() {
        assert_eq!(
            normalize_credential_origin(Build::International, "WORKBUDDY.AI"),
            Some("https://workbuddy.ai".to_owned())
        );
        assert_eq!(
            normalize_credential_origin(Build::International, "https://www.workbuddy.ai"),
            Some("https://www.workbuddy.ai".to_owned())
        );
        assert_eq!(
            normalize_credential_origin(Build::China, "https://www.workbuddy.ai"),
            None
        );
    }

    #[test]
    fn host_gate_is_specific_to_each_build() {
        assert!(host_allowed(Build::China, "copilot.tencent.com"));
        assert!(host_allowed(Build::China, "acme.sso.copilot.tencent.com"));
        assert!(host_allowed(Build::China, "acme.copilot.qq.com"));
        assert!(host_allowed(Build::China, "acme.sso.codebuddy.cn"));
        // Personal accounts report the China console host as their domain; it
        // is a credential destination just like the international main domain.
        assert!(host_allowed(Build::China, "www.workbuddy.cn"));
        assert!(host_allowed(Build::China, "WORKBUDDY.CN"));
        assert!(!host_allowed(Build::China, "www.workbuddy.ai"));
        assert!(!host_allowed(Build::China, "evil.example.com"));
        assert!(host_allowed(Build::International, "www.workbuddy.ai"));
        assert!(host_allowed(Build::International, "WORKBUDDY.AI"));
        assert!(!host_allowed(Build::International, "copilot.tencent.com"));
    }

    #[test]
    fn credential_host_requires_allowed_https_origin_without_path_or_port() {
        assert!(validate_credential_host(
            Build::China,
            "https://copilot.tencent.com"
        ));
        assert!(validate_credential_host(
            Build::China,
            "copilot.tencent.com"
        ));
        assert!(!validate_credential_host(
            Build::China,
            "http://copilot.tencent.com"
        ));
        assert!(!validate_credential_host(
            Build::China,
            "https://copilot.tencent.com:443"
        ));
        assert!(!validate_credential_host(
            Build::China,
            "https://copilot.tencent.com/v2"
        ));
        assert!(!validate_credential_host(
            Build::International,
            "https://copilot.tencent.com"
        ));
    }

    #[test]
    fn invalid_account_domain_does_not_emit_bearer() {
        let headers = headers(
            Build::China,
            WorkbuddyCredential::Account {
                access_token: "secret",
                uid: "user",
                domain: Some("https://evil.example.com"),
            },
            None,
        );
        assert!(header(&headers, "authorization").is_none());
    }

    #[test]
    fn key_headers_include_key_identity_without_domain() {
        let headers = headers(Build::China, WorkbuddyCredential::Key("密钥abcdefgh"), None);
        assert_eq!(
            header(&headers, "authorization"),
            Some("Bearer 密钥abcdefgh")
        );
        assert_eq!(header(&headers, "x-api-key"), Some("密钥abcdefgh"));
        assert_eq!(header(&headers, "x-user-id"), Some("anonymous_abcdefgh"));
        assert!(header(&headers, "x-domain").is_none());
    }

    #[test]
    fn account_headers_include_account_identity_without_api_key() {
        let headers = headers(
            Build::International,
            WorkbuddyCredential::Account {
                access_token: "token",
                uid: "user-1",
                domain: None,
            },
            None,
        );
        assert_eq!(header(&headers, "authorization"), Some("Bearer token"));
        assert_eq!(header(&headers, "x-user-id"), Some("user-1"));
        assert_eq!(header(&headers, "x-domain"), Some("www.workbuddy.ai"));
        assert!(header(&headers, "x-api-key").is_none());
    }

    #[test]
    fn headers_have_build_identity_and_stable_session_ids() {
        let china = headers(Build::China, WorkbuddyCredential::Key("key"), None);
        let international = headers(Build::International, WorkbuddyCredential::Key("key"), None);
        assert_eq!(
            header(&china, "user-agent"),
            Some("WorkBuddy/5.9.3 WorkBuddy/5.9.3 CLI/2.165.0")
        );
        assert_eq!(
            header(&international, "user-agent"),
            Some("WorkBuddy/5.9.3 workbuddy-ai/5.9.3 CLI/2.165.0")
        );
        let first = headers(Build::China, WorkbuddyCredential::Key("key"), Some("seed"));
        let second = headers(Build::China, WorkbuddyCredential::Key("key"), Some("seed"));
        assert_eq!(
            header(&first, "x-conversation-id"),
            header(&second, "x-conversation-id")
        );
        assert_eq!(
            header(&first, "x-conversation-request-id"),
            header(&second, "x-conversation-request-id")
        );
        assert_ne!(
            header(&first, "x-request-id"),
            header(&second, "x-request-id")
        );
        assert_ne!(
            header(&first, "x-conversation-message-id"),
            header(&second, "x-conversation-message-id")
        );
    }
}
