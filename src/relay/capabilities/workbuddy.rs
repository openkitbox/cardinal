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
