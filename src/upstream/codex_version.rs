use std::sync::{Arc, RwLock};

use crate::upstream::transport::Transport;
use crate::upstream::{Dns, ProxySpec};

pub const FALLBACK_VERSION: &str = "0.170.0";
const GITHUB_RELEASE_URL: &str = "https://api.github.com/repos/openai/codex/releases/latest";
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(8);
const MAX_BODY: usize = 10 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodexReleaseFailureStage {
    Transport,
    HttpStatus,
    ResponseBody,
    Json,
    ReleaseTag,
}

impl CodexReleaseFailureStage {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Transport => "transport",
            Self::HttpStatus => "http_status",
            Self::ResponseBody => "response_body",
            Self::Json => "json",
            Self::ReleaseTag => "release_tag",
        }
    }
}

#[derive(Debug)]
pub struct CodexReleaseFailure {
    stage: CodexReleaseFailureStage,
}

impl CodexReleaseFailure {
    pub const fn stage(&self) -> CodexReleaseFailureStage {
        self.stage
    }
}

impl std::fmt::Display for CodexReleaseFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Codex latest release lookup failed")
    }
}

impl std::error::Error for CodexReleaseFailure {}

fn release_failure(stage: CodexReleaseFailureStage) -> CodexReleaseFailure {
    CodexReleaseFailure { stage }
}

#[derive(Clone)]
pub struct CodexClientVersion {
    current: Arc<RwLock<Arc<str>>>,
}

/// A shared Codex client-version value without exposing its storage strategy.
#[derive(Clone)]
pub struct CodexClientVersionValue(Arc<str>);

impl AsRef<str> for CodexClientVersionValue {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl CodexClientVersion {
    pub fn new() -> Self {
        Self {
            current: Arc::new(RwLock::new(Arc::from(FALLBACK_VERSION))),
        }
    }

    pub fn current(&self) -> CodexClientVersionValue {
        CodexClientVersionValue(
            self.current
                .read()
                .unwrap_or_else(|error| error.into_inner())
                .clone(),
        )
    }

    pub fn update(&self, version: &str) -> bool {
        let Some(version) = parse_version(version) else {
            return false;
        };
        *self
            .current
            .write()
            .unwrap_or_else(|error| error.into_inner()) = Arc::from(version);
        true
    }

    pub fn update_after_probe(
        &self,
        github_version: Option<&str>,
        model_list_succeeded: bool,
    ) -> CodexClientVersionValue {
        let current = self.current();
        let next = version_after_probe(current.as_ref(), github_version, model_list_succeeded);
        if model_list_succeeded {
            self.update(&next);
        }
        self.current()
    }
}

impl Default for CodexClientVersion {
    fn default() -> Self {
        Self::new()
    }
}

pub fn parse_release_tag(tag: &str) -> Option<String> {
    let version = tag.strip_prefix("rust-v")?;
    parse_version(version)
}

fn parse_version(version: &str) -> Option<String> {
    let mut components = version.split('.');
    let major = components.next()?;
    let minor = components.next()?;
    let patch = components.next()?;
    if components.next().is_some()
        || [major, minor, patch].iter().any(|component| {
            component.is_empty()
                || !component
                    .chars()
                    .all(|character| character.is_ascii_digit())
        })
    {
        return None;
    }
    Some(format!("{major}.{minor}.{patch}"))
}

/// Select the next version after GitHub and model-list probing.
///
/// This pure transition keeps a failed GitHub lookup or an empty/failed model
/// list from replacing the last usable version.
#[must_use]
pub fn version_after_probe(
    current: &str,
    github_version: Option<&str>,
    model_list_succeeded: bool,
) -> String {
    if model_list_succeeded {
        github_version.unwrap_or(current).to_owned()
    } else {
        current.to_owned()
    }
}

pub async fn fetch_latest(
    transport: &Transport,
    proxy: Option<&ProxySpec>,
) -> Result<String, CodexReleaseFailure> {
    let headers = vec![("user-agent", "cardinal".to_owned())];
    let response = transport
        .send_get_with_headers_with_proxy(
            GITHUB_RELEASE_URL,
            Dns::Overseas,
            &headers,
            &[],
            proxy,
            std::time::Instant::now() + REQUEST_TIMEOUT,
        )
        .await
        .map_err(|_| release_failure(CodexReleaseFailureStage::Transport))?;
    if !response.status().is_success() {
        return Err(release_failure(CodexReleaseFailureStage::HttpStatus));
    }
    let body = transport
        .read_body(
            response,
            MAX_BODY,
            std::time::Instant::now() + REQUEST_TIMEOUT,
        )
        .await
        .map_err(|_| release_failure(CodexReleaseFailureStage::ResponseBody))?;
    let release: Release = serde_json::from_slice(&body)
        .map_err(|_| release_failure(CodexReleaseFailureStage::Json))?;
    parse_release_tag(&release.tag_name)
        .ok_or_else(|| release_failure(CodexReleaseFailureStage::ReleaseTag))
}

#[derive(serde::Deserialize)]
struct Release {
    tag_name: String,
}
