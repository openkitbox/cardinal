//! DeepSeek direct: all three protocols are native, every client passes
//! through.
//!
//! Evidence: official docs (api-docs.deepseek.com — first API call lists the
//! OpenAI and Anthropic base_urls, /guides/responses_api documents the
//! Responses surface) plus 2026-10-18 invalid-key probes (401 = routed past
//! auth) on /chat/completions, /responses and /anthropic/v1/messages. The
//! official Anthropic base_url is `https://api.deepseek.com/anthropic` (the
//! Anthropic SDK appends `/v1`), hence the /anthropic/v1/messages leaf.

use crate::protocol::ProtocolId;

use super::{Capability, bearer};

pub(super) fn capabilities(base: &str) -> Vec<Capability> {
    vec![
        bearer(ProtocolId::OpenAiChat, format!("{base}/chat/completions")),
        bearer(
            ProtocolId::AnthropicMessages,
            format!("{base}/anthropic/v1/messages"),
        ),
        bearer(ProtocolId::OpenAiResponses, format!("{base}/responses")),
    ]
}

pub(super) fn validate_base_url(path: String) -> anyhow::Result<()> {
    anyhow::ensure!(
        path.is_empty() || path == "/",
        "deepseek base_url 应为站点根（如 https://api.deepseek.com）——各协议端点由网关拼接"
    );
    Ok(())
}
