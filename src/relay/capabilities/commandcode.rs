//! Command Code's Provider API: one Bearer credential, all three protocols
//! under the `/provider` root (/v1 leaves). Which protocol a MODEL answers on
//! is per-model and the table can't know it — its Claude models serve
//! /messages alone and the rest chat/responses (the model list's
//! `supported_endpoints` says which) — so the Anthropic row is `claude_only`:
//! Claude models keep the native passthrough, non-Claude Anthropic clients
//! translate to chat instead of failing with the upstream's wrong-endpoint
//! 400.

use crate::protocol::ProtocolId;

use super::{Capability, bearer};

pub(super) fn capabilities(base: &str) -> Vec<Capability> {
    vec![
        bearer(
            ProtocolId::OpenAiChat,
            format!("{base}/v1/chat/completions"),
        ),
        Capability {
            claude_only: true,
            ..bearer(ProtocolId::AnthropicMessages, format!("{base}/v1/messages"))
        },
        bearer(ProtocolId::OpenAiResponses, format!("{base}/v1/responses")),
    ]
}

pub(super) fn validate_base_url(path: String) -> anyhow::Result<()> {
    // The base is the `/provider` root; the /v1 leaves are the service's own
    // (a pasted …/provider/v1 would double into /v1/v1/…).
    anyhow::ensure!(
        path == "/provider",
        "commandcode base_url 应为 Provider API 根（如 https://api.commandcode.ai/provider）——/v1/chat/completions、/v1/messages、/v1/responses 由网关拼接"
    );
    Ok(())
}

/// CommandCode:chat schema 全 provider 收 off|low|medium|high|xhigh|max,
/// 但显式 off 仅 deepseek 族模型返回 200;其余模型 400
/// "Only models that can turn thinking off accept it." → 降级最低档
/// (2026-10-21 实测)。
pub(super) fn effort_dial(model: &str) -> super::EffortDial {
    super::EffortDial {
        accepted: super::Accepted::Known(super::STANDARD_TIERS),
        off: if model.to_ascii_lowercase().contains("deepseek") {
            super::OffPolicy::Wire("off")
        } else {
            super::OffPolicy::Lowest
        },
    }
}
