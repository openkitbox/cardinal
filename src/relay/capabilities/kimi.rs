//! Kimi (Moonshot): all three protocols are native, every client passes
//! through.
//!
//! Coding Plan (`…/coding/v1`): probe evidence (2026-10-18, invalid-key
//! requests return 401 — routed past auth) on /messages, /chat/completions
//! and /responses: the plan serves anthropic, chat and responses natively.
//! Platform (site root, api.moonshot.cn): probe evidence 2026-10-18 —
//! invalid-key 401 on /v1/chat/completions, /v1/responses and
//! /anthropic/v1/messages (the /v1/messages control correctly 404s), matching
//! the official endpoint table (platform.kimi.com docs, API overview). The
//! leaves serve KIMI's OWN models, so no row is `claude_only`.

use crate::protocol::ProtocolId;

use super::{Capability, bearer};

pub(super) fn capabilities(base: &str, code: bool) -> Vec<Capability> {
    if code {
        // Coding Plan: the base IS the version root (`…/coding/v1`).
        vec![
            bearer(ProtocolId::OpenAiChat, format!("{base}/chat/completions")),
            bearer(ProtocolId::AnthropicMessages, format!("{base}/messages")),
            bearer(ProtocolId::OpenAiResponses, format!("{base}/responses")),
        ]
    } else {
        // Platform: the base is the site root.
        vec![
            bearer(
                ProtocolId::OpenAiChat,
                format!("{base}/v1/chat/completions"),
            ),
            bearer(
                ProtocolId::AnthropicMessages,
                format!("{base}/anthropic/v1/messages"),
            ),
            bearer(ProtocolId::OpenAiResponses, format!("{base}/v1/responses")),
        ]
    }
}

pub(super) fn validate_base_url(path: String, code: bool) -> anyhow::Result<()> {
    if code {
        anyhow::ensure!(
            path == "/coding/v1",
            "kimi code base_url 应为编码版版本根（如 https://api.kimi.com/coding/v1）——协议路径由网关拼接"
        );
    } else {
        anyhow::ensure!(
            path.is_empty() || path == "/",
            "kimi base_url 应为站点根（如 https://api.moonshot.cn）——协议端点由网关拼接"
        );
    }
    Ok(())
}

/// Kimi 直连:chat 实测收 off|low|medium|high|xhigh|max,显式 off 线名 `off`
/// (2026-10-21 实测;`none` 400)。
pub(super) fn effort_dial() -> super::EffortDial {
    super::EffortDial {
        accepted: super::Accepted::Known(super::STANDARD_TIERS),
        off: super::OffPolicy::Wire("off"),
    }
}
