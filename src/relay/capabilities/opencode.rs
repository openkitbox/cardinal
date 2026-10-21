//! OpenCode subscription gateways (Go at `…/zen/go`, Zen at `…/zen` — the
//! base says which): one Bearer credential, all three protocols under /v1.
//! Each MODEL answers on exactly one protocol (zen's per-model endpoint
//! table) and rejects the others — so the Anthropic row is `claude_only`:
//! Claude models keep the native /messages passthrough, non-Claude Anthropic
//! clients translate to chat instead of failing with the upstream's
//! wrong-endpoint error. The relay adds OpenCode's mandatory
//! `x-opencode-session` header family itself (see relay::opencode_headers).

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
    // The base is the gateway root; the /v1 leaves are the gateway's own (a
    // pasted …/v1 would double into /v1/v1/…).
    anyhow::ensure!(
        path == "/zen/go" || path == "/zen",
        "opencode base_url 应为网关根（如 https://opencode.ai/zen/go）——/v1/chat/completions、/v1/messages、/v1/responses 由网关拼接"
    );
    Ok(())
}

/// OpenCode(zen/go 聚合):接受集按模型族实测(2026-10-21)。
/// deepseek/qwen 族全档 + off 线名 `none`;glm 族纯思考(off→最低档);
/// kimi 族只收 low/high/max + `none`(medium/xhigh 400);未实测模型
/// Unknown——原样转发,绝不猜测。
pub(super) fn effort_dial(model: &str) -> super::EffortDial {
    use super::{Accepted, EffortDial, OffPolicy};
    const KIMI_TIERS: &[super::Effort] =
        &[super::Effort::Low, super::Effort::High, super::Effort::Max];
    let family = model
        .rsplit('/')
        .next()
        .unwrap_or(model)
        .split('-')
        .next()
        .unwrap_or(model)
        .to_ascii_lowercase();
    match family.as_str() {
        "deepseek" | "qwen" => EffortDial {
            accepted: Accepted::Known(super::STANDARD_TIERS),
            off: OffPolicy::Wire("none"),
        },
        "glm" => EffortDial {
            accepted: Accepted::Known(super::STANDARD_TIERS),
            off: OffPolicy::Lowest,
        },
        "kimi" => EffortDial {
            accepted: Accepted::Known(KIMI_TIERS),
            off: OffPolicy::Wire("none"),
        },
        _ => EffortDial {
            accepted: Accepted::Unknown,
            off: OffPolicy::Wire("none"),
        },
    }
}
