//! GLM Coding Plan: chat + responses under the version root with Bearer, plus
//! an anthropic endpoint on the ORIGIN (`{origin}/api/anthropic/v1/messages`)
//! with the Anthropic-style `x-api-key` credential. The anthropic leaf serves
//! GLM's OWN models — not `claude_only`.

use crate::protocol::ProtocolId;
use crate::providers::AuthScheme;

use super::{Capability, bearer, origin_of};

pub(super) fn capabilities(base: &str) -> Vec<Capability> {
    let mut caps = vec![
        bearer(ProtocolId::OpenAiChat, format!("{base}/chat/completions")),
        bearer(ProtocolId::OpenAiResponses, format!("{base}/responses")),
    ];
    if let Some(origin) = origin_of(base) {
        caps.insert(
            1,
            Capability {
                protocol: ProtocolId::AnthropicMessages,
                endpoint: format!("{origin}/api/anthropic/v1/messages"),
                stream_endpoint: None,
                auth_scheme: AuthScheme::XApiKey,
                claude_only: false,
            },
        );
    } else {
        // The chat/responses capabilities still work; only the anthropic one
        // needs the origin. Loud because a silently-missing capability would
        // route anthropic clients into chat translation instead.
        tracing::warn!(
            base_url = base,
            "glm coding plan base_url has no parsable origin; dropping its anthropic capability"
        );
    }
    caps
}

pub(super) fn validate_base_url(path: String) -> anyhow::Result<()> {
    anyhow::ensure!(
        path == "/api/coding/paas/v4",
        "glm code base_url 应为编码版版本根（如 https://open.bigmodel.cn/api/coding/paas/v4）——协议路径由网关拼接"
    );
    Ok(())
}
