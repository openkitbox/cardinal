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
