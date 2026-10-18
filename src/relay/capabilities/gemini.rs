//! Google Gemini: native generateContent first, then Google's official
//! OpenAI-compat layer as the chat fallback. The native capability carries a
//! `{model}` placeholder — Gemini bakes the upstream model into the URL, so
//! the relay substitutes it per candidate (URL-escaped, any `models/` prefix
//! stripped). The OpenAI-compat layer authenticates with `Authorization:
//! Bearer`, not `x-goog-api-key` — the two surfaces differ.

use crate::protocol::ProtocolId;
use crate::providers::AuthScheme;

use super::Capability;

pub(super) fn capabilities(base: &str) -> Vec<Capability> {
    vec![
        Capability {
            protocol: ProtocolId::Gemini,
            endpoint: format!("{base}/models/{{model}}:generateContent"),
            stream_endpoint: Some(format!("{base}/models/{{model}}:streamGenerateContent")),
            auth_scheme: AuthScheme::XGoogApiKey,
            claude_only: false,
        },
        Capability {
            protocol: ProtocolId::OpenAiChat,
            endpoint: format!("{base}/openai/chat/completions"),
            stream_endpoint: None,
            auth_scheme: AuthScheme::Bearer,
            claude_only: false,
        },
    ]
}
