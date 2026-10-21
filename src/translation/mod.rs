//! Cross-protocol translation layer.
//!
//! Hub-and-spoke: each client dialect knows how to parse its request envelope
//! into the IR and how to rebuild its envelope from it; a from/to pair is
//! composed from the two adapters, so the behaviour cost is N+N rather than
//! N². Same-protocol calls never touch this module — they stay on the
//! byte-faithful pass-through path.
//!
//! beaver opens four directed pairs: Chat ↔ Anthropic Messages, Responses →
//! Chat, and Responses → Anthropic Messages (Responses as a *client* only —
//! nothing translates into a Responses upstream; the kimi arm routes every
//! upstream connection over Anthropic, so a Responses client on kimi needs
//! this pair).

pub mod anthropic_messages;
pub mod effort_clamp;
pub mod ir;
pub mod openai_chat;
pub mod openai_responses;
pub mod stream;

use crate::protocol::ProtocolId;

/// Whether a request in the `from` dialect may be served by a provider row
/// speaking the `to` dialect via IR translation.
///
/// Identity pairs are always `false` (they take the pass-through path, never
/// the translation branch).
const OPENED: &[(ProtocolId, ProtocolId)] = &[
    (ProtocolId::OpenAiChat, ProtocolId::AnthropicMessages),
    (ProtocolId::AnthropicMessages, ProtocolId::OpenAiChat),
    (ProtocolId::OpenAiResponses, ProtocolId::OpenAiChat),
    (ProtocolId::OpenAiResponses, ProtocolId::AnthropicMessages),
];

pub fn translatable(from: ProtocolId, to: ProtocolId) -> bool {
    if from == to {
        return false;
    }
    OPENED.contains(&(from, to))
}

/// The dialects that take part in translation.
pub const MATRIX_DIALECTS: [ProtocolId; 3] = [
    ProtocolId::OpenAiChat,
    ProtocolId::AnthropicMessages,
    ProtocolId::OpenAiResponses,
];

/// Parse result: the IR plus structured notes on concepts that did not survive.
pub type Parsed<T> = Result<(T, Vec<&'static str>), crate::protocol::ProtocolError>;

/// Protocol-neutral dialect surface used by the relay pipeline. Only dialects
/// whose adapters have shipped return a value.
pub struct Dialect {
    pub to_ir: fn(&serde_json::Value, u64) -> Parsed<ir::IrRequest>,
    pub from_ir: fn(&ir::IrRequest, &str) -> Parsed<serde_json::Value>,
    pub emit_response_json: fn(&ir::IrResponse) -> Vec<u8>,
    pub response_to_ir: fn(&[u8]) -> Result<ir::IrResponse, crate::protocol::ProtocolError>,
}

pub fn for_protocol(protocol: ProtocolId) -> Option<Dialect> {
    match protocol {
        ProtocolId::OpenAiChat => Some(Dialect {
            to_ir: openai_chat::to_ir,
            from_ir: openai_chat::from_ir,
            emit_response_json: openai_chat::emit_response_json,
            response_to_ir: openai_chat::response_to_ir,
        }),
        ProtocolId::AnthropicMessages => Some(Dialect {
            to_ir: anthropic_messages::to_ir,
            from_ir: anthropic_messages::from_ir,
            emit_response_json: anthropic_messages::emit_response_json,
            response_to_ir: anthropic_messages::response_to_ir,
        }),
        // Client-side half only: to_ir/emit_response_json are live, while
        // from_ir/response_to_ir refuse — nothing translates *into* Responses.
        ProtocolId::OpenAiResponses => Some(Dialect {
            to_ir: openai_responses::to_ir,
            from_ir: openai_responses::from_ir,
            emit_response_json: openai_responses::emit_response_json,
            response_to_ir: openai_responses::response_to_ir,
        }),
        // Gemini is passthrough-only: it takes part in no IR translation in
        // either direction (the OPENED matrix is untouched by design).
        // Embeddings is likewise passthrough-only, and structurally so: a
        // retrieval call carries no conversation to put in the IR.
        ProtocolId::Gemini | ProtocolId::OpenAiEmbeddings => None,
    }
}

/// anyhow-flavored version of `for_protocol`: the relay loop can use `?` directly.
pub fn dialect(protocol: ProtocolId) -> Result<Dialect, crate::protocol::ProtocolError> {
    for_protocol(protocol).ok_or(crate::protocol::ProtocolError::UnsupportedApi)
}
