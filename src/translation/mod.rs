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
//! this pair). Kiro opens one more: Chat → Kiro, an upstream-only dialect.

pub mod anthropic_messages;
pub mod effort_clamp;
pub mod ir;
pub mod kiro;
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
    // Kiro is a translation target only: nothing serves Kiro's wire inbound,
    // so it never appears as the `from` side of a pair.
    (ProtocolId::OpenAiChat, ProtocolId::Kiro),
];

pub fn translatable(from: ProtocolId, to: ProtocolId) -> bool {
    if from == to {
        return false;
    }
    OPENED.contains(&(from, to))
}

/// The dialects that take part in translation.
pub const MATRIX_DIALECTS: [ProtocolId; 4] = [
    ProtocolId::OpenAiChat,
    ProtocolId::AnthropicMessages,
    ProtocolId::OpenAiResponses,
    ProtocolId::Kiro,
];

/// Parse result: the IR plus structured notes on concepts that did not survive.
pub type Parsed<T> = Result<(T, Vec<&'static str>), crate::protocol::ProtocolError>;

/// The `response_to_ir` shape: body plus the served model's declared metadata.
pub type ResponseToIr = fn(
    &[u8],
    Option<u64>,
    Option<f64>,
    Option<&str>,
) -> Result<ir::IrResponse, crate::protocol::ProtocolError>;

/// Protocol-neutral dialect surface used by the relay pipeline. Only dialects
/// whose adapters have shipped return a value.
///
/// `response_to_ir` takes the served model's declared context window, rate
/// multiplier and requested id, which the Kiro dialect uses to estimate prompt
/// tokens and derive its GPT-5.6 cache-read split; every other dialect ignores
/// them.
pub struct Dialect {
    pub to_ir: fn(&serde_json::Value, u64) -> Parsed<ir::IrRequest>,
    pub from_ir: fn(&ir::IrRequest, &str) -> Parsed<serde_json::Value>,
    pub emit_response_json: fn(&ir::IrResponse) -> Result<Vec<u8>, crate::protocol::ProtocolError>,
    pub response_to_ir: ResponseToIr,
    /// The dialect derives token usage from context percentages instead of
    /// vendor-reported counts (Kiro: KAS reports credits and a context
    /// percentage, never token counts). The relay keeps such an estimate for
    /// the ledger only — a derived number must not reach the client, where
    /// every other upstream puts what the vendor actually reported.
    pub estimates_usage: bool,
}

pub fn for_protocol(protocol: ProtocolId) -> Option<Dialect> {
    match protocol {
        ProtocolId::OpenAiChat => Some(Dialect {
            to_ir: openai_chat::to_ir,
            from_ir: openai_chat::from_ir,
            emit_response_json: openai_chat::emit_response_json,
            response_to_ir: openai_chat::response_to_ir,
            estimates_usage: false,
        }),
        ProtocolId::AnthropicMessages => Some(Dialect {
            to_ir: anthropic_messages::to_ir,
            from_ir: anthropic_messages::from_ir,
            emit_response_json: anthropic_messages::emit_response_json,
            response_to_ir: anthropic_messages::response_to_ir,
            estimates_usage: false,
        }),
        // Client-side half only: to_ir/emit_response_json are live, while
        // from_ir/response_to_ir refuse — nothing translates *into* Responses.
        ProtocolId::OpenAiResponses => Some(Dialect {
            to_ir: openai_responses::to_ir,
            from_ir: openai_responses::from_ir,
            emit_response_json: openai_responses::emit_response_json,
            response_to_ir: openai_responses::response_to_ir,
            estimates_usage: false,
        }),
        // Gemini is passthrough-only: it takes part in no IR translation in
        // either direction (the OPENED matrix is untouched by design).
        // Embeddings is likewise passthrough-only, and structurally so: a
        // retrieval call carries no conversation to put in the IR.
        ProtocolId::Gemini | ProtocolId::OpenAiEmbeddings => None,
        // Target-only dialect: `from_ir` renders the KAS session and
        // `response_to_ir` decodes its event stream, while the ingress half
        // refuses explicitly — nothing serves Kiro's wire.
        ProtocolId::Kiro => Some(Dialect {
            to_ir: kiro::to_ir,
            from_ir: kiro::from_ir,
            emit_response_json: kiro::emit_response_json,
            response_to_ir: kiro::response_to_ir,
            estimates_usage: true,
        }),
    }
}

/// anyhow-flavored version of `for_protocol`: the relay loop can use `?` directly.
pub fn dialect(protocol: ProtocolId) -> Result<Dialect, crate::protocol::ProtocolError> {
    for_protocol(protocol).ok_or(crate::protocol::ProtocolError::UnsupportedApi)
}
