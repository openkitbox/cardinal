//! Compatibility decisions for the public OpenAI Chat endpoint.

use crate::protocol::openai_chat::ChatDialect;
use serde_json::Value;

/// Choose the wire dialect for one OpenAI Chat candidate.
///
/// This is deliberately limited to the ordinary `openai` provider. Codex has
/// its own Responses dialect and other OpenAI-compatible vendors must retain
/// their existing request fields.
pub(crate) fn chat_dialect(provider_name: &str, model: &str, body: &Value) -> ChatDialect {
    if super::provider_kind(provider_name).0 != "openai" || super::codex::is_codex(provider_name) {
        return ChatDialect::NATIVE;
    }
    let reasoning = is_reasoning_model(model);
    ChatDialect {
        max_completion_tokens_only: reasoning,
        omit_reasoning_sampling: reasoning && !explicit_reasoning_none(body),
        ..ChatDialect::NATIVE
    }
}

fn explicit_reasoning_none(body: &Value) -> bool {
    body.get("reasoning_effort")
        .and_then(Value::as_str)
        .is_some_and(|effort| effort == "none")
}

/// OpenAI's reasoning families: `o<digit>…` and `gpt-N…` for N >= 5.
fn is_reasoning_model(model: &str) -> bool {
    let model = model.trim().as_bytes();
    if model.len() >= 5 && model[..4].eq_ignore_ascii_case(b"gpt-") {
        let digits = &model[4..];
        let Some(first) = digits.first() else {
            return false;
        };
        if !first.is_ascii_digit() || *first == b'4' {
            return false;
        }
        let major =
            digits
                .iter()
                .take_while(|byte| byte.is_ascii_digit())
                .fold(0_u32, |major, byte| {
                    major
                        .saturating_mul(10)
                        .saturating_add(u32::from(*byte - b'0'))
                });
        return major >= 5;
    }
    model
        .first()
        .is_some_and(|byte| byte.eq_ignore_ascii_case(&b'o'))
        && model.get(1).is_some_and(u8::is_ascii_digit)
}
