//! Passthrough effort rewriting.
//!
//! When the upstream speaks the client's protocol the IR is never built, so
//! the effort dial is clamped in place on the wire-shaped body. Planning is
//! read-only; the caller materializes a copy only when a rewrite is due.

use serde_json::Value;

use crate::protocol::ProtocolId;
use crate::translation::ir::Effort;

/// Where a planned rewrite lands in the wire body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Slot {
    ReasoningEffort,
    ThinkingEffort,
    ReasoningNestedEffort,
    OutputConfigEffort,
    ThinkingBudget,
}

impl Slot {
    fn write(self, body: &mut Value, value: Value) {
        match self {
            Self::ReasoningEffort => body["reasoning_effort"] = value,
            Self::ThinkingEffort => body["thinking"]["effort"] = value,
            Self::ReasoningNestedEffort => body["reasoning"]["effort"] = value,
            Self::OutputConfigEffort => body["output_config"]["effort"] = value,
            Self::ThinkingBudget => body["thinking"]["budget_tokens"] = value,
        }
    }
}

/// One planned rewrite: where it lands, its wire value, and the human-readable
/// values for the clamp log line.
#[derive(Clone, Debug)]
pub struct Rewrite {
    slot: Slot,
    from: String,
    to: String,
    value: Value,
}

/// Plan the effort rewrites a passthrough body needs, without touching it.
/// Empty when the client's dial is absent, outside the closed vocabulary,
/// already supported, or the protocol has no effort concept.
pub fn plan(protocol: ProtocolId, body: &Value, supported: &[Effort]) -> Vec<Rewrite> {
    if supported.is_empty() {
        return Vec::new();
    }
    let mut rewrites = Vec::new();
    match protocol {
        ProtocolId::OpenAiChat => {
            push_name(
                &mut rewrites,
                body,
                Slot::ReasoningEffort,
                &["reasoning_effort"],
                supported,
            );
            push_name(
                &mut rewrites,
                body,
                Slot::ThinkingEffort,
                &["thinking", "effort"],
                supported,
            );
        }
        ProtocolId::OpenAiResponses => {
            push_name(
                &mut rewrites,
                body,
                Slot::ReasoningNestedEffort,
                &["reasoning", "effort"],
                supported,
            );
        }
        ProtocolId::AnthropicMessages => {
            push_name(
                &mut rewrites,
                body,
                Slot::OutputConfigEffort,
                &["output_config", "effort"],
                supported,
            );
            push_budget(&mut rewrites, body, supported);
        }
        ProtocolId::Gemini | ProtocolId::OpenAiEmbeddings => {}
    }
    rewrites
}

/// Apply planned rewrites in place; returns the first `(from, to)` when any
/// rewrite actually landed.
pub fn apply(body: &mut Value, rewrites: &[Rewrite]) -> Option<(String, String)> {
    let mut note = None;
    for rewrite in rewrites {
        rewrite.slot.write(body, rewrite.value.clone());
        if note.is_none() {
            note = Some((rewrite.from.clone(), rewrite.to.clone()));
        }
    }
    note
}

fn value_at<'a>(body: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut current = body;
    for key in path {
        current = current.get(*key)?;
    }
    Some(current)
}

fn push_name(
    rewrites: &mut Vec<Rewrite>,
    body: &Value,
    slot: Slot,
    path: &[&str],
    supported: &[Effort],
) {
    let Some(raw) = value_at(body, path).and_then(Value::as_str) else {
        return;
    };
    let Some(level) = Effort::parse_name(raw) else {
        return;
    };
    if matches!(level, Effort::None) {
        return;
    }
    let clamped = level.clamp_against(supported);
    if clamped == level {
        return;
    }
    let name = clamped.chat_name().to_owned();
    rewrites.push(Rewrite {
        slot,
        from: raw.to_owned(),
        to: name.clone(),
        value: Value::String(name),
    });
}

fn push_budget(rewrites: &mut Vec<Rewrite>, body: &Value, supported: &[Effort]) {
    let Some(budget) = value_at(body, &["thinking", "budget_tokens"]).and_then(Value::as_u64) else {
        return;
    };
    let Some(level) = Effort::from_budget(budget) else {
        return;
    };
    let clamped = level.clamp_against(supported);
    if clamped == level {
        return;
    }
    let sent = clamped.budget();
    rewrites.push(Rewrite {
        slot: Slot::ThinkingBudget,
        from: format!("budget {budget}"),
        to: format!("budget {sent}"),
        value: sent.into(),
    });
}
