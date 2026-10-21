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

/// The target model's effort vocabulary: declared levels (empty = unknown),
/// vendor default, and the vendor's explicit-off wire marker.
#[derive(Clone, Copy)]
struct Dial<'a> {
    supported: &'a [Effort],
    default: Option<Effort>,
    off_name: &'a str,
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
/// Empty when the client's dial is absent, already in the upstream's wire
/// vocabulary, or the protocol has no effort concept.
///
/// `supported` is the target model's declared level set (empty = unknown) and
/// `default` its vendor-declared fallback. `off_name` is the vendor's explicit
/// off marker. Values outside the closed vocabulary are repaired to `default`
/// (or a neutral medium) rather than forwarded to a strict upstream that would
/// answer 400.
pub fn plan(
    protocol: ProtocolId,
    body: &Value,
    supported: &[Effort],
    default: Option<Effort>,
    off_name: &str,
) -> Vec<Rewrite> {
    let mut rewrites = Vec::new();
    let dial = Dial {
        supported,
        default,
        off_name,
    };
    match protocol {
        ProtocolId::OpenAiChat => {
            push_name(
                &mut rewrites,
                body,
                Slot::ReasoningEffort,
                &["reasoning_effort"],
                dial,
            );
            push_name(
                &mut rewrites,
                body,
                Slot::ThinkingEffort,
                &["thinking", "effort"],
                dial,
            );
        }
        ProtocolId::OpenAiResponses => {
            push_name(
                &mut rewrites,
                body,
                Slot::ReasoningNestedEffort,
                &["reasoning", "effort"],
                dial,
            );
        }
        ProtocolId::AnthropicMessages => {
            push_name(
                &mut rewrites,
                body,
                Slot::OutputConfigEffort,
                &["output_config", "effort"],
                dial,
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

fn push_name(rewrites: &mut Vec<Rewrite>, body: &Value, slot: Slot, path: &[&str], dial: Dial<'_>) {
    let Some(raw) = value_at(body, path).and_then(Value::as_str) else {
        return;
    };
    let name = match Effort::parse_name(raw) {
        // Explicit off: encode it with the target vendor's own marker.
        Some(Effort::None) => dial.off_name.to_owned(),
        Some(level) => level.clamp_against(dial.supported).chat_name().to_owned(),
        // Outside the closed vocabulary: repair to the vendor default instead
        // of forwarding a name the upstream would reject.
        None => dial
            .default
            .filter(|level| !matches!(*level, Effort::None))
            .unwrap_or(Effort::Medium)
            .clamp_against(dial.supported)
            .chat_name()
            .to_owned(),
    };
    if raw == name {
        return;
    }
    rewrites.push(Rewrite {
        slot,
        from: raw.to_owned(),
        to: name.clone(),
        value: Value::String(name),
    });
}

fn push_budget(rewrites: &mut Vec<Rewrite>, body: &Value, supported: &[Effort]) {
    let Some(budget) = value_at(body, &["thinking", "budget_tokens"]).and_then(Value::as_u64)
    else {
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
