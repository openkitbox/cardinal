//! Passthrough effort rewriting.
//!
//! When the upstream speaks the client's protocol the IR is never built, so
//! the effort dial is clamped in place on the wire-shaped body. Planning is
//! read-only; the caller materializes a copy only when a rewrite is due.
//!
//! Shaping walks two vocabulary layers: the route's configured level list
//! (authoritative once set, legacy snapshot otherwise) and the vendor
//! dialect's measured accepted set ([`crate::relay::capabilities::EffortDial`]),
//! which also encodes how the explicit-off state reaches the wire.

use serde_json::Value;

use crate::protocol::ProtocolId;
use crate::relay::capabilities::{Accepted, EffortDial, OffPolicy};
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

/// 一次 effort 归一的全部输入:路由固定档位、legacy 快照、修复默认值、
/// 厂商方言。`Copy` 友好的借用包,替代 plan 不断变长的参数列表。
#[derive(Clone, Copy)]
pub struct EffortTarget<'a> {
    /// 路由层固定档位(升序)。`Some` = 路由已配置(含显式空数组)——
    /// 此时快照不再参与 clamp,这是 `medium` 不被快照静默降档的保证;
    /// `None` = legacy,按快照 clamp。
    pub route: Option<&'a [Effort]>,
    /// legacy 快照档位(空 = 未知);配置路由后仅 `default` 仍来自快照。
    pub snapshot: &'a [Effort],
    /// 闭词表外输入的修复值(候选快照的 default_effort,缺省 Medium)。
    pub default: Effort,
    /// 当前 (provider, model family) 的方言。
    pub dial: EffortDial,
}

/// 显式 off 的出站线名:厂商自己的标记;纯思考模型降级最低可接受档。
pub fn off_wire_name(dial: EffortDial) -> &'static str {
    match dial.off {
        OffPolicy::Wire(name) => name,
        OffPolicy::Lowest => match dial.accepted {
            Accepted::Known(levels) => levels.first().copied().unwrap_or(Effort::Low).chat_name(),
            Accepted::Permissive | Accepted::Unknown => "low",
        },
    }
}

/// 命名档的两级 shaping:先路由列表(已配置时)或 legacy 快照,再按方言
/// 可接受集向下就近。显式 off 原样返回(由 [`off_wire_name`] 另行编码);
/// Budget 经 [`Effort::clamp_against`] 保形状。
pub fn resolve_level(level: Effort, target: &EffortTarget<'_>) -> Effort {
    if matches!(level, Effort::None) {
        return level;
    }
    let shaped = match target.route {
        Some(route) => level.clamp_against(route),
        None => level.clamp_against(target.snapshot),
    };
    match target.dial.accepted {
        Accepted::Known(levels) => shaped.clamp_to(levels),
        Accepted::Permissive | Accepted::Unknown => shaped,
    }
}

/// 客户端原始 effort 名 → 出站线名。别名归一(minimal→low、ultra→max),
/// 显式 off 用 [`off_wire_name`],闭词表外的名字修复为 default(同样过
/// shaping)。返回值与输入相同时调用方跳过改写。
pub fn resolve(raw: &str, target: &EffortTarget<'_>) -> String {
    match Effort::parse_name(raw) {
        Some(Effort::None) => off_wire_name(target.dial).to_owned(),
        Some(level) => resolve_level(level, target).chat_name().to_owned(),
        None => resolve_level(target.default, target).chat_name().to_owned(),
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
/// Empty when the client's dial is absent, already in the upstream's wire
/// vocabulary, or the protocol has no effort concept.
///
/// `target` carries the whole normalization input ([`EffortTarget`]): route
/// list or legacy snapshot, the repair default, and the vendor dialect.
/// Values outside the closed vocabulary are repaired to `default` rather
/// than forwarded to a strict upstream that would answer 400.
pub fn plan(protocol: ProtocolId, body: &Value, target: &EffortTarget<'_>) -> Vec<Rewrite> {
    let mut rewrites = Vec::new();
    match protocol {
        ProtocolId::OpenAiChat => {
            push_name(
                &mut rewrites,
                body,
                Slot::ReasoningEffort,
                &["reasoning_effort"],
                target,
            );
            push_name(
                &mut rewrites,
                body,
                Slot::ThinkingEffort,
                &["thinking", "effort"],
                target,
            );
        }
        ProtocolId::OpenAiResponses => {
            push_name(
                &mut rewrites,
                body,
                Slot::ReasoningNestedEffort,
                &["reasoning", "effort"],
                target,
            );
        }
        ProtocolId::AnthropicMessages => {
            push_name(
                &mut rewrites,
                body,
                Slot::OutputConfigEffort,
                &["output_config", "effort"],
                target,
            );
            push_budget(&mut rewrites, body, target);
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
    target: &EffortTarget<'_>,
) {
    let Some(raw) = value_at(body, path).and_then(Value::as_str) else {
        return;
    };
    let name = resolve(raw, target);
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

fn push_budget(rewrites: &mut Vec<Rewrite>, body: &Value, target: &EffortTarget<'_>) {
    let Some(budget) = value_at(body, &["thinking", "budget_tokens"]).and_then(Value::as_u64)
    else {
        return;
    };
    let Some(level) = Effort::from_budget(budget) else {
        return;
    };
    // 路由已配置(含空表)→ 按路由 shaping;否则 legacy 快照。
    let levels = target.route.unwrap_or(target.snapshot);
    let clamped = level.clamp_against(levels);
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
