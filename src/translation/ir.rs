//! **The IR only carries concepts that survive a cross-dialect hop.** Concepts
//! owned by a single dialect (Anthropic `metadata` and block signatures,
//! Responses `include`/`store`, Gemini `safetySettings`, Chat `logprobs`/`seed`)
//! are carried by the pass-through layer when both sides speak the same
//! protocol, and are necessarily lost on any translated hop. They therefore do
//! not enter the IR: parsing strips them into the `dropped_fields` metadata
//! list instead of storing them. This is why the xHarbor IR is strictly smaller
//! than a union of every dialect's concepts — xHarbor keeps a Tier 1
//! byte-faithful pass-through path instead.
//!
//! The types are data-carrying enums matched exhaustively at the emit sites, in
//! the same style as the `protocol` kernels: illegal states are
//! unrepresentable and adding a concept is an explicit compile-time change.

use crate::protocol::usage::UsageCounts;

/// The separator every dialect joins multi-part system prompts with. Kernels
/// impose no join expectation; keeping it here means parsers and emitters
/// cannot drift apart (audit #902).
pub(crate) const SYSTEM_JOIN: &str = "\n\n";

/// Normalized reasoning effort.
///
/// [`Effort::None`] is an *explicit* client request to turn reasoning off; an
/// absent `Option` means the client said nothing. Wire names map as follows:
/// `minimal` → `Low`, `none`/`off` → `None`, `ultra` → `Max`, the remaining
/// names pass through. The off state is modelled explicitly so emitters can
/// honour it exactly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Effort {
    None,
    Low,
    Medium,
    High,
    Xhigh,
    Max,
    /// Anthropic's explicit thinking budget.
    Budget(u64),
}

impl Effort {
    /// Parse a wire effort name (Chat `reasoning_effort`, Anthropic
    /// `output_config.effort`). Unknown names are dropped by the caller.
    /// Vendors disagree on the explicit-off marker (`none` on DeepSeek,
    /// `off` on Kimi), so both parse to [`Self::None`].
    pub fn parse_name(name: &str) -> Option<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "minimal" => Some(Self::Low),
            "none" | "off" => Some(Self::None),
            "low" => Some(Self::Low),
            "medium" => Some(Self::Medium),
            "high" => Some(Self::High),
            "xhigh" => Some(Self::Xhigh),
            "max" | "ultra" => Some(Self::Max),
            _ => None,
        }
    }

    /// The Anthropic thinking budget for this effort level.
    /// [`Effort::None`] yields zero: a disabled budget.
    pub fn budget(self) -> u64 {
        match self {
            Self::None => 0,
            Self::Low => 4096,
            Self::Medium => 10_000,
            Self::High => 24_000,
            Self::Xhigh | Self::Max => 32_000,
            Self::Budget(budget) => budget,
        }
    }

    /// Inverse of [`Effort::budget`] for Anthropic clients; a zero budget
    /// means the client said nothing.
    pub fn from_budget(budget: u64) -> Option<Self> {
        match budget {
            0 => None,
            1..=4096 => Some(Self::Low),
            4097..=12_000 => Some(Self::Medium),
            12_001..=24_000 => Some(Self::High),
            _ => Some(Self::Xhigh),
        }
    }

    /// The ordered dial position of a named level. `None` (explicit off) and
    /// `Budget` have no position — callers fold budgets via
    /// [`Self::from_budget`] first.
    pub fn rank(self) -> Option<u8> {
        match self {
            Self::None | Self::Budget(_) => None,
            Self::Low => Some(0),
            Self::Medium => Some(1),
            Self::High => Some(2),
            Self::Xhigh => Some(3),
            Self::Max => Some(4),
        }
    }

    /// The nearest supported level at or below `self`; the lowest supported
    /// level when `self` sits below all of them; `self` unchanged when the
    /// supported set is empty. `supported` must be ascending named levels.
    pub fn clamp_to(self, supported: &[Self]) -> Self {
        let Some(lowest) = supported.first() else {
            return self;
        };
        let Some(rank) = self.rank() else {
            return self;
        };
        supported
            .iter()
            .rev()
            .find(|level| level.rank().is_some_and(|r| r <= rank))
            .copied()
            .unwrap_or(*lowest)
    }

    /// Clamp this effort against a candidate's supported levels (ascending,
    /// named only, possibly empty). Explicit off passes through; a budget
    /// folds to its level and keeps the budget shape when no change is due.
    pub fn clamp_against(self, supported: &[Self]) -> Self {
        match self {
            Self::None => self,
            Self::Budget(budget) => match Self::from_budget(budget) {
                Some(level) => {
                    let clamped = level.clamp_to(supported);
                    if clamped == level {
                        self
                    } else {
                        Self::Budget(clamped.budget())
                    }
                }
                None => self,
            },
            named => named.clamp_to(supported),
        }
    }

    /// The wire name for the Chat-family emitters (Chat `reasoning_effort`,
    /// Responses `reasoning.effort`). Each variant maps back to its canonical
    /// wire name; dispatch clamps the dial against the candidate model's
    /// supported levels before emission (see [`Effort::clamp_against`]).
    /// `None` never reaches this function — both emitters omit the field for it.
    pub fn chat_name(self) -> &'static str {
        match self {
            Self::None | Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Xhigh => "xhigh",
            Self::Max => "max",
            Self::Budget(_) => "high",
        }
    }

    /// Canonical wire names for a vendor-declared supported-levels list:
    /// unknown names and the explicit-off marker are dropped, duplicates
    /// collapse in first-seen order. The probe stores this shape and
    /// `/v1/models` re-normalizes through it, so snapshots written before this
    /// normalization age out without a migration.
    pub fn canonical_levels(levels: &[String]) -> Vec<String> {
        let mut names: Vec<&'static str> = Vec::new();
        for name in levels {
            let Some(level) = Self::parse_name(name) else {
                continue;
            };
            if matches!(level, Self::None) {
                continue;
            }
            let canonical = level.chat_name();
            if !names.contains(&canonical) {
                names.push(canonical);
            }
        }
        names.into_iter().map(str::to_owned).collect()
    }

    /// 路由层固定档位列表的入库归一化:别名归一(`minimal→low`、`ultra→max`),
    /// 拒绝显式 off 标记(`none`/`off`——off 永远接受、永不入表)与未知名,
    /// 结果按 rank 升序去重。`Err` 携带被拒的原始名,供调用方拼错误消息。
    pub fn route_levels(names: &[String]) -> Result<Vec<String>, String> {
        let mut levels = Vec::new();
        for name in names {
            let level = Self::parse_name(name).ok_or_else(|| name.clone())?;
            if matches!(level, Self::None) {
                return Err(name.clone());
            }
            levels.push(level);
        }
        levels.sort_by_key(|level| level.rank().unwrap_or(u8::MAX));
        levels.dedup();
        Ok(levels
            .iter()
            .map(|level| level.chat_name().to_owned())
            .collect())
    }
}

/// The only two roles that survive translation; every other wire role is
/// folded into one of these (`tool` into `user`, `system` into the top-level
/// system prompt).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IrRole {
    User,
    Assistant,
}

/// Where an image's bytes live.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ImageSource {
    Base64(String),
    Url(String),
}

/// Where a document's bytes live (Responses `input_file` ↔ Anthropic
/// `document` are the surviving hops).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FileSource {
    Base64(String),
    Url(String),
}

/// One block of a message. Only concepts with at least one surviving
/// cross-dialect hop are represented.
#[derive(Clone, Debug, PartialEq)]
pub enum IrPart {
    Text(String),
    Image {
        media: String,
        source: ImageSource,
    },
    File {
        media: String,
        source: FileSource,
    },
    /// `id` is optional because Chat tool calls may arrive without one; the
    /// emitting dialect synthesizes a dialect-shaped id when required.
    ToolCall {
        id: Option<String>,
        name: String,
        args: serde_json::Value,
    },
    ToolResult {
        call_id: String,
        text: String,
        images: Vec<IrPart>,
        is_error: bool,
    },
    /// Thinking text without a signature: no signature survives any translated
    /// hop, and the Anthropic emitter drops unsigned thinking entirely.
    Thinking {
        text: String,
    },
}

/// One conversation turn.
#[derive(Clone, Debug, PartialEq)]
pub struct IrMessage {
    pub role: IrRole,
    pub parts: Vec<IrPart>,
}

/// A callable tool.
#[derive(Clone, Debug, PartialEq)]
pub struct IrTool {
    pub name: String,
    pub description: String,
    /// JSON schema of the arguments.
    pub schema: serde_json::Value,
}

#[derive(Clone, Debug, PartialEq)]
pub enum IrToolChoice {
    Auto,
    None,
    Required,
    Name(String),
}

/// Sentinel for `IrRequest::ceiling`: the client declared no output limit.
pub const NO_DECLARED_LIMIT: u64 = u64::MAX;

/// Anthropic upstreams reject a request without `max_tokens`; a client that
/// declared no output limit gets this conservative default instead of an
/// invalid value. 8192 fits every current vendor's per-model output maximum.
pub const DEFAULT_ANTHROPIC_MAX_TOKENS: u64 = 8192;

/// One translated request.
///
/// Ceiling sentinels:
/// - [`NO_DECLARED_LIMIT`] — the client declared no output limit.
/// - [`DEFAULT_ANTHROPIC_MAX_TOKENS`] — the fallback written when the target
///   dialect mandates an output limit (anthropic) but the client declared none.
#[derive(Clone, Debug, PartialEq)]
pub struct IrRequest {
    pub system: Option<String>,
    pub messages: Vec<IrMessage>,
    pub tools: Vec<IrTool>,
    pub tool_choice: Option<IrToolChoice>,
    /// F1 anchor: the output ceiling reservation and the upstream body share
    /// this exact value. Emitters inject it into their dialect's output limit
    /// field, mirroring `bounded_output`. The client's own declared output limit
    /// (max_tokens / max_completion_tokens / max_output_tokens) lowers it;
    /// NO_DECLARED_LIMIT means the client declared none, and emitters then omit
    /// the field (chat, where it is optional) or fall back to a conservative
    /// default (anthropic, where it is mandatory).
    pub ceiling: u64,
    pub temperature: Option<f64>,
    pub top_p: Option<f64>,
    /// Survivor hop: Anthropic ↔ Gemini.
    pub top_k: Option<u64>,
    pub stop: Vec<String>,
    pub effort: Option<Effort>,
    /// Survivor hop: Chat ↔ Responses; Anthropic drops it audibly because the
    /// kernel rejects the field on the wire.
    pub parallel_tool_calls: Option<bool>,
    /// Survivor hop: Chat `response_format` ↔ Responses `text.format` ↔ Gemini
    /// `responseSchema`.
    pub structured_output: Option<serde_json::Value>,
    /// Upstream prompt-cache routing hint (Chat/Responses `prompt_cache_key`).
    /// Chat and Responses parse it instead of dropping it: a translated hop may
    /// still reach an upstream that understands the concept (Kiro derives its
    /// conversation id from it), while emitters whose target has no such concept
    /// record the loss as dropped.
    pub prompt_cache_key: Option<String>,
}

/// The cache-routing hint an envelope carries: a non-empty string, else `None`.
/// A present-but-unusable value stays the caller's to record as dropped.
pub(crate) fn prompt_cache_key_of(
    object: &serde_json::Map<String, serde_json::Value>,
) -> Option<String> {
    object
        .get("prompt_cache_key")
        .and_then(serde_json::Value::as_str)
        .filter(|key| !key.is_empty())
        .map(str::to_owned)
}

/// Why generation stopped, normalized across dialects.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IrStop {
    Stop,
    Length,
    ToolUse,
    /// A dialect-specific reason with no cross-dialect mapping (for example a
    /// content filter); emitters fall back to their neutral stop.
    Other(String),
}

/// One translated response, used to rebuild a non-streaming body in the entry
/// dialect.
///
/// `usage` is optional because not every upstream reports token usage: KAS
/// reports credits/context percentages only. `None` means "unknown", and every
/// emitter must then omit its usage field rather than fabricate three zeroes.
#[derive(Clone, Debug, PartialEq)]
pub struct IrResponse {
    pub model: String,
    pub content: Vec<IrPart>,
    pub stop: IrStop,
    pub usage: Option<UsageCounts>,
}
