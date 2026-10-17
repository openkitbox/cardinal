//! Usage evidence produced by the server-role protocol kernels.
//!
//! `UsageCounts` is wire evidence: the kernels extract it from upstream
//! responses during observation. Billing/cost policy (certainty classification,
//! pricing) stays with the consumer — it is not part of this crate.
//!
//! Sub-item fields preserve each protocol's own inclusion relationships
//! (B §4.2–§4.6). `None` means the upstream did not report that quantity; it is
//! never silently treated as zero.

use serde::{Deserialize, Serialize};

/// Observed usage for one attempt (A §10.2).
///
/// `input_tokens`/`output_tokens` are the *billable* totals. The sub-items are
/// evidence only and must never be added to them again:
/// - Chat/Responses/GenerateContent/Interactions: cached and reasoning/thought
///   quantities are already contained in the reported totals;
/// - Anthropic Messages: `input_tokens` here is the sum of the non-cached
///   input, cache creation and cache read, which are mutually exclusive parts
///   (B §4.4).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageCounts {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub calls: u64,
    /// Chat `prompt_cache_hit_tokens` / `prompt_tokens_details.cached_tokens`,
    /// Responses `input_tokens_details.cached_tokens`, Messages
    /// `cache_read_input_tokens`, Gemini `cachedContentTokenCount`, Interactions
    /// `total_cached_tokens`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cached_input_tokens: Option<u64>,
    /// Messages `cache_creation_input_tokens`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_creation_input_tokens: Option<u64>,
    /// Messages `cache_creation.ephemeral_1h_input_tokens` — the part of the
    /// cache write whose TTL (and price) is the 1-hour one. Always a subset of
    /// `cache_creation_input_tokens`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_creation_1h_input_tokens: Option<u64>,
    /// Chat `completion_tokens_details.reasoning_tokens`, Responses
    /// `output_tokens_details.reasoning_tokens`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reasoning_output_tokens: Option<u64>,
    /// Gemini `thoughtsTokenCount`, Interactions `total_thought_tokens`. A
    /// distinct quantity from visible output.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thought_output_tokens: Option<u64>,
    /// Gemini `toolUsePromptTokenCount`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_prompt_tokens: Option<u64>,
    /// Interactions `total_tool_use_tokens`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_use_tokens: Option<u64>,
}
