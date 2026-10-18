//! Kimi (Moonshot): the Anthropic-compatible endpoint IS the connection.
//!
//! The Anthropic Messages wire is the most complete surface Kimi offers
//! (native thinking fields, cache_control; Kimi Code itself speaks Anthropic
//! to the managed endpoint) — so kimi rows connect at the anthropic leaf only,
//! one Bearer credential. Chat and Responses clients reach kimi through the
//! translation layer. The leaf serves KIMI's OWN models, so its rows are not
//! `claude_only`: Anthropic clients targeting kimi models passthrough.

use crate::protocol::ProtocolId;

use super::{Capability, bearer};

pub(super) fn capabilities(base: &str, code: bool) -> Vec<Capability> {
    if code {
        // Coding Plan: the base IS the version root (`…/coding/v1`).
        vec![bearer(
            ProtocolId::AnthropicMessages,
            format!("{base}/messages"),
        )]
    } else {
        // Platform: the base is the site root.
        vec![bearer(
            ProtocolId::AnthropicMessages,
            format!("{base}/anthropic/v1/messages"),
        )]
    }
}

pub(super) fn validate_base_url(path: String, code: bool) -> anyhow::Result<()> {
    if code {
        anyhow::ensure!(
            path == "/coding/v1",
            "kimi code base_url 应为编码版版本根（如 https://api.kimi.com/coding/v1）——协议路径由网关拼接"
        );
    } else {
        anyhow::ensure!(
            path.is_empty() || path == "/",
            "kimi base_url 应为站点根（如 https://api.moonshot.cn）——anthropic 端点 /anthropic/v1/messages 由网关拼接"
        );
    }
    Ok(())
}
