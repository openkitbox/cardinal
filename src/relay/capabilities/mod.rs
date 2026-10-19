//! Vendor capability table, hardcoded BY PROVIDER NAME.
//!
//! Passthrough-first routing knowledge: which protocols a provider can serve
//! natively, at which endpoint, with which auth scheme. The candidate loop
//! consults this per candidate: an exact protocol match is a passthrough
//! attempt (Tier 1); otherwise the table's order picks the preferred
//! translation target that has an IR path from the client protocol (Tier 2).
//!
//! Dispatch model: the provider NAME is normalized by [`provider_kind`] into
//! (vendor, is_code) — the vendor is the first '-'-separated segment, and any
//! "code" segment marks the Coding Plan variant; a region suffix ("-intl")
//! only changes the base_url host, never the path knowledge. Vendors with
//! more than the default single row own a submodule carrying their rows,
//! their base_url contract and their per-row facts; this file owns only the
//! generic contract ([`Capability`], [`select`], [`resolve_for_model`]) and
//! the single-protocol fallback. Vendor modules: [`kimi`], [`glm`],
//! [`gemini`], [`opencode`], [`commandcode`], [`deepseek`].
//!
//! Endpoints are FULL request URLs: the protocol kernels use
//! `TargetView.endpoint` verbatim.

mod commandcode;
mod deepseek;
mod gemini;
mod glm;
mod kimi;
mod opencode;

use crate::protocol::ProtocolId;
use crate::providers::AuthScheme;
use crate::translation;

/// One protocol a provider can serve natively.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Capability {
    pub protocol: ProtocolId,
    /// Full request URL (kernels use `TargetView.endpoint` verbatim), or a
    /// pattern carrying the literal `{model}` placeholder (Gemini bakes the
    /// upstream model into the URL; substituted per candidate by
    /// [`crate::relay::resolve_capability`]).
    pub endpoint: String,
    /// The stream URL for protocols whose streaming path differs from the
    /// non-streaming one (Gemini's `streamGenerateContent`); `None` means the
    /// protocol streams at `endpoint` (`ProtocolId::streaming_shares_endpoint`).
    pub stream_endpoint: Option<String>,
    pub auth_scheme: AuthScheme,
    /// Marks an Anthropic-messages row whose endpoint serves ONLY
    /// Claude-family models (the aggregator vendors: their own catalogs
    /// answer chat/responses). [`select`] skips such a row for non-Claude
    /// models, so those clients reach chat through IR translation instead of
    /// a passthrough the upstream would reject with a wrong-endpoint error.
    /// Rows serving the vendor's OWN models (kimi, glm) keep the default
    /// `false`. Set only by the vendor module that owns the row; `select` is
    /// the only reader.
    pub claude_only: bool,
}

/// Normalize a provider name into (vendor, is_code): the vendor is the first
/// '-'-separated segment ("kimi-code-intl" → "kimi"); any "code" segment marks
/// the Coding Plan variant. A region suffix ("-intl") only changes the
/// base_url host — it carries no path knowledge.
pub(crate) fn provider_kind(name: &str) -> (&str, bool) {
    let mut segments = name.split('-');
    let vendor = segments.next().unwrap_or(name);
    (vendor, segments.any(|segment| segment == "code"))
}

/// `scheme://host[:port]` of a base_url, when it parses as http(s).
pub(crate) fn origin_of(base_url: &str) -> Option<String> {
    let url = reqwest::Url::parse(base_url.trim()).ok()?;
    if !matches!(url.scheme(), "http" | "https") {
        return None;
    }
    let mut origin = format!("{}://{}", url.scheme(), url.host_str()?);
    if let Some(port) = url.port() {
        origin = format!("{origin}:{port}");
    }
    Some(origin)
}

/// The protocol leaf appended to a version root for single-protocol rows
/// (and for the Coding Plan variants, whose base IS the version root).
fn protocol_suffix(protocol: ProtocolId) -> &'static str {
    match protocol {
        ProtocolId::OpenAiChat => "chat/completions",
        ProtocolId::AnthropicMessages => "v1/messages",
        ProtocolId::OpenAiResponses => "responses",
        // Retrieval sits one leaf under the version root, exactly like chat:
        // OpenAI `…/v1/embeddings`, SiliconFlow/Voyage `…/v1/embeddings`,
        // Jina `…/v1/embeddings`, Cohere `…/v2/embeddings` (base = `…/v2`).
        ProtocolId::OpenAiEmbeddings => "embeddings",
        // The gemini row never takes this arm: it is served by the gemini
        // vendor module. A gemini protocol on a non-gemini name yields NO
        // capability (config error).
        ProtocolId::Gemini => unreachable!("gemini rows are served by the vendor module"),
    }
}

/// Save-time base_url contract. Every provider's base_url must be a version
/// root — never a full endpoint (the gateway appends the protocol path
/// itself). Vendors with a pinned path keep that contract in their own
/// module (hardcoded: kimi platform = host root, kimi code = `/coding/v1`,
/// glm code = `/api/coding/paas/v4`, opencode = `/zen/go` | `/zen`,
/// commandcode = `/provider`).
pub fn validate_base_url(provider_name: &str, base_url: &str) -> anyhow::Result<()> {
    let path = reqwest::Url::parse(base_url)
        .map(|url| url.path().to_owned())
        .unwrap_or_default();
    for leaf in [
        "/chat/completions",
        "/v1/messages",
        "/messages",
        "/responses",
        "/embeddings",
    ] {
        anyhow::ensure!(
            !path.ends_with(leaf),
            "base_url 应为版本根，不要包含端点叶子路径 {leaf}——协议路径由网关拼接"
        );
    }
    match provider_kind(provider_name) {
        ("kimi", code) => kimi::validate_base_url(path, code),
        ("glm", code) => glm::validate_base_url(path, code),
        ("deepseek", _) => deepseek::validate_base_url(path),
        ("opencode", _) => opencode::validate_base_url(path),
        ("commandcode", _) => commandcode::validate_base_url(path),
        _ => Ok(()),
    }
}

/// The capabilities of one provider row. Vendors with dedicated knowledge own
/// a submodule; every other row yields exactly one capability — its protocol
/// at `{base}/{suffix}` with its auth scheme (an unparsable protocol or auth
/// scheme yields NO capabilities: the caller skips the candidate as a config
/// error). Order is the translation-preference order (chat > anthropic >
/// responses).
pub fn capabilities(
    provider_name: &str,
    row_protocol: &str,
    row_base_url: &str,
    row_auth_scheme: &str,
) -> Vec<Capability> {
    let base = row_base_url.trim_end_matches('/');
    // Retrieval rows are served by the generic arm whatever the provider is
    // called. Vendor modules know a vendor's chat endpoints, never its
    // retrieval one, and they dispatch on the NAME alone — so a row named
    // "glm-embed" would otherwise be handed that vendor's three chat
    // capabilities and silently fail every retrieval call.
    if row_protocol == ProtocolId::OpenAiEmbeddings.as_str() {
        return single_protocol(row_protocol, row_auth_scheme, base);
    }
    match provider_kind(provider_name) {
        ("kimi", code) => kimi::capabilities(base, code),
        ("glm", _) => glm::capabilities(base),
        ("gemini", _) => gemini::capabilities(base),
        ("opencode", _) => opencode::capabilities(base),
        ("commandcode", _) => commandcode::capabilities(base),
        ("deepseek", _) => deepseek::capabilities(base),
        _ => single_protocol(row_protocol, row_auth_scheme, base),
    }
}

/// Single-protocol rows (standard glm included): the row's protocol at the
/// version root plus its canonical leaf, with the row's auth scheme.
fn single_protocol(row_protocol: &str, row_auth_scheme: &str, base: &str) -> Vec<Capability> {
    let (Some(protocol), Ok(auth_scheme)) = (
        ProtocolId::parse(row_protocol),
        AuthScheme::parse(row_auth_scheme),
    ) else {
        return Vec::new();
    };
    if protocol == ProtocolId::Gemini {
        // A gemini protocol row only makes sense under the gemini vendor arm
        // above; anywhere else it is a config error, loudly served by nothing.
        return Vec::new();
    }
    vec![Capability {
        protocol,
        endpoint: format!("{base}/{}", protocol_suffix(protocol)),
        stream_endpoint: None,
        auth_scheme,
        claude_only: false,
    }]
}

/// Pick the capability serving the client protocol: exact match (passthrough)
/// first, else the table-preferred capability with an IR translation path
/// from the client protocol. `None` = this candidate cannot serve the client
/// at all; the caller logs the skip and fails over.
///
/// Generic over vendors: rows carrying `claude_only` (set by their vendor
/// modules) are skipped for non-Claude models, so those clients take the
/// translation branch instead of a passthrough the upstream would reject.
pub fn select<'a>(
    caps: &'a [Capability],
    client: ProtocolId,
    upstream_model: &str,
) -> Option<&'a Capability> {
    caps.iter()
        .find(|cap| cap.protocol == client && (!cap.claude_only || is_claude_model(upstream_model)))
        .or_else(|| {
            caps.iter()
                .find(|cap| translation::translatable(client, cap.protocol))
        })
}

/// A Claude-family model id (case-insensitive substring), mirroring
/// `is_deepseek_model`.
fn is_claude_model(model: &str) -> bool {
    model.to_ascii_lowercase().contains("claude")
}

/// A Bearer-credential row with no stream endpoint and no model gate — the
/// common row shape every vendor module starts from. Private to this module:
/// child vendor modules reach it via `super::`.
fn bearer(protocol: ProtocolId, endpoint: String) -> Capability {
    Capability {
        protocol,
        endpoint,
        stream_endpoint: None,
        auth_scheme: AuthScheme::Bearer,
        claude_only: false,
    }
}

/// Bake the upstream model into a capability's endpoint pattern(s). Gemini's
/// URLs carry the model (`…/models/{model}:generateContent`); the substitution
/// URL-escapes the path segment and strips any `models/` prefix the stored
/// model may carry. A capability without the
/// placeholder is returned unchanged.
///
/// Known limitation: escaping `/` means tuned models (served under the
/// `tunedModels/` collection) cannot be addressed — acceptable, we only serve
/// base models.
pub fn resolve_for_model(capability: &Capability, upstream_model: &str) -> Capability {
    if !capability.endpoint.contains("{model}") {
        return capability.clone();
    }
    let model = path_escape(
        upstream_model
            .strip_prefix("models/")
            .unwrap_or(upstream_model),
    );
    Capability {
        protocol: capability.protocol,
        endpoint: capability.endpoint.replace("{model}", &model),
        stream_endpoint: capability
            .stream_endpoint
            .as_ref()
            .map(|endpoint| endpoint.replace("{model}", &model)),
        auth_scheme: capability.auth_scheme,
        claude_only: capability.claude_only,
    }
}

/// Escape one URL path segment: everything outside the RFC 3986 unreserved
/// set is percent-encoded (the model id is caller-controlled, so `/` and `?`
/// must never survive into the upstream URL).
fn path_escape(value: &str) -> String {
    const UNRESERVED: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
    let mut out = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        if UNRESERVED.contains(byte) {
            out.push(*byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}
