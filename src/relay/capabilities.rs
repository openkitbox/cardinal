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
//! only changes the base_url host, never the path knowledge:
//!
//! - (kimi, platform): the anthropic-compatible endpoint is the connection —
//!   the Anthropic Messages wire is the most complete surface Kimi offers
//!   (native thinking fields, cache_control; Kimi Code itself speaks
//!   Anthropic to the managed endpoint) — so kimi rows connect at
//!   `{base}/anthropic/v1/messages` only, one Bearer credential. Chat and
//!   Responses clients reach kimi through the translation layer.
//! - (kimi, code): same, at the Coding Plan base's anthropic leaf
//!   (`{base}/messages` where the base IS the version root `…/coding/v1`).
//! - (glm, code): chat `{base}/chat/completions` + responses `{base}/responses`
//!   (Bearer), plus anthropic at `{origin}/api/anthropic/v1/messages` with the
//!   Anthropic-style `x-api-key` credential.
//! - (opencode, any): OpenCode's subscription gateways (Go at `{base}` =
//!   `…/zen/go`, Zen at `…/zen` — the base says which) serve all three
//!   protocols under one Bearer credential: chat `{base}/v1/chat/completions`, anthropic
//!   `{base}/v1/messages`, responses `{base}/v1/responses`. Each MODEL answers
//!   on exactly one protocol (models.dev's per-model npm mapping) and 400s
//!   "Model does not support this protocol" on the others —
//!   the table can't know per-model, so a mismatched client protocol fails
//!   with the upstream's own words. The relay adds OpenCode's mandatory
//!   `x-opencode-session` header family itself (see relay::opencode_headers).
//! - everything else (including the standard glm): exactly one capability —
//!   the row's own protocol at `{base}/{suffix}` with the row's auth scheme,
//!   where the suffix is the protocol's canonical leaf (`chat/completions`,
//!   `v1/messages`, `responses`). A row with an unparsable protocol or auth
//!   scheme yields NO capabilities — the caller skips the candidate as a
//!   config error.
//!
//! Endpoints are FULL request URLs: the protocol kernels use
//! `TargetView.endpoint` verbatim.

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
        // The gemini row never takes this arm: it is the vendor arm below. A
        // gemini protocol on a non-gemini name yields NO capability (config error).
        ProtocolId::Gemini => unreachable!("gemini rows are served by the vendor arm"),
    }
}

/// Save-time base_url contract. Every provider's base_url must be a version
/// root — never a full endpoint (the gateway appends the protocol path
/// itself). Hardcoded multi-protocol vendors additionally pin the path:
/// kimi platform = host root, kimi code = `/coding/v1`, glm code =
/// `/api/coding/paas/v4`.
pub fn validate_base_url(provider_name: &str, base_url: &str) -> anyhow::Result<()> {
    let path = reqwest::Url::parse(base_url)
        .map(|url| url.path().to_owned())
        .unwrap_or_default();
    for leaf in [
        "/chat/completions",
        "/v1/messages",
        "/messages",
        "/responses",
    ] {
        anyhow::ensure!(
            !path.ends_with(leaf),
            "base_url 应为版本根，不要包含端点叶子路径 {leaf}——协议路径由网关拼接"
        );
    }
    match provider_kind(provider_name) {
        ("kimi", false) => anyhow::ensure!(
            path.is_empty() || path == "/",
            "kimi base_url 应为站点根（如 https://api.moonshot.cn）——anthropic 端点 /anthropic/v1/messages 由网关拼接"
        ),
        ("kimi", true) => {
            anyhow::ensure!(
                path == "/coding/v1",
                "kimi code base_url 应为编码版版本根（如 https://api.kimi.com/coding/v1）——协议路径由网关拼接"
            )
        }
        ("glm", true) => anyhow::ensure!(
            path == "/api/coding/paas/v4",
            "glm code base_url 应为编码版版本根（如 https://open.bigmodel.cn/api/coding/paas/v4）——协议路径由网关拼接"
        ),
        // OpenCode Go/Zen: the base is the gateway root; the /v1 leaves are the
        // gateway's own (a pasted …/v1 would double into /v1/v1/…).
        ("opencode", _) => anyhow::ensure!(
            path == "/zen/go" || path == "/zen",
            "opencode base_url 应为网关根（如 https://opencode.ai/zen/go）——/v1/chat/completions、/v1/messages、/v1/responses 由网关拼接"
        ),
        // Command Code's Provider API: the base is the `/provider` root; the /v1
        // leaves are the service's own (a pasted …/provider/v1 would double into
        // /v1/v1/…).
        ("commandcode", _) => anyhow::ensure!(
            path == "/provider",
            "commandcode base_url 应为 Provider API 根（如 https://api.commandcode.ai/provider）——/v1/chat/completions、/v1/messages、/v1/responses 由网关拼接"
        ),
        _ => {}
    }
    Ok(())
}

/// The capabilities of one provider row. Kimi rows yield exactly one
/// capability (Anthropic Messages — see the module doc); every other vendor
/// yields its native surface. Order is the translation-preference order
/// (chat > anthropic > responses).
pub fn capabilities(
    provider_name: &str,
    row_protocol: &str,
    row_base_url: &str,
    row_auth_scheme: &str,
) -> Vec<Capability> {
    let base = row_base_url.trim_end_matches('/');
    let bearer = |protocol: ProtocolId, endpoint: String| Capability {
        protocol,
        endpoint,
        stream_endpoint: None,
        auth_scheme: AuthScheme::Bearer,
    };
    match provider_kind(provider_name) {
        // Kimi connects over Anthropic Messages only (see module doc): one
        // Bearer credential at the anthropic leaf. Chat/Responses clients reach
        // kimi through the translation layer.
        ("kimi", false) => vec![bearer(
            ProtocolId::AnthropicMessages,
            format!("{base}/anthropic/v1/messages"),
        )],
        ("kimi", true) => vec![bearer(
            ProtocolId::AnthropicMessages,
            format!("{base}/messages"),
        )],
        // GLM Coding Plan: chat + responses under the base with Bearer, plus an
        // anthropic endpoint on the origin with the Anthropic-style credential.
        ("glm", true) => {
            let mut caps = vec![
                bearer(ProtocolId::OpenAiChat, format!("{base}/chat/completions")),
                bearer(ProtocolId::OpenAiResponses, format!("{base}/responses")),
            ];
            if let Some(origin) = origin_of(row_base_url) {
                caps.insert(
                    1,
                    Capability {
                        protocol: ProtocolId::AnthropicMessages,
                        endpoint: format!("{origin}/api/anthropic/v1/messages"),
                        stream_endpoint: None,
                        auth_scheme: AuthScheme::XApiKey,
                    },
                );
            } else {
                // The chat/responses capabilities still work; only the anthropic one
                // needs the origin. Loud because a silently-missing capability would
                // route anthropic clients into chat translation instead.
                tracing::warn!(
                    base_url = row_base_url,
                    "glm coding plan base_url has no parsable origin; dropping its anthropic capability"
                );
            }
            caps
        }
        // Google Gemini: native generateContent first, then Google's official
        // OpenAI-compat layer as the chat fallback. The native capability carries
        // a `{model}` placeholder — Gemini bakes the upstream model into the URL,
        // so the relay substitutes it per candidate (URL-escaped, any "models/"
        // prefix stripped).
        ("gemini", _) => vec![
            Capability {
                protocol: ProtocolId::Gemini,
                endpoint: format!("{base}/models/{{model}}:generateContent"),
                stream_endpoint: Some(format!("{base}/models/{{model}}:streamGenerateContent")),
                auth_scheme: AuthScheme::XGoogApiKey,
            },
            Capability {
                protocol: ProtocolId::OpenAiChat,
                endpoint: format!("{base}/openai/chat/completions"),
                stream_endpoint: None,
                // Google's OpenAI-compat layer authenticates with Authorization:
                // Bearer, not x-goog-api-key — the two surfaces differ.
                auth_scheme: AuthScheme::Bearer,
            },
        ],
        // OpenCode Go / Zen: one Bearer credential, all three protocols — chat
        // and responses under /v1, anthropic messages at /v1/messages.
        ("opencode", _) => [
            bearer(
                ProtocolId::OpenAiChat,
                format!("{base}/v1/chat/completions"),
            ),
            bearer(ProtocolId::AnthropicMessages, format!("{base}/v1/messages")),
            bearer(ProtocolId::OpenAiResponses, format!("{base}/v1/responses")),
        ]
        .into_iter()
        .collect(),
        // Command Code's Provider API: one Bearer credential, all three protocols
        // under the `/provider` root (/v1 leaves). Like opencode, which protocol
        // a MODEL answers on is per-model and the table can't know it — its
        // Claude models serve /messages alone and the rest chat/responses (the
        // model list's `supported_endpoints` says which); a mismatched client
        // protocol fails with the upstream's own words.
        ("commandcode", _) => [
            bearer(
                ProtocolId::OpenAiChat,
                format!("{base}/v1/chat/completions"),
            ),
            bearer(ProtocolId::AnthropicMessages, format!("{base}/v1/messages")),
            bearer(ProtocolId::OpenAiResponses, format!("{base}/v1/responses")),
        ]
        .into_iter()
        .collect(),
        // Single-protocol rows (standard glm included): the row's protocol at the
        // version root plus its canonical leaf, with the row's auth scheme.
        _ => {
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
            }]
        }
    }
}

/// Pick the capability serving the client protocol: exact match (passthrough)
/// first, else the table-preferred capability with an IR translation path
/// from the client protocol. `None` = this candidate cannot serve the client
/// at all; the caller logs the skip and fails over.
pub fn select(caps: &[Capability], client: ProtocolId) -> Option<&Capability> {
    caps.iter().find(|cap| cap.protocol == client).or_else(|| {
        caps.iter()
            .find(|cap| translation::translatable(client, cap.protocol))
    })
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
