//! The ChatGPT Codex backend (`openai-codex`): one Bearer credential minted by
//! the account's OAuth login, one endpoint speaking the Responses dialect.
//! The path is `/codex/responses` under `https://chatgpt.com/backend-api`, not
//! the `/v1/responses` the public API uses, so the generic single-protocol row
//! cannot serve it. The relay adds the account headers and adapts the body
//! itself (see `relay::dialects`).

use crate::openai::OpenaiOAuth;
use crate::protocol::ProtocolId;

use super::{Capability, bearer};

/// The provider is the ChatGPT Codex backend: vendor `openai` with a `codex`
/// segment. [`super::provider_kind`] cannot say so, since it only recognizes a
/// `code` segment (`openai-code`).
pub(super) fn is_codex(name: &str) -> bool {
    let mut segments = name.split('-');
    segments.next() == Some("openai") && segments.any(|segment| segment == "codex")
}

/// The only origin an account's bearer may reach. The relay checks the chosen
/// endpoint against it before attaching the credential, so a key row attached
/// to a provider on another host never sends the token there.
const BACKEND_PREFIX: &str = "https://chatgpt.com/backend-api/";

/// Whether `endpoint` is on the ChatGPT backend.
#[must_use]
pub(crate) fn is_backend_endpoint(endpoint: &str) -> bool {
    endpoint.starts_with(BACKEND_PREFIX)
}

pub(super) fn capabilities(base: &str) -> Vec<Capability> {
    vec![bearer(
        ProtocolId::OpenAiResponses,
        format!("{base}/codex/responses"),
    )]
}

pub(super) fn validate_base_url(path: String) -> anyhow::Result<()> {
    // The base is the backend root; `/codex/responses` is the gateway's own
    // leaf (a pasted …/codex would double into /codex/codex/responses).
    anyhow::ensure!(
        path.trim_end_matches('/') == "/backend-api",
        "openai-codex 的 base_url 应为 https://chatgpt.com/backend-api——/codex/responses 由网关拼接"
    );
    Ok(())
}

/// What the Codex backend demands of the request body, applied per candidate
/// at wire-render time (the client's tree is never touched).
///
/// The backend only streams and never stores. It refuses every sampling
/// control and output cap with `400 {"detail":"Unsupported parameter: …"}`;
/// the list below is oh-my-pi's `openai-codex/request-transformer.ts`
/// (sampling controls absent from its request type; `max_output_tokens` and
/// `max_completion_tokens` deleted at the end of `transformRequestBody`).
pub(crate) const SKIP_FIELDS: &[&str] = &[
    "temperature",
    "top_p",
    "top_k",
    "min_p",
    "presence_penalty",
    "frequency_penalty",
    "repetition_penalty",
    "stop",
    "max_output_tokens",
    "max_completion_tokens",
];

/// Fields written with a fixed value whatever the client sent.
pub(crate) const FORCED_FIELDS: &[(&str, &str)] = &[("store", "false"), ("stream", "true")];

/// `instructions` is required by the backend. An empty string stands in when
/// the client sent none.
// Unverified: whether the backend accepts an empty `instructions` awaits the
// operator's live test (plan Q3).
pub(crate) const REQUIRED_FIELDS: &[(&str, &str)] = &[("instructions", "\"\"")];

/// Codex CLI identity the backend expects beside the bearer. The version is
/// the CLI release oh-my-pi claims. The shared transport sets no User-Agent of
/// its own, so [`headers`] carries one.
const ORIGINATOR: &str = "cardinal";
pub(crate) const CLIENT_VERSION: &str = "0.159.0";

/// The account's request headers: bearer, workspace, and client identity.
pub(crate) fn headers(bundle: &OpenaiOAuth) -> Vec<(&'static str, String)> {
    vec![
        ("authorization", format!("Bearer {}", bundle.access_token)),
        ("chatgpt-account-id", bundle.account_id.clone()),
        ("originator", ORIGINATOR.to_owned()),
        ("version", CLIENT_VERSION.to_owned()),
        (
            "user-agent",
            format!("cardinal/{}", env!("CARGO_PKG_VERSION")),
        ),
    ]
}
