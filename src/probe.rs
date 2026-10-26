//! Upstream model-list probing (admin plane): a provider's `/models` list
//! doubles as the key validation for the add-key flow — the fetch proving
//! "this key authenticates and the endpoint answers" also returns the model
//! ids the route editor offers for picking. Nothing here is on the relay hot
//! path; requests are plain GETs with a per-attempt timeout and a bounded
//! body read.
//!
//! Kiro is the one vendor whose catalogue is neither a `/models` GET nor keyed
//! by an API key: [`fetch_kiro_models`] POSTs the control plane
//! (`KiroControlPlaneBearerService.ListAvailableModels`) with the OIDC bearer
//! and parses the AWS JSON answer.

use anyhow::Context as _;

/// One probe attempt's budget (matches the magnitude the relay allows for
/// opening a response).
const PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(8);
/// A model list is a few hundred small objects; 8 MiB caps abuse/misconfig.
const MAX_BODY: usize = 8 << 20;
/// How much of an error body's text is quoted in the failure message.
const ERROR_SNIPPET: usize = 200;

/// One model a key can list at its provider, with the attributes the list
/// carries. Most vendor endpoints return ids only; the optional fields are
/// populated when the wire says so. Two attribute namings are read:
/// OpenRouter-flavoured (`context_length`, `modalities.input`) and
/// DeepSeek/Kimi-flavoured (`context_window`, flat `input_modalities`, and the
/// effort block in any of its published shapes — see the model-list parser).
///
/// The struct is also the wire shape of a key's persisted model-list snapshot
/// (`gateway_provider_keys.models`), so it round-trips through serde; the
/// defaults keep older/partial payloads decodable.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProbeModel {
    pub id: String,
    /// Context window in tokens (`context_length` or `context_window`).
    #[serde(default)]
    pub context: Option<u64>,
    /// Longest reply in tokens (`max_output_tokens`).
    #[serde(default)]
    pub max_output: Option<u64>,
    /// Non-text input modalities (`image`, `audio`, …).
    #[serde(default)]
    pub input_modalities: Vec<String>,
    /// Reasoning effort levels the list says the model takes.
    #[serde(default)]
    pub effort_levels: Vec<String>,
    /// The vendor's default reasoning level, canonical; `None` when the list
    /// does not name one. Dispatch falls back to it when a client sends a
    /// level outside the closed vocabulary.
    #[serde(default)]
    pub default_effort: Option<String>,
}

/// Fetch the models a key can list at a provider endpoint.
///
/// Candidate URLs follow the relay's addressing shape: a versioned base
/// (…/v1, …/paas/v4) is asked only at `{base}/models`; a bare host is asked
/// at `{base}/models` then `{base}/v1/models`. `anthropic_messages` goes to
/// `{base}/v1/models` with the version header. Every candidate is tried in
/// order; the error aggregates all attempts so a misconfigured base_url
/// shows everything that was asked.
pub async fn fetch_models(
    base_url: &str,
    protocol: &str,
    auth_scheme: &str,
    api_key: &str,
) -> anyhow::Result<Vec<ProbeModel>> {
    let urls = model_list_urls(base_url, protocol)?;
    let client = reqwest::Client::new();
    let mut errors = Vec::new();
    for url in &urls {
        match fetch_at(&client, url, protocol, auth_scheme, api_key).await {
            Ok(models) if !models.is_empty() => return Ok(models),
            Ok(_) => errors.push(format!("{url}: no models listed")),
            Err(error) => errors.push(format!("{error:#}")),
        }
    }
    anyhow::bail!("拉取模型列表失败：{}", errors.join("；"))
}

/// The candidate model-list URLs for an endpoint, in try order.
fn model_list_urls(base_url: &str, protocol: &str) -> anyhow::Result<Vec<String>> {
    let base = base_url.trim().trim_end_matches('/');
    anyhow::ensure!(!base.is_empty(), "base_url 不能为空");
    let mut urls = vec![format!("{base}/models")];
    match protocol {
        "anthropic_messages" => urls = vec![format!("{base}/v1/models")],
        // Gemini's base is the version root (`…/v1beta`): the native list is
        // `{base}/models`, paginated (pageSize/pageToken) by the fetcher.
        "gemini" => {}
        // A bare host may carry its API one version segment down (kimi's
        // https://api.moonshot.cn lists at /v1/models); a versioned base names
        // the API as it is and is asked only as written. The Coding Plan
        // variants fit this rule unchanged: kimi-code's base IS the version root
        // (`…/coding/v1`), so the probe hits `{base}/models` = `/coding/v1/models`
        // — a route the service answers.
        //
        // Retrieval providers share the rule exactly: the model list lives
        // beside the embedding endpoint (`…/v1/models` for `…/v1/embeddings`),
        // so a bare host gets the same version-segment probe and a versioned
        // base is asked as written.
        "openai_chat" | "openai_embeddings" if !versioned(base) => {
            urls.push(format!("{base}/v1/models"));
        }
        "openai_chat" | "openai_embeddings" => {}
        other => anyhow::bail!("协议 {other} 没有模型列表端点"),
    }
    Ok(urls)
}

/// Whether an API base URL carries a version path segment (v1, v4, v1beta…).
fn versioned(base: &str) -> bool {
    let rest = base
        .split_once("://")
        .map(|(_, after)| after)
        .unwrap_or(base);
    let path = rest.split_once('/').map(|(_, path)| path).unwrap_or("");
    let path = path.split(['?', '#']).next().unwrap_or("");
    path.split('/').any(|seg| {
        seg.len() >= 2
            && seg.as_bytes()[0].eq_ignore_ascii_case(&b'v')
            && seg.as_bytes()[1].is_ascii_digit()
    })
}

async fn fetch_at(
    client: &reqwest::Client,
    url: &str,
    protocol: &str,
    auth_scheme: &str,
    api_key: &str,
) -> anyhow::Result<Vec<ProbeModel>> {
    let mut request = client
        .get(url)
        .timeout(PROBE_TIMEOUT)
        .header(reqwest::header::ACCEPT, "application/json");
    request = match auth_scheme {
        "bearer" => request.bearer_auth(api_key),
        "x_api_key" => request.header("x-api-key", api_key),
        "x_goog_api_key" => request.header("x-goog-api-key", api_key),
        "query" => request.query(&[("key", api_key)]),
        other => anyhow::bail!("auth scheme {other} 不支持探测"),
    };
    if protocol == "anthropic_messages" {
        request = request.header("anthropic-version", "2023-06-01");
    }
    if protocol == "gemini" {
        // Google's list pages: ask generously, follow nextPageToken (the walk
        // is capped at 20 pages — a buggy endpoint's self-link must not loop).
        let mut models = Vec::new();
        let mut page_token: Option<String> = None;
        for _ in 0..20 {
            let mut page_request = request
                .try_clone()
                .context("probe request is not cloneable")?
                .query(&[("pageSize", "1000")]);
            if let Some(token) = &page_token {
                page_request = page_request.query(&[("pageToken", token.as_str())]);
            }
            let response = page_request.send().await.context(url.to_string())?;
            let status = response.status();
            let body = read_bounded(response).await.context(url.to_string())?;
            if !status.is_success() {
                let snippet: String = body.chars().take(ERROR_SNIPPET).collect();
                anyhow::bail!("{url}: {status} {snippet}");
            }
            // The page's models go through the merged parser; only the pagination
            // token is Gemini-specific.
            #[derive(serde::Deserialize)]
            struct Page {
                #[serde(rename = "nextPageToken")]
                next: Option<String>,
            }
            let mut page =
                parse_models(&body).with_context(|| format!("{url}: 响应不是模型列表"))?;
            let next = serde_json::from_str::<Page>(&body)
                .ok()
                .and_then(|page| page.next);
            models.append(&mut page);
            match next {
                Some(token) if !token.is_empty() => page_token = Some(token),
                _ => return Ok(models),
            }
        }
        return Ok(models);
    }
    let response = request.send().await.context(url.to_string())?;
    let status = response.status();
    let body = read_bounded(response).await.context(url.to_string())?;
    if !status.is_success() {
        let snippet: String = body.chars().take(ERROR_SNIPPET).collect();
        anyhow::bail!("{url}: {status} {snippet}");
    }
    parse_models(&body).context(format!("{url}: 响应不是模型列表"))
}

/// Read a response body with a hard byte cap (the model list is small; a
/// runaway or hostile endpoint must not fill memory).
async fn read_bounded(response: reqwest::Response) -> anyhow::Result<String> {
    use futures::StreamExt as _;
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        body.extend_from_slice(&chunk?);
        anyhow::ensure!(body.len() <= MAX_BODY, "模型列表超过 {MAX_BODY} 字节上限");
    }
    Ok(String::from_utf8_lossy(&body).into_owned())
}

/// Parse both wire shapes a model list comes in: OpenAI's `{"data": [...]}`
/// and the `{"models": [...]}` flavour (Gemini/Anthropic); the id is `id` or
/// `name` (a Gemini `models/<id>` name is stripped to the id). Blank ids are
/// skipped, and a Gemini entry whose `supportedGenerationMethods` exists but
/// lacks `generateContent` (embedding/Imagen/Veo models) is skipped; optional
/// attributes (context window, output cap, extra input modalities, effort
/// levels) are kept when the list carries them, under either naming (see
/// [`ProbeModel`]). Display names (`name`/`display_name`/`label`) are ignored
/// — callers show the id only.
fn parse_models(body: &str) -> anyhow::Result<Vec<ProbeModel>> {
    #[derive(serde::Deserialize)]
    struct List {
        #[serde(default)]
        data: Vec<Entry>,
        #[serde(default)]
        models: Vec<Entry>,
    }
    #[derive(serde::Deserialize)]
    struct Entry {
        id: Option<String>,
        /// Gemini's id when `id` is absent (a DeepSeek-style display name in
        /// `name` is ignored — callers show ids only).
        name: Option<String>,
        kind: Option<String>,
        modalities: Option<Modalities>,
        input_modalities: Option<Vec<String>>,
        /// OpenRouter naming; some lists hand it over as a string.
        context_length: Option<serde_json::Value>,
        /// DeepSeek naming.
        context_window: Option<serde_json::Value>,
        max_output_tokens: Option<serde_json::Value>,
        /// Gemini naming (`inputTokenLimit` / `outputTokenLimit`).
        #[serde(rename = "inputTokenLimit")]
        input_token_limit: Option<serde_json::Value>,
        #[serde(rename = "outputTokenLimit")]
        output_token_limit: Option<serde_json::Value>,
        /// Gemini: the methods the model serves. When the list carries it, a
        /// model without generateContent (embedding, Imagen, Veo) is skipped —
        /// no agent can talk to it.
        #[serde(rename = "supportedGenerationMethods")]
        supported_generation_methods: Option<Vec<String>>,
        /// DeepSeek: `effort.supported_levels` + `default_level`.
        effort: Option<EffortBlock>,
        /// Kimi: `think_efforts.valid_efforts` + `default_effort`.
        think_efforts: Option<EffortBlock>,
        /// Kimi's alternate spelling: `reasoning.effort.valid` + `default`.
        reasoning: Option<Reasoning>,
    }
    #[derive(serde::Deserialize)]
    struct Modalities {
        input: Vec<String>,
    }
    #[derive(serde::Deserialize)]
    struct EffortBlock {
        #[serde(default)]
        supported_levels: Vec<String>,
        #[serde(default)]
        valid_efforts: Vec<String>,
        #[serde(default)]
        valid: Vec<String>,
        #[serde(default)]
        default_level: Option<String>,
        #[serde(default)]
        default_effort: Option<String>,
        #[serde(default)]
        default: Option<String>,
    }
    #[derive(serde::Deserialize)]
    struct Reasoning {
        effort: Option<EffortBlock>,
    }
    fn token_count(value: serde_json::Value) -> Option<u64> {
        match value {
            serde_json::Value::Number(number) => {
                number.as_f64().filter(|n| *n > 0.0).map(|n| n as u64)
            }
            serde_json::Value::String(text) => text.trim().parse::<u64>().ok().filter(|n| *n > 0),
            _ => None,
        }
    }
    let list: List = serde_json::from_str(body)?;
    let models = list
        .data
        .into_iter()
        .chain(list.models)
        .filter_map(|entry| {
            // Gemini's list also carries embedding/Imagen/Veo models; a method list
            // that lacks generateContent means no agent can talk to it.
            if entry
                .supported_generation_methods
                .as_ref()
                .is_some_and(|methods| !methods.iter().any(|method| method == "generateContent"))
            {
                return None;
            }
            let id = entry.id.or(entry.name)?;
            let id = id
                .trim()
                .strip_prefix("models/")
                .unwrap_or(id.trim())
                .to_owned();
            if id.is_empty() {
                return None;
            }
            let context = entry
                .context_length
                .or(entry.context_window)
                .or(entry.input_token_limit)
                .and_then(token_count);
            let max_output = entry
                .max_output_tokens
                .or(entry.output_token_limit)
                .and_then(token_count);
            let mut input_modalities: Vec<String> = entry
                .modalities
                .map(|m| m.input)
                .or(entry.input_modalities)
                .unwrap_or_default()
                .into_iter()
                .filter(|input| input != "text")
                .collect();
            if entry.kind.as_deref() == Some("image")
                && !input_modalities.iter().any(|input| input == "image")
            {
                input_modalities.push("image".into());
            }
            // Vendors publish the same effort data under different names:
            // DeepSeek `effort.supported_levels`, Kimi `think_efforts.valid_efforts`
            // or `reasoning.effort.valid`. Take the first block that actually
            // lists levels, and its matching default.
            let effort = [
                entry.effort,
                entry.think_efforts,
                entry.reasoning.and_then(|reasoning| reasoning.effort),
            ]
            .into_iter()
            .flatten()
            .find(|block| {
                !block.supported_levels.is_empty()
                    || !block.valid_efforts.is_empty()
                    || !block.valid.is_empty()
            });
            let (effort_levels, default_effort) = match effort {
                Some(effort) => {
                    let levels = if !effort.supported_levels.is_empty() {
                        effort.supported_levels
                    } else if !effort.valid_efforts.is_empty() {
                        effort.valid_efforts
                    } else {
                        effort.valid
                    };
                    let default = effort
                        .default_level
                        .or(effort.default_effort)
                        .or(effort.default);
                    let levels = crate::translation::ir::Effort::canonical_levels(&levels);
                    let default = default
                        .as_deref()
                        .and_then(crate::translation::ir::Effort::parse_name)
                        .filter(|level| !matches!(level, crate::translation::ir::Effort::None))
                        .map(crate::translation::ir::Effort::chat_name)
                        .map(str::to_owned);
                    (levels, default)
                }
                None => (Vec::new(), None),
            };
            Some(ProbeModel {
                id,
                context,
                max_output,
                input_modalities,
                effort_levels,
                default_effort,
            })
        })
        .collect();
    Ok(models)
}

// ---------- Kiro (control-plane model catalogue) ----------

/// Fetch a Kiro key's model catalogue.
///
/// The call lives on the KAS control plane (`management.{api_region}.kiro.dev`)
/// — neither the runtime host the chat path speaks to nor the CodeWhisperer
/// host of the quota probe answers `ListAvailableModels` — and its bearer is
/// the shared token manager's, so this probe and dispatch run over one
/// credential cache and one refresh path. Region and `profileArn` come from
/// that credential, never from the provider row: the region becomes part of
/// the hostname, and the bearer travels with the call.
///
/// Effort/reasoning schemas (`additionalModelRequestFieldsSchema`) are
/// deliberately not mapped into [`ProbeModel::effort_levels`]: the Kiro kernel
/// does not encode effort yet, so advertising levels it cannot honor would
/// over-promise.
pub async fn fetch_kiro_models(
    transport: &crate::upstream::transport::Transport,
    context: &crate::upstream::KiroCallContext,
) -> anyhow::Result<Vec<ProbeModel>> {
    anyhow::ensure!(
        crate::upstream::kiro_tokens::valid_region(&context.api_region),
        "Kiro API region {:?} cannot form a control-plane host",
        context.api_region
    );
    let mut body = serde_json::Map::new();
    body.insert(
        "origin".to_owned(),
        serde_json::Value::String("KIRO_CLI".to_owned()),
    );
    if let Some(profile_arn) = &context.profile_arn {
        body.insert(
            "profileArn".to_owned(),
            serde_json::Value::String(profile_arn.clone()),
        );
    }
    let prepared = crate::protocol::Prepared {
        protocol: crate::protocol::ProtocolId::Kiro,
        url: crate::kiro::profile::management_endpoint(&context.api_region),
        content_type: "application/x-amz-json-1.0",
        body: bytes::Bytes::from(serde_json::Value::Object(body).to_string()),
        stream: false,
        headers: crate::kiro::profile::models_static_headers(),
    };
    let auth = [("authorization", format!("Bearer {}", context.bearer()))];
    let deadline = std::time::Instant::now() + PROBE_TIMEOUT;
    let response = transport
        .send_with_headers(&prepared, &auth, &[], deadline)
        .await
        .context("Kiro 模型列表请求失败")?;
    let status = response.status();
    let body = transport
        .read_body(response, MAX_BODY, deadline)
        .await
        .context("Kiro 模型列表响应不可读")?;
    if !status.is_success() {
        let snippet: String = String::from_utf8_lossy(&body)
            .chars()
            .take(ERROR_SNIPPET)
            .collect();
        anyhow::bail!("Kiro 模型列表: {status} {snippet}");
    }
    parse_kiro_models(&String::from_utf8_lossy(&body)).context("Kiro 模型列表响应格式不认识")
}

/// Parse the control plane's `{"models": [...]}` answer into [`ProbeModel`]s.
///
/// `tokenLimits` carries the windows the account actually holds, so a route
/// object derived from this snapshot advertises the real context/output caps;
/// `supportedInputTypes` names the modalities beyond text. `auto` is kept — it
/// is a model the vendor dispatches server-side, not a placeholder.
fn parse_kiro_models(body: &str) -> anyhow::Result<Vec<ProbeModel>> {
    #[derive(serde::Deserialize)]
    struct List {
        #[serde(default)]
        models: Vec<Entry>,
    }
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Entry {
        model_id: Option<String>,
        token_limits: Option<TokenLimits>,
        #[serde(default)]
        supported_input_types: Vec<String>,
    }
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct TokenLimits {
        max_input_tokens: Option<u64>,
        max_output_tokens: Option<u64>,
    }
    let list: List = serde_json::from_str(body)?;
    Ok(list
        .models
        .into_iter()
        .filter_map(|entry| {
            let id = entry.model_id?.trim().to_owned();
            if id.is_empty() {
                return None;
            }
            let input_modalities = entry
                .supported_input_types
                .into_iter()
                .map(|kind| kind.trim().to_ascii_lowercase())
                .filter(|kind| !kind.is_empty() && kind != "text")
                .collect();
            let limits = entry.token_limits;
            Some(ProbeModel {
                id,
                context: limits
                    .as_ref()
                    .and_then(|limits| limits.max_input_tokens)
                    .filter(|tokens| *tokens > 0),
                max_output: limits
                    .as_ref()
                    .and_then(|limits| limits.max_output_tokens)
                    .filter(|tokens| *tokens > 0),
                input_modalities,
                // See the fetch's doc: the vendor's effort schemas are not
                // encoded by the Kiro kernel, so they are not advertised.
                effort_levels: Vec::new(),
                default_effort: None,
            })
        })
        .collect())
}
