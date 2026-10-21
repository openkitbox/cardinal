//! Upstream model-list probing (admin plane): a provider's `/models` list
//! doubles as the key validation for the add-key flow — the fetch proving
//! "this key authenticates and the endpoint answers" also returns the model
//! ids the route editor offers for picking. Nothing here is on the relay hot
//! path; requests are plain GETs with a per-attempt timeout and a bounded
//! body read.

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
/// DeepSeek-flavoured (`context_window`, flat `input_modalities`,
/// `effort.supported_levels`).
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
        effort: Option<Effort>,
    }
    #[derive(serde::Deserialize)]
    struct Modalities {
        input: Vec<String>,
    }
    #[derive(serde::Deserialize)]
    struct Effort {
        supported_levels: Vec<String>,
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
            let effort_levels = entry
                .effort
                .map(|effort| {
                    crate::translation::ir::Effort::canonical_levels(&effort.supported_levels)
                })
                .unwrap_or_default();
            Some(ProbeModel {
                id,
                context,
                max_output,
                input_modalities,
                effort_levels,
            })
        })
        .collect();
    Ok(models)
}
