//! Vendor Chat-wire dialects — the per-candidate body adaptations one upstream
//! needs and its siblings must not see.
//!
//! Two dialects today, both Chat-wire and both candidate-scoped (the client's
//! own tree is never touched): GLM wants inline images as bare base64, and a
//! DeepSeek model requires a calling assistant turn to be followed straight away
//! by its tool results. [`ChatFixups`] is the once-per-candidate decision the
//! relay honors on both prepare paths; the undesired-field list
//! ([`vendor_thinking_off_fields`]) rides the prepare skip list instead.

use crate::protocol::ProtocolId;
use serde_json::Value;

use super::capabilities;

/// The upstream speaks GLM (Zhipu). The provider NAME is user-chosen (e.g.
/// "智谱") so it cannot be relied on alone — the wire endpoint is the factual
/// identity: `bigmodel.cn` (open.bigmodel.cn incl. /api/coding/paas) or `z.ai`
/// (Zhipu's international brand, same GLM models and thinking API).
pub(super) fn is_glm_upstream(name: &str, base_url: &str) -> bool {
    if capabilities::provider_kind(name).0 == "glm" {
        return true;
    }
    let Ok(url) = reqwest::Url::parse(base_url) else {
        return false;
    };
    url.host_str().is_some_and(|host| {
        ["bigmodel.cn", "z.ai"]
            .iter()
            .any(|suffix| host == *suffix || host.ends_with(&format!(".{suffix}")))
    })
}

/// The OpenCode release the gateway claims to be toward OpenCode's own
/// gateway: Zen's free tier turns away anything
/// older than 1.18.0 (426), and the version rides the User-Agent OpenCode
/// itself sends.
const OPENCODE_VERSION: &str = "1.18.34";

/// The endpoint is OpenCode's gateway (Zen or Go). The provider name is
/// user-chosen, so the wire host is the factual identity (same rule as
/// `is_glm_upstream`).
pub(super) fn is_opencode_upstream(endpoint: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(endpoint) else {
        return false;
    };
    url.host_str()
        .is_some_and(|host| host == "opencode.ai" || host.ends_with(".opencode.ai"))
}

/// The headers OpenCode's gateway requires of every request, sent as OpenCode
/// itself sends them (mirroring
/// packages/opencode/src/session/llm/request.ts). Without
/// `x-opencode-session` the request is turned away (400 MissingSessionID —
/// verified against opencode.ai/zen/go, October 2026); OpenCode routes and
/// caches by it, so the id is derived from the conversation's first user
/// message and stays stable across the conversation's turns and processes.
/// The request id names the single turn and is fresh per attempt.
pub(super) fn opencode_headers(seed: &str) -> Vec<(&'static str, String)> {
    vec![
        ("user-agent", format!("opencode/{OPENCODE_VERSION}")),
        ("x-opencode-session", opencode_id("ses", Some(seed))),
        ("x-opencode-request", opencode_id("msg", None)),
        ("x-opencode-client", "cli".to_string()),
        // OpenCode's project outside a git repository.
        ("x-opencode-project", "global".to_string()),
    ]
}

/// An id in OpenCode's shape (`ses_…` / `msg_…`: the prefix, 12 hex digits
/// and 14 base62 ones). With a seed the id is the
/// seed's sha256 (deterministic: one conversation, one session id); without
/// one it is random (each attempt its own request id).
fn opencode_id(prefix: &str, seed: Option<&str>) -> String {
    const BASE62: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    // 64 hex digits, either hashed or random (uuid is the workspace's random
    // source; two v4s are the 32 bytes a sha256 would give).
    let hex = match seed {
        Some(seed) => crate::db::sha256_hex(seed),
        None => format!(
            "{}{}",
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple()
        ),
    };
    let mut id = String::with_capacity(prefix.len() + 27);
    id.push_str(prefix);
    id.push('_');
    id.push_str(&hex[..12]);
    // Raw hash bytes map to base62; pairs of the hex encoding are
    // those same bytes.
    for pair in 0..14 {
        let byte = u8::from_str_radix(&hex[12 + pair * 2..14 + pair * 2], 16).unwrap_or(0);
        id.push(BASE62[byte as usize % BASE62.len()] as char);
    }
    id
}

/// A conversation's stable identity, for `x-opencode-session`: the first user
/// message, which every later turn replays (the conversation id's
/// fallback — cardinal's inbound requests carry no agent session header).
/// Chat and Anthropic bodies list `messages`, Responses `input`, Gemini
/// `contents` (an omitted role there means user). A body with no user item
/// seeds on the whole body — still stable for the same request.
pub(super) fn conversation_seed(body: &Value) -> String {
    let non_empty = |key: &str| {
        body.get(key)
            .and_then(Value::as_array)
            .filter(|items| !items.is_empty())
    };
    let messages = non_empty("messages");
    let gemini = messages.is_none() && non_empty("contents").is_some();
    let items = messages
        .or_else(|| non_empty("contents"))
        .or_else(|| non_empty("input"));
    let first_user = items.and_then(|items| {
        items.iter().find(|item| {
            let role = item.get("role").and_then(Value::as_str);
            role == Some("user") || (gemini && role.is_none())
        })
    });
    first_user.unwrap_or(body).to_string()
}

/// Models that think unconditionally: any `thinking` field — including
/// `{"type":"low"}` — is rejected (HTTP 400 code 1210 "该模型始终思考"). The
/// fixup strips the whole field so the model just runs its default always-on
/// behaviour. Matched on the wire `model` string; extend as vendors ship more
/// always-thinking models. Evidence: bigmodel thinking-mode docs ("GLM-5.3
/// 强制思考不能关闭") + live probe (#84/#85: `disabled` and `low` both 400).
fn is_always_thinking_model(target_model: &str) -> bool {
    let lower = target_model.to_ascii_lowercase();
    lower.contains("glm-5.3") || lower.contains("glm5.3")
}

/// Vendor fixups for passthrough bodies, applied per candidate before send.
/// `vendor_thinking_off_fields` covers upstreams that cannot turn thinking
/// off: today only Zhipu GLM; the always-thinking table
/// (`is_always_thinking_model`) is vendor-agnostic so a future provider can
/// join without a new mechanism. Returns the top-level fields prepare must
/// omit for this candidate — the same skip-list mechanism the learned
/// refusals use, so the client's body is never copied — or an empty slice
/// when the request is fine as-is.
///
/// The provider NAME is user-chosen (e.g. "智谱") so it cannot be relied on
/// alone — the wire endpoint is the factual identity: `bigmodel.cn`
/// (open.bigmodel.cn incl. /api/coding/paas) or `z.ai` (Zhipu's international
/// brand, same GLM models and thinking API).
pub(super) fn vendor_thinking_off_fields(
    name: &str,
    base_url: &str,
    target_model: &str,
    client: ProtocolId,
    upstream: ProtocolId,
    body: &Value,
) -> &'static [&'static str] {
    let glm = is_glm_upstream(name, base_url);
    if !glm
        || client != ProtocolId::OpenAiChat
        || upstream != ProtocolId::OpenAiChat
        || !is_always_thinking_model(target_model)
    {
        return &[];
    }
    if body.get("thinking").is_some() {
        &["thinking"]
    } else {
        &[]
    }
}

/// GLM's chat endpoints reject inline images sent as data URIs (`400 图片输入
/// 格式/解析错误`) while bare base64 and remote `https://` URLs both work —
/// verified live by CodexPlusPlus #2031 (fixed upstream, v1.6.0) and mirrored
/// by the official zai-sdk, which runs `drop_prefix_image_data` over every
/// chat request's messages for exactly this reason. Rewrites `image_url.url`
/// strings of the shape `data:image/…;base64,…` down to their base64 payload.
///
/// Copy-on-write walk: a body without any data URI is returned as borrowed
/// (zero copies — the common text-only request), one with them is rebuilt
/// only along the paths that carry one. Every other shape (`https://` URLs,
/// `data:` URIs of other media, `detail` fields beside the URL) passes
/// through untouched.
pub(super) fn strip_image_data_uris(body: &Value) -> std::borrow::Cow<'_, Value> {
    match body {
        Value::String(url) => match url
            .strip_prefix("data:image/")
            .and_then(|rest| rest.split_once(";base64,"))
        {
            Some((_, payload)) => std::borrow::Cow::Owned(Value::String(payload.to_owned())),
            None => std::borrow::Cow::Borrowed(body),
        },
        Value::Array(items) => {
            let mut owned: Option<Vec<Value>> = None;
            for (index, item) in items.iter().enumerate() {
                let stripped = strip_image_data_uris(item);
                if let std::borrow::Cow::Owned(stripped) = stripped {
                    owned.get_or_insert_with(|| items.clone())[index] = stripped;
                }
            }
            match owned {
                Some(items) => std::borrow::Cow::Owned(Value::Array(items)),
                None => std::borrow::Cow::Borrowed(body),
            }
        }
        Value::Object(map) => {
            let mut owned: Option<serde_json::Map<String, Value>> = None;
            for (key, value) in map {
                let stripped = strip_image_data_uris(value);
                if let std::borrow::Cow::Owned(stripped) = stripped {
                    owned
                        .get_or_insert_with(|| map.clone())
                        .insert(key.clone(), stripped);
                }
            }
            match owned {
                Some(map) => std::borrow::Cow::Owned(Value::Object(map)),
                None => std::borrow::Cow::Borrowed(body),
            }
        }
        _ => std::borrow::Cow::Borrowed(body),
    }
}

/// DeepSeek's Chat dialect belongs to the MODEL, not the row that serves it: the
/// official API, OpenCode Go/Zen and Command Code all carry the same DeepSeek
/// models, and a later provider reselling one joins the same rule. So the switch
/// is the upstream model's name — never the provider — and every real row's model
/// carries it (`deepseek-v4.1-flash`, `deepseek/deepseek-v4.1-flash`,
/// `deepseek-v4-pro`). The reasoning-replay rule likewise matches the model
/// (and the host for a renamed one); the model is the half that survives a
/// reseller's own naming.
pub(super) fn is_deepseek_model(model: &str) -> bool {
    model.to_ascii_lowercase().contains("deepseek")
}

/// Concatenate a follower assistant message's `content` onto the call-bearing
/// message it is being joined into. A string joins a string, a null contributes
/// nothing, and an array of parts (an image-carrying turn, vanishingly rare on an
/// assistant message) flattens a string neighbour into a text part — the result
/// stays a plain string whenever both sides are, so the common body keeps its
/// exact shape.
fn concat_content(into: Option<&Value>, from: Option<&Value>) -> Value {
    let parts = |value: Option<&Value>| -> Vec<Value> {
        match value {
            Some(Value::String(text)) if !text.is_empty() => vec![Value::String(text.clone())],
            Some(Value::Array(items)) => items.clone(),
            _ => Vec::new(),
        }
    };
    let mut merged = parts(into);
    merged.extend(parts(from));
    match merged.len() {
        0 => Value::Null,
        1 if merged[0].is_string() => merged.swap_remove(0),
        _ if merged.iter().all(Value::is_string) => {
            let text: String = merged.iter().filter_map(Value::as_str).collect();
            Value::String(text)
        }
        _ => {
            // Mixed shapes: a string beside an array becomes a text part, keeping the
            // text before the parts it preceded.
            let parts = merged
                .into_iter()
                .flat_map(|item| match item {
                    Value::String(text) => vec![serde_json::json!({"type": "text", "text": text})],
                    other => vec![other],
                })
                .collect();
            Value::Array(parts)
        }
    }
}

/// Join every assistant message that follows a call-bearing assistant message
/// into it, so the calls and the tool messages answering them stay adjacent.
///
/// The Chat wire — DeepSeek's own words for it: "An assistant message with
/// 'tool_calls' must be followed by tool messages responding to each
/// 'tool_call_id' (insufficient tool messages following tool_calls message)" —
/// requires each calling turn's results to come straight after it. A client that
/// splits one turn's parallel calls over two assistant messages, or slips a
/// text-only assistant message between a call and its result, breaks that pairing
/// and loses the whole request: DeepSeek answers 400, and OpenCode Go's backend
/// answers 400 too, there under the thoroughly misleading "The `reasoning_content`
/// in the thinking mode must be passed back to the API" — which names no cause,
/// because the cause is the pairing, not the field (proven live against both
/// 2026-10-15). Joining the follower into the message it follows restores the
/// pairing without reordering or dropping a byte of the turn.
///
/// Only a follower of a CALL-BEARING assistant message is joined, so two plain
/// assistant messages are left as they are; a body with nothing to join comes
/// back borrowed — callers gate on [`is_deepseek_model`] first, so a non-DeepSeek
/// request pays nothing.
pub(super) fn join_split_tool_call_turns(body: &Value) -> std::borrow::Cow<'_, Value> {
    let Some(messages) = body.get("messages").and_then(Value::as_array) else {
        return std::borrow::Cow::Borrowed(body);
    };
    let mut joined: Vec<Value> = Vec::with_capacity(messages.len());
    let mut changed = false;
    for message in messages {
        let follows_call = message.get("role").and_then(Value::as_str) == Some("assistant")
            && joined.last().is_some_and(|previous| {
                previous.get("role").and_then(Value::as_str) == Some("assistant")
                    && previous
                        .get("tool_calls")
                        .and_then(Value::as_array)
                        .is_some_and(|calls| !calls.is_empty())
            });
        if !follows_call {
            joined.push(message.clone());
            continue;
        }
        changed = true;
        let previous = joined
            .last_mut()
            .expect("follows_call checked the last message");
        let Some(previous) = previous.as_object_mut() else {
            continue;
        };
        let follower = message.as_object().expect("a message is an object");
        previous.insert(
            "content".to_owned(),
            concat_content(previous.get("content"), follower.get("content")),
        );
        if let Some(calls) = follower.get("tool_calls").and_then(Value::as_array) {
            let mut merged = previous
                .get("tool_calls")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            merged.extend(calls.iter().cloned());
            previous.insert("tool_calls".to_owned(), Value::Array(merged));
        }
        // The follower's thinking, if the joined-into message has none of its own.
        let keeps_reasoning = previous
            .get("reasoning_content")
            .and_then(Value::as_str)
            .is_some_and(|text| !text.is_empty());
        if !keeps_reasoning && let Some(reasoning) = follower.get("reasoning_content") {
            previous.insert("reasoning_content".to_owned(), reasoning.clone());
        }
        // Any other field the follower carried alone (a `name`, say) rides along.
        for (key, value) in follower {
            if !previous.contains_key(key) {
                previous.insert(key.clone(), value.clone());
            }
        }
    }
    match changed {
        true => {
            let mut object = body.as_object().cloned().unwrap_or_default();
            object.insert("messages".to_owned(), Value::Array(joined));
            std::borrow::Cow::Owned(Value::Object(object))
        }
        false => std::borrow::Cow::Borrowed(body),
    }
}

/// The Chat-body adaptations one candidate's request needs, decided once in the
/// candidate loop and honored by both prepare paths (same-protocol passthrough
/// and cross-protocol translation). Both are vendor dialects of the outgoing
/// Chat wire, and both default off — the common request borrows the client's own
/// tree and copies nothing.
#[derive(Clone, Copy, Default)]
pub(super) struct ChatFixups {
    /// GLM chat upstream: inline images must go out as bare base64, never data
    /// URIs (see [`strip_image_data_uris`]).
    pub(super) strip_glm_images: bool,
    /// DeepSeek Chat dialect (see [`is_deepseek_model`]): a calling assistant
    /// turn must be followed straight away by its tool results, so a split or
    /// interrupted turn is joined back together (see
    /// [`join_split_tool_call_turns`]).
    pub(super) deepseek_dialect: bool,
}
