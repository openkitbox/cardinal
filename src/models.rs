//! `/v1/models` model objects: each route is exposed as a full standard model
//! object, enriched with the model attributes derivable from the member keys'
//! model-list snapshots (see [`crate::probe`]).
//!
//! Derivation is pure and total: a route whose entries cannot ALL be resolved
//! against the snapshots (key deleted, snapshot missing, model absent from it)
//! still lists — it just carries no derived attributes. A declared context
//! window on the route always wins over derivation.

use serde_json::{Value, json};

use crate::probe::ProbeModel;
use crate::store::{KeyModels, RouteRow};

/// The standard /v1/models object for one route:
/// - always: `id` (the route alias), `object: "model"`, `created: 0`,
///   `owned_by: "cardinal"`;
/// - `context_window` / `context_length` / `max_input_tokens` (the names
///   different clients read the window by):
///   the route's DECLARED window when set, else the minimum over the member
///   models' snapshots (only when every entry resolves AND every resolved
///   model carries a context value);
/// - `max_output_tokens`: the minimum over members (same all-members rule);
/// - `modalities.input`: `["text", …]` — the intersection of all members'
///   extra input modalities (a modality is advertised only when every member
///   lists it);
/// - `reasoning: true` + `supported_reasoning_levels`: the intersection of
///   the members that DECLARE effort levels (a member whose list is silent is
///   treated as unconstrained, not as a veto), in the first declaring member's
///   order, only when non-empty.
///
/// Any entry that fails to resolve (key deleted, snapshot missing, model not
/// in the snapshot) voids ALL derived fields; a declared context window is
/// still emitted.
///
/// `chat_capable` = the route serves a chat protocol. A retrieval route
/// (`openai_embeddings`) is listed — OpenAI's own catalog lists embedding
/// models — but bare: it gets no context window, no modalities and no
/// reasoning, because none of those describe an embeddings id and a picker
/// would trust them. Its derived attributes are suppressed wholesale rather
/// than individually, so the enrichment block stays one decision.
pub fn route_model_object(route: &RouteRow, keys: &[KeyModels], chat_capable: bool) -> Value {
    let mut object = json!({
        "id": route.alias,
        "object": "model",
        "created": 0,
        "owned_by": "cardinal",
    });
    // A retrieval route is listed bare (see the doc comment): nothing below
    // describes an embeddings id, a declared context window included.
    if !chat_capable {
        return object;
    }
    if let Some(window) = route.context_window {
        object["context_window"] = window.into();
        object["context_length"] = window.into();
        object["max_input_tokens"] = window.into();
    }
    let Some(members) = resolve_members(route, keys) else {
        return object;
    };
    if route.context_window.is_none()
        && let Some(context) = members.iter().map(|model| model.context).min()
        && let Some(context) = context
    {
        object["context_window"] = context.into();
        object["context_length"] = context.into();
        object["max_input_tokens"] = context.into();
    }
    if let Some(Some(max_output)) = members.iter().map(|model| model.max_output).min() {
        object["max_output_tokens"] = max_output.into();
    }
    // Routes are multimodal at the gateway level: every member model in every
    // route accepts image input, so the route advertises it unconditionally
    // regardless of what each provider's /models snapshot reports.
    object["modalities"] = json!({ "input": ["text", "image"] });
    // Snapshots may predate the probe-side normalization: canonicalize on the
    // way in so the advertised levels always match the request-side vocabulary.
    // A member that declares nothing is not a veto — most vendors' model lists
    // carry no effort block at all, while dispatch clamps/normalizes per
    // candidate anyway.
    let declared: Vec<Vec<String>> = members
        .iter()
        .map(|model| crate::translation::ir::Effort::canonical_levels(&model.effort_levels))
        .filter(|levels| !levels.is_empty())
        .collect();
    let efforts = intersection(declared.iter().map(Vec::as_slice));
    if !efforts.is_empty() {
        object["reasoning"] = true.into();
        object["supported_reasoning_levels"] = efforts
            .into_iter()
            .map(|effort| json!({ "effort": effort }))
            .collect();
    }
    object
}

/// The Gemini `/v1beta/models` object for one route:
/// `name: models/<alias>`, `displayName: <alias>`, the two generation
/// methods, and the token limits derivable from the same member resolution
/// as [`route_model_object`] — omitted when not derivable.
pub fn gemini_model_object(route: &RouteRow, keys: &[KeyModels]) -> Value {
    let mut object = json!({
        "name": format!("models/{}", route.alias),
        "displayName": route.alias,
        "supportedGenerationMethods": ["generateContent", "streamGenerateContent"],
    });
    let members = resolve_members(route, keys);
    // A declared context window on the route always wins over derivation.
    let context = route
        .context_window
        .and_then(|window| u64::try_from(window).ok())
        .or_else(|| {
            members
                .as_deref()
                .and_then(|members| members.iter().map(|model| model.context).min().flatten())
        });
    if let Some(context) = context {
        object["inputTokenLimit"] = context.into();
    }
    if let Some(max_output) = members
        .as_deref()
        .and_then(|members| members.iter().map(|model| model.max_output).min().flatten())
    {
        object["outputTokenLimit"] = max_output.into();
    }
    object
}

/// Every route entry's member model: its key's snapshot must exist and contain
/// the entry's model id. `None` when any entry fails to resolve. Empty routes
/// are a real state (key deletion cascades entries out, the emptied route
/// keeps its alias so it can be re-pointed) and resolve to no attributes.
fn resolve_members<'a>(route: &RouteRow, keys: &'a [KeyModels]) -> Option<Vec<&'a ProbeModel>> {
    if route.entries.is_empty() {
        return None;
    }
    let members: Vec<&'a ProbeModel> = route
        .entries
        .iter()
        // The whitelist gates the same way relay dispatch does: a key that does not
        // serve the entry's model is not a member at all — skip it (do not poison
        // the whole route the way an unresolvable entry does).
        .filter(|entry| {
            let key = keys.iter().find(|key| key.id == entry.key_id);
            !key.is_some_and(|key| {
                key.allowed_models.as_ref().is_some_and(|allowed| {
                    !allowed.is_empty() && !allowed.iter().any(|model| model == &entry.model)
                })
            })
        })
        .map(|entry| {
            let key = keys.iter().find(|key| key.id == entry.key_id)?;
            key.models
                .as_ref()?
                .iter()
                .find(|model| model.id == entry.model)
        })
        .collect::<Option<Vec<_>>>()?;
    // Every member whitelisted away: nothing to derive from (the route still
    // exists and is listed, just without derived attributes).
    if members.is_empty() {
        return None;
    }
    Some(members)
}

/// The values present in EVERY list, in the first list's order, deduplicated.
/// `"text"` is never in the extras (the probe already strips it; filtered
/// defensively).
fn intersection<'a>(lists: impl Iterator<Item = &'a [String]>) -> Vec<String> {
    let lists: Vec<&[String]> = lists.collect();
    let Some(first) = lists.first() else {
        return Vec::new();
    };
    let mut out: Vec<String> = Vec::new();
    for item in *first {
        if item.as_str() != "text"
            && !out.contains(item)
            && lists[1..].iter().all(|list| list.contains(item))
        {
            out.push(item.clone());
        }
    }
    out
}
