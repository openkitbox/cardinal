//! `openai_embeddings` kernel (OpenAI's Embeddings retrieval API).
//!
//! Not a chat: the request carries no conversation, the answer generates
//! nothing, and there is no streaming wire. So the kernel has exactly two
//! jobs — validate the envelope before any send, and read the input-only
//! usage back out of the answer.
//!
//! Passthrough fidelity is the contract here. Every field the client sent
//! reaches the vendor byte-identically except `model`, which the relay
//! rewrites for the candidate. That matters because the retrieval API carries
//! vendor-specific knobs no allowlist can keep up with (`dimensions`,
//! `encoding_format`, `user`, Cohere's `input_type`/`truncate`, Jina's
//! `task`/`normalize`, Voyage's `output_dtype`) — and guessing wrong would
//! silently change the vectors the caller gets back.
//!
//! The response is likewise forwarded untouched: vector payloads are megabytes
//! (`encoding_format: "base64"` above all), so observation reads only the
//! handful of scalars it needs and never materializes `data`.

use super::usage::UsageCounts;
use super::{
    ObservedResponse, Prepared, ProtocolError, ProtocolId, RawValue, TargetView, Terminal,
};
use serde_json::Value;

/// Build the upstream request for one attempt.
///
/// The wire is written field-by-field straight from the client's tree — no
/// intermediate `Value`, no deep copy of `input` (which holds the documents) —
/// with only `model` overridden. `skip` names top-level fields the wire must
/// not carry (learned refusals): the kernel omits them while building, so a
/// strip never costs a parse/re-serialize round-trip.
///
/// `stream` is rejected rather than ignored: the protocol has no streaming
/// wire, and a relay that quietly answered a stream request with one JSON body
/// would break the client's framing contract. The HTTP layer clears the field
/// before dispatch (see `api::embeddings`), so this only fires on a caller that
/// bypassed the entry point.
pub fn prepare(
    client_body: &Value,
    target: &TargetView<'_>,
    stream: bool,
    skip: &[&str],
) -> Result<Prepared, ProtocolError> {
    if stream {
        return Err(ProtocolError::UnsupportedParameter);
    }
    validate_request(client_body)?;
    let object = client_body
        .as_object()
        .ok_or(ProtocolError::InvalidRequest)?;
    let url = target.url(false)?;
    let mut out = Vec::new();
    out.push(b'{');
    let mut first = true;
    for (field, value) in object {
        if skip.contains(&field.as_str()) {
            continue;
        }
        if !first {
            out.push(b',');
        }
        first = false;
        super::write_json(&mut out, field)?;
        out.push(b':');
        if field == "model" {
            super::write_json(&mut out, target.upstream_model)?;
        } else {
            // No `strip_images` variant: a retrieval body holds text, and the
            // GLM data-URI dialect belongs to the chat wire alone.
            super::write_json_value(&mut out, value, false)?;
        }
    }
    out.push(b'}');
    Ok(Prepared {
        protocol: ProtocolId::OpenAiEmbeddings,
        url: url.to_owned(),
        content_type: "application/json",
        body: bytes::Bytes::from(out),
        stream: false,
        headers: Vec::new(),
    })
}

/// Structural validation shared by both execution paths: a non-empty model id
/// and the `input` the vendor will embed. The three accepted `input` shapes
/// are the API's own (a string, an array of strings, an array of token
/// ids/arrays); anything else is refused here rather than at the vendor, so a
/// malformed call costs no upstream round-trip.
pub fn validate_request(client_body: &Value) -> Result<(), ProtocolError> {
    let object = client_body
        .as_object()
        .ok_or(ProtocolError::InvalidRequest)?;
    match object.get("model").and_then(Value::as_str) {
        Some(model) if !model.trim().is_empty() => {}
        _ => return Err(ProtocolError::InvalidRequest),
    }
    match object.get("input") {
        Some(Value::String(text)) if !text.is_empty() => Ok(()),
        Some(Value::Array(items)) if !items.is_empty() => Ok(()),
        _ => Err(ProtocolError::InvalidRequest),
    }
}

/// Observe a non-streaming response.
///
/// Only the observed fields are deserialized, borrowed straight from the wire
/// (`raw_str`/`raw_value`): the `data` array — every vector the vendor
/// produced — is never materialized.
pub fn parse_json(body: &[u8]) -> Result<ObservedResponse, ProtocolError> {
    let observation: EmbeddingObservation =
        serde_json::from_slice(body).map_err(|_| ProtocolError::InvalidUpstreamResponse)?;
    // JSON `null` deserializes to `None` here, so `is_some()` is exactly the
    // old `!error.is_null()` verdict — a 200 that still reports an error (some
    // OpenAI-compatible vendors do) is a failed attempt, not a success.
    if observation.error.is_some() {
        return Ok(ObservedResponse {
            usage: None,
            terminal: Terminal::Failed,
            upstream_model: None,
        });
    }
    Ok(ObservedResponse {
        usage: observation
            .usage
            .as_ref()
            .and_then(|usage| super::raw_value(usage))
            .as_ref()
            .and_then(usage_counts),
        terminal: Terminal::Completed,
        upstream_model: super::raw_str(observation.model).map(str::to_owned),
    })
}

/// The observed fields of an embeddings response; `data` is ignored without
/// being materialized.
#[derive(serde::Deserialize)]
struct EmbeddingObservation<'a> {
    #[serde(default, borrow)]
    error: Option<&'a RawValue>,
    #[serde(default, borrow)]
    usage: Option<&'a RawValue>,
    #[serde(default, borrow)]
    model: Option<&'a RawValue>,
}

/// Read the input-only usage. Embeddings generate nothing, so `output_tokens`
/// is zero unless a vendor oddly reports a completion; the prompt count is the
/// one quantity every shape names, under four different names:
/// OpenAI's `prompt_tokens`, the `input_tokens` spelling, Jina/Voyage's
/// `total_tokens`, and Cohere's `meta.billed_units.input_tokens`.
///
/// A response that names none yields `None` (usage unknown, never zero): a
/// vendor behind a proxy may drop the object, and billing an unknown quantity
/// as empty would be a silent lie.
fn usage_counts(usage: &Value) -> Option<UsageCounts> {
    let output = usage
        .get("completion_tokens")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let billed = |holder: &Value| {
        holder
            .get("billed_units")
            .and_then(|billed| billed.get("input_tokens"))
            .and_then(Value::as_u64)
    };
    let input = usage
        .get("prompt_tokens")
        .and_then(Value::as_u64)
        .or_else(|| usage.get("input_tokens").and_then(Value::as_u64))
        .or_else(|| billed(usage))
        .or_else(|| usage.get("meta").and_then(billed))
        // The total is the only quantity Jina and Voyage report; nothing was
        // generated here, so the total is the prompt.
        .or_else(|| {
            usage
                .get("total_tokens")
                .and_then(Value::as_u64)
                .map(|total| total.saturating_sub(output))
        })?;
    Some(UsageCounts {
        input_tokens: input,
        output_tokens: output,
        ..Default::default()
    })
}
