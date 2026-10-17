//! Optional-field learning.
//!
//! The kernels no longer hold a client-field allowlist: whether a request
//! field is supported is the upstream's call. A strict upstream that turns a
//! request away for an optional field it doesn't know is asked again without
//! that field, and the refusal is remembered so later requests to the same
//! provider pre-strip it instead of paying a 400 round-trip every time.

use crate::protocol::ProtocolId;
use dashmap::DashMap;
use regex::Regex;
use serde_json::Value;
use std::sync::OnceLock;

/// Request fields a request does without: an upstream that refuses one by
/// name is asked again without it.
pub const OPTIONAL_FIELDS: &[&str] = &[
    "store",
    "metadata",
    "service_tier",
    "prompt_cache_key",
    "prompt_cache_retention",
    "safety_identifier",
    "stream_options",
    "parallel_tool_calls",
    "verbosity",
    "thinking",
    "enable_thinking",
];

/// Upper bound on strip-and-retry rounds for one send. Each round strips at
/// least one newly refused field, and the list above is finite, so this is a
/// safety rail rather than a real limit.
pub const MAX_STRIP_ROUNDS: u32 = 6;

/// Learned per-upstream field refusals. Identity = (provider row id,
/// protocol, field): the refusal is a property of the upstream API, not of a
/// key, and protocol body shapes differ. Stale rows after a provider edit or
/// delete are negligible (same disclosure as `Failures`).
pub struct Unfit {
    refused: DashMap<(i64, ProtocolId, &'static str), ()>,
}

impl Unfit {
    pub fn new() -> Self {
        Self {
            refused: DashMap::new(),
        }
    }

    /// Remember that the provider's API refused `field` on this protocol.
    pub fn record(&self, provider_id: i64, protocol: ProtocolId, field: &'static str) {
        self.refused.insert((provider_id, protocol, field), ());
    }

    /// The optional fields this provider's API is known to refuse.
    pub fn refused_fields(&self, provider_id: i64, protocol: ProtocolId) -> Vec<&'static str> {
        OPTIONAL_FIELDS
            .iter()
            .copied()
            .filter(|field| self.refused.contains_key(&(provider_id, protocol, field)))
            .collect()
    }
}

impl Default for Unfit {
    fn default() -> Self {
        Self::new()
    }
}

/// Optional fields present in `request_body` that `error_body` (a 400/422
/// from the upstream) names as refused. An empty result means the error is
/// about something else — a value problem, or a non-optional field — and the
/// request must NOT be retried stripped (an invalid value must reach
/// the client without dropping the field).
pub fn refused_optional(status: u16, error_body: &[u8], request_body: &Value) -> Vec<&'static str> {
    // 400 or 422 only — any other status is not a field refusal.
    if status != 400 && status != 422 {
        return Vec::new();
    }
    let Some(object) = request_body.as_object() else {
        return Vec::new();
    };
    let text = String::from_utf8_lossy(error_body);
    let fault = serde_json::from_str::<Value>(&text).unwrap_or(Value::String(text.into_owned()));
    let mut out = Vec::new();
    for field in OPTIONAL_FIELDS {
        if !object.contains_key(*field) {
            continue;
        }
        if unsupported_optional_field(&fault, field) {
            out.push(*field);
        }
    }
    out
}

struct Tables {
    unknown: Option<Regex>,
    unquoted: Option<Regex>,
    rejected: Option<Regex>,
}

fn tables() -> &'static Tables {
    static TABLES: OnceLock<Tables> = OnceLock::new();
    TABLES.get_or_init(|| {
    let compile = |pattern: &str| Regex::new(pattern).ok();
    Tables {
      // Quoted field name after an
      // unknown/unsupported/unrecognized lead-in.
      unknown: compile(
        r#"(?i)\b(?:unknown (?:name|field|parameter)|unsupported (?:parameter|field|property|argument)|unrecognized (?:request )?(?:argument|parameter)(?: supplied)?):?\s*['"\x60]([a-z_]+)['"\x60]"#,
      ),
      // Unquoted `unsupported parameter: store`.
      unquoted: compile(r"(?i)\bunsupported (?:parameter|field|property|argument):\s*([a-z_]+)\b"),
      // Rejected word order: `'store' is unsupported`.
      rejected: compile(r#"(?i)(?:^|\b(?:parameter|field|property|argument)\s+)['"\x60]([a-z_]+)['"\x60]\s+(?:is\s+)?(?:unsupported|not supported)\b"#),
    }
  })
}

/// Does this error value say `field` (a top-level request field) is
/// unsupported?
fn unsupported_optional_field(fault: &Value, field: &str) -> bool {
    match fault {
        Value::String(text) => {
            // A proxy can embed the vendor's JSON error in prose. Prefer its
            // structure to text matching, which could mistake an input echo or a
            // different parameter's error for a refusal.
            for inner in embedded_json_values(text) {
                if has_optional_error_object(&inner) {
                    return unsupported_optional_field(&inner, field);
                }
            }
            text_names_field(tables(), text, field)
        }
        Value::Array(items) => items
            .iter()
            .any(|item| unsupported_optional_field(item, field)),
        Value::Object(map) => {
            // Mistral-style extra_forbidden: loc ["body", "store"] (or ["store"]).
            if map.get("type").and_then(Value::as_str) == Some("extra_forbidden") {
                let loc: Vec<&str> = map
                    .get("loc")
                    .and_then(Value::as_array)
                    .map(|loc| loc.iter().filter_map(Value::as_str).collect())
                    .unwrap_or_default();
                return (loc.len() == 1 && loc[0] == field)
                    || (loc.len() == 2 && loc[0] == "body" && loc[1] == field);
            }
            // A located validation error concerns the value, not support for the
            // top-level field. Never inspect its input echo.
            if map.contains_key("loc") {
                return false;
            }
            if map.get("code").and_then(Value::as_str) == Some("unsupported_value")
                || map.get("type").and_then(Value::as_str) == Some("unsupported_value")
            {
                return false;
            }
            let param = map.get("param").and_then(Value::as_str).unwrap_or("");
            if !param.is_empty() && param != field {
                return false;
            }
            if map.get("code").and_then(Value::as_str) == Some("unsupported_parameter")
                && param == field
            {
                return true;
            }
            [
                "error",
                "message",
                "detail",
                "details",
                "errors",
                "description",
                "metadata",
                "raw",
            ]
            .iter()
            .any(|key| {
                map.get(*key)
                    .is_some_and(|inner| unsupported_optional_field(inner, field))
            })
        }
        _ => false,
    }
}

/// Does this value contain any object? (An
/// embedded JSON document with an object wins over prose matching.)
fn has_optional_error_object(value: &Value) -> bool {
    match value {
        Value::Object(_) => true,
        Value::Array(items) => items.iter().any(has_optional_error_object),
        _ => false,
    }
}

/// JSON documents embedded in prose: scan for `{`/`[` and take each document
/// a stream parse can complete from there.
fn embedded_json_values(text: &str) -> Vec<Value> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'{' || bytes[i] == b'[' {
            let mut stream = serde_json::Deserializer::from_str(&text[i..]).into_iter::<Value>();
            if let Some(Ok(value)) = stream.next() {
                i += stream.byte_offset().max(1);
                out.push(value);
                continue;
            }
        }
        i += 1;
    }
    out
}

/// Prose matching: the three recognized vendor wordings.
fn text_names_field(tables: &Tables, text: &str, field: &str) -> bool {
    if let Some(re) = &tables.unknown {
        for captures in re.captures_iter(text) {
            if captures.get(1).is_some_and(|m| m.as_str() == field) {
                // Gemini names a nested field with "at 'path'"; only an absent or
                // empty path identifies a top-level request field.
                let end = captures.get(0).map(|m| m.end()).unwrap_or(text.len());
                let tail = text[end..].trim_start().to_lowercase();
                if tail.starts_with("at ")
                    && !tail.starts_with("at '':")
                    && !tail.starts_with("at \"\":")
                {
                    continue;
                }
                return true;
            }
        }
    }
    let simple = |re: &Option<Regex>| {
        re.as_ref().is_some_and(|re| {
            re.captures_iter(text)
                .any(|c| c.get(1).is_some_and(|m| m.as_str() == field))
        })
    };
    simple(&tables.unquoted) || simple(&tables.rejected)
}
