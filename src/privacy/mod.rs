//! Privacy redaction: mask sensitive strings on the way to an upstream, put the
//! real values back on the way to the client, and scrub what is kept.
//!
//! The outbound transform runs at **wire-render time** (see [`protocol`]), so the
//! client's parsed tree is never cloned and each candidate attempt masks the
//! shared read-only body into its own bytes — the same placement as the image
//! strip. Detection is regex-only ([`rules`]); placeholders are stable per value
//! ([`placeholders`]) to keep upstream prompt caches and signed reasoning valid.
//!
//! Two kinds of state, each with the lifetime its job needs:
//!
//! - [`MaskCtx`] — **one request**: the policy plus `placeholder -> value`, so
//!   the response can be restored. Created per dispatch, shared by every
//!   candidate attempt (they mask the same values to the same placeholders).
//! - [`placeholders`]' index — **durable**: the values a later request may
//!   replay as prose, which no stateless rule can recognise. Encrypted at rest
//!   so a restart does not reopen the leak.
//!
//! [`protocol`]: crate::protocol

mod placeholders;
mod rules;
mod stream;

pub(crate) use stream::{OutFrame, StreamRestore};

use std::borrow::Cow;
use std::collections::HashMap;
use std::path::Path;
use std::sync::{LazyLock, Mutex};

use regex::Regex;

/// What to mask. Read from `[gateway.privacy]`.
#[derive(Debug, Clone, Default)]
pub struct Policy {
    /// Credentials: keys, tokens, passwords, private keys.
    pub secrets: bool,
    /// Personal data: email, phone, national id, bank card.
    pub personal: bool,
    /// The operator's own terms to mask.
    pub words: Vec<String>,
}

impl Policy {
    /// Whether anything is masked at all.
    pub fn is_on(&self) -> bool {
        self.secrets || self.personal || !self.words.is_empty()
    }
}

/// One request's masking state: the policy and the `placeholder -> value` map
/// the response restore reads. Lives with the request, so it can never hold a
/// value longer than it is needed, and needs no eviction.
pub struct MaskCtx {
    policy: Policy,
    values: Mutex<HashMap<String, String>>,
}

impl MaskCtx {
    /// A context for `policy`. Only built when something is masked.
    pub fn new(policy: Policy) -> Self {
        Self {
            policy,
            values: Mutex::new(HashMap::new()),
        }
    }

    fn values(&self) -> std::sync::MutexGuard<'_, HashMap<String, String>> {
        // Poisoned only by a panic while held (nothing here panics) and the map
        // is still consistent — recover rather than take the gateway down.
        self.values
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Record what a placeholder stands for: here (for this request's restore)
    /// and in the durable index (for a later request's re-mask).
    fn remember(&self, kind: &str, value: &str, ph: &str) {
        self.values().insert(ph.to_string(), value.to_string());
        placeholders::remember(kind, value, ph);
    }

    /// The value a placeholder stands for: this request's map first, then the
    /// durable index (a placeholder replayed from an earlier request).
    fn resolve(&self, ph: &str) -> Option<String> {
        if let Some(value) = self.values().get(ph) {
            return Some(value.clone());
        }
        placeholders::resolve(ph)
    }
}

/// Where a matched span's replacement comes from.
pub(crate) enum Repl {
    /// Derive a placeholder from the kind and the matched value.
    Derive(&'static str),
    /// A known placeholder (the value came back as prose).
    Fixed(String),
}

/// A byte range of a string to replace, with how to replace it.
pub(crate) struct Span {
    pub(crate) start: usize,
    pub(crate) end: usize,
    pub(crate) repl: Repl,
}

/// An existing placeholder body (`KIND_suffix`).
const BODY: &str = r"[A-Za-z][A-Za-z0-9_]*_[A-Za-z2-7]{8}";

/// An existing placeholder as it was emitted.
static PLACEHOLDER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(r"\{{\{{\s*({BODY})\s*\}}\}}")).expect("placeholder pattern")
});

/// Load the placeholder key, then the durable re-mask index.
pub fn init(key: Option<&Path>, index: Option<&Path>) {
    placeholders::init_key(key);
    placeholders::init_index(index);
}

/// A field whose value is an opaque carrier the *upstream* computed — a
/// signature or an encrypted payload. The request side never masks inside it
/// (masking the plaintext would void the signature and the replay would be
/// rejected), and the response side must therefore never restore inside it
/// either: the block went out verbatim, so it comes back verbatim.
pub(crate) fn opaque(key: &str) -> bool {
    matches!(
        key,
        "signature" | "encrypted_content" | "thoughtSignature" | "thought_signature"
    )
}

/// A field whose value is an identifier, an enum, or a token the vendor matches
/// against its own: masking it would break routing, validation, or the vendor's
/// own matching, and — because the same rule applies to the response — it would
/// corrupt the round trip. Both directions use this one list.
pub(crate) fn structural(key: &str) -> bool {
    opaque(key)
        || matches!(
            key,
            "type"
                | "id"
                | "ids"
                | "role"
                | "name"
                | "model"
                | "object"
                | "status"
                | "finish_reason"
                | "stop_reason"
                | "item_id"
                | "tool_use_id"
                | "call_id"
                | "previous_response_id"
                | "url"
                | "image_url"
                | "media_type"
                | "mime_type"
                | "mimeType"
                | "tool_choice"
                | "reasoning_effort"
                | "effort"
                | "encoding_format"
                | "index"
                | "output_index"
                | "content_index"
                | "sequence_number"
        )
        || key.ends_with("_id")
        || key.ends_with("_ids")
        || key.ends_with("Id")
        || key.ends_with("Ids")
}

/// Mask what `ctx`'s policy covers in `s`; returns the text and how many values
/// were masked (a borrowed `s` when nothing matched).
pub(crate) fn mask<'a>(s: &'a str, ctx: &MaskCtx) -> (Cow<'a, str>, usize) {
    if !ctx.policy.is_on() || s.len() < 3 || !s.contains(|c: char| c.is_ascii_alphanumeric()) {
        return (Cow::Borrowed(s), 0);
    }
    let mut found = rules::spans(s, ctx.policy.secrets, ctx.policy.personal);
    for word in &ctx.policy.words {
        let word = word.trim();
        if word.len() < 2 {
            continue;
        }
        let mut from = 0;
        while let Some(at) = s[from..].find(word) {
            let start = from + at;
            let end = start + word.len();
            from = end;
            // A bare substring match would rewrite ordinary words inside longer
            // ones (and inside identifiers); only a whole token counts.
            if !whole_token(s, start, end) {
                continue;
            }
            found.push(Span {
                start,
                end,
                repl: Repl::Derive("TERM"),
            });
        }
    }
    found.extend(placeholders::known_spans(s));
    splice(s, found, false, Some(ctx))
}

/// Whether `start..end` is bounded by non-alphanumerics on both sides.
fn whole_token(s: &str, start: usize, end: usize) -> bool {
    let bytes = s.as_bytes();
    let before = start
        .checked_sub(1)
        .map(|at| bytes[at].is_ascii_alphanumeric())
        .unwrap_or(false);
    let after = bytes.get(end).is_some_and(u8::is_ascii_alphanumeric);
    !before && !after
}

/// Put the values back in `s` (the client-facing side of the response).
/// `escaped` escapes each value for a string that is itself JSON (tool arguments).
pub(crate) fn restore<'a>(s: &'a str, escaped: bool, ctx: &MaskCtx) -> Cow<'a, str> {
    if !s.contains("{{") {
        return Cow::Borrowed(s);
    }
    PLACEHOLDER.replace_all(s, |caps: &regex::Captures<'_>| {
        let full = caps.get(0).map(|m| m.as_str()).unwrap_or_default();
        match caps
            .get(1)
            .and_then(|body| resolve_bottom(body.as_str(), ctx))
        {
            Some(value) if escaped => json_escape(&value),
            Some(value) => value,
            None => full.to_string(),
        }
    })
}

/// Scrub `s` for storage: secrets and personal data go for good as
/// `[REDACTED:KIND]` — no placeholder, nothing to put back. Applied to every
/// captured body (the payload log is read by any local operator).
pub(crate) fn scrub(s: &str) -> Cow<'_, str> {
    let mut found = rules::spans(s, true, true);
    // A value the index remembers is one no rule finds again — without this it
    // would survive into the stored log in the clear.
    found.extend(placeholders::redacted_spans(s));
    splice(s, found, true, None).0
}

/// Replace the (non-overlapping) spans in `s`, ignoring any that fall inside an
/// existing placeholder.
fn splice<'a>(
    s: &'a str,
    mut found: Vec<Span>,
    redacted: bool,
    ctx: Option<&MaskCtx>,
) -> (Cow<'a, str>, usize) {
    if found.is_empty() {
        return (Cow::Borrowed(s), 0);
    }
    if s.contains("{{") {
        let existing: Vec<(usize, usize)> = PLACEHOLDER
            .find_iter(s)
            .map(|m| (m.start(), m.end()))
            .collect();
        found.retain(|sp| !existing.iter().any(|&(a, b)| sp.start < b && a < sp.end));
    }
    if found.is_empty() {
        return (Cow::Borrowed(s), 0);
    }
    // First match wins; a later, shorter overlapping match is dropped.
    found.sort_by(|a, b| a.start.cmp(&b.start).then(b.end.cmp(&a.end)));
    let mut out = String::with_capacity(s.len() + 16);
    let mut at = 0usize;
    let mut hits = 0usize;
    for sp in found {
        if sp.start < at {
            continue;
        }
        let value = &s[sp.start..sp.end];
        let text = match &sp.repl {
            Repl::Derive(kind) if redacted => format!("[REDACTED:{kind}]"),
            Repl::Derive(kind) => {
                let ph = placeholders::placeholder_for(kind, value);
                if let Some(ctx) = ctx {
                    ctx.remember(kind, value, &ph);
                }
                ph
            }
            Repl::Fixed(ph) => ph.clone(),
        };
        out.push_str(&s[at..sp.start]);
        out.push_str(&text);
        at = sp.end;
        hits += 1;
    }
    if hits == 0 {
        return (Cow::Borrowed(s), 0);
    }
    out.push_str(&s[at..]);
    (Cow::Owned(out), hits)
}

/// The canonical placeholder for an as-seen body, if it is one we made: the kind
/// is upper-cased and the suffix lower-cased (a vendor may change the case).
fn resolve_bottom(body: &str, ctx: &MaskCtx) -> Option<String> {
    for (at, _) in body.match_indices('_').rev() {
        let kind = body[..at].to_ascii_uppercase();
        let suffix = body[at + 1..].to_ascii_lowercase();
        if let Some(value) = ctx.resolve(&format!("{{{{{kind}_{suffix}}}}}")) {
            return Some(value);
        }
    }
    None
}

/// Whether `data` could hold a placeholder (a `{{` pair), the cheap pre-check
/// that keeps the common frame/body on the borrowed fast path.
pub(crate) fn contains_open(data: &[u8]) -> bool {
    data.windows(2).any(|w| w == b"{{")
}

/// Restore placeholders inside a complete response body (the non-streaming
/// path). A body that is not JSON is restored as raw text when it is valid
/// UTF-8, and left alone when it is binary.
pub(crate) fn restore_json(body: &[u8], ctx: Option<&MaskCtx>) -> Vec<u8> {
    let Some(ctx) = ctx else {
        return body.to_vec();
    };
    if !contains_open(body) {
        return body.to_vec();
    }
    match serde_json::from_slice::<serde_json::Value>(body) {
        Ok(mut value) => {
            restore_value(&mut value, ctx);
            serde_json::to_vec(&value).unwrap_or_else(|_| body.to_vec())
        }
        Err(_) => match std::str::from_utf8(body) {
            Ok(text) => match restore(text, false, ctx) {
                Cow::Owned(out) => out.into_bytes(),
                Cow::Borrowed(_) => body.to_vec(),
            },
            Err(_) => body.to_vec(),
        },
    }
}

/// Restore placeholders inside a complete JSON body, the non-streaming path
/// (the streaming path is the [`StreamRestore`] state machine).
fn restore_value(value: &mut serde_json::Value, ctx: &MaskCtx) {
    let mut path = String::new();
    walk_strings(value, &mut path, "", &mut |_path, key, text| {
        restore(text, as_json(key, None), ctx).into_owned()
    });
}

/// Walk every string in a response value, replacing it with `f(path, key, text)`.
/// An object carrying an opaque carrier is skipped whole, and a structural key
/// is left alone: the request side emitted both verbatim, so the response side
/// restores them verbatim — the two directions cannot drift. Shared by the
/// non-streaming body and the streaming frame walkers.
pub(crate) fn walk_strings(
    value: &mut serde_json::Value,
    path: &mut String,
    key: &str,
    f: &mut dyn FnMut(&str, &str, &str) -> String,
) {
    match value {
        serde_json::Value::String(text) => *text = f(path, key, text),
        serde_json::Value::Array(items) => {
            let base = path.len();
            for (index, item) in items.iter_mut().enumerate() {
                path.push('[');
                path.push_str(&index.to_string());
                path.push(']');
                walk_strings(item, path, key, f);
                path.truncate(base);
            }
        }
        serde_json::Value::Object(object) => {
            if object.keys().any(|name| opaque(name)) {
                return;
            }
            let base = path.len();
            for (name, item) in object.iter_mut() {
                if !path.is_empty() {
                    path.push('.');
                }
                path.push_str(name);
                let name = name.clone();
                walk_strings(item, path, &name, f);
                path.truncate(base);
            }
        }
        _ => {}
    }
}

/// Whether a value under `key` is itself JSON text (tool arguments): a value put
/// back into it must be escaped first, because it lands inside a nested JSON
/// document rather than in a plain string.
pub(crate) fn as_json(key: &str, event: Option<&str>) -> bool {
    key == "arguments"
        || key == "partial_json"
        || (key == "delta" && event.is_some_and(|event| event.contains("arguments")))
}

/// Escape `s` to sit inside a JSON string.
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    const KEY: &str = "sk-ant-api03-ZZZZsecret0000111122223333";
    const MAIL: &str = "zhang.san@corp.cn";

    fn ctx() -> MaskCtx {
        MaskCtx::new(Policy {
            secrets: true,
            personal: true,
            words: Vec::new(),
        })
    }

    #[test]
    fn masks_and_restores_round_trip() {
        let ctx = ctx();
        let text = format!("key {KEY} mail {MAIL}");
        let (masked, hits) = mask(&text, &ctx);
        assert_eq!(hits, 2, "{masked}");
        assert!(!masked.contains(KEY));
        assert!(!masked.contains(MAIL));
        assert_eq!(restore(&masked, false, &ctx), text);
    }

    #[test]
    fn placeholder_is_stable_across_calls() {
        let a = mask(KEY, &ctx());
        let b = mask(KEY, &ctx());
        assert_eq!(a.0, b.0, "same value must derive the same placeholder");
    }

    #[test]
    fn off_policy_changes_nothing() {
        let off = MaskCtx::new(Policy::default());
        let text = format!("key {KEY}");
        let (masked, hits) = mask(&text, &off);
        assert_eq!(hits, 0);
        assert_eq!(masked, text);
    }

    #[test]
    fn words_only_match_whole_tokens() {
        let ctx = MaskCtx::new(Policy {
            secrets: false,
            personal: false,
            words: vec!["acme".to_string()],
        });
        // `acme` inside a longer word is left alone; a standalone one is masked.
        let (masked, hits) = mask("the acmecorp and acme ltd", &ctx);
        assert_eq!(hits, 1, "{masked}");
        assert!(masked.contains("acmecorp"), "{masked}");
        assert!(!masked.contains(" acme "), "{masked}");
    }

    #[test]
    fn a_later_request_remasks_a_value_it_never_saw_a_rule_for() {
        // Turn 1 finds the value by its context; turn 2 replays it bare, where
        // no rule matches — the durable index is what catches it.
        let first = ctx();
        let (masked, hits) = mask("password=Tr0ub4dor", &first);
        assert_eq!(hits, 1, "{masked}");
        let placeholder = masked
            .split_once('=')
            .expect("password=<placeholder>")
            .1
            .to_string();
        assert!(placeholder.starts_with("{{"), "{placeholder}");

        let second = ctx();
        let (again, hits) = mask("curl -u admin:Tr0ub4dor http://x", &second);
        assert_eq!(hits, 1, "bare replay must be re-masked: {again}");
        assert!(!again.contains("Tr0ub4dor"), "{again}");
        assert!(again.contains(&placeholder), "same placeholder: {again}");
    }

    #[test]
    fn scrub_is_irreversible() {
        let ctx = ctx();
        let text = format!("key {KEY} mail {MAIL}");
        let scrubbed = scrub(&text);
        assert!(scrubbed.contains("[REDACTED:"), "{scrubbed}");
        assert!(!scrubbed.contains(KEY));
        assert!(!scrubbed.contains(MAIL));
        assert_eq!(
            restore(&scrubbed, false, &ctx),
            scrubbed,
            "no value comes back"
        );
    }

    /// The two SSE payloads an upstream emits when it splits a placeholder.
    fn frame(text: &str, index: u32) -> Vec<u8> {
        format!("{{\"choices\":[{{\"index\":{index},\"delta\":{{\"content\":\"{text}\"}}}}]}}")
            .into_bytes()
    }

    #[test]
    fn streaming_split_placeholder_reassembles() {
        let ctx = Arc::new(ctx());
        let (masked, _) = mask(KEY, &ctx);
        let masked = masked.into_owned();
        let (head, rest) = masked.split_at(masked.len() / 2);
        let mut restore = StreamRestore::new(Some(Arc::clone(&ctx)));

        let first = restore.frame(None, &frame(head, 0));
        assert!(first.release.is_none());
        assert!(first.emit.is_none(), "a partial placeholder is held");

        let second = restore.frame(None, &frame(rest, 0));
        let released = String::from_utf8(second.release.expect("held frame out").data).unwrap();
        let emitted = String::from_utf8(second.emit.expect("completing frame out").data).unwrap();
        assert!(!released.contains("{{"), "tail must not leak: {released}");
        assert!(
            emitted.contains(KEY),
            "value must be whole in the completing frame: {emitted}"
        );
    }

    #[test]
    fn streaming_releases_a_held_frame_when_nothing_continues_it() {
        let ctx = Arc::new(ctx());
        let (masked, _) = mask(KEY, &ctx);
        let masked = masked.into_owned();
        let (head, _) = masked.split_at(masked.len() / 2);
        let mut restore = StreamRestore::new(Some(Arc::clone(&ctx)));

        let _ = restore.frame(None, &frame(head, 0));
        // A frame on another channel (index 7) does not continue it.
        let other = restore.frame(None, &frame("bye", 7));
        let released = String::from_utf8(other.release.expect("held frame out").data).unwrap();
        assert!(released.contains(head), "held text lost: {released}");
    }

    #[test]
    fn streaming_passes_plain_frames_through_untouched() {
        let ctx = Arc::new(ctx());
        let plain = frame("hello world", 0);
        let mut restore = StreamRestore::new(Some(ctx));
        let out = restore.frame(None, &plain);
        assert_eq!(out.emit.expect("emitted").data, plain);
        assert!(restore.finish().is_none());
    }

    #[test]
    fn streaming_is_a_pass_through_with_no_context() {
        let plain = frame("hello world", 0);
        let mut restore = StreamRestore::new(None);
        let out = restore.frame(None, &plain);
        assert_eq!(out.emit.expect("emitted").data, plain);
        assert!(restore.finish().is_none());
    }

    #[test]
    fn streaming_finish_releases_the_tail() {
        let ctx = Arc::new(ctx());
        let (masked, _) = mask(KEY, &ctx);
        let masked = masked.into_owned();
        let (head, _) = masked.split_at(masked.len() / 2);
        let mut restore = StreamRestore::new(Some(Arc::clone(&ctx)));
        let _ = restore.frame(None, &frame(head, 0));
        let tail = restore.finish().expect("held tail released at end");
        assert!(String::from_utf8(tail.data).unwrap().contains(head));
    }

    #[test]
    fn masking_and_restoring_are_idempotent() {
        let ctx = ctx();
        let (masked, first) = mask(MAIL, &ctx);
        assert_eq!(first, 1);
        // Masking an already-masked value adds nothing.
        let (again, hits) = mask(&masked, &ctx);
        assert_eq!(hits, 0, "double masking: {again}");
        assert_eq!(masked, again);
        // Restore puts the value back and is a no-op the second time.
        let restored = restore(&masked, false, &ctx).into_owned();
        assert_eq!(restored, MAIL);
        assert_eq!(restore(&restored, false, &ctx).into_owned(), MAIL);
    }

    #[test]
    fn round_trip_preserves_escapes() {
        for raw in [
            "plain-abc",
            "with \"quote\"",
            "line\nbreak",
            "back\\slash",
            "tab\there",
        ] {
            let ctx = ctx();
            let placeholder = placeholders::placeholder_for("TERM", raw);
            ctx.remember("TERM", raw, &placeholder);
            let body = serde_json::json!({"content": format!("x {placeholder} y")});
            let bytes = serde_json::to_vec(&body).unwrap();
            let out = restore_json(&bytes, Some(&ctx));
            let parsed: serde_json::Value = serde_json::from_slice(&out).unwrap();
            assert_eq!(
                parsed["content"],
                serde_json::json!(format!("x {raw} y")),
                "round trip corrupted {raw:?}: {out:?}"
            );
        }
    }

    #[test]
    fn restore_skips_opaque_carriers() {
        let ctx = ctx();
        let (masked, _) = mask(MAIL, &ctx);
        let placeholder = masked.into_owned();
        // The same placeholder in plain text and inside a block that also
        // carries a signature: the block went out verbatim, so it comes back
        // verbatim — restoring inside it would void the signature.
        let body = format!(
            r#"{{"text":"{placeholder}","block":{{"type":"thinking","thinking":"{placeholder}","signature":"{placeholder}"}}}}"#
        );
        let out = String::from_utf8(restore_json(body.as_bytes(), Some(&ctx))).unwrap();
        assert_eq!(
            out.matches(MAIL).count(),
            1,
            "the plain text is restored: {out}"
        );
        assert_eq!(
            out.matches(&placeholder).count(),
            2,
            "the signed block stays verbatim: {out}"
        );
    }

    #[test]
    fn a_non_json_body_is_restored_as_raw_text() {
        let ctx = ctx();
        let (masked, _) = mask(MAIL, &ctx);
        let body = format!("upstream said: {masked} (not json)");
        let out = String::from_utf8(restore_json(body.as_bytes(), Some(&ctx))).unwrap();
        assert!(out.contains(MAIL), "{out}");
    }

    #[test]
    fn a_binary_body_is_left_alone() {
        let ctx = ctx();
        let mut body = b"{{PHONE_aaaaaaaa}}".to_vec();
        body.extend_from_slice(&[0xff, 0xfe, 0x00]);
        assert_eq!(restore_json(&body, Some(&ctx)), body);
    }

    /// A digit run inside an opaque blob (base64 image, hex checksum) is not a
    /// phone number: its neighbours are alphanumeric, so the rule declines.
    /// Masking it would corrupt the payload and the upstream would reject it.
    #[test]
    fn an_opaque_blob_is_not_mistaken_for_prose() {
        let ctx = ctx();
        for blob in [
            "iVBORw0KGgo13800138000AAAAB",
            "sha256=ab12cd13800138000ef34",
            "data:image/png;base64,9j4AA13800138000QQ",
        ] {
            let (out, hits) = mask(blob, &ctx);
            assert_eq!(hits, 0, "{blob} was rewritten as {out}");
            assert_eq!(out, blob);
        }
        // The same digits in prose still match.
        let (out, hits) = mask("call 13800138000 now", &ctx);
        assert_eq!(hits, 1, "{out}");
    }

    /// A secret a rule found only through its context (`user:pass@host`) is
    /// remembered even when it is shorter than the 8-char floor the assignment
    /// rules use, so a bare replay is still masked.
    #[test]
    fn a_short_secret_is_remembered_for_a_bare_replay() {
        let ctx = ctx();
        let (masked, hits) = mask("redis://default:hunter2@cache", &ctx);
        assert_eq!(hits, 1, "{masked}");
        assert!(!masked.contains("hunter2"), "{masked}");
        let placeholder = placeholders::placeholder_for("PASSWORD", "hunter2");

        let later = super::tests::ctx();
        let (again, hits) = mask("the pass is hunter2 ok", &later);
        assert_eq!(hits, 1, "bare short replay: {again}");
        assert!(again.contains(&placeholder), "{again}");
    }

    /// A value the index remembers must not survive into a stored log: the scrub
    /// consults the index too, not only the rules.
    #[test]
    fn scrub_redacts_a_value_only_the_index_knows() {
        let ctx = ctx();
        let (masked, hits) = mask("redis://default:s3cr3tpw@cache", &ctx);
        assert_eq!(hits, 1, "{masked}");

        let logged = scrub("the pass is s3cr3tpw ok");
        assert!(!logged.contains("s3cr3tpw"), "{logged}");
        assert!(logged.contains("[REDACTED:PASSWORD]"), "{logged}");
    }
}
