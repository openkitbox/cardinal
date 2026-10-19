//! Streaming (SSE) restore: put masked values back in a stream as it arrives.
//!
//! The hard part is a placeholder an upstream splits across two frames — a text
//! delta ending `{{API_` and the next carrying `KEY_k3v9x2mq}}`. SSE frames are
//! independent JSON documents, so the two cannot be joined as raw bytes: the
//! partial placeholder must be held *at its own JSON path* and finished on the
//! frame that completes the same path, with the held frame's other bytes emitted
//! first. This is magpie's `redact.Writer` mechanism.
//!
//! The state machine is owned here so the relay's frame sender only has to hand
//! over `(event, data)` and write what comes back.

use std::sync::Arc;

use serde_json::Value;

use super::MaskCtx;

/// Which text an event continues: the event name plus the identifiers a vendor
/// puts on a channel (its own `type`, `item_id`, and the numeric `index`es).
type Ctx = String;

/// One frame to write to the client.
pub(crate) struct OutFrame {
    pub event: Option<String>,
    pub data: Vec<u8>,
}

/// What one incoming frame produces.
pub(crate) struct Emit {
    /// The frame held by the previous call, released now (write it first).
    pub release: Option<OutFrame>,
    /// This frame's payload, when it is not itself being held.
    pub emit: Option<OutFrame>,
}

/// A partial placeholder held at the path it started at.
struct Held {
    ctx: Ctx,
    path: String,
    tail: String,
    /// The payload restored, without the tail (written when the next frame
    /// continues this one).
    cut: Vec<u8>,
}

/// Per-stream restore state.
pub(crate) struct StreamRestore {
    /// The request's masking context; `None` (nothing was masked) makes the
    /// whole thing a pass-through.
    ctx: Option<Arc<MaskCtx>>,
    held: Option<(Option<String>, Held, Vec<u8>)>,
}

impl StreamRestore {
    pub(crate) fn new(ctx: Option<Arc<MaskCtx>>) -> Self {
        Self { ctx, held: None }
    }

    /// Restore one SSE payload. A payload that carries no placeholder and
    /// continues nothing is passed through byte for byte — no parse, no
    /// re-serialize.
    pub(crate) fn frame(&mut self, event: Option<&str>, data: &[u8]) -> Emit {
        let out = |data: Vec<u8>| OutFrame {
            event: event.map(str::to_string),
            data,
        };
        let Some(ctx) = self.ctx.as_ref().cloned() else {
            return Emit {
                release: None,
                emit: Some(out(data.to_vec())),
            };
        };
        if self.held.is_none() && !super::contains_open(data) {
            return Emit {
                release: None,
                emit: Some(out(data.to_vec())),
            };
        }
        // A payload that is not JSON cannot continue a hold, and its tail cannot
        // be picked up: release whatever was held whole (lossless) and move on.
        let Ok(mut value) = serde_json::from_slice::<Value>(data) else {
            return Emit {
                release: self
                    .held
                    .take()
                    .map(|(event, _, full)| OutFrame { event, data: full }),
                emit: Some(out(data.to_vec())),
            };
        };

        let (full, joined, next) = restore_payload(event, &mut value, self.held.as_ref(), &ctx);
        // Release the held frame now that this one has been walked: either its
        // cut form, when the value was continued here, or the whole original
        // when this frame had nothing to do with it.
        let release = self.held.take().map(|(event, held, whole)| OutFrame {
            event,
            data: if joined { held.cut } else { whole },
        });
        match next {
            // Hold this frame until the placeholder that starts in it ends.
            Some(held) => {
                self.held = Some((event.map(str::to_string), held, full));
                Emit {
                    release,
                    emit: None,
                }
            }
            None => Emit {
                release,
                emit: Some(out(full)),
            },
        }
    }

    /// Release whatever is held, at end of stream (lossless: the tail goes out).
    pub(crate) fn finish(&mut self) -> Option<OutFrame> {
        self.held
            .take()
            .map(|(event, _held, full)| OutFrame { event, data: full })
    }
}

/// Restore the values in one JSON payload, report whether it continued the held
/// frame, and hand back a trailing partial placeholder to hold. The returned
/// bytes are the payload with this frame's values restored.
fn restore_payload(
    event: Option<&str>,
    value: &mut Value,
    held: Option<&(Option<String>, Held, Vec<u8>)>,
    ctx: &MaskCtx,
) -> (Vec<u8>, bool, Option<Held>) {
    let channel = ctx_of(value, event);
    // The held tail is only joined when this frame belongs to the same channel.
    let carry = held.filter(|(_, held, _)| held.ctx == channel);
    let carry_path = carry.map(|(_, held, _)| held.path.clone());
    let carry_tail = carry
        .map(|(_, held, _)| held.tail.clone())
        .unwrap_or_default();
    let mut joined = false;

    let mut tail: Option<(String, String)> = None;
    super::walk_strings(value, &mut String::new(), "", &mut |path, key, text| {
        if super::structural(key) {
            return text.to_string();
        }
        let text = if Some(path) == carry_path.as_deref() {
            joined = true;
            format!("{carry_tail}{text}")
        } else {
            text.to_string()
        };
        let (_, partial) = split_partial(&text);
        if !partial.is_empty() {
            tail = Some((path.to_string(), partial.to_string()));
        }
        super::restore(&text, super::as_json(key, event), ctx).into_owned()
    });

    let (path, tail_text) = match tail {
        None => return (serialize(value), joined, None),
        Some(found) => found,
    };
    // Serialize the full form first: the cut form below mutates `value` in place.
    let full = serialize(value);
    super::walk_strings(value, &mut String::new(), "", &mut |p, _, text| {
        if p == path {
            let (head, _) = split_partial(text);
            return super::restore(head, false, ctx).into_owned();
        }
        text.to_string()
    });
    let cut = serialize(value);
    (
        full,
        joined,
        Some(Held {
            ctx: channel,
            path,
            tail: tail_text,
            cut,
        }),
    )
}

fn serialize(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).unwrap_or_default()
}

/// The context key of a payload: the event name and the channel identifiers.
fn ctx_of(value: &Value, event: Option<&str>) -> Ctx {
    let mut out = String::new();
    if let Some(event) = event {
        out.push_str(event);
        out.push('|');
    }
    ctx_walk(value, &mut out);
    out
}

fn ctx_walk(value: &Value, out: &mut String) {
    match value {
        Value::Object(object) => {
            for (key, item) in object {
                match key.as_str() {
                    "type" | "item_id" => {
                        if let Some(text) = item.as_str() {
                            out.push_str(text);
                            out.push(';');
                        }
                    }
                    "index" | "output_index" | "content_index" => {
                        if let Some(number) = item.as_i64() {
                            out.push_str(&number.to_string());
                            out.push(';');
                        }
                    }
                    _ => {}
                }
                ctx_walk(item, out);
            }
        }
        Value::Array(items) => items.iter().for_each(|item| ctx_walk(item, out)),
        _ => {}
    }
}

/// The longest placeholder the renderer writes (`{{` + kind + `_` + 8 + `}}`).
const MAX_PLACEHOLDER: usize = 48;

/// Split a string into (head, partial) where `partial` is a trailing fragment
/// that may be the start of a placeholder the next frame finishes.
fn split_partial(s: &str) -> (&str, &str) {
    let Some(at) = s.rfind('{') else {
        return (s, "");
    };
    let start = if at > 0 && s.as_bytes()[at - 1] == b'{' {
        at - 1
    } else {
        at
    };
    let tail = &s[start..];
    if tail.len() > MAX_PLACEHOLDER || tail.contains("}}") {
        return (s, "");
    }
    let body = tail.trim_start_matches('{').trim_start_matches([' ', '\t']);
    if body.is_empty() {
        return (&s[..start], tail);
    }
    if !body
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'}' || b == b' ')
    {
        return (s, "");
    }
    (&s[..start], tail)
}
