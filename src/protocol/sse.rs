//! Bounded SSE framing shared by the server-role kernels (observation) and the
//! gateway relay consumer's `upstream` (wire reading) and `translation`
//! (stream re-encoding) layers (B §4.1, §4.7).
//!
//! Framing only: it never interprets protocol payloads. Every limit is explicit
//! so a hostile or broken upstream cannot grow memory without bound:
//! - a single line may not exceed [`MAX_LINE_BYTES`];
//! - a single event (all its `data:` lines) may not exceed [`MAX_EVENT_BYTES`].
//!
//! This is the server role's push-based, raw-preserving framer for the relay
//! pump. The client role's pull-based parser for semantic decode lives at
//! `crate::client::streaming::sse` — the two are deliberately separate.

use bytes::{Bytes, BytesMut};

/// Maximum bytes accumulated for one dispatched event.
pub const MAX_EVENT_BYTES: usize = 4 * 1024 * 1024;
/// Maximum bytes in one SSE line, including the trailing newline.
///
/// A `data:` line carries a whole JSON payload, and a Responses upstream echoes
/// the full request (instructions, tools, input) inside `response.created` and
/// `response.completed`, so a long prompt makes one line as large as the
/// event. The line cap therefore equals the event cap: a smaller one fails
/// every request whose prompt passes it.
pub const MAX_LINE_BYTES: usize = MAX_EVENT_BYTES;
/// A parsed SSE event whose data remains in its reference-counted byte buffer.
///
/// This is intentionally a framing-level type: protocol kernels decide how to
/// interpret `data`. Use [`RawFrame::into_frame`] only at compatibility
/// boundaries that still require the legacy string representation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawFrame {
    pub event: Option<String>,
    pub id: Option<String>,
    pub data: Bytes,
}

impl RawFrame {
    /// Convert this frame to the legacy owned-string representation.
    pub fn into_frame(self) -> Result<Frame, SseError> {
        let data = String::from_utf8(self.data.to_vec()).map_err(|_| SseError::InvalidUtf8)?;
        Ok(Frame {
            event: self.event,
            id: self.id,
            data,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub event: Option<String>,
    pub id: Option<String>,
    pub data: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SseError {
    LineTooLong,
    EventTooLarge,
    InvalidUtf8,
}

impl std::fmt::Display for SseError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::LineTooLong => "SSE line exceeds the limit",
            Self::EventTooLarge => "SSE event exceeds the limit",
            Self::InvalidUtf8 => "SSE payload is not valid UTF-8",
        })
    }
}

impl std::error::Error for SseError {}

/// Incremental SSE parser. Feed chunks, receive complete frames.
pub struct Framer {
    line: Vec<u8>,
    data: BytesMut,
    event: Option<String>,
    id: Option<String>,
    event_bytes: usize,
    skip_lf: bool,
    started: bool,
}

impl Default for Framer {
    fn default() -> Self {
        Self::new()
    }
}

impl Framer {
    pub fn new() -> Self {
        Self {
            line: Vec::new(),
            data: BytesMut::new(),
            event: None,
            id: None,
            event_bytes: 0,
            skip_lf: false,
            started: false,
        }
    }

    /// Feed a chunk without copying completed data into a `String`.
    ///
    /// The chunk is scanned run by run: a line that lies wholly inside the
    /// chunk is parsed in place, and only a line split across chunks is
    /// buffered. An error is terminal (the caller marks its stream broken and
    /// never feeds the framer again), and the frames this call already
    /// completed are discarded with it.
    pub fn push_raw(&mut self, chunk: &[u8]) -> Result<Vec<RawFrame>, SseError> {
        let mut frames = Vec::new();
        let mut rest = chunk;
        if !self.started {
            self.started = true;
            if rest.len() >= 3 && rest[..3] == [0xEF, 0xBB, 0xBF] {
                rest = &rest[3..];
            }
        }
        while let Some((&first, tail)) = rest.split_first() {
            if self.skip_lf {
                self.skip_lf = false;
                if first == b'\n' {
                    rest = tail;
                    continue;
                }
            }
            let Some(end) = rest.iter().position(|byte| matches!(byte, b'\n' | b'\r')) else {
                self.append(rest)?;
                break;
            };
            let run = &rest[..end];
            if self.line.is_empty() && run.len() <= MAX_LINE_BYTES {
                self.dispatch_line(run, &mut frames)?;
            } else {
                self.append(run)?;
                self.end_line(&mut frames)?;
            }
            if rest[end] == b'\r' {
                self.skip_lf = true;
            }
            rest = &rest[end + 1..];
        }
        Ok(frames)
    }

    /// Flush a trailing partial line/event without allocating a string copy.
    pub fn finish_raw(&mut self) -> Result<Vec<RawFrame>, SseError> {
        let mut frames = Vec::new();
        if !self.line.is_empty() {
            self.end_line(&mut frames)?;
        }
        if !self.data.is_empty() {
            frames.push(self.take_event());
        }
        Ok(frames)
    }

    /// Buffer part of a line that continues past the current chunk.
    fn append(&mut self, run: &[u8]) -> Result<(), SseError> {
        if self.line.len() + run.len() > MAX_LINE_BYTES {
            return Err(SseError::LineTooLong);
        }
        self.line.extend_from_slice(run);
        Ok(())
    }

    /// Parse the buffered line, then empty the buffer keeping its capacity.
    fn end_line(&mut self, frames: &mut Vec<RawFrame>) -> Result<(), SseError> {
        let mut line = std::mem::take(&mut self.line);
        let result = self.dispatch_line(&line, frames);
        line.clear();
        self.line = line;
        result
    }

    fn dispatch_line(&mut self, line: &[u8], frames: &mut Vec<RawFrame>) -> Result<(), SseError> {
        if line.is_empty() {
            if !self.data.is_empty() {
                frames.push(self.take_event());
            }
            return Ok(());
        }
        if line[0] == b':' {
            return Ok(());
        }
        let (field, value) = match line.iter().position(|byte| *byte == b':') {
            Some(position) => {
                let value = &line[position + 1..];
                (
                    &line[..position],
                    if value.first() == Some(&b' ') {
                        &value[1..]
                    } else {
                        value
                    },
                )
            }
            None => (line, &line[line.len()..]),
        };
        let value = std::str::from_utf8(value).map_err(|_| SseError::InvalidUtf8)?;
        match field {
            b"data" => {
                self.event_bytes += value.len() + 1;
                if self.event_bytes > MAX_EVENT_BYTES {
                    return Err(SseError::EventTooLarge);
                }
                self.data.extend_from_slice(value.as_bytes());
                self.data.extend_from_slice(b"\n");
            }
            b"event" => self.event = Some(value.to_owned()),
            b"id" => self.id = Some(value.to_owned()),
            _ => {}
        }
        Ok(())
    }

    fn take_event(&mut self) -> RawFrame {
        if self.data.last() == Some(&b'\n') {
            self.data.truncate(self.data.len() - 1);
        }
        let frame = RawFrame {
            event: self.event.take(),
            id: self.id.take(),
            data: self.data.split().freeze(),
        };
        self.event_bytes = 0;
        frame
    }
}
