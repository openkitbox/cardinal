//! AWS Event Stream framing for the Kiro (KAS) response wire.
//!
//! KAS answers with a binary event stream, not SSE:
//!
//! ```text
//! +-------------+--------------+------------+---------+---------+---------+
//! | Total Len   | Header Len   | Prelude CRC| Headers | Payload | Msg CRC |
//! |  (4 bytes)  |  (4 bytes)   | (4 bytes)  | (var)   | (var)   |(4 bytes)|
//! +-------------+--------------+------------+---------+---------+---------+
//! ```
//!
//! * total length includes itself;
//! * the prelude CRC covers the two length fields;
//! * the message CRC covers every byte before it.
//!
//! [`Framer`] accepts arbitrary byte chunks and yields only completed
//! messages, so a socket read boundary can fall anywhere inside a frame.
//! Completed frames are split off the accumulation buffer
//! (`BytesMut::split_to`) and sliced (`Bytes::slice`), so neither the payload
//! nor a byte-array header value is copied per chunk.
//!
//! Deliberate deviations from the reference implementation
//! (`kiro2claude` `parser/frame.ts`), where the wire bytes are identical:
//!
//! * Length bounds (`total >= 16`, `total <= MAX_FRAME`, header length fits
//!   between prelude and message CRC) are checked **before** the prelude CRC,
//!   so a malformed length reports [`AwsError::InvalidLength`] /
//!   [`AwsError::FrameTooLarge`] instead of being masked as a CRC mismatch.
//!   The reference checks the length range, then awaits the full message,
//!   then the CRC.
//! * The prelude CRC is verified as soon as the 12-byte prelude has arrived;
//!   the body is only awaited afterwards. The reference awaits the full
//!   message before verifying either CRC.
//! * Header names and string values must be valid UTF-8 ([`AwsError::InvalidUtf8`]).
//!   The reference decodes with `Buffer::toString('utf-8')`, which silently
//!   substitutes U+FFFD, so a lossy decode cannot be mistaken for real text.
//! * Headers stay an ordered `Vec` of `(name, value)` pairs instead of the
//!   reference's map: order and duplicates are preserved. Lookups (see
//!   [`Message::string_header`]) take the **first string-typed** match;
//!   duplicate names are first-wins, whereas the reference's `Map::set` makes
//!   them last-wins, and a non-string value never masks a later string value.
//! * A malformed header region inside an already length-validated frame is
//!   [`AwsError::InvalidHeader`], never "incomplete": completeness is decided
//!   by `total` alone.
//! * Header parsing is bounded against amplification (deliberate): a frame may
//!   declare a header region up to `MAX_FRAME` and each header allocates its
//!   name (and string value), so an attacker-sized header region would
//!   otherwise multiply a 16 MiB frame into millions of allocations. The
//!   region is capped at [`MAX_HEADER_REGION`] and the count at
//!   [`MAX_HEADERS`]; both are checked with constants **before** the offending
//!   name is allocated and both report [`AwsError::InvalidHeader`]. The
//!   reference has no such bound.
//! * `push` returns the frames completed by a chunk, but an error on a later
//!   frame discards the frames already parsed in that same call (a corrupted
//!   stream is terminal, so the caller drops the framer instead of committing
//!   a partial batch).
//! * `Message::payload` and byte-array header values are `Bytes::slice`s of the
//!   completed frame, so they retain that frame's whole allocation for as long
//!   as they live (the reference's `subarray` behaves the same way).
//!
//! An error is terminal — the framer's buffer is left in an undefined state
//! and the caller drops it (a corrupted stream cannot be resynchronized).
//!
//! These headers are transport metadata (`:message-type`, `:event-type`,
//! `:exception-type`, …). They are read here and must never be copied into a
//! client-facing event; the KAS kernel translates payloads only.

use bytes::{Bytes, BytesMut};

/// Largest accepted frame, including its 12-byte prelude and 4-byte CRC.
pub const MAX_FRAME: usize = 16 << 20;

/// Fixed prelude: total length, header length, prelude CRC.
const PRELUDE: usize = 12;

/// Smallest possible frame: prelude plus the message CRC, no headers/payload.
const MIN_FRAME: usize = PRELUDE + 4;

/// Largest accepted header region (deliberate amplification bound, see the
/// module docs): the region is otherwise only bounded by [`MAX_FRAME`].
const MAX_HEADER_REGION: usize = 64 << 10;

/// Largest accepted number of headers per frame (deliberate amplification
/// bound, see the module docs).
const MAX_HEADERS: usize = 1024;

/// One header value, exactly the ten types the protocol defines.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HeaderValue {
    Bool(bool),
    Byte(i8),
    Short(i16),
    Integer(i32),
    Long(i64),
    Bytes(Bytes),
    String(String),
    /// Milliseconds since the Unix epoch.
    Timestamp(i64),
    Uuid([u8; 16]),
}

/// One completed frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    pub headers: Vec<(String, HeaderValue)>,
    pub payload: Bytes,
}

impl Message {
    /// The first string-typed header with this name; a header of another type
    /// with the same name is skipped rather than masking a later string value.
    /// Duplicates are first-wins.
    pub fn string_header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find_map(|(header, value)| match value {
            HeaderValue::String(text) if header == name => Some(text.as_str()),
            _ => None,
        })
    }
}

/// Framing failure. Terminal: the framer must be dropped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AwsError {
    /// The stream ended in the middle of a frame.
    Truncated,
    /// The declared total length exceeds [`MAX_FRAME`].
    FrameTooLarge,
    /// The declared total/header length cannot describe a frame.
    InvalidLength,
    /// The prelude CRC does not cover the two length fields.
    InvalidPreludeCrc,
    /// The message CRC does not cover the preceding bytes.
    InvalidMessageCrc,
    /// A header is malformed: unknown type, empty name, or overruns its region.
    InvalidHeader,
    /// A header name or string value is not valid UTF-8.
    InvalidUtf8,
}

/// Incremental frame parser.
#[derive(Debug, Default)]
pub struct Framer {
    buffer: BytesMut,
}

impl Framer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Append one chunk and return the frames it completed. A frame is only
    /// returned once its whole byte range has arrived and both CRCs match.
    pub fn push(&mut self, chunk: &[u8]) -> Result<Vec<Message>, AwsError> {
        self.buffer.extend_from_slice(chunk);
        let mut messages = Vec::new();
        while let Some(message) = self.next_frame()? {
            messages.push(message);
        }
        Ok(messages)
    }

    /// The stream ended here: clean only when nothing is buffered.
    pub fn finish(&self) -> Result<(), AwsError> {
        if self.buffer.is_empty() {
            Ok(())
        } else {
            Err(AwsError::Truncated)
        }
    }

    fn next_frame(&mut self) -> Result<Option<Message>, AwsError> {
        if self.buffer.len() < PRELUDE {
            return Ok(None);
        }
        let total = be_u32(&self.buffer, 0)? as usize;
        let header_length = be_u32(&self.buffer, 4)? as usize;
        if total < MIN_FRAME {
            return Err(AwsError::InvalidLength);
        }
        if total > MAX_FRAME {
            return Err(AwsError::FrameTooLarge);
        }
        // The CRC trailer must start at or after the end of the header region.
        if header_length > total - MIN_FRAME {
            return Err(AwsError::InvalidLength);
        }
        let prelude_crc = be_u32(&self.buffer, 8)?;
        if crc32fast::hash(&self.buffer[..8]) != prelude_crc {
            return Err(AwsError::InvalidPreludeCrc);
        }
        if self.buffer.len() < total {
            return Ok(None);
        }
        let message_crc = be_u32(&self.buffer, total - 4)?;
        if crc32fast::hash(&self.buffer[..total - 4]) != message_crc {
            return Err(AwsError::InvalidMessageCrc);
        }

        // Everything below reads from the completed frame: split it off the
        // accumulation buffer and slice it, so payload and byte-array headers
        // share the received allocation instead of being copied.
        let frame = self.buffer.split_to(total).freeze();
        let headers = parse_headers(&frame, PRELUDE, header_length)?;
        let payload = frame.slice(PRELUDE + header_length..total - 4);
        Ok(Some(Message { headers, payload }))
    }
}

fn be_u32(data: &[u8], offset: usize) -> Result<u32, AwsError> {
    let bytes = data
        .get(offset..offset + 4)
        .ok_or(AwsError::InvalidLength)?;
    let array: [u8; 4] = bytes.try_into().map_err(|_| AwsError::InvalidLength)?;
    Ok(u32::from_be_bytes(array))
}

/// A fixed-size byte array. The slice comes from [`take`], so it is already
/// confined to the header region; conversion is fallible rather than panicking
/// on a short slice.
fn be_bytes<const N: usize>(data: &[u8]) -> Result<[u8; N], AwsError> {
    data.try_into().map_err(|_| AwsError::InvalidHeader)
}

/// The `count` bytes at `offset`, confined to the header region `[.., end)`.
fn take(data: &[u8], end: usize, offset: usize, count: usize) -> Result<&[u8], AwsError> {
    let limit = offset
        .checked_add(count)
        .filter(|limit| *limit <= end)
        .ok_or(AwsError::InvalidHeader)?;
    data.get(offset..limit).ok_or(AwsError::InvalidHeader)
}

/// The single byte at `offset`, confined to the header region.
fn byte(data: &[u8], end: usize, offset: usize) -> Result<u8, AwsError> {
    match take(data, end, offset, 1)? {
        [value] => Ok(*value),
        _ => Err(AwsError::InvalidHeader),
    }
}

/// Parse the header region exactly: leftover bytes are an error, never ignored.
fn parse_headers(
    frame: &Bytes,
    start: usize,
    length: usize,
) -> Result<Vec<(String, HeaderValue)>, AwsError> {
    // Deliberate amplification bounds: reject before parsing (and before
    // allocating a single name) rather than multiplying the frame allocation.
    if length > MAX_HEADER_REGION {
        return Err(AwsError::InvalidHeader);
    }
    let end = start + length;
    let mut offset = start;
    let mut headers: Vec<(String, HeaderValue)> = Vec::new();
    while offset < end {
        if headers.len() >= MAX_HEADERS {
            return Err(AwsError::InvalidHeader);
        }
        let name_length = byte(frame, end, offset)? as usize;
        offset += 1;
        if name_length == 0 {
            return Err(AwsError::InvalidHeader);
        }
        let name_bytes = take(frame, end, offset, name_length)?;
        let name = std::str::from_utf8(name_bytes)
            .map_err(|_| AwsError::InvalidUtf8)?
            .to_owned();
        offset += name_length;

        // The type byte belongs to the header region: a name that ends exactly
        // at `end` has no value and must not borrow the first payload byte.
        let value_type = byte(frame, end, offset)?;
        offset += 1;
        let (value, consumed) = parse_value(frame, end, offset, value_type)?;
        offset += consumed;
        headers.push((name, value));
    }
    Ok(headers)
}

/// One header value; returns the value and how many bytes it consumed.
fn parse_value(
    frame: &Bytes,
    end: usize,
    offset: usize,
    value_type: u8,
) -> Result<(HeaderValue, usize), AwsError> {
    match value_type {
        0 => Ok((HeaderValue::Bool(true), 0)),
        1 => Ok((HeaderValue::Bool(false), 0)),
        2 => Ok((
            HeaderValue::Byte(i8::from_be_bytes(be_bytes(take(frame, end, offset, 1)?)?)),
            1,
        )),
        3 => Ok((
            HeaderValue::Short(i16::from_be_bytes(be_bytes(take(frame, end, offset, 2)?)?)),
            2,
        )),
        4 => Ok((
            HeaderValue::Integer(i32::from_be_bytes(be_bytes(take(frame, end, offset, 4)?)?)),
            4,
        )),
        5 => Ok((
            HeaderValue::Long(i64::from_be_bytes(be_bytes(take(frame, end, offset, 8)?)?)),
            8,
        )),
        6 => {
            let length = u16::from_be_bytes(be_bytes(take(frame, end, offset, 2)?)?) as usize;
            take(frame, end, offset + 2, length)?;
            let value = frame.slice(offset + 2..offset + 2 + length);
            Ok((HeaderValue::Bytes(value), 2 + length))
        }
        7 => {
            let length = u16::from_be_bytes(be_bytes(take(frame, end, offset, 2)?)?) as usize;
            let body = take(frame, end, offset + 2, length)?;
            let text = std::str::from_utf8(body)
                .map_err(|_| AwsError::InvalidUtf8)?
                .to_owned();
            Ok((HeaderValue::String(text), 2 + length))
        }
        8 => Ok((
            HeaderValue::Timestamp(i64::from_be_bytes(be_bytes(take(frame, end, offset, 8)?)?)),
            8,
        )),
        9 => Ok((
            HeaderValue::Uuid(be_bytes(take(frame, end, offset, 16)?)?),
            16,
        )),
        _ => Err(AwsError::InvalidHeader),
    }
}
